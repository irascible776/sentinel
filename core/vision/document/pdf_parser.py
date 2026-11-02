"""
PDF Threat Parser (Pillar III)
Analyzes multi-page PDF documents for hidden-text prompt injections,
microscopic typography, render-mode 3 invisibility, and embedded raster image threats.
"""

import io
from typing import List, Tuple, Dict, Any, Optional
from PIL import Image
import pymupdf as fitz

from core.vision.schemas import PageScanResult, DocHiddenTextFinding, BoundingBox
from core.vision.document.hidden_text_rules import evaluate_span_security
from core.vision.config import MAX_DOC_PAGES


class PDFThreatParser:
    """
    Deep forensic parser for PDF documents utilizing PyMuPDF (fitz).
    Exposes granular span-level graphics state, render modes, and embedded images.
    """

    def parse_pdf_bytes(
        self,
        doc_bytes: bytes,
        scan_embedded_images: bool = True,
        vision_engine=None,
    ) -> Tuple[List[PageScanResult], List[DocHiddenTextFinding], str]:
        """
        Parses PDF document bytes and inspects all pages and spans.

        Returns:
            (page_results, all_findings, aggregated_plain_text)
        """
        doc = fitz.open(stream=doc_bytes, filetype="pdf")
        total_pages = len(doc)

        if total_pages > MAX_DOC_PAGES:
            raise ValueError(
                f"Document exceeds maximum page threshold ({total_pages} > {MAX_DOC_PAGES})."
            )

        page_results: List[PageScanResult] = []
        all_findings: List[DocHiddenTextFinding] = []
        full_text_parts: List[str] = []

        for p_idx in range(total_pages):
            page = doc[p_idx]
            page_num = p_idx + 1
            pw, ph = float(page.rect.width), float(page.rect.height)

            raw_dict = page.get_text("rawdict")
            blocks = raw_dict.get("blocks", [])

            # Phase 1: Collect all font sizes to compute page median
            all_spans_data = []
            font_sizes = []

            for block in blocks:
                if block.get("type") == 0:  # Text block
                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            txt = span.get("text")
                            if not txt and "chars" in span:
                                txt = "".join(c.get("c", "") for c in span["chars"])
                            txt = (txt or "").strip()
                            span["text"] = txt
                            sz = float(span.get("size", 10.0))
                            if txt:
                                font_sizes.append(sz)
                                all_spans_data.append(span)
                                full_text_parts.append(txt)

            median_font = float(sorted(font_sizes)[len(font_sizes) // 2]) if font_sizes else 10.0

            # Phase 2: Inspect individual spans against security rules
            page_findings: List[DocHiddenTextFinding] = []

            for span in all_spans_data:
                txt = span.get("text", "")
                sz = float(span.get("size", 10.0))
                bbox = span.get("bbox", [0, 0, 0, 0])
                render_mode = int(span.get("render_mode", 0))

                # Color parsing: sRGB integer or tuple
                raw_color = span.get("color", 0)
                if isinstance(raw_color, int):
                    r = (raw_color >> 16) & 0xFF
                    g = (raw_color >> 8) & 0xFF
                    b = raw_color & 0xFF
                    font_rgb = (r, g, b)
                elif isinstance(raw_color, (list, tuple)) and len(raw_color) >= 3:
                    font_rgb = (int(raw_color[0]), int(raw_color[1]), int(raw_color[2]))
                else:
                    font_rgb = (0, 0, 0)

                # Estimate CTM scale from bounding box height vs nominal font size
                bbox_h = max(0.1, bbox[3] - bbox[1])
                ctm_scale = max(0.5, min(10.0, bbox_h / max(0.1, sz)))

                norm_box = BoundingBox(
                    x1=bbox[0],
                    y1=bbox[1],
                    x2=bbox[2],
                    y2=bbox[3],
                    is_normalized=False,
                )

                span_findings = evaluate_span_security(
                    text=txt,
                    font_size=sz,
                    ctm_scale=ctm_scale,
                    font_rgb=font_rgb,
                    bg_rgb=(255, 255, 255),  # Standard white page background
                    render_mode=render_mode,
                    box=norm_box,
                    page_w=pw,
                    page_h=ph,
                    page_median_font=median_font,
                    page_num=page_num,
                )

                page_findings.extend(span_findings)

            # Phase 3: Inspect embedded raster images
            embedded_risks: List[float] = []
            img_list = page.get_images(full=True)

            if scan_embedded_images and vision_engine is not None:
                for img_info in img_list:
                    xref = img_info[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image.get("image")
                    if image_bytes:
                        try:
                            pil_img = Image.open(io.BytesIO(image_bytes))
                            res = vision_engine.scan_image(image_bytes=image_bytes)
                            embedded_risks.append(res.composite_risk_score)
                        except Exception:
                            pass

            # Calculate page composite risk
            page_risk = 0.0
            if page_findings:
                # Critical findings (e.g. Color distance / zero contrast) score 85.0
                has_critical = any(f.severity == "CRITICAL" for f in page_findings)
                has_high = any(f.severity == "HIGH" for f in page_findings)
                if has_critical:
                    page_risk = 85.0
                elif has_high:
                    page_risk = 70.0
                else:
                    page_risk = 50.0

            if embedded_risks:
                max_img_risk = max(embedded_risks)
                page_risk = max(page_risk, max_img_risk)

            page_result = PageScanResult(
                page_num=page_num,
                text_length=sum(len(s.get("text", "")) for s in all_spans_data),
                findings=page_findings,
                embedded_images_count=len(img_list),
                embedded_image_risks=embedded_risks,
                page_risk_score=page_risk,
            )

            page_results.append(page_result)
            all_findings.extend(page_findings)

        doc.close()
        aggregated_text = " ".join(full_text_parts)
        return page_results, all_findings, aggregated_text


# Global PDF parser instance
pdf_threat_parser = PDFThreatParser()
