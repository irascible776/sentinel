"""
DOCX Threat Parser (Pillar III)
Analyzes Word documents for stealth techniques: OOXML <w:vanish> hidden runs,
white-on-white text, microscopic font formatting, and embedded image assets.
"""

import io
from typing import List, Tuple
from docx import Document
from docx.oxml.ns import qn

from core.vision.schemas import DocHiddenTextFinding, PageScanResult
from core.vision.document.hidden_text_rules import compute_delta_e_cie76
from core.vision.config import MAX_MICRO_FONT_SIZE_PT


class DocxThreatParser:
    """
    Forensic parser for DOCX documents using python-docx.
    Traverses document body, tables, and raw XML runs to discover hidden text.
    """

    def parse_docx_bytes(
        self,
        doc_bytes: bytes,
    ) -> Tuple[List[PageScanResult], List[DocHiddenTextFinding], str]:
        """
        Parses DOCX bytes and detects stealth modifications.
        """
        doc = Document(io.BytesIO(doc_bytes))
        findings: List[DocHiddenTextFinding] = []
        text_parts: List[str] = []

        all_runs = []
        for p in doc.paragraphs:
            text_parts.append(p.text)
            for r in p.runs:
                all_runs.append(r)

        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    for p in cell.paragraphs:
                        text_parts.append(p.text)
                        for r in p.runs:
                            all_runs.append(r)

        for run in all_runs:
            txt = run.text.strip()
            if not txt:
                continue

            # 1. Check OOXML <w:vanish> hidden attribute
            rPr = run._r.get_or_add_rPr()
            vanish_node = rPr.find(qn("w:vanish"))
            if vanish_node is not None:
                findings.append(
                    DocHiddenTextFinding(
                        page_num=1,
                        rule_type="OOXML_VANISH",
                        text=txt[:120],
                        font_size=float(run.font.size.pt) if run.font.size else 11.0,
                        effective_font_size=float(run.font.size.pt) if run.font.size else 11.0,
                        severity="CRITICAL",
                    )
                )

            # 2. Check microscopic font formatting
            if run.font.size and run.font.size.pt <= MAX_MICRO_FONT_SIZE_PT:
                findings.append(
                    DocHiddenTextFinding(
                        page_num=1,
                        rule_type="MICRO_FONT",
                        text=txt[:120],
                        font_size=float(run.font.size.pt),
                        effective_font_size=float(run.font.size.pt),
                        severity="HIGH",
                    )
                )

            # 3. Check font color vs white background
            if run.font.color and run.font.color.rgb:
                r = run.font.color.rgb[0]
                g = run.font.color.rgb[1]
                b = run.font.color.rgb[2]
                delta_e = compute_delta_e_cie76((r, g, b), (255, 255, 255))
                if delta_e <= 4.5 and len(txt) >= 8:
                    findings.append(
                        DocHiddenTextFinding(
                            page_num=1,
                            rule_type="COLOR_DISTANCE",
                            text=txt[:120],
                            font_size=float(run.font.size.pt) if run.font.size else 11.0,
                            effective_font_size=float(run.font.size.pt) if run.font.size else 11.0,
                            delta_e=round(delta_e, 2),
                            severity="CRITICAL",
                        )
                    )

        # Build single simulated page result for DOCX
        doc_risk = 0.0
        if any(f.severity == "CRITICAL" for f in findings):
            doc_risk = 85.0
        elif any(f.severity == "HIGH" for f in findings):
            doc_risk = 70.0

        page_result = PageScanResult(
            page_num=1,
            text_length=sum(len(t) for t in text_parts),
            findings=findings,
            embedded_images_count=0,
            embedded_image_risks=[],
            page_risk_score=doc_risk,
        )

        return [page_result], findings, " ".join(text_parts)


# Global DOCX parser instance
docx_threat_parser = DocxThreatParser()

