"""
Developer 3 (Utkarsh) - RAG Poisoning Detection Scanner (Add-on 11)
DTU B.Tech Minor Project (IT401) | Group 138

Intercepts retrieved knowledge-base chunks BEFORE they enter the LLM prompt context window.
Evaluates each chunk against Rohit's JudgeAgent (Multi-Agent Defense Engine) to detect
indirect prompt injection, administrative override directives, and exfiltration attempts.
"""

import os
from typing import List, Dict, Any, Optional
from core.detection.judge import JudgeAgent


class RAGScanResult:
    """
    Structured outcome of a RAG document / chunk scan.
    Implements dict-like access for full backward and cross-module compatibility.
    """
    def __init__(self, safe_chunks: List[str], quarantined_chunks: List[Dict[str, Any]], is_poisoned: bool):
        self.safe_chunks = safe_chunks
        self.quarantined_chunks = quarantined_chunks
        self.is_poisoned = is_poisoned

    def to_dict(self) -> Dict[str, Any]:
        return {
            "safe_chunks": self.safe_chunks,
            "quarantined_chunks": self.quarantined_chunks,
            "is_poisoned": self.is_poisoned
        }

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def __repr__(self) -> str:
        return f"<RAGScanResult safe={len(self.safe_chunks)} quarantined={len(self.quarantined_chunks)} poisoned={self.is_poisoned}>"


class RAGScanner:
    """
    RAG Poisoning Scanner.
    Calls Rohit's JudgeAgent (direct Python in-process call) to evaluate untrusted chunks.
    """
    def __init__(self, judge: Optional[JudgeAgent] = None, quarantine_threshold: float = 75.0):
        self.judge = judge or JudgeAgent()
        self.quarantine_threshold = quarantine_threshold

    def chunk_text(self, text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
        """
        Splits raw text into sliding window overlapping chunks to prevent
        adversarial payloads split across boundary lines from escaping detection.
        """
        if not text or not text.strip():
            return []
        
        # If text is smaller than chunk size, return directly
        if len(text) <= chunk_size:
            return [text.strip()]
        
        chunks = []
        start = 0
        text_len = len(text)
        step = max(1, chunk_size - overlap)

        while start < text_len:
            end = min(start + chunk_size, text_len)
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            if end >= text_len:
                break
            start += step

        return chunks

    def scan_chunks(self, chunks: List[str], session_id: str = "rag-session") -> RAGScanResult:
        """
        Iterates through document chunks and evaluates each with JudgeAgent.
        Returns safe chunks and a list of quarantined chunks with metadata.
        """
        safe = []
        quarantined = []

        for chunk in chunks:
            eval_res = self.judge.evaluate(prompt=chunk, session_id=session_id)
            is_blocked = (
                eval_res.get("decision") == "BLOCK" or 
                eval_res.get("risk_score", 0.0) >= self.quarantine_threshold or
                len(eval_res.get("matched_signatures", [])) > 0
            )

            if is_blocked:
                quarantined.append({
                    "chunk": chunk,
                    "risk_score": eval_res.get("risk_score", 0.0),
                    "matched_signatures": eval_res.get("matched_signatures", []),
                    "reasoning": eval_res.get("reasoning", "Malicious or adversarial content detected.")
                })
            else:
                safe.append(chunk)

        return RAGScanResult(
            safe_chunks=safe,
            quarantined_chunks=quarantined,
            is_poisoned=len(quarantined) > 0
        )

    def scan_file(self, file_path: str, chunk_size: int = 500, overlap: int = 50, session_id: str = "rag-file") -> RAGScanResult:
        """
        Reads a document file (.txt, .md, .pdf) from disk, chunks it, and scans each chunk.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target document not found at: {file_path}")

        ext = os.path.splitext(file_path)[1].lower()
        content = ""

        if ext in [".txt", ".md", ".json", ".csv"]:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        elif ext == ".pdf":
            try:
                import pypdf
                reader = pypdf.PdfReader(file_path)
                content = "".join([page.extract_text() or "" for page in reader.pages])
            except ImportError:
                # Fallback binary decode if pypdf is not available
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
        else:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

        chunks = self.chunk_text(content, chunk_size=chunk_size, overlap=overlap)
        return self.scan_chunks(chunks, session_id=session_id)
