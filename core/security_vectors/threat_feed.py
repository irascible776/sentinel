"""
Developer 3 (Utkarsh) - Threat Intelligence Feed (Add-on 12)
DTU B.Tech Minor Project (IT401) | Group 138

Automated self-learning security loop:
1. Queries blocked adversarial prompts from SQLite database (gateway.db).
2. Clusters recurring attack payloads using TF-IDF n-gram extraction (scikit-learn).
3. Synthesizes new regex detection signatures with assigned risk weights.
4. Hot-updates core/detection/threat_rules.json so Rohit's JudgeAgent reloads immediately.
"""

import os
import re
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sklearn.feature_extraction.text import TfidfVectorizer


class ThreatIntelligenceFeed:
    def __init__(self, db_path: str = "gateway.db", rules_path: str = "core/detection/threat_rules.json"):
        self.db_path = db_path
        self.rules_path = rules_path

    def fetch_blocked_prompts(self, limit: int = 100) -> List[str]:
        """
        Fetches the latest blocked prompts from Rupesh's SQLite database.
        Safely returns an empty list if the database or table is not yet initialized.
        """
        if not os.path.exists(self.db_path):
            return []
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            cursor = conn.cursor()
            # Verify table exists before querying
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='requests'")
            if not cursor.fetchone():
                conn.close()
                return []
            cursor.execute(
                "SELECT prompt FROM requests WHERE decision = 'BLOCK' ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            conn.close()
            return [r[0] for r in rows if r[0] and isinstance(r[0], str)]
        except Exception:
            return []

    def extract_attack_patterns(self, prompts: List[str], max_patterns: int = 5) -> List[str]:
        """
        Extracts repeated 2-gram to 4-gram phrases across blocked prompts using TF-IDF.
        """
        if not prompts or len(prompts) < 2:
            return []
        try:
            vec = TfidfVectorizer(
                ngram_range=(2, 4),
                stop_words="english",
                max_features=max_patterns,
                token_pattern=r"(?u)\b\w+\b"
            )
            vec.fit(prompts)
            return list(vec.vocabulary_.keys())
        except Exception:
            return []

    def load_existing_rules(self) -> Dict[str, Any]:
        """Loads existing threat_rules.json file or creates default structure."""
        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"version": "1.0.0", "updated_at": "", "rules": []}

    def generate_signatures(self, phrases: List[str]) -> List[Dict[str, Any]]:
        """Converts extracted attack phrases into rule signature dictionaries."""
        rules = []
        for phrase in phrases:
            clean_phrase = phrase.strip()
            if not clean_phrase or len(clean_phrase) < 4:
                continue
            words = [re.escape(w) for w in clean_phrase.split()]
            if not words:
                continue
            pattern = r"(?i)\b" + r"\s+(?:\w+\s+)*?".join(words) + r"\b"
            rule_id = f"AUTO-{uuid.uuid4().hex[:6].upper()}"
            rules.append({
                "id": rule_id,
                "name": f"Auto-Clustered: {clean_phrase[:40]}",
                "pattern": pattern,
                "severity": "HIGH",
                "weight": 85,
                "source": "threat_intelligence_feed",
                "created_at": datetime.now(timezone.utc).isoformat()
            })
        return rules

    def run_clustering_and_update(
        self,
        lookback_limit: int = 100,
        fallback_prompts: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Executes the clustering pipeline and appends newly synthesized signatures to threat_rules.json.
        Supports fallback_prompts for testing and simulation before gateway traffic accumulates.
        """
        prompts = self.fetch_blocked_prompts(lookback_limit)
        if not prompts and fallback_prompts:
            prompts = fallback_prompts

        if not prompts:
            return {
                "success": False,
                "new_rules_count": 0,
                "total_rules": len(self.load_existing_rules().get("rules", [])),
                "generated_signatures": [],
                "message": "No blocked prompts available for clustering."
            }

        extracted_phrases = self.extract_attack_patterns(prompts)
        if not extracted_phrases:
            return {
                "success": False,
                "new_rules_count": 0,
                "total_rules": len(self.load_existing_rules().get("rules", [])),
                "generated_signatures": [],
                "message": "No recurring attack patterns detected."
            }

        new_candidates = self.generate_signatures(extracted_phrases)
        rules_data = self.load_existing_rules()
        existing_rules = rules_data.get("rules", [])
        existing_patterns = {r.get("pattern") for r in existing_rules}

        added_rules = []
        for candidate in new_candidates:
            if candidate["pattern"] not in existing_patterns:
                existing_rules.append(candidate)
                existing_patterns.add(candidate["pattern"])
                added_rules.append(candidate["name"])

        rules_data["rules"] = existing_rules
        rules_data["updated_at"] = datetime.now(timezone.utc).isoformat()

        # Atomic write
        temp_path = f"{self.rules_path}.tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(rules_data, f, indent=2)
        os.replace(temp_path, self.rules_path)

        return {
            "success": True,
            "new_rules_count": len(added_rules),
            "total_rules": len(existing_rules),
            "generated_signatures": added_rules,
            "extracted_phrases": extracted_phrases,
            "message": f"Successfully updated threat rules with {len(added_rules)} new signature(s)."
        }
