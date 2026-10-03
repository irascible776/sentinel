"""
Developer 1 (Rohit Verma) — Behavioral Profiler Agent
Stateful in-memory session and temporal history tracking.
Detects multi-turn probing, escalating boundary testing, and rapid fuzzing velocity.
"""

import time
import os
from typing import Dict, List, Any, Optional
from collections import defaultdict

class BehavioralProfiler:
    def __init__(self, window_minutes: Optional[int] = None, max_sessions: int = 10000):
        if window_minutes is None:
            try:
                window_minutes = int(os.getenv("SLIDING_WINDOW_MINUTES", "10"))
            except ValueError:
                window_minutes = 10
        self.window_seconds = window_minutes * 60
        self.max_sessions = max_sessions
        # session_id -> list of records: [{"timestamp": float, "score": float, "prompt_len": int}]
        self.sessions: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._last_prune_time = time.time()

    def _prune_session(self, session_id: str, current_time: float) -> List[Dict[str, Any]]:
        """Removes records older than the sliding temporal window."""
        cutoff = current_time - self.window_seconds
        valid_records = [r for r in self.sessions[session_id] if r["timestamp"] >= cutoff]
        self.sessions[session_id] = valid_records
        return valid_records

    def _periodic_global_cleanup(self, current_time: float):
        """Evicts inactive sessions if memory cap is approached."""
        if current_time - self._last_prune_time < 300:  # every 5 minutes
            return
        self._last_prune_time = current_time
        cutoff = current_time - self.window_seconds

        stale_sessions = [
            sid for sid, recs in self.sessions.items()
            if not recs or recs[-1]["timestamp"] < cutoff
        ]
        for sid in stale_sessions:
            del self.sessions[sid]

        # Hard safety cap
        if len(self.sessions) > self.max_sessions:
            # Drop oldest 20%
            sorted_by_activity = sorted(
                self.sessions.items(),
                key=lambda item: item[1][-1]["timestamp"] if item[1] else 0
            )
            for sid, _ in sorted_by_activity[:int(self.max_sessions * 0.2)]:
                self.sessions.pop(sid, None)

    def evaluate_session(
        self,
        session_id: str = "default",
        prompt: str = "",
        preliminary_risk: float = 0.0
    ) -> Dict[str, Any]:
        """
        Records the current interaction and calculates the behavioral risk score.
        
        Returns:
            {
                "score": float,                   # 0.0 to 100.0 (behavioral risk contribution)
                "session_prompt_count": int,      # Requests in active window
                "velocity_rpm": float,            # Requests per minute
                "escalation_detected": bool,      # True if scores are trending upwards
                "escalation_factor": float,       # Escalation penalty applied
                "latency_ms": float
            }
        """
        t0 = time.perf_counter()
        now = time.time()

        self._periodic_global_cleanup(now)
        active_records = self._prune_session(session_id, now)

        # Baseline behavioral score
        behavioral_score = 5.0
        escalation_detected = False
        escalation_factor = 0.0

        if len(active_records) >= 2:
            # Check for escalation across last 3 prompts
            recent_scores = [r["score"] for r in active_records[-3:]] + [preliminary_risk]
            # Escalation: at least 3 points where each is higher than the previous by at least 10 points
            if len(recent_scores) >= 3:
                is_increasing = all(
                    recent_scores[i] < recent_scores[i+1]
                    for i in range(len(recent_scores) - 1)
                )
                if is_increasing and (recent_scores[-1] - recent_scores[0]) >= 20.0:
                    escalation_detected = True
                    escalation_factor = 30.0

            # Historical baseline from average of recent suspicious activity
            recent_avg = sum(r["score"] for r in active_records) / len(active_records)
            behavioral_score = max(behavioral_score, recent_avg * 0.5)

            # Prior Blocked Attack Penalty:
            has_prior_attack = any(r["score"] >= 70.0 for r in active_records)
            if has_prior_attack:
                behavioral_score = max(behavioral_score, 60.0)

        # Calculate request velocity (requests per minute)
        prompt_count = len(active_records) + 1
        window_span_minutes = max(1.0, (now - active_records[0]["timestamp"]) / 60.0) if active_records else 1.0
        velocity_rpm = prompt_count / window_span_minutes

        # Velocity penalty for automated fuzzing / rapid scanning (>15 req/min)
        if velocity_rpm > 15.0:
            behavioral_score += min(35.0, (velocity_rpm - 15.0) * 2.0)

        # Add escalation bonus if multi-turn probing is identified:
        if escalation_detected:
            behavioral_score += escalation_factor

        # Add new record to session history:
        active_records.append({
            "timestamp": now,
            "score": preliminary_risk,
            "prompt_len": len(prompt)
        })
        self.sessions[session_id] = active_records

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "score": round(max(0.0, min(100.0, behavioral_score)), 2),
            "session_prompt_count": len(active_records),
            "velocity_rpm": round(velocity_rpm, 2),
            "escalation_detected": escalation_detected,
            "escalation_factor": round(escalation_factor, 2),
            "latency_ms": round(elapsed_ms, 3)
        }
