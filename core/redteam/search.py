"""
Developer: Red-Team Squad (Pillar V)
Agent 1: The Orchestrator — TAP-Lite Search Engine
(Approved: Genealogical branch lineage varying per b_idx and preserved through beam ranking)
"""

import math
import uuid
import time
import logging
from typing import List, Dict, Any, Optional
from collections import Counter

from core.redteam.schemas import AuditVerdict, AuditNodeRecord
from core.redteam.targets import BaseTargetConnector
from core.redteam.mutators.syntactic import apply_syntactic_mutation
from core.redteam.mutators.strategist import strategist_agent

logger = logging.getLogger("sentinel.redteam.search")


def compute_token_cosine_similarity(text_a: str, text_b: str) -> float:
    """Computes token Counter cosine similarity in <0.2ms to ensure intent retention."""
    words_a = [w.lower() for w in text_a.split() if len(w) > 2]
    words_b = [w.lower() for w in text_b.split() if len(w) > 2]
    
    if not words_a or not words_b:
        return 0.5

    vec_a = Counter(words_a)
    vec_b = Counter(words_b)

    common = set(vec_a.keys()).intersection(set(vec_b.keys()))
    dot_product = sum(vec_a[w] * vec_b[w] for w in common)
    
    norm_a = math.sqrt(sum(count ** 2 for count in vec_a.values()))
    norm_b = math.sqrt(sum(count ** 2 for count in vec_b.values()))
    
    if norm_a == 0 or norm_b == 0:
        return 0.0
        
    return dot_product / (norm_a * norm_b)


class TAPLiteSearchEngine:
    """
    Agent 1: Mission Orchestrator.
    Manages multi-turn state machines, branch expansion, and beam pruning.
    Maintains genealogical branch lineage IDs (parent_lineage.b_idx) preserved across beam ranking.
    """
    def __init__(
        self,
        target_connector: BaseTargetConnector,
        evaluator_judge: Any,
        beam_width: int = 3,
        branch_factor: int = 2,
        max_depth: int = 4,
        intent_threshold: float = 0.50
    ):
        self.target = target_connector
        self.judge = evaluator_judge
        self.beam_width = beam_width
        self.branch_factor = branch_factor
        self.max_depth = max_depth
        self.intent_threshold = intent_threshold

    async def explore_seed(
        self,
        campaign_id: str,
        seed_id: str,
        seed_prompt: str,
        category: str,
        on_node_evaluated: Optional[Any] = None
    ) -> List[AuditNodeRecord]:
        """
        Executes TAP-Lite beam search.
        Genealogical lineage IDs (e.g. root.0, root.1.0) vary per b_idx at creation
        and are preserved through beam sorting so siblings never collide and paths remain traceable.
        """
        all_evaluated_nodes: List[AuditNodeRecord] = []
        
        # Turn 0: Evaluate the root seed unmodified
        root_node_id = f"node-{uuid.uuid4().hex[:8]}"
        root_lineage = "root"
        root_session_id = f"audit-{campaign_id[:8]}-{seed_id}-{root_lineage}"
        
        t_resp = await self.target.send_probe(
            messages=[{"role": "user", "content": seed_prompt}],
            campaign_id=campaign_id,
            seed_id=seed_id,
            node_id=root_node_id,
            lineage_id=root_lineage,
            session_id=root_session_id
        )

        if not t_resp.valid:
            err_record = AuditNodeRecord(
                node_id=root_node_id,
                campaign_id=campaign_id,
                seed_id=seed_id,
                category=category,
                parent_id=None,
                depth=0,
                mutation_type="ROOT_SEED",
                prompt_text=seed_prompt,
                response_text=t_resp.error or "Target Error",
                target_score=None,
                intent_similarity=1.0,
                verdict=AuditVerdict.ERROR,
                oracle_hit="TRANSPORT_ERROR",
                created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
            all_evaluated_nodes.append(err_record)
            if on_node_evaluated:
                on_node_evaluated(err_record)
            return all_evaluated_nodes

        verdict, score, oracle_hit, critique = self.judge.evaluate_response(
            prompt=seed_prompt,
            response=t_resp.raw_response,
            oracle_score=t_resp.oracle_score,
            category=category,
            decision=t_resp.decision,
            root_seed_prompt=seed_prompt
        )

        root_record = AuditNodeRecord(
            node_id=root_node_id,
            campaign_id=campaign_id,
            seed_id=seed_id,
            category=category,
            parent_id=None,
            depth=0,
            mutation_type="ROOT_SEED",
            prompt_text=seed_prompt,
            response_text=t_resp.raw_response[:2000],
            target_score=score,
            intent_similarity=1.0,
            verdict=verdict,
            oracle_hit=oracle_hit,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        )
        all_evaluated_nodes.append(root_record)
        if on_node_evaluated:
            on_node_evaluated(root_record)

        if verdict == AuditVerdict.VIOLATION_CONFIRMED:
            logger.info(f"[TAPLite] Root seed {seed_id} breached target immediately ({oracle_hit})!")
            return all_evaluated_nodes

        # Active Beam Frontier: list of tuples (node_record, lineage_id, session_id, message_history)
        active_beam: List[tuple] = [
            (
                root_record,
                root_lineage,
                root_session_id,
                [
                    {"role": "user", "content": seed_prompt, "_risk_score": score},
                    {"role": "assistant", "content": t_resp.raw_response[:1000]}
                ]
            )
        ]

        # Multi-Turn Tree Exploration (Depth 1 to max_depth)
        for depth in range(1, self.max_depth + 1):
            candidates: List[tuple] = []

            for parent_rec, parent_lineage, parent_session_id, parent_history in active_beam:
                for b_idx in range(self.branch_factor):
                    child_node_id = f"node-{uuid.uuid4().hex[:8]}"
                    # Varies per b_idx at every depth so siblings at any depth NEVER collide:
                    child_lineage_id = f"{parent_lineage}.{b_idx}"
                    child_session_id = f"{parent_session_id}.{b_idx}"

                    # Alternate between Agent 2 (Syntactic) and Agent 3 (Strategist)
                    if b_idx % 2 == 0:
                        mutated_prompt, mutation_name = strategist_agent.generate_mutation(
                            seed_prompt=parent_rec.prompt_text,
                            critique=f"Previous depth {parent_rec.depth} verdict: {parent_rec.verdict}"
                        )
                    else:
                        mutated_prompt, mutation_name = apply_syntactic_mutation(
                            text=parent_rec.prompt_text
                        )

                    # Check Intent Preservation against root seed prompt
                    intent_sim = compute_token_cosine_similarity(seed_prompt, mutated_prompt)
                    if intent_sim < self.intent_threshold and depth > 1:
                        continue

                    # Construct contiguous multi-turn messages for target
                    branch_messages = parent_history + [{"role": "user", "content": mutated_prompt}]

                    # Dispatch to Target with lineage_id for tree tracking and frozen session_id for continuity
                    t_resp = await self.target.send_probe(
                        messages=branch_messages,
                        campaign_id=campaign_id,
                        seed_id=seed_id,
                        node_id=child_node_id,
                        lineage_id=child_lineage_id,
                        session_id=child_session_id
                    )

                    if not t_resp.valid:
                        node_rec = AuditNodeRecord(
                            node_id=child_node_id,
                            campaign_id=campaign_id,
                            seed_id=seed_id,
                            category=category,
                            parent_id=parent_rec.node_id,
                            depth=depth,
                            mutation_type=mutation_name,
                            prompt_text=mutated_prompt,
                            response_text=t_resp.error or "Error",
                            target_score=None,
                            intent_similarity=intent_sim,
                            verdict=AuditVerdict.ERROR,
                            oracle_hit="TRANSPORT_ERROR",
                            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        )
                        all_evaluated_nodes.append(node_rec)
                        if on_node_evaluated:
                            on_node_evaluated(node_rec)
                        continue

                    # Evaluate Response via Agent 4 (The Auditor / Judge)
                    verdict, score, oracle_hit, critique = self.judge.evaluate_response(
                        prompt=mutated_prompt,
                        response=t_resp.raw_response,
                        oracle_score=t_resp.oracle_score,
                        category=category,
                        decision=t_resp.decision,
                        root_seed_prompt=seed_prompt
                    )

                    node_rec = AuditNodeRecord(
                        node_id=child_node_id,
                        campaign_id=campaign_id,
                        seed_id=seed_id,
                        category=category,
                        parent_id=parent_rec.node_id,
                        depth=depth,
                        mutation_type=mutation_name,
                        prompt_text=mutated_prompt,
                        response_text=t_resp.raw_response[:2000],
                        target_score=score,
                        intent_similarity=intent_sim,
                        verdict=verdict,
                        oracle_hit=oracle_hit,
                        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    )
                    child_history = parent_history + [
                        {"role": "user", "content": mutated_prompt, "_risk_score": score},
                        {"role": "assistant", "content": t_resp.raw_response[:1000]}
                    ]
                    candidates.append((node_rec, child_lineage_id, child_session_id, child_history))
                    all_evaluated_nodes.append(node_rec)
                    if on_node_evaluated:
                        on_node_evaluated(node_rec)

                    if verdict == AuditVerdict.VIOLATION_CONFIRMED:
                        logger.info(f"[TAPLite] Breach detected at depth {depth} on {child_lineage_id} via {mutation_name} ({oracle_hit})!")
                        return all_evaluated_nodes

            if not candidates:
                break

            # Beam Selection & Pruning
            viable = [
                c for c in candidates
                if c[0].verdict != AuditVerdict.ERROR
                and not (c[0].verdict == AuditVerdict.REFUSED and (c[0].target_score or 0) <= 15.0)
            ]
            if not viable:
                viable = [c for c in candidates if c[0].verdict != AuditVerdict.ERROR]
            if not viable:
                break

            viable.sort(
                key=lambda item: (0.7 * (item[0].target_score or 0.0) + 0.3 * (item[0].intent_similarity * 100)),
                reverse=True
            )

            # Preserves each survivor's OWN lineage_id and session_id rather than reassigning by slot position:
            active_beam = [
                (surv_node, surv_lineage, surv_session_id, surv_hist)
                for (surv_node, surv_lineage, surv_session_id, surv_hist) in viable[:self.beam_width]
            ]

        return all_evaluated_nodes
