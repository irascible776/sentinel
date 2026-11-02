"""
Developer: Red-Team Squad (Pillar V)
Isolated OS Subprocess Runner for Adversarial Campaigns
Guarantees 100% Apple Metal GPU & mmap memory reclamation upon completion.
"""

import os
import sys
import json
import uuid
import asyncio
import argparse
import logging
from typing import List, Dict, Any

from core.redteam.schemas import (
    TargetType,
    AttackCategory,
    AuditVerdict,
    SynthesizedRuleRecord
)
from core.redteam.targets import get_target_connector
from core.redteam.mutators.strategist import strategist_agent
from core.redteam.judge import evaluative_judge
from core.redteam.search import TAPLiteSearchEngine
from core.redteam.hardening import auto_hardener
from core.gateway.database import (
    create_redteam_campaign,
    update_redteam_campaign,
    log_redteam_node
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.redteam.runner")


def load_seed_probes(categories: List[str]) -> List[Dict[str, Any]]:
    """Loads matching seed probes from local seed_probes.json."""
    seeds_path = os.path.join(os.path.dirname(__file__), "data", "seed_probes.json")
    if not os.path.exists(seeds_path):
        logger.warning(f"Seed probes file not found at {seeds_path}")
        return []

    with open(seeds_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    all_seeds = data.get("seeds", [])
    if not categories:
        return all_seeds

    cat_set = set(categories)
    return [s for s in all_seeds if s.get("category") in cat_set]


async def run_campaign(
    campaign_id: str,
    target_type: TargetType,
    target_endpoint: str,
    target_model: str = "",
    categories: List[str] = None,
    max_turns: int = 4,
    beam_width: int = 3,
    branch_factor: int = 2,
    auto_harden_shadow: bool = True
):
    """
    Main asynchronous campaign loop executed within the isolated process.
    """
    logger.info(f"Starting audit campaign '{campaign_id}' against {target_endpoint} ({target_type.value})")

    # 1. Initialize Target Connector
    target = get_target_connector(
        target_type=target_type,
        endpoint=target_endpoint,
        model=target_model or None
    )

    # 2. Load Selected Seeds
    categories = categories or ["prompt_injection", "canary_exfiltration", "tool_hijacking", "data_leakage"]
    seeds = load_seed_probes(categories)
    logger.info(f"Loaded {len(seeds)} audit seed probes across categories: {categories}")

    # 3. Initialize Campaign Record in SQLite
    create_redteam_campaign(
        campaign_id=campaign_id,
        target_type=target_type.value,
        target_endpoint=target_endpoint,
        target_model=target_model,
        total_seeds=len(seeds)
    )

    # 4. Initialize Search Engine
    search_engine = TAPLiteSearchEngine(
        target_connector=target,
        evaluator_judge=evaluative_judge,
        beam_width=beam_width,
        branch_factor=branch_factor,
        max_depth=max_turns
    )

    total_nodes_evaluated = 0
    breaches_detected = 0
    candidate_rules: List[SynthesizedRuleRecord] = []

    def on_node(record):
        nonlocal total_nodes_evaluated
        total_nodes_evaluated += 1
        log_redteam_node(
            node_id=record.node_id,
            campaign_id=record.campaign_id,
            parent_id=record.parent_id,
            depth=record.depth,
            mutation_type=record.mutation_type,
            prompt_text=record.prompt_text,
            response_text=record.response_text,
            target_score=record.target_score or 0.0,
            intent_similarity=record.intent_similarity,
            verdict=record.verdict.value,
            oracle_hit=record.oracle_hit
        )

    # 5. Execute Campaign Seeds
    try:
        for seed_idx, seed in enumerate(seeds):
            seed_id = seed.get("id", f"SEED-{seed_idx}")
            prompt = seed.get("prompt", "")
            cat = seed.get("category", "prompt_injection")

            logger.info(f"[{seed_idx+1}/{len(seeds)}] Auditing seed {seed_id} ({cat})...")

            nodes = await search_engine.explore_seed(
                campaign_id=campaign_id,
                seed_id=seed_id,
                seed_prompt=prompt,
                category=cat,
                on_node_evaluated=on_node
            )

            # Check if this seed resulted in any breach
            seed_breaches = [n for n in nodes if n.verdict == AuditVerdict.VIOLATION_CONFIRMED]
            if seed_breaches:
                breaches_detected += len(seed_breaches)
                for b_node in seed_breaches:
                    rule = auto_hardener.synthesize_rule(
                        node_id=b_node.node_id,
                        prompt=b_node.prompt_text,
                        category=cat,
                        campaign_id=campaign_id
                    )
                    if rule:
                        candidate_rules.append(rule)

            # Update live stats
            update_redteam_campaign(
                campaign_id=campaign_id,
                status="RUNNING",
                total_nodes=total_nodes_evaluated,
                breaches=breaches_detected,
                rules=len(candidate_rules)
            )

            # Small thermal-pause between seeds for fanless M1 Air
            await asyncio.sleep(0.5)

        # 6. Defer Rule Commitment Until Campaign Completes (as Claude recommended!)
        committed_ids = []
        if auto_harden_shadow and candidate_rules:
            logger.info(f"Committing {len(candidate_rules)} synthesized shadow rules to threat_rules.json...")
            committed_ids = auto_hardener.commit_shadow_rules(candidate_rules)
            logger.info(f"Committed {len(committed_ids)} rules in SHADOW mode.")

        # 7. Complete Campaign
        update_redteam_campaign(
            campaign_id=campaign_id,
            status="COMPLETED",
            total_nodes=total_nodes_evaluated,
            breaches=breaches_detected,
            rules=len(committed_ids),
            completed=True
        )
        logger.info(f"Campaign {campaign_id} completed successfully. Breaches: {breaches_detected}, Rules: {len(committed_ids)}")

    except Exception as e:
        logger.exception(f"Campaign {campaign_id} failed with error: {e}")
        update_redteam_campaign(campaign_id=campaign_id, status="FAILED", completed=True)
    finally:
        if hasattr(target, "aclose"):
            await target.aclose()


def main():
    parser = argparse.ArgumentParser(description="Pillar V Adversarial Audit Subprocess Runner")
    parser.add_argument("--campaign-id", type=str, default=f"cmp-{uuid.uuid4().hex[:8]}")
    parser.add_argument("--target-type", type=str, default="sentinel_local")
    parser.add_argument("--target-endpoint", type=str, default="http://127.0.0.1:8000")
    parser.add_argument("--target-model", type=str, default="")
    parser.add_argument("--categories", type=str, default="prompt_injection,canary_exfiltration,tool_hijacking,data_leakage")
    parser.add_argument("--max-turns", type=int, default=4)
    parser.add_argument("--beam-width", type=int, default=3)
    parser.add_argument("--branch-factor", type=int, default=2)
    parser.add_argument("--no-auto-harden", action="store_true", default=False)

    args = parser.parse_args()

    cat_list = [c.strip() for c in args.categories.split(",") if c.strip()]
    target_type_enum = TargetType(args.target_type)

    asyncio.run(
        run_campaign(
            campaign_id=args.campaign_id,
            target_type=target_type_enum,
            target_endpoint=args.target_endpoint,
            target_model=args.target_model,
            categories=cat_list,
            max_turns=args.max_turns,
            beam_width=args.beam_width,
            branch_factor=args.branch_factor,
            auto_harden_shadow=not args.no_auto_harden
        )
    )


if __name__ == "__main__":
    main()

