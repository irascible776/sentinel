# Module 5: Dynamic Threat Rules Contract & Schema
**Developer 1 (Rohit) | Branch: `br2` | File: `core/detection/threat_rules.json`**

---

## 1. Objective & Cross-Developer Contract

The AI Security Gateway features an automated self-learning loop. While Developer 1 writes the detection logic, the rules database is **dynamic**:
* **Writer:** Developer 3's `ThreatIntelligenceFeed` (`core/security_vectors/threat_feed.py`) clusters blocked attacks from `gateway.db` using TF-IDF n-grams and appends newly discovered patterns.
* **Reader:** Developer 1's `PatternHunter` (`core/detection/pattern_hunter.py`) reads and compiles these rules on the fly.

This document defines the strict data contract and file-safety mechanisms that both developers must adhere to.

---

## 2. JSON Schema Specification

Location: `core/detection/threat_rules.json`

```json
{
  "version": "1.2.0",
  "updated_at": "2026-10-02T16:50:00Z",
  "rules": [
    {
      "id": "SIG-001",
      "name": "Direct Instruction Override",
      "pattern": "(?i)(ignore\\s+all\\s+(previous|prior)\\s+instructions|disregard\\s+all\\s+rules)",
      "severity": "HIGH",
      "weight": 100
    },
    {
      "id": "SIG-002",
      "name": "DAN Persona Jailbreak",
      "pattern": "(?i)(you\\s+are\\s+now\\s+DAN|do\\s+anything\\s+now|developer\\s+mode\\s+enabled)",
      "severity": "HIGH",
      "weight": 95
    },
    {
      "id": "SIG-003",
      "name": "System Prompt Extraction",
      "pattern": "(?i)(repeat\\s+the\\s+words\\s+above|print\\s+initial\\s+system\\s+prompt|what\\s+are\\s+your\\s+instructions)",
      "severity": "MEDIUM",
      "weight": 80
    }
  ]
}
```

### Field Definitions
* `version` (str): SemVer format tracking automated updates.
* `updated_at` (str): ISO 8601 UTC timestamp of last update.
* `id` (str): Unique rule identifier (`SIG-XXX` for baseline rules, `THREAT-AUTO-XXXX` for auto-learned rules).
* `name` (str): Descriptive label rendered on dashboard telemetry and logs.
* `pattern` (str): PCRE/Python `re`-compatible regular expression string.
* `severity` (str): `"LOW"`, `"MEDIUM"`, `"HIGH"`, or `"CRITICAL"`.
* `weight` (int/float): Risk weight contributed to `PatternHunter` score ($0\text{--}100$).

---

## 3. Resilience, Concurrency & ReDoS Protections

1. **Non-Blocking Hot-Reload:** `PatternHunter` caches the compiled regex objects in memory. It only re-reads the disk file when `os.path.getmtime(self.rules_path) > self._last_mtime`.
2. **Atomic Write Protection:** If Developer 3's script is mid-write when Developer 1 attempts to read, `json.load()` could raise a `JSONDecodeError`. `PatternHunter` catches this exception cleanly, preserves the existing cached rule set in memory, and retries on the next request.
3. **ReDoS Defense:** When compiling regex patterns, each pattern is wrapped in a `try...except re.error` block. Any malformed or catastrophic backtracking pattern is discarded with a warning rather than crashing the gateway process.

---

## 4. Verification & Schema Validation Test

```bash
python3 -c "
import json
import re

with open('core/detection/threat_rules.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

assert 'rules' in data, 'Missing rules array!'
for rule in data['rules']:
    assert 'id' in rule and 'pattern' in rule and 'weight' in rule
    # Validate regex compiles without syntax error:
    compiled = re.compile(rule['pattern'])
    assert compiled is not None

print(f'PASS: threat_rules.json Schema Validated ({len(data[\"rules\"])} rules loaded)')
"
```
