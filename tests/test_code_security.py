"""
Unit & Integration Test Suite for Pillar II: Code Security & AST Vulnerability Detection
Tests Shannon string entropy, verified secret detection & redaction,
Python AST taint analysis (CWE-89, CWE-78, CWE-502), suppression handling,
multi-language structural parsing, GraphCodeBERT forward passes, 3-tier judge consensus,
thread-safe LRU caching, and FastAPI /api/v1/scan-code gateway endpoint.
"""

import pytest
from fastapi.testclient import TestClient

from core.codesec.config import TARGET_CWES
from core.codesec.schemas import VerdictEnum, PolicyActionEnum
from core.codesec.secret_scanner import (
    calculate_string_entropy,
    is_placeholder_secret,
    is_valid_jwt,
    redact_secret,
    SecretScanner,
)
from core.codesec.ast_parser import ASTParserEngine
from core.codesec.codebert_head import (
    GraphCodeBERTClassificationHead,
    tokenize_code_deterministic,
    codebert_classifier,
)
from core.codesec.judge import CodeSecurityJudge
from core.codesec.engine import CodeSecurityEngine
from core.gateway.app import app


client = TestClient(app)


# --------------------------------------------------------------------------
# 1. Shannon String Entropy & Secret Scanner Tests
# --------------------------------------------------------------------------
def test_shannon_string_entropy_bounds():
    assert calculate_string_entropy("") == 0.0
    assert calculate_string_entropy("aaaaaaaaaaaa") == 0.0
    # Alternating 2 characters -> 1.0 bit
    assert round(calculate_string_entropy("abababababab"), 2) == 1.0
    # Base64 high entropy string -> > 4.5 bits
    high_entropy_secret = "dGhpcy1pcy1hLXZlcnktc2VjcmV0LXRva2VuLTEyMzQ1Njc4"
    assert calculate_string_entropy(high_entropy_secret) > 4.0


def test_secret_scanner_aws_key_and_placeholder():
    scanner = SecretScanner()

    # Real-looking AWS Key
    code = 'AWS_KEY = "AKIA1234567890ABCDEF"\n'
    secrets, findings = scanner.scan_code(code)
    assert len(secrets) == 1
    assert secrets[0].kind == "AWS Access Key ID"
    assert secrets[0].verified_structure is True
    assert "AKIA***" in secrets[0].redacted_preview
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-798"
    assert findings[0].tier == 1

    # Placeholder AWS Key (Should be ignored as documentation sample)
    doc_sample = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    secrets_doc, findings_doc = scanner.scan_code(doc_sample)
    assert len(secrets_doc) == 0
    assert len(findings_doc) == 0


def test_secret_scanner_jwt_and_pem():
    scanner = SecretScanner()

    # Valid JWT format: header with {"alg": "HS256"} -> eyJhbGciOiJIUzI1NiJ9
    jwt_code = (
        'TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.'
        'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"\n'
    )
    secrets, findings = scanner.scan_code(jwt_code)
    assert len(secrets) >= 1
    assert any(s.kind == "JSON Web Token (JWT)" for s in secrets)

    # PEM Private Key
    pem_code = (
        'PRIVATE_KEY = """\n'
        '-----BEGIN RSA PRIVATE KEY-----\n'
        'MIIEowIBAAKCAQEA0Y1v...\n'
        '-----END RSA PRIVATE KEY-----\n'
        '"""\n'
    )
    secrets_pem, findings_pem = scanner.scan_code(pem_code)
    assert any("Private Key" in s.kind for s in secrets_pem)


def test_secret_scanner_high_entropy_assignment():
    scanner = SecretScanner()

    # Sensitive variable with high-entropy token
    code = 'api_secret_key = "9a8f7c6e5b4a3d2e1f0a9b8c7d6e5f4a"\n'
    secrets, findings = scanner.scan_code(code)
    assert len(secrets) == 1
    assert secrets[0].verified_structure is False
    assert secrets[0].entropy >= 3.5

    # Low entropy / common password
    low_entropy_code = 'api_key = "changeme123"\n'
    secrets_low, findings_low = scanner.scan_code(low_entropy_code)
    assert len(secrets_low) == 0


# --------------------------------------------------------------------------
# 2. Python AST Taint Analysis Tests (CWE-89, CWE-78, CWE-502)
# --------------------------------------------------------------------------
def test_ast_python_sqli_detection():
    parser = ASTParserEngine()

    # Dynamic f-string SQL query -> Flagged
    vuln_code = (
        "def query_user(user_id):\n"
        "    query = f'SELECT * FROM accounts WHERE id = {user_id}'\n"
        "    cursor.execute(query)\n"
    )
    report = parser.analyze_code(vuln_code, language="python")
    assert report.parser_backend == "python_ast"
    assert any(f.cwe == "CWE-89" for f in report.findings)
    assert report.taint_sinks_detected >= 1

    # Parameterized query -> Safe
    safe_code = (
        "def query_user(user_id):\n"
        "    query = 'SELECT * FROM accounts WHERE id = %s'\n"
        "    cursor.execute(query, (user_id,))\n"
    )
    report_safe = parser.analyze_code(safe_code, language="python")
    assert not any(f.cwe == "CWE-89" for f in report_safe.findings)


def test_ast_python_command_injection():
    parser = ASTParserEngine()

    # os.system with concatenation -> Flagged
    cmd_code = (
        "import os\n"
        "def ping(host):\n"
        "    os.system('ping -c 1 ' + host)\n"
    )
    report = parser.analyze_code(cmd_code, language="python")
    assert any(f.cwe == "CWE-78" for f in report.findings)

    # subprocess with shell=True and dynamic command -> Flagged
    sp_code = (
        "import subprocess\n"
        "def run_cmd(user_cmd):\n"
        "    subprocess.run(user_cmd, shell=True)\n"
    )
    report_sp = parser.analyze_code(sp_code, language="python")
    assert any(f.cwe == "CWE-78" for f in report_sp.findings)

    # Safe subprocess with argument list and shell=False
    safe_sp = (
        "import subprocess\n"
        "def safe_run():\n"
        "    subprocess.run(['ls', '-la'])\n"
    )
    report_safe_sp = parser.analyze_code(safe_sp, language="python")
    assert not any(f.cwe == "CWE-78" for f in report_safe_sp.findings)


def test_ast_python_insecure_deserialization():
    parser = ASTParserEngine()

    # pickle.loads -> Flagged
    pickle_code = (
        "import pickle\n"
        "def load_payload(raw_data):\n"
        "    return pickle.loads(raw_data)\n"
    )
    report = parser.analyze_code(pickle_code, language="python")
    assert any(f.cwe == "CWE-502" for f in report.findings)

    # yaml.unsafe_load -> Flagged
    yaml_code = (
        "import yaml\n"
        "def parse_config(cfg):\n"
        "    return yaml.unsafe_load(cfg)\n"
    )
    report_yaml = parser.analyze_code(yaml_code, language="python")
    assert any(f.cwe == "CWE-502" for f in report_yaml.findings)

    # json.loads -> Safe
    safe_json = (
        "import json\n"
        "def parse_json(raw):\n"
        "    return json.loads(raw)\n"
    )
    report_safe_json = parser.analyze_code(safe_json, language="python")
    assert not any(f.cwe == "CWE-502" for f in report_safe_json.findings)


def test_ast_suppression_nosec():
    parser = ASTParserEngine()

    # Suppressed vulnerability
    suppressed_code = (
        "import os\n"
        "def test_cmd(cmd):\n"
        "    os.system(cmd)  # nosec\n"
    )
    report = parser.analyze_code(suppressed_code, language="python")
    findings = [f for f in report.findings if f.cwe == "CWE-78"]
    assert len(findings) == 1
    assert findings[0].suppressed_by == "# nosec"
    assert findings[0].tier == 2


# --------------------------------------------------------------------------
# 3. Multi-Language Structural Lexer Fallback Tests
# --------------------------------------------------------------------------
def test_multilanguage_structural_lexer():
    parser = ASTParserEngine()

    # JavaScript SQL concatenation
    js_code = (
        "function getUser(id) {\n"
        "    db.query('SELECT * FROM users WHERE id = ' + id);\n"
        "}\n"
    )
    report_js = parser.analyze_code(js_code, language="javascript")
    assert report_js.parser_backend == "structural_fallback"
    assert any(f.cwe == "CWE-89" for f in report_js.findings)

    # Java Command Execution
    java_code = (
        "public class App {\n"
        "    public void run(String cmd) throws Exception {\n"
        "        Runtime.getRuntime().exec(cmd);\n"
        "    }\n"
        "}\n"
    )
    report_java = parser.analyze_code(java_code, language="java")
    assert any(f.cwe == "CWE-78" for f in report_java.findings)

    # Commented-out lines should NOT trigger false alarms
    comment_code = (
        "// os.system(untrusted_input);\n"
        "/* db.query('SELECT ' + id); */\n"
        "console.log('Normal application code');\n"
    )
    report_comment = parser.analyze_code(comment_code, language="javascript")
    assert len(report_comment.findings) == 0


# --------------------------------------------------------------------------
# 4. GraphCodeBERT Classifier Tests
# --------------------------------------------------------------------------
def test_codebert_deterministic_tokenization():
    code = "def authenticate(user, password): return user == 'admin'"
    tensor1, mask1 = tokenize_code_deterministic(code)
    tensor2, mask2 = tokenize_code_deterministic(code)
    assert (tensor1 == tensor2).all()
    assert (mask1 == mask2).all()
    assert tensor1.shape == (1, 128)
    assert mask1.shape == (1, 128, 128)


def test_codebert_classifier_inference():
    score = codebert_classifier.score_code("import os\nos.system('rm -rf /')")
    assert score.status == "OK"
    assert 0.0 <= score.risk_score <= 100.0
    assert "CWE-89" in score.cwe_scores
    assert "CWE-78" in score.cwe_scores
    assert score.latency_ms >= 0.0


# --------------------------------------------------------------------------
# 5. Judge 3-Tier Precedence Consensus Tests
# --------------------------------------------------------------------------
def test_judge_3tier_precedence():
    judge = CodeSecurityJudge()
    parser = ASTParserEngine()

    # Tier 1 Override: High-Confidence SQLi
    report = parser.analyze_code("cursor.execute(f'SELECT * FROM x WHERE id={i}')", language="python")
    codebert_score = codebert_classifier.score_code("")
    verdict, policy, risk, conf, reason = judge.evaluate(
        ast_report=report,
        codebert_score=codebert_score,
        secrets=[],
        all_findings=report.findings,
    )
    assert verdict == VerdictEnum.MALICIOUS
    assert policy == PolicyActionEnum.BLOCK
    assert risk >= 90.0

    # Tier 2 Override: Suppressed vulnerability with valid # nosec
    suppressed_report = parser.analyze_code("os.system(x)  # nosec", language="python")
    verdict_s, policy_s, risk_s, conf_s, reason_s = judge.evaluate(
        ast_report=suppressed_report,
        codebert_score=codebert_score,
        secrets=[],
        all_findings=suppressed_report.findings,
    )
    assert verdict_s == VerdictEnum.CLEAN
    assert policy_s == PolicyActionEnum.ALLOW
    assert risk_s < 20.0


# --------------------------------------------------------------------------
# 6. Unified Engine & LRU Cache Tests
# --------------------------------------------------------------------------
def test_engine_scan_and_caching():
    engine = CodeSecurityEngine()

    code = "import json\ndef parse(s):\n    return json.loads(s)\n"
    res1 = engine.scan_code(code, language="python")
    assert res1.verdict == VerdictEnum.CLEAN
    assert res1.cached is False

    # Second scan -> Cache hit
    res2 = engine.scan_code(code, language="python")
    assert res2.verdict == VerdictEnum.CLEAN
    assert res2.cached is True
    assert res1.sha256 == res2.sha256


def test_engine_oversized_payload():
    engine = CodeSecurityEngine()
    oversized = "a = 1\n" * (1024 * 300)  # > 1MB
    res = engine.scan_code(oversized, language="python")
    assert res.verdict == VerdictEnum.UNSCANNABLE
    assert res.policy_action == PolicyActionEnum.REJECT


# --------------------------------------------------------------------------
# 7. Gateway REST API Integration (/api/v1/scan-code)
# --------------------------------------------------------------------------
def test_gateway_api_scan_code_clean():
    clean_payload = {
        "code": "def add(a, b):\n    return a + b\n",
        "language": "python",
        "filename": "calc.py"
    }
    response = client.post("/api/v1/scan-code", json=clean_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["policy_action"] == "ALLOW"
    assert data["verdict"] == "CLEAN"


def test_gateway_api_scan_code_vulnerable():
    vuln_payload = {
        "code": "import os\ndef ping(host):\n    os.system(f'ping -c 1 {host}')\n",
        "language": "python",
        "filename": "net.py"
    }
    response = client.post("/api/v1/scan-code", json=vuln_payload)
    assert response.status_code == 403
    data = response.json()
    assert data["policy_action"] == "BLOCK"
    assert data["verdict"] == "MALICIOUS"
    assert len(data["findings"]) >= 1


def test_gateway_api_scan_code_empty_400():
    response = client.post("/api/v1/scan-code", json={"code": ""})
    assert response.status_code == 400


# --------------------------------------------------------------------------
# 8. Claude Review Hardening & Edge Case Tests
# --------------------------------------------------------------------------
def test_ast_constant_query_not_tainted():
    """Verifies that queries stored in constant variables do not trigger false positives."""
    parser = ASTParserEngine()
    code = (
        "def list_items():\n"
        "    SQL_QUERY = 'SELECT * FROM inventory ORDER BY id DESC'\n"
        "    cursor.execute(SQL_QUERY)\n"
    )
    report = parser.analyze_code(code, language="python")
    assert not any(f.cwe == "CWE-89" for f in report.findings)


def test_ast_reassignment_cleans_taint():
    """Verifies that assigning a constant cleans a previously tainted variable."""
    parser = ASTParserEngine()
    code = (
        "def sanitize_and_query():\n"
        "    query = input('Enter search: ')\n"
        "    query = 'SELECT * FROM public_items'\n"
        "    cursor.execute(query)\n"
    )
    report = parser.analyze_code(code, language="python")
    assert not any(f.cwe == "CWE-89" for f in report.findings)


def test_ast_os_popen_flagged():
    """Verifies that os.popen with dynamic input is flagged as CWE-78."""
    parser = ASTParserEngine()
    code = (
        "import os\n"
        "def run_pipe(target):\n"
        "    pipe = os.popen('nslookup ' + target)\n"
        "    return pipe.read()\n"
    )
    report = parser.analyze_code(code, language="python")
    assert any(f.cwe == "CWE-78" for f in report.findings)


def test_judge_suppression_does_not_bypass_unsuppressed_tier1():
    """Verifies that # nosec on one line cannot bypass an unsuppressed vulnerability on another line."""
    judge = CodeSecurityJudge()
    engine = CodeSecurityEngine()
    mixed_code = (
        "import os\n"
        "os.system('ls')  # nosec\n"
        "AWS_KEY = 'AKIA1234567890ABCDEF'\n"
    )
    res = engine.scan_code(mixed_code, language="python")
    assert res.verdict == VerdictEnum.MALICIOUS
    assert res.policy_action == PolicyActionEnum.BLOCK


def test_secret_in_comment_detected():
    """Verifies that structural verified secrets committed inside comments are detected."""
    scanner = SecretScanner()
    commented_leak = "# TODO: remove before prod AWS_KEY = AKIA9988776655443322\n"
    secrets, findings = scanner.scan_code(commented_leak)
    assert len(secrets) == 1
    assert secrets[0].kind == "AWS Access Key ID"
    assert secrets[0].verified_structure is True


def test_ast_cursor_execute_with_receiver():
    """Verifies that self.cursor.execute(...) is properly resolved via rpartition."""
    parser = ASTParserEngine()
    code = (
        "class DB:\n"
        "    def query_user(self, user_id):\n"
        "        self.cursor.execute('SELECT * FROM users WHERE id = ' + user_id)\n"
    )
    report = parser.analyze_code(code, language="python")
    assert any(f.cwe == "CWE-89" for f in report.findings)


def test_ast_tuple_modulo_formatting():
    """Verifies that old-style tuple modulo string formatting (%s % (var,)) is flagged."""
    parser = ASTParserEngine()
    code = (
        "def query_user(user_id):\n"
        "    cursor.execute('SELECT * FROM users WHERE id = %s' % (user_id,))\n"
    )
    report = parser.analyze_code(code, language="python")
    assert any(f.cwe == "CWE-89" for f in report.findings)


def test_ast_parameterized_query_with_interpolated_string_flagged():
    """Verifies that passing parameters cannot bypass a dynamic query string containing interpolation."""
    parser = ASTParserEngine()
    code = (
        "def query_user(name, uid):\n"
        "    cursor.execute(f'SELECT * FROM users WHERE name = {name} AND id = %s', (uid,))\n"
    )
    report = parser.analyze_code(code, language="python")
    assert any(f.cwe == "CWE-89" for f in report.findings)


def test_ast_function_parameter_shadows_outer_constant():
    """Verifies that function parameters properly shadow outer constants."""
    parser = ASTParserEngine()
    code = (
        "q = 'SELECT 1'\n"
        "def search(q):\n"
        "    cursor.execute(q)\n"
    )
    report = parser.analyze_code(code, language="python")
    assert any(f.cwe == "CWE-89" for f in report.findings)


def test_secret_scanner_quoted_json_keys():
    """Verifies that secret scanner handles quoted JSON/dict keys."""
    scanner = SecretScanner()
    code = '{"api_key": "9a8f7c6e5b4a3d2e1f0a9b8c7d6e5f4a"}\n'
    secrets, findings = scanner.scan_code(code)
    assert len(secrets) == 1
    assert secrets[0].kind == "High-Entropy Credential Assignment"


def test_secret_scanner_false_positive_rejection():
    """Verifies that words like author, cache_key, and public_key do not trigger false alarms."""
    scanner = SecretScanner()
    code = (
        "author = 'Jane Austen 1234567890'\n"
        "cache_key = 'user:profile:settings:1234567890'\n"
        "key_name = 'primary_key_identifier_index'\n"
    )
    secrets, findings = scanner.scan_code(code)
    assert len(secrets) == 0


def test_judge_suppressed_tier1_quarantined_not_allowed():
    """Verifies that a critical Tier 1 vulnerability cannot be suppressed into ALLOW via # nosec."""
    engine = CodeSecurityEngine()
    code = (
        "import os\n"
        "def run_cmd(c):\n"
        "    os.system(c)  # nosec\n"
    )
    res = engine.scan_code(code, language="python")
    # Must NOT be ALLOW / CLEAN
    assert res.verdict != VerdictEnum.CLEAN
    assert res.policy_action != PolicyActionEnum.ALLOW
    assert res.policy_action in (PolicyActionEnum.QUARANTINE, PolicyActionEnum.BLOCK)


def test_ast_python3_language_normalization():
    """Verifies that passing language='python3' invokes native Python AST parser."""
    parser = ASTParserEngine()
    code = "def test(x): return x + 1"
    report = parser.analyze_code(code, language="python3")
    assert report.parser_backend == "python_ast"

