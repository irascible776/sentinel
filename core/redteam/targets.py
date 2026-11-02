"""
Developer: Red-Team Squad (Pillar V)
Universal Target Connectors with Strict Allow-List Guardrails
(Refined with Claude Security Review Findings)
"""

import os
import abc
import time
import ipaddress
import httpx
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from core.redteam.schemas import TargetType, TargetResponse


def is_host_allowed(target_url: str, extra_allowed: Optional[List[str]] = None) -> bool:
    """
    Security Guardrail: Ensures the red-team engine only targets authorized loopback,
    private test environments, or explicitly declared enterprise hosts.
    Explicitly DENIES cloud metadata service (169.254.0.0/16) and link-local ranges.
    """
    try:
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return False
            
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False

        # Block cloud metadata service and IPv4 link-local (169.254.0.0/16)
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False
            # Block 169.254.169.254 AWS/GCP metadata explicitly
            if str(ip).startswith("169.254."):
                return False
        except ValueError:
            # Hostname is a string domain (e.g. localhost)
            pass

        # Permitted default hosts
        permitted = {"127.0.0.1", "localhost", "::1"}
        
        # Load from environment or argument
        env_allowed = os.getenv("REDTEAM_ALLOWED_HOSTS", "")
        if env_allowed:
            permitted.update([h.strip().lower() for h in env_allowed.split(",") if h.strip()])
        if extra_allowed:
            permitted.update([h.strip().lower() for h in extra_allowed if h.strip()])
            
        return hostname in permitted
    except Exception:
        return False


class BaseTargetConnector(abc.ABC):
    """Abstract interface for all adversarial target endpoints."""
    
    def __init__(self, endpoint: str):
        if not is_host_allowed(endpoint):
            raise ValueError(f"Target endpoint '{endpoint}' is not authorized in REDTEAM_ALLOWED_HOSTS.")
        self.endpoint = endpoint

    @abc.abstractmethod
    async def send_probe(self, messages: List[Dict[str, str]], **kwargs) -> TargetResponse:
        """Sends an adversarial probe and returns normalized TargetResponse."""
        pass

    @abc.abstractmethod
    async def health_check(self) -> bool:
        """Verifies target availability and readiness."""
        pass

    def extract_oracle_score(self, response: TargetResponse) -> Optional[float]:
        """Returns target risk score if target exposes an internal risk oracle."""
        return response.oracle_score


class SentinelLocalTarget(BaseTargetConnector):
    """
    Targets Sentinel's local Gateway (/api/v1/inspect).
    Extracts Sentinel's consensus score as a free hill-climbing oracle for the search tree.
    Sends X-Sentinel-Audit header to isolate audit traffic from production learning loops.
    """
    def __init__(self, base_url: str = "http://127.0.0.1:8000", api_key: Optional[str] = None):
        super().__init__(endpoint=base_url)
        self.base_url = base_url.rstrip("/")
        from core.gateway.config import settings
        resolved_key = api_key or os.getenv("REDTEAM_SERVICE_KEY") or getattr(settings, "REDTEAM_SERVICE_KEY", None)
        if not resolved_key:
            raise ValueError(
                "REDTEAM_SERVICE_KEY is not configured. Set REDTEAM_SERVICE_KEY in environment or pass api_key explicitly."
            )
        self.api_key = resolved_key
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)

    async def aclose(self):
        await self.client.aclose()

    async def send_probe(self, messages: List[Dict[str, str]], **kwargs) -> TargetResponse:
        t0 = time.perf_counter()
        last_prompt = messages[-1]["content"] if messages else ""
        campaign_id = kwargs.get("campaign_id", "default")
        seed_id = kwargs.get("seed_id", "0")
        lineage_id = kwargs.get("lineage_id", "root")
        
        # Frozen session ID preserves multi-turn session continuity along a path
        # while strictly isolating divergent sibling branches
        session_id = kwargs.get("session_id") or f"audit-{campaign_id[:8]}-{seed_id}-{lineage_id}"
        
        headers = {
            "Content-Type": "application/json",
            "X-Sentinel-Audit": campaign_id  # Informs gateway to isolate from production threat feed
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            resp = await self.client.post(
                f"{self.base_url}/api/v1/inspect",
                json={"prompt": last_prompt, "messages": messages, "session_id": session_id},
                headers=headers
            )
            lat = (time.perf_counter() - t0) * 1000.0

            # Guard against HTTP errors, 429 rate limits, and 500s
            if resp.status_code != 200:
                return TargetResponse(
                    raw_response="",
                    latency_ms=lat,
                    status_code=resp.status_code,
                    decision=None,
                    oracle_score=None,
                    valid=False,
                    error=f"HTTP Error {resp.status_code}: {resp.text[:200]}"
                )

            data = resp.json()
            if "consensus_score" not in data or "decision" not in data:
                return TargetResponse(
                    raw_response=resp.text,
                    latency_ms=lat,
                    status_code=resp.status_code,
                    decision=None,
                    oracle_score=None,
                    valid=False,
                    error="Malformed inspection response (missing consensus_score or decision)"
                )

            decision = data.get("decision", "ALLOW")
            raw_consensus = float(data.get("consensus_score", 0.0))
            # Consensus score is in range 0.0 to 1.0; scale to 0.0-100.0
            risk_score = raw_consensus * 100.0
            response_text = data.get("response") or f"[SENTINEL_INSPECT: {decision} (Risk: {risk_score:.1f})]"

            return TargetResponse(
                raw_response=response_text,
                latency_ms=lat,
                status_code=200,
                decision=decision,
                oracle_score=risk_score,
                valid=True,
                headers=dict(resp.headers)
            )
        except Exception as e:
            lat = (time.perf_counter() - t0) * 1000.0
            return TargetResponse(
                raw_response="",
                latency_ms=lat,
                status_code=0,
                decision=None,
                oracle_score=None,
                valid=False,
                error=f"Connection failure: {str(e)}"
            )

    async def health_check(self) -> bool:
        try:
            r = await self.client.get(f"{self.base_url}/health")
            return r.status_code == 200
        except Exception:
            return False


class OllamaTarget(BaseTargetConnector):
    """Targets a local or remote Ollama instance (http://localhost:11434)."""
    
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3.2:1b"):
        super().__init__(endpoint=host)
        self.host = host.rstrip("/")
        self.model = model
        self.client = httpx.AsyncClient(timeout=45.0, follow_redirects=False)

    async def aclose(self):
        await self.client.aclose()

    async def send_probe(self, messages: List[Dict[str, str]], **kwargs) -> TargetResponse:
        t0 = time.perf_counter()
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": 0.2, "num_predict": 512}
            }
            resp = await self.client.post(f"{self.host}/api/chat", json=payload)
            lat = (time.perf_counter() - t0) * 1000.0
            
            if resp.status_code != 200:
                return TargetResponse(
                    raw_response="",
                    latency_ms=lat,
                    status_code=resp.status_code,
                    valid=False,
                    error=f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}"
                )

            data = resp.json()
            content = data.get("message", {}).get("content", "")
            return TargetResponse(
                raw_response=content,
                latency_ms=lat,
                status_code=200,
                valid=True
            )
        except Exception as e:
            lat = (time.perf_counter() - t0) * 1000.0
            return TargetResponse(raw_response="", latency_ms=lat, status_code=0, valid=False, error=str(e))

    async def health_check(self) -> bool:
        try:
            r = await self.client.get(f"{self.host}/api/tags")
            return r.status_code == 200
        except Exception:
            return False


class VLLMOpenAITarget(BaseTargetConnector):
    """Targets an OpenAI-compatible server (vLLM, SGLang, or LocalAI)."""
    
    def __init__(self, base_url: str, model: str, api_key: Optional[str] = None):
        super().__init__(endpoint=base_url)
        # Normalize endpoint (strip /v1 or trailing slash to avoid /v1/v1)
        cleaned = base_url.rstrip("/")
        if cleaned.endswith("/v1"):
            cleaned = cleaned[:-3]
        self.base_url = cleaned
        self.model = model
        self.api_key = api_key or "EMPTY"
        self.client = httpx.AsyncClient(timeout=45.0, follow_redirects=False)

    async def aclose(self):
        await self.client.aclose()

    async def send_probe(self, messages: List[Dict[str, str]], **kwargs) -> TargetResponse:
        t0 = time.perf_counter()
        try:
            headers = {"Content-Type": "application/json"}
            if self.api_key and self.api_key != "EMPTY":
                headers["Authorization"] = f"Bearer {self.api_key}"
            payload = {
                "model": self.model,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 512
            }
            resp = await self.client.post(f"{self.base_url}/v1/chat/completions", json=payload, headers=headers)
            lat = (time.perf_counter() - t0) * 1000.0

            if resp.status_code != 200:
                return TargetResponse(
                    raw_response="",
                    latency_ms=lat,
                    status_code=resp.status_code,
                    valid=False,
                    error=f"vLLM returned HTTP {resp.status_code}: {resp.text[:200]}"
                )

            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                return TargetResponse(
                    raw_response="",
                    latency_ms=lat,
                    status_code=resp.status_code,
                    valid=False,
                    error="Missing choices in vLLM response"
                )

            content = choices[0].get("message", {}).get("content", "")
            return TargetResponse(raw_response=content, latency_ms=lat, status_code=200, valid=True)
        except Exception as e:
            lat = (time.perf_counter() - t0) * 1000.0
            return TargetResponse(raw_response="", latency_ms=lat, status_code=0, valid=False, error=str(e))

    async def health_check(self) -> bool:
        try:
            r = await self.client.get(f"{self.base_url}/v1/models")
            return r.status_code == 200
        except Exception:
            return False


class GenericHttpTarget(BaseTargetConnector):
    """Targets arbitrary REST endpoints with configurable JSON body format."""
    
    def __init__(self, endpoint: str, headers: Optional[Dict[str, str]] = None):
        super().__init__(endpoint=endpoint)
        self.headers = headers or {}
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)

    async def aclose(self):
        await self.client.aclose()

    async def send_probe(self, messages: List[Dict[str, str]], **kwargs) -> TargetResponse:
        t0 = time.perf_counter()
        last_prompt = messages[-1]["content"] if messages else ""
        try:
            resp = await self.client.post(
                self.endpoint,
                json={"prompt": last_prompt, "messages": messages},
                headers=self.headers
            )
            lat = (time.perf_counter() - t0) * 1000.0

            if resp.status_code >= 400:
                return TargetResponse(
                    raw_response="",
                    latency_ms=lat,
                    status_code=resp.status_code,
                    valid=False,
                    error=f"Target returned HTTP {resp.status_code}"
                )

            try:
                data = resp.json()
                content = data.get("response") or data.get("text") or str(data)[:1000]
            except Exception:
                content = resp.text[:1000]
            return TargetResponse(raw_response=content, latency_ms=lat, status_code=200, valid=True)
        except Exception as e:
            lat = (time.perf_counter() - t0) * 1000.0
            return TargetResponse(raw_response="", latency_ms=lat, status_code=0, valid=False, error=str(e))

    async def health_check(self) -> bool:
        try:
            r = await self.client.head(self.endpoint)
            return r.status_code < 500
        except Exception:
            return False


def get_target_connector(
    target_type: TargetType,
    endpoint: str,
    model: Optional[str] = None,
    api_key: Optional[str] = None
) -> BaseTargetConnector:
    """Factory creating appropriate target connector with security validation."""
    if target_type == TargetType.SENTINEL_LOCAL:
        return SentinelLocalTarget(base_url=endpoint, api_key=api_key)
    elif target_type == TargetType.OLLAMA:
        return OllamaTarget(host=endpoint, model=model or "llama3.2:1b")
    elif target_type == TargetType.VLLM_OPENAI:
        return VLLMOpenAITarget(base_url=endpoint, model=model or "default", api_key=api_key)
    elif target_type == TargetType.GENERIC_HTTP:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        return GenericHttpTarget(endpoint=endpoint, headers=headers)
    else:
        raise ValueError(f"Unsupported target type: {target_type}")
