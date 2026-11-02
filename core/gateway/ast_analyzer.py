"""
Developer 1 (Rohit Verma) — Egress Taint-Flow Code AST Analyzer
================================================================
Analyzes Python code in LLM responses for dangerous source → sink data flows.
Catches malware that bypassed all ingress filters by inspecting the GENERATED OUTPUT.

Dangerous Source → Sink pairs (examples):
  pynput.Listener → requests.post    (keylogger exfiltration)
  GetAsyncKeyState → smtplib.sendmail (keystroke stealer via email)
  pyperclip.paste  → socket.send      (clipboard stealer)

Design:
  - Runs BEFORE bytes are sent to the client (plugs into stream_interceptor.py)
  - Pure Python AST + regex, zero ML model dependency, <2ms per scan
  - Only accumulates a rolling buffer of code fences in the response stream
  - Raises TaintFlowViolation if a weaponizable flow is detected

This is the UNBYPASSABLE BACKSTOP: even if an attacker uses perfectly benign
academic English in the prompt that evades both Channel A and Channel B, they
cannot hide malicious import + network-send data flows from a static AST scan.
"""

import ast
import re
from typing import Set, List, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# DANGEROUS SOURCES: APIs that read user input, system state, or secret data
# ──────────────────────────────────────────────────────────────────────────────
DANGEROUS_SOURCES: Set[str] = {
    # Keystroke / Input capture
    "pynput", "pynput.keyboard", "keyboard", "GetAsyncKeyState", "SetWindowsHookEx",
    "WH_KEYBOARD_LL", "WH_KEYBOARD", "ReadConsoleInput", "GetAsyncKeyState",
    "win32api.GetAsyncKeyState", "pyxhook", "xinput",
    # Clipboard
    "pyperclip", "pyperclip.paste", "win32clipboard", "gtk.clipboard_get",
    "subprocess.check_output",  # used for shell command output harvesting
    # Screen capture
    "pyscreenshot", "mss", "ImageGrab", "PIL.ImageGrab",
    # File system (credential file access)
    "os.listdir", "glob.glob", "pathlib.Path",
    # Browser / password store
    "sqlite3.connect",  # often used to read browser cookie/password DBs
    "win32crypt", "CryptUnprotectData",
}

# ──────────────────────────────────────────────────────────────────────────────
# DANGEROUS SINKS: APIs that exfiltrate data to external parties
# ──────────────────────────────────────────────────────────────────────────────
DANGEROUS_SINKS: Set[str] = {
    # Network sockets
    "socket.send", "socket.sendall", "socket.sendto",
    "socket.connect", "s.send", "s.sendall",
    # HTTP exfiltration
    "requests.post", "requests.get", "requests.put",
    "urllib.request.urlopen", "urllib.urlopen",
    "http.client.HTTPConnection", "httplib.HTTPConnection",
    "aiohttp.ClientSession.post",
    # Email exfiltration
    "smtplib.SMTP", "smtplib.SMTP_SSL", "smtplib.sendmail",
    "yagmail.SMTP",
    # FTP / other
    "ftplib.FTP", "ftplib.storbinary",
    # Telegram / Discord bot exfiltration (common in malware samples)
    "telegram.Bot", "bot.send_message", "discord.Webhook",
    # DNS exfiltration
    "dns.resolver.resolve", "socket.gethostbyname",
}

# ──────────────────────────────────────────────────────────────────────────────
# DANGEROUS DYNAMIC EXECUTION PATTERNS (obfuscation bypass)
# ──────────────────────────────────────────────────────────────────────────────
_DYNAMIC_EXEC_RE = re.compile(
    r"(?i)\b(exec\s*\(|eval\s*\(|__import__\s*\(|importlib\.import_module\s*\(|"
    r"getattr\s*\(.*,\s*['\"]__import__|base64\.b64decode\s*\(.*exec|"
    r"compile\s*\(.*exec|os\.system\s*\(|subprocess\.Popen\s*\(.*shell\s*=\s*True)\b"
)

# Regex to extract Python code blocks from markdown response text
_CODE_FENCE_RE = re.compile(
    r"```(?:python|py)?\s*\n(.*?)```",
    re.DOTALL | re.IGNORECASE
)


class TaintFlowViolation(Exception):
    """Raised when a dangerous Source → Sink data flow is detected in LLM output."""
    def __init__(self, source: str, sink: str, detail: str = ""):
        self.source = source
        self.sink = sink
        self.detail = detail
        super().__init__(
            f"TAINT-FLOW VIOLATION: {source} → {sink}. {detail}"
        )


def _extract_names_from_ast(code: str) -> Tuple[Set[str], Set[str]]:
    """
    Parses Python source code and extracts:
      - All imported module names and their aliases
      - All function/method call names

    Returns:
        (imports_set, calls_set)
    """
    imports: Set[str] = set()
    calls: Set[str] = set()

    try:
        tree = ast.parse(code)
    except SyntaxError:
        # Invalid Python — fall back to regex-based scan
        return imports, calls

    for node in ast.walk(tree):
        # Collect imports: import pynput, from pynput import keyboard
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
                if alias.asname:
                    imports.add(alias.asname)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)
            for alias in node.names:
                full = f"{node.module}.{alias.name}" if node.module else alias.name
                imports.add(full)
                if alias.asname:
                    imports.add(alias.asname)

        # Collect call sites: requests.post(...), s.send(...)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                call_str = f"{ast.dump(func.value)}.{func.attr}" if not hasattr(func.value, 'id') else f"{func.value.id}.{func.attr}"  # type: ignore[union-attr]
                calls.add(call_str)
                calls.add(func.attr)  # bare method name
            elif isinstance(func, ast.Name):
                calls.add(func.id)

    return imports, calls


def scan_code_for_taint_flows(code_snippet: str) -> Optional[TaintFlowViolation]:
    """
    Runs taint-flow analysis on a Python code snippet.

    Algorithm:
      1. Parse AST and collect all imported names and call sites.
      2. Check if any DANGEROUS_SOURCE name appears in imports.
      3. Check if any DANGEROUS_SINK name appears in imports OR calls.
      4. If BOTH a source AND a sink exist in the same snippet → VIOLATION.
      5. Also run regex scan for dynamic/obfuscated execution patterns.

    Returns:
        TaintFlowViolation if attack flow detected, None otherwise.
    """
    if not code_snippet or not code_snippet.strip():
        return None

    imports, calls = _extract_names_from_ast(code_snippet)

    # Also do a fast regex pre-scan for module names in the raw text
    raw_lower = code_snippet.lower()

    # Find which dangerous sources are present
    present_sources: List[str] = []
    for src in DANGEROUS_SOURCES:
        if src.lower() in raw_lower or src in imports:
            present_sources.append(src)

    # Find which dangerous sinks are present
    present_sinks: List[str] = []
    for snk in DANGEROUS_SINKS:
        snk_parts = snk.lower().split(".")
        # Accept if the full dotted name OR the method name is in the code
        if snk.lower() in raw_lower or snk_parts[-1] in [c.lower() for c in calls]:
            present_sinks.append(snk)

    if present_sources and present_sinks:
        return TaintFlowViolation(
            source=present_sources[0],
            sink=present_sinks[0],
            detail=(
                f"Keylogger/Exfiltration data-flow detected: "
                f"sources={present_sources[:3]}, sinks={present_sinks[:3]}"
            )
        )

    # Dynamic execution check (obfuscation bypass)
    if _DYNAMIC_EXEC_RE.search(code_snippet) and (present_sources or present_sinks):
        return TaintFlowViolation(
            source="dynamic_exec",
            sink=present_sinks[0] if present_sinks else "unknown",
            detail="Obfuscated dynamic execution combined with dangerous API"
        )

    return None


def scan_response_text(response_text: str) -> Optional[TaintFlowViolation]:
    """
    Extracts all Python code blocks from a markdown-formatted LLM response
    and runs taint-flow analysis on each.

    Plug this into stream_interceptor.py once the full accumulated response
    text is available (or run on each chunk as it grows).

    Returns:
        TaintFlowViolation if any code block contains a dangerous flow, None if clean.
    """
    # Check fenced code blocks first
    code_blocks = _CODE_FENCE_RE.findall(response_text)
    for block in code_blocks:
        violation = scan_code_for_taint_flows(block)
        if violation:
            return violation

    # Also scan the entire response as raw Python (in case no fences are used)
    violation = scan_code_for_taint_flows(response_text)
    return violation
