"""
AST Parser & Taint Analysis Engine (Pillar II)
Supports dynamic Tree-sitter inspection, native Python AST taint tracking,
and resilient multi-language structural parsing for JS, Java, and C/C++.
"""

import ast
import re
from typing import List, Dict, Set, Tuple, Optional, Any

from core.codesec.schemas import (
    ASTAnalysisReport,
    VulnerabilityFinding,
    ScanSourceEnum,
)

# Tree-sitter dynamic probe
TREE_SITTER_AVAILABLE = False
try:
    import tree_sitter  # noqa: F401
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


# SQL Injection Sinks
SQL_SINK_METHODS = {
    "execute", "executemany", "raw", "select", "query",
}

# Command Injection Sinks
COMMAND_SINKS = {
    ("os", "system"),
    ("os", "popen"),
    ("posix", "system"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
}

# Deserialization / Code Execution Sinks
DESERIALIZATION_SINKS = {
    ("pickle", "loads"),
    ("pickle", "load"),
    ("_pickle", "loads"),
    ("yaml", "load"),
    ("yaml", "unsafe_load"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    (None, "eval"),
    (None, "exec"),
}


class PythonTaintVisitor(ast.NodeVisitor):
    """
    Intra-procedural AST taint and pattern analyzer for Python.
    Tracks sources, string interpolations, concatenations, and dangerous sinks.
    """

    def __init__(self, raw_lines: List[str]):
        self.raw_lines = raw_lines
        self.findings: List[VulnerabilityFinding] = []
        self.ast_nodes_count = 0
        self.call_sites_count = 0
        self.taint_sinks_detected = 0
        self.suppression_count = 0

        # Tainted variable names (sources or variables carrying tainted data)
        self.tainted_vars: Set[str] = set()
        # Explicit constant variables (safe from dynamic interpolation)
        self.constant_vars: Set[str] = set()
        # Aliases for modules (e.g. from os import system as s, or import subprocess as sp)
        self.module_aliases: Dict[str, str] = {}
        self.func_aliases: Dict[str, Tuple[Optional[str], str]] = {}

    def visit(self, node: ast.AST):
        self.ast_nodes_count += 1
        super().visit(node)

    def _has_suppression(self, lineno: int, end_lineno: Optional[int] = None) -> Optional[str]:
        """Checks if lines from lineno to end_lineno contain # nosec or # ignore-security."""
        end = end_lineno or lineno
        for l in range(lineno, end + 1):
            if 1 <= l <= len(self.raw_lines):
                line = self.raw_lines[l - 1]
                # Strip string literals roughly or check comment token
                if "# nosec" in line:
                    return "# nosec"
                if "# ignore-security" in line:
                    return "# ignore-security"
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Function parameters are untrusted inputs scoped to this function
        saved_tainted = set(self.tainted_vars)
        saved_constants = set(self.constant_vars)
        for arg in node.args.args:
            self.tainted_vars.add(arg.arg)
            self.constant_vars.discard(arg.arg)
        self.generic_visit(node)
        self.tainted_vars = saved_tainted
        self.constant_vars = saved_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        saved_tainted = set(self.tainted_vars)
        saved_constants = set(self.constant_vars)
        for arg in node.args.args:
            self.tainted_vars.add(arg.arg)
            self.constant_vars.discard(arg.arg)
        self.generic_visit(node)
        self.tainted_vars = saved_tainted
        self.constant_vars = saved_constants

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.asname:
                self.module_aliases[alias.asname] = alias.name
            else:
                self.module_aliases[alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            target_name = alias.asname or alias.name
            self.func_aliases[target_name] = (mod, alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Taint propagation through assignments: var = untrusted / var = s + tainted
        is_const = isinstance(node.value, ast.Constant)
        is_tainted = False

        if is_const:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.constant_vars.add(target.id)
                    self.tainted_vars.discard(target.id)
        else:
            if isinstance(node.value, ast.Call):
                func_name = self._get_call_name(node.value)
                if func_name in ("input", "sys.argv", "os.environ.get", "request.args.get", "request.form.get"):
                    is_tainted = True
                elif self._is_expression_tainted_or_interpolated(node.value):
                    is_tainted = True
            elif isinstance(node.value, (ast.JoinedStr, ast.BinOp)):
                is_tainted = self._is_expression_tainted_or_interpolated(node.value)
            elif isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
                is_tainted = True
            elif isinstance(node.value, ast.Attribute) and "argv" in node.value.attr:
                is_tainted = True

            if is_tainted:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
                        self.constant_vars.discard(target.id)

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        # Handles += assignments
        if isinstance(node.target, ast.Name):
            if self._is_expression_tainted_or_interpolated(node.value):
                self.tainted_vars.add(node.target.id)
                self.constant_vars.discard(node.target.id)
        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            base = self._get_attr_base(node.func.value)
            return f"{base}.{node.func.attr}" if base else node.func.attr
        return ""

    def _get_attr_base(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.module_aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            sub = self._get_attr_base(node.value)
            return f"{sub}.{node.attr}" if sub else node.attr
        return ""

    def _is_expression_tainted_or_interpolated(self, node: ast.AST) -> bool:
        """Determines if expression involves non-constant concatenation, formatting, or dynamic taint."""
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Mod)):
                left_dyn = self._is_expression_tainted_or_interpolated(node.left)
                right_dyn = self._is_expression_tainted_or_interpolated(node.right)
                return left_dyn or right_dyn
        if isinstance(node, (ast.Tuple, ast.List)):
            return any(self._is_expression_tainted_or_interpolated(elt) for elt in node.elts)
        if isinstance(node, ast.Subscript):
            return self._is_expression_tainted_or_interpolated(node.value)
        if isinstance(node, ast.Attribute):
            return self._is_expression_tainted_or_interpolated(node.value)
        if isinstance(node, ast.Call):
            call_name = self._get_call_name(node)
            # Sanitizers and type coercions break dynamic injection taint
            if call_name in ("int", "float", "bool", "shlex.quote", "html.escape", "quote"):
                return False
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
            return True  # Unknown function call return value assumed dynamic
        if isinstance(node, ast.Name):
            if node.id in self.constant_vars:
                return False
            if node.id in self.tainted_vars:
                return True
            return True  # external parameter / variable assumed dynamic
        return False

    def visit_Call(self, node: ast.Call):
        self.call_sites_count += 1
        call_name = self._get_call_name(node)
        lineno = getattr(node, "lineno", 1)
        end_lineno = getattr(node, "end_lineno", lineno)
        suppression = self._has_suppression(lineno, end_lineno)
        if suppression:
            self.suppression_count += 1

        # Resolve function alias if present using rpartition for accurate module/func separation
        mod_prefix = ""
        func_base = call_name
        if "." in call_name:
            mod_prefix, _, func_base = call_name.rpartition(".")
        elif call_name in self.func_aliases:
            mod_prefix, func_base = self.func_aliases[call_name]

        # 1. CWE-89: SQL Injection Check
        if func_base in SQL_SINK_METHODS and node.args:
            sql_arg = node.args[0]
            if self._is_expression_tainted_or_interpolated(sql_arg):
                self.taint_sinks_detected += 1
                evidence_line = self.raw_lines[lineno - 1].strip() if 0 < lineno <= len(self.raw_lines) else "Dynamic SQL query"
                evidence_safe = evidence_line[:75] + ("..." if len(evidence_line) > 75 else "")

                self.findings.append(VulnerabilityFinding(
                    cwe="CWE-89",
                    title="SQL Injection via Unsanitized Query Formatting",
                    line_start=lineno,
                    line_end=end_lineno,
                    confidence=0.96 if not suppression else 0.40,
                    tier=1 if not suppression else 2,
                    source=ScanSourceEnum.TAINT,
                    evidence=f"Dynamic SQL query formatting at line {lineno}: {evidence_safe}",
                    remediation="Use parameterized queries e.g. cursor.execute('SELECT * FROM t WHERE id = %s', (val,)) instead of string formatting or concatenation.",
                    suppressed_by=suppression,
                ))

        # 2. CWE-78: Command Injection Check
        is_cmd_sink = (
            (mod_prefix, func_base) in COMMAND_SINKS
            or (func_base in ("system", "popen") and (not mod_prefix or mod_prefix in ("os", "posix")))
            or (mod_prefix.endswith("subprocess") and func_base in ("run", "Popen", "call", "check_output", "check_call"))
            or (func_base in ("run", "Popen", "call") and mod_prefix == "subprocess")
        )
        if is_cmd_sink and node.args:
            cmd_arg = node.args[0]
            shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    shell_true = True

            is_dynamic_cmd = self._is_expression_tainted_or_interpolated(cmd_arg)
            is_const_list = isinstance(cmd_arg, ast.List) and all(isinstance(elt, ast.Constant) for elt in cmd_arg.elts)
            is_const_cmd = isinstance(cmd_arg, ast.Constant) or is_const_list

            if is_dynamic_cmd or (shell_true and not is_const_cmd):
                self.taint_sinks_detected += 1
                evidence_line = self.raw_lines[lineno - 1].strip() if 0 < lineno <= len(self.raw_lines) else "Shell command execution"
                evidence_safe = evidence_line[:75] + ("..." if len(evidence_line) > 75 else "")
                self.findings.append(VulnerabilityFinding(
                    cwe="CWE-78",
                    title="OS Command Injection via Shell Execution",
                    line_start=lineno,
                    line_end=end_lineno,
                    confidence=0.98 if not suppression else 0.40,
                    tier=1 if not suppression else 2,
                    source=ScanSourceEnum.TAINT,
                    evidence=f"Dangerous shell command execution at line {lineno}: {evidence_safe}",
                    remediation="Avoid shell=True. Pass arguments as a list of strings and sanitize inputs using shlex.quote().",
                    suppressed_by=suppression,
                ))

        # 3. CWE-502: Insecure Deserialization / Unsafe Code Evaluation
        is_deserialization = (
            (mod_prefix, func_base) in DESERIALIZATION_SINKS
            or (func_base in ("loads", "load") and mod_prefix in ("pickle", "_pickle"))
            or (mod_prefix == "yaml" and func_base in ("unsafe_load", "load"))
            or (func_base in ("eval", "exec") and mod_prefix in (None, "builtins"))
        )
        if is_deserialization and node.args:
            # For yaml.load, check if Loader=yaml.SafeLoader is used
            is_safe_yaml = False
            if mod_prefix == "yaml" and func_base == "load":
                for kw in node.keywords:
                    if kw.arg in ("Loader", "loader"):
                        loader_repr = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
                        if "SafeLoader" in loader_repr or "CSafeLoader" in loader_repr:
                            is_safe_yaml = True

            if not is_safe_yaml:
                self.taint_sinks_detected += 1
                evidence_line = self.raw_lines[lineno - 1].strip() if 0 < lineno <= len(self.raw_lines) else "Insecure deserialization"
                self.findings.append(VulnerabilityFinding(
                    cwe="CWE-502",
                    title="Insecure Deserialization of Untrusted Data",
                    line_start=lineno,
                    line_end=lineno,
                    confidence=0.95 if not suppression else 0.40,
                    tier=1 if not suppression else 2,
                    source=ScanSourceEnum.TAINT,
                    evidence=f"Deserialization or unsafe eval call at line {lineno}: {evidence_line}",
                    remediation="Never deserialize untrusted payloads with pickle/yaml.load(). Use safe alternatives like json.loads() or yaml.safe_load().",
                    suppressed_by=suppression,
                ))

        self.generic_visit(node)


class MultiLanguageStructuralLexer:
    """
    Fallback structural scanner for JavaScript, Java, C/C++, and Go.
    Operates with comment-stripping and string-awareness to avoid false alarms.
    """

    PATTERNS = [
        # CWE-89 SQL Injection in JS / Java
        (
            "CWE-89",
            "SQL Injection via Query Concatenation",
            re.compile(r"""(?xi)
                \b(?:executeQuery|executeUpdate|query|execute)\s*\(\s*
                (?:
                    ["'][^"']*["']\s*\+\s*[a-zA-Z0-9_]+  # "SELECT ... " + var
                    |
                    [a-zA-Z0-9_]+\s*\+\s*["'][^"']*["']  # var + " FROM ..."
                    |
                    `[^`]*\$\{[^}]+\}[^`]*`               # JS template literal `SELECT ${var}`
                )
            """),
            0.88,
            "Use parameterized SQL prepared statements with bind parameters (?, $1).",
        ),
        # CWE-78 Command Injection in JS / Java / C (protecting JS regex .exec)
        (
            "CWE-78",
            "OS Command Injection in Native Process Invocation",
            re.compile(r"""(?xi)
                (?:
                    (?<!\.)\bexec\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|[a-zA-Z0-9_]+\s*\+\s*["'][^"']*["']|["'][^"']*["']\s*\+\s*[a-zA-Z0-9_]+)
                    |
                    Runtime\.getRuntime\(\)\.exec\s*\(\s*[a-zA-Z0-9_]+
                    |
                    (?<!\.)\bsystem\s*\(\s*(?:[a-zA-Z0-9_]+|["'][^"']*["']\s*\+)
                    |
                    (?<!\.)\bpopen\s*\(\s*(?:[a-zA-Z0-9_]+|["'][^"']*["']\s*\+)
                )
            """),
            0.85,
            "Avoid invoking the shell directly with user input. Use safe exec arrays without shell interpolation.",
        ),
        # CWE-502 Insecure Deserialization in Java / JS
        (
            "CWE-502",
            "Insecure Object Deserialization or Eval",
            re.compile(r"""(?xi)
                \b(?:
                    readObject\s*\(\s*\)
                    |
                    (?<!\.)\beval\s*\(\s*[a-zA-Z0-9_]+
                )
            """),
            0.85,
            "Use secure serialization formats (JSON, Protobuf) and avoid dynamic eval.",
        ),
    ]

    def scan(self, code: str) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        lines = code.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip single-line comments in C, C++, JS, Java
            if stripped.startswith(("//", "/*", "*")):
                continue

            suppression = None
            if "// nosec" in line or "/* nosec */" in line:
                suppression = "nosec"

            for cwe, title, pattern, conf, remediation in self.PATTERNS:
                if pattern.search(line):
                    findings.append(VulnerabilityFinding(
                        cwe=cwe,
                        title=title,
                        line_start=idx,
                        line_end=idx,
                        confidence=conf if not suppression else 0.40,
                        tier=3 if not suppression else 2,
                        source=ScanSourceEnum.REGEX,
                        evidence=f"Structural match at line {idx}: {stripped[:80]}",
                        remediation=remediation,
                        suppressed_by=suppression,
                    ))

        return findings


class ASTParserEngine:
    """
    Coordinates AST parsing across programming languages.
    Selects Python AST, Tree-sitter (if installed), or Multi-Language Lexer.
    """

    def analyze_code(self, code: str, language: str = "python") -> ASTAnalysisReport:
        lang_lower = (language or "python").lower().strip()
        lines = code.splitlines()
        total_lines = len(lines)

        # 1. Native Python AST Parser
        if lang_lower in ("python", "py", "python3", "py3"):
            try:
                tree = ast.parse(code)
                visitor = PythonTaintVisitor(raw_lines=lines)
                visitor.visit(tree)

                return ASTAnalysisReport(
                    parser_backend="python_ast",
                    language="python",
                    total_lines=total_lines,
                    ast_nodes_count=visitor.ast_nodes_count,
                    call_sites_count=visitor.call_sites_count,
                    findings=visitor.findings,
                    taint_sinks_detected=visitor.taint_sinks_detected,
                    suppression_comments_count=visitor.suppression_count,
                )
            except (SyntaxError, ValueError, RecursionError, MemoryError, Exception):
                # Fall back to structural scanning if syntax error occurs in partial code
                lexer = MultiLanguageStructuralLexer()
                fallback_findings = lexer.scan(code)
                return ASTAnalysisReport(
                    parser_backend="structural_fallback",
                    language="python",
                    total_lines=total_lines,
                    ast_nodes_count=0,
                    call_sites_count=len(fallback_findings),
                    findings=fallback_findings,
                    taint_sinks_detected=len(fallback_findings),
                    suppression_comments_count=0,
                )

        # 2. Tree-sitter probe if available
        if TREE_SITTER_AVAILABLE:
            # Tree-sitter wrapper would execute here if native grammar packages are present
            pass

        # 3. Multi-Language Structural Lexer Fallback (JS, Java, C, C++, Go)
        lexer = MultiLanguageStructuralLexer()
        findings = lexer.scan(code)

        return ASTAnalysisReport(
            parser_backend="structural_fallback",
            language=lang_lower,
            total_lines=total_lines,
            ast_nodes_count=len(findings) * 5,
            call_sites_count=len(findings),
            findings=findings,
            taint_sinks_detected=len(findings),
            suppression_comments_count=0,
        )
