"""
Smart Context Extractor — Reduces LLM token usage by 60-80%.

Instead of sending the entire file to the LLM, extracts only:
1. The vulnerable function/block (AST-aware for Python, brace-matching for others)
2. Relevant imports/dependencies
3. Surrounding context (5 lines above/below)

This reduces a 500-line file to ~30-50 lines of relevant context,
saving tokens and improving fix accuracy (less noise for the LLM).
"""

import ast
import re
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


def extract_relevant_context(
    code: str,
    findings: List[Dict[str, Any]],
    file_path: str,
    max_context_lines: int = 80,
) -> Dict[str, Any]:
    """
    Extract only the relevant code context for LLM fix generation.

    Returns:
        {
            "context_code": "...",       # Minimal code to send to LLM
            "full_code": "...",          # Original full file
            "line_offset": 0,            # Where context starts in original
            "imports": "...",            # Import statements
            "token_savings_pct": 72.5,   # How much we saved
        }
    """
    lines = code.splitlines()
    total_lines = len(lines)

    if total_lines <= max_context_lines:
        # File is small enough, send it all
        return {
            "context_code": code,
            "full_code": code,
            "line_offset": 0,
            "imports": "",
            "token_savings_pct": 0,
        }

    # Get all affected line numbers
    affected_lines = set()
    for f in findings:
        line = f.get("line", 0)
        end_line = f.get("end_line", line)
        if line:
            affected_lines.add(line)
            if end_line:
                affected_lines.update(range(line, end_line + 1))

    if not affected_lines:
        # No line info, send first max_context_lines
        return {
            "context_code": "\n".join(lines[:max_context_lines]),
            "full_code": code,
            "line_offset": 0,
            "imports": "",
            "token_savings_pct": round((1 - max_context_lines / total_lines) * 100, 1),
        }

    # --- IMPLEMENTATION OF CONTEXTUAL SNIPPETS ---
    # Find the range that covers all affected lines with a 20-line buffer
    sorted_lines = sorted(list(affected_lines))
    start_line = max(0, sorted_lines[0] - 21)  # 0-indexed
    end_line = min(total_lines, sorted_lines[-1] + 20)

    # Extract imports (always needed for context prepending)
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    imports = _extract_imports(lines, ext)

    # If the range is too large, we fall back to the function-aware extraction
    if (end_line - start_line) > max_context_lines:
        # Extract function/block containing the vulnerability
        if ext == "py":
            context_range = _python_function_range(code, affected_lines)
        else:
            context_range = _brace_block_range(lines, affected_lines)

        if context_range:
            start, end = context_range
            start = max(0, start - 5)
            end = min(total_lines, end + 5)
        else:
            center = sorted(affected_lines)[len(affected_lines) // 2]
            half = max_context_lines // 2
            start = max(0, center - half)
            end = min(total_lines, center + half)
    else:
        start, end = start_line, end_line

    # Build context
    context_lines = lines[start:end]
    context_code = "\n".join(context_lines)

    # Prepend imports if they're not already in the context
    if imports and start > 0:
        context_code = imports + "\n\n# ... (context around line {}) ...\n\n".format(
            sorted(affected_lines)[0]
        ) + context_code

    savings = round((1 - len(context_code.splitlines()) / total_lines) * 100, 1)

    return {
        "context_code": context_code,
        "full_code": code,
        "line_offset": start,
        "imports": imports,
        "token_savings_pct": max(0, savings),
    }


def reconstruct_full_file(
    full_code: str,
    fixed_context: str,
    line_offset: int,
    context_line_count: int,
) -> str:
    """
    Reconstruct the full file by replacing the context section with the fix.
    Used when we only sent a portion of the file to the LLM.
    """
    if line_offset == 0 and context_line_count >= len(full_code.splitlines()):
        # We sent the whole file, return the fix as-is
        return fixed_context

    full_lines = full_code.splitlines()

    # Remove import section from fixed_context if it was prepended
    fixed_lines = fixed_context.splitlines()

    # Find where the actual fix starts (skip re-added imports)
    fix_start = 0
    for i, line in enumerate(fixed_lines):
        if "# ... (context around line" in line:
            fix_start = i + 1
            break

    if fix_start > 0:
        fixed_lines = fixed_lines[fix_start:]

    # Replace the section in the original file
    end_offset = line_offset + context_line_count
    result_lines = full_lines[:line_offset] + fixed_lines + full_lines[end_offset:]

    return "\n".join(result_lines)


def _extract_imports(lines: List[str], ext: str) -> str:
    """Extract import/require statements from the top of the file."""
    imports = []

    for line in lines[:50]:  # Only check first 50 lines
        stripped = line.strip()
        if ext == "py":
            if stripped.startswith(("import ", "from ")):
                imports.append(line)
        elif ext in ("js", "ts", "jsx", "tsx"):
            if stripped.startswith(("import ", "const ")) and ("require(" in stripped or "from " in stripped):
                imports.append(line)
            elif stripped.startswith("require("):
                imports.append(line)
        elif ext == "java":
            if stripped.startswith(("import ", "package ")):
                imports.append(line)
        elif ext in ("cs", "fs"):
            if stripped.startswith("using "):
                imports.append(line)
        elif ext == "go":
            if stripped.startswith(("import ", "package ")):
                imports.append(line)
            # Multi-line import block
            if stripped == "import (":
                imports.append(line)
                for next_line in lines[lines.index(line) + 1:]:
                    imports.append(next_line)
                    if next_line.strip() == ")":
                        break

    return "\n".join(imports)


def _python_function_range(code: str, affected_lines: set) -> Optional[Tuple[int, int]]:
    """Find the function/class containing the affected lines using Python AST."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None

    best_range = None
    best_size = float("inf")

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = node.lineno - 1  # 0-indexed
            end = node.end_lineno or start + 1

            # Check if any affected line is in this node
            node_lines = set(range(node.lineno, (node.end_lineno or node.lineno) + 1))
            if affected_lines & node_lines:
                size = end - start
                if size < best_size:
                    best_size = size
                    best_range = (start, end)

    return best_range


def _brace_block_range(lines: List[str], affected_lines: set) -> Optional[Tuple[int, int]]:
    """Find the enclosing brace block for non-Python languages."""
    # Find the first affected line
    target = min(affected_lines) - 1  # 0-indexed

    # Search backwards for function/method start
    start = target
    brace_count = 0

    for i in range(target, max(0, target - 100), -1):
        line = lines[i]
        brace_count += line.count('}') - line.count('{')

        # Look for function signature patterns
        if re.match(r'^\s*(public|private|protected|static|async|function|def|func|fn)\s', line):
            start = i
            break
        if brace_count > 0 and '{' in line:
            start = i
            break

    # Search forward for block end
    end = target
    brace_count = 0
    for i in range(start, min(len(lines), start + 200)):
        line = lines[i]
        brace_count += line.count('{') - line.count('}')
        if brace_count <= 0 and i > start:
            end = i + 1
            break
    else:
        end = min(len(lines), target + 40)

    return (start, end)


def estimate_tokens(text: str) -> int:
    """Rough token estimate (1 token ≈ 4 chars for code)."""
    return len(text) // 4
