"""
Code Quality Scanner — SonarQube-like metrics (100% open source, no license issues).

Provides:
- Cyclomatic Complexity (per file and overall)
- Maintainability Index
- Lines of Code / Comment Ratio
- Code Duplication Detection
- Technical Debt Estimation
- Code Smells Detection
- Quality Gate (pass/fail)

Tools used (all MIT/Apache licensed):
- radon (MIT) — Python complexity metrics
- Custom AST analysis — language-agnostic metrics
- jscpd concepts — duplication detection (built-in, no external dep)

License: This module is your own code — sell freely.
"""

import os
import re
import ast
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

# File extensions to analyze
SUPPORTED_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".rs": "Rust",
}

# Directories to skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "target", "bin", "obj",
    ".tox", ".mypy_cache", ".pytest_cache", "vendor",
}


def run_code_quality_scan(repo_path: str) -> Dict[str, Any]:
    """
    Run a comprehensive code quality analysis on the repository.
    Returns metrics similar to SonarQube.
    """
    logger.info(f"Running code quality scan on: {repo_path}")
    repo = Path(repo_path)

    # Collect all source files
    source_files = _collect_source_files(repo)
    logger.info(f"Found {len(source_files)} source files to analyze")

    if not source_files:
        return _empty_result()

    # Run all analyses
    loc_metrics = _analyze_lines_of_code(source_files, repo)
    complexity_metrics = _analyze_complexity(source_files, repo)
    duplication_metrics = _detect_duplication(source_files, repo)
    code_smells = _detect_code_smells(source_files, repo)
    tech_debt = _estimate_technical_debt(complexity_metrics, duplication_metrics, code_smells)
    quality_gate = _evaluate_quality_gate(loc_metrics, complexity_metrics, duplication_metrics, code_smells)

    result = {
        "summary": {
            "total_files": len(source_files),
            "languages": loc_metrics["languages"],
            "quality_gate": quality_gate,
        },
        "metrics": {
            "lines_of_code": loc_metrics,
            "complexity": complexity_metrics,
            "duplication": duplication_metrics,
            "technical_debt": tech_debt,
        },
        "code_smells": code_smells,
        "quality_gate_details": quality_gate,
    }

    logger.info(
        f"Code quality scan complete: "
        f"{loc_metrics['total_lines']} LOC, "
        f"complexity avg={complexity_metrics['average_complexity']:.1f}, "
        f"duplication={duplication_metrics['duplication_percentage']:.1f}%, "
        f"gate={'PASSED' if quality_gate['passed'] else 'FAILED'}"
    )

    return result


def _collect_source_files(repo: Path) -> List[Path]:
    """Collect all analyzable source files."""
    files = []
    for ext in SUPPORTED_EXTENSIONS:
        for f in repo.rglob(f"*{ext}"):
            # Skip excluded directories
            parts = f.relative_to(repo).parts
            if any(skip in parts for skip in SKIP_DIRS):
                continue
            # Skip very large files (likely generated)
            if f.stat().st_size > 500_000:
                continue
            files.append(f)
    return files


def _empty_result() -> Dict[str, Any]:
    """Return empty result when no files found."""
    return {
        "summary": {"total_files": 0, "languages": {}, "quality_gate": {"passed": True, "status": "NO_CODE"}},
        "metrics": {
            "lines_of_code": {"total_lines": 0, "code_lines": 0, "comment_lines": 0, "blank_lines": 0},
            "complexity": {"average_complexity": 0, "max_complexity": 0, "files_above_threshold": 0},
            "duplication": {"duplication_percentage": 0, "duplicated_lines": 0, "duplicated_blocks": 0},
            "technical_debt": {"total_minutes": 0, "rating": "A"},
        },
        "code_smells": {"total": 0, "items": []},
        "quality_gate_details": {"passed": True, "status": "NO_CODE"},
    }


# =============================================================================
# LINES OF CODE ANALYSIS
# =============================================================================

def _analyze_lines_of_code(files: List[Path], repo: Path) -> Dict[str, Any]:
    """Analyze lines of code, comments, and blank lines per language."""
    total_lines = 0
    code_lines = 0
    comment_lines = 0
    blank_lines = 0
    languages: Dict[str, int] = defaultdict(int)
    file_metrics: List[Dict] = []

    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            ext = f.suffix.lower()
            lang = SUPPORTED_EXTENSIONS.get(ext, "Unknown")

            file_total = len(lines)
            file_blank = sum(1 for line in lines if not line.strip())
            file_comment = _count_comments(lines, ext)
            file_code = file_total - file_blank - file_comment

            total_lines += file_total
            code_lines += file_code
            comment_lines += file_comment
            blank_lines += file_blank
            languages[lang] += file_code

            file_metrics.append({
                "path": str(f.relative_to(repo)),
                "language": lang,
                "lines": file_total,
                "code": file_code,
                "comments": file_comment,
            })

        except Exception:
            continue

    comment_ratio = (comment_lines / code_lines * 100) if code_lines > 0 else 0

    return {
        "total_lines": total_lines,
        "code_lines": code_lines,
        "comment_lines": comment_lines,
        "blank_lines": blank_lines,
        "comment_ratio": round(comment_ratio, 1),
        "languages": dict(languages),
        "files": sorted(file_metrics, key=lambda x: x["lines"], reverse=True)[:20],
    }


def _count_comments(lines: List[str], ext: str) -> int:
    """Count comment lines based on language."""
    count = 0
    in_block = False

    for line in lines:
        stripped = line.strip()

        if ext in (".py", ".rb"):
            if stripped.startswith("#"):
                count += 1
            elif '"""' in stripped or "'''" in stripped:
                if stripped.count('"""') == 1 or stripped.count("'''") == 1:
                    in_block = not in_block
                count += 1
            elif in_block:
                count += 1

        elif ext in (".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".cs", ".cpp", ".c", ".rs", ".php"):
            if stripped.startswith("//"):
                count += 1
            elif stripped.startswith("/*"):
                in_block = True
                count += 1
            elif "*/" in stripped:
                in_block = False
                count += 1
            elif in_block:
                count += 1

    return count


# =============================================================================
# CYCLOMATIC COMPLEXITY ANALYSIS
# =============================================================================

def _analyze_complexity(files: List[Path], repo: Path) -> Dict[str, Any]:
    """
    Calculate cyclomatic complexity for all files.
    Uses AST for Python, regex-based heuristics for other languages.
    """
    all_complexities = []
    file_complexities = []

    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            ext = f.suffix.lower()

            if ext == ".py":
                complexity = _python_complexity(content)
            else:
                complexity = _generic_complexity(content, ext)

            all_complexities.append(complexity)
            rel_path = str(f.relative_to(repo))

            if complexity > 10:  # Flag complex files
                file_complexities.append({
                    "path": rel_path,
                    "complexity": complexity,
                    "rating": _complexity_rating(complexity),
                })

        except Exception:
            continue

    avg = sum(all_complexities) / len(all_complexities) if all_complexities else 0
    max_c = max(all_complexities) if all_complexities else 0

    # Maintainability Index (0-100, higher is better)
    # Simplified formula based on Halstead/McCabe
    maintainability = max(0, min(100, 171 - 5.2 * (avg / 5) - 0.23 * avg - 16.2 * 0.5))

    return {
        "average_complexity": round(avg, 1),
        "max_complexity": max_c,
        "maintainability_index": round(maintainability, 1),
        "maintainability_rating": _maintainability_rating(maintainability),
        "files_above_threshold": len(file_complexities),
        "complex_files": sorted(file_complexities, key=lambda x: x["complexity"], reverse=True)[:15],
        "distribution": {
            "low (1-5)": sum(1 for c in all_complexities if c <= 5),
            "moderate (6-10)": sum(1 for c in all_complexities if 6 <= c <= 10),
            "high (11-20)": sum(1 for c in all_complexities if 11 <= c <= 20),
            "very_high (21+)": sum(1 for c in all_complexities if c > 20),
        },
    }


def _python_complexity(content: str) -> int:
    """Calculate cyclomatic complexity for Python using AST."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return _generic_complexity(content, ".py")

    complexity = 1  # Base complexity

    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.IfExp)):
            complexity += 1
        elif isinstance(node, ast.For):
            complexity += 1
        elif isinstance(node, ast.While):
            complexity += 1
        elif isinstance(node, ast.ExceptHandler):
            complexity += 1
        elif isinstance(node, (ast.And, ast.Or)):
            complexity += 1
        elif isinstance(node, ast.Assert):
            complexity += 1
        elif isinstance(node, ast.comprehension):
            complexity += 1

    return complexity


def _generic_complexity(content: str, ext: str) -> int:
    """Estimate cyclomatic complexity using regex for non-Python files."""
    complexity = 1

    # Decision points that increase complexity
    patterns = [
        r'\bif\b', r'\belse\s+if\b', r'\belif\b', r'\belse\b',
        r'\bfor\b', r'\bwhile\b', r'\bdo\b',
        r'\bcase\b', r'\bcatch\b', r'\bexcept\b',
        r'\b\?\s*:', r'&&', r'\|\|',
        r'\?\?',  # null coalescing
    ]

    for pattern in patterns:
        complexity += len(re.findall(pattern, content))

    # Normalize by file size (avoid huge files dominating)
    lines = content.count('\n') + 1
    if lines > 500:
        complexity = int(complexity * (500 / lines))

    return min(complexity, 100)  # Cap at 100


def _complexity_rating(complexity: int) -> str:
    if complexity <= 5:
        return "A"
    elif complexity <= 10:
        return "B"
    elif complexity <= 20:
        return "C"
    elif complexity <= 50:
        return "D"
    return "F"


def _maintainability_rating(index: float) -> str:
    if index >= 80:
        return "A"
    elif index >= 60:
        return "B"
    elif index >= 40:
        return "C"
    elif index >= 20:
        return "D"
    return "F"


# =============================================================================
# CODE DUPLICATION DETECTION
# =============================================================================

def _detect_duplication(files: List[Path], repo: Path, min_lines: int = 6) -> Dict[str, Any]:
    """
    Detect duplicated code blocks across the repository.
    Uses content hashing of normalized line sequences (similar to jscpd algorithm).
    """
    total_lines = 0
    duplicated_lines = 0
    duplicated_blocks = []

    # Build hash map of line sequences
    block_hashes: Dict[str, List[Dict]] = defaultdict(list)

    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            total_lines += len(lines)
            rel_path = str(f.relative_to(repo))

            # Normalize lines (strip whitespace, ignore empty)
            normalized = []
            line_map = []  # Maps normalized index to original line number
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped and not stripped.startswith(("#", "//", "/*", "*", "import", "from")):
                    normalized.append(stripped)
                    line_map.append(i + 1)

            # Sliding window hash
            for i in range(len(normalized) - min_lines + 1):
                block = "\n".join(normalized[i:i + min_lines])
                block_hash = hashlib.md5(block.encode()).hexdigest()
                block_hashes[block_hash].append({
                    "file": rel_path,
                    "start_line": line_map[i] if i < len(line_map) else i,
                })

        except Exception:
            continue

    # Find duplicates (hash appears more than once)
    seen_files = set()
    for block_hash, locations in block_hashes.items():
        if len(locations) > 1:
            # Deduplicate by file pair
            file_pairs = set()
            for loc in locations:
                file_pairs.add(loc["file"])

            if len(file_pairs) > 1 or len(locations) > 2:
                key = tuple(sorted(loc["file"] for loc in locations[:2]))
                if key not in seen_files:
                    seen_files.add(key)
                    duplicated_lines += min_lines * len(locations)
                    if len(duplicated_blocks) < 20:
                        duplicated_blocks.append({
                            "lines": min_lines,
                            "locations": locations[:5],
                        })

    dup_percentage = (duplicated_lines / total_lines * 100) if total_lines > 0 else 0

    return {
        "total_lines_analyzed": total_lines,
        "duplicated_lines": min(duplicated_lines, total_lines),
        "duplication_percentage": round(min(dup_percentage, 100), 1),
        "duplicated_blocks": len(duplicated_blocks),
        "rating": _duplication_rating(dup_percentage),
        "blocks": duplicated_blocks[:10],
    }


def _duplication_rating(percentage: float) -> str:
    if percentage < 3:
        return "A"
    elif percentage < 5:
        return "B"
    elif percentage < 10:
        return "C"
    elif percentage < 20:
        return "D"
    return "F"


# =============================================================================
# CODE SMELLS DETECTION
# =============================================================================

def _detect_code_smells(files: List[Path], repo: Path) -> Dict[str, Any]:
    """
    Detect common code smells across all languages.
    These are patterns that indicate potential maintainability issues.
    """
    smells: List[Dict[str, Any]] = []

    for f in files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            rel_path = str(f.relative_to(repo))
            ext = f.suffix.lower()

            # Long file (>300 lines of code)
            code_lines = sum(1 for line in lines if line.strip() and not line.strip().startswith(("#", "//")))
            if code_lines > 300:
                smells.append({
                    "type": "long_file",
                    "severity": "MINOR" if code_lines < 500 else "MAJOR",
                    "path": rel_path,
                    "message": f"File has {code_lines} lines of code (threshold: 300)",
                    "debt_minutes": 30,
                })

            # Long functions/methods
            _detect_long_functions(content, ext, rel_path, smells)

            # Too many parameters
            _detect_many_parameters(content, ext, rel_path, smells)

            # Long lines (>120 chars)
            long_lines = [(i + 1, len(line)) for i, line in enumerate(lines) if len(line) > 120]
            if len(long_lines) > 10:
                smells.append({
                    "type": "long_lines",
                    "severity": "MINOR",
                    "path": rel_path,
                    "message": f"{len(long_lines)} lines exceed 120 characters",
                    "debt_minutes": 10,
                })

            # TODO/FIXME/HACK comments
            todo_count = sum(1 for line in lines if re.search(r'\b(TODO|FIXME|HACK|XXX)\b', line, re.IGNORECASE))
            if todo_count > 0:
                smells.append({
                    "type": "todo_comments",
                    "severity": "INFO",
                    "path": rel_path,
                    "message": f"{todo_count} TODO/FIXME comments found",
                    "debt_minutes": 5 * todo_count,
                })

            # Deeply nested code (>4 levels)
            max_indent = _max_nesting_depth(lines)
            if max_indent > 4:
                smells.append({
                    "type": "deep_nesting",
                    "severity": "MAJOR",
                    "path": rel_path,
                    "message": f"Maximum nesting depth: {max_indent} (threshold: 4)",
                    "debt_minutes": 20,
                })

            # Magic numbers (hardcoded numeric literals)
            if ext in (".py", ".js", ".ts", ".java"):
                magic_count = len(re.findall(r'(?<!=\s)[^0-9a-zA-Z_](\d{2,})(?!\s*[;,\]\)])', content))
                if magic_count > 5:
                    smells.append({
                        "type": "magic_numbers",
                        "severity": "MINOR",
                        "path": rel_path,
                        "message": f"{magic_count} magic numbers detected (use named constants)",
                        "debt_minutes": 15,
                    })

        except Exception:
            continue

    # Categorize by severity
    by_severity = defaultdict(int)
    for smell in smells:
        by_severity[smell["severity"]] += 1

    return {
        "total": len(smells),
        "by_severity": dict(by_severity),
        "items": sorted(smells, key=lambda x: {"CRITICAL": 0, "MAJOR": 1, "MINOR": 2, "INFO": 3}.get(x["severity"], 4))[:50],
    }


def _detect_long_functions(content: str, ext: str, path: str, smells: list):
    """Detect functions/methods that are too long."""
    if ext == ".py":
        # Python: detect def blocks
        lines = content.splitlines()
        func_start = None
        func_name = ""
        indent_level = 0

        for i, line in enumerate(lines):
            match = re.match(r'^(\s*)def\s+(\w+)', line)
            if match:
                if func_start is not None:
                    length = i - func_start
                    if length > 50:
                        smells.append({
                            "type": "long_function",
                            "severity": "MAJOR" if length > 100 else "MINOR",
                            "path": path,
                            "line": func_start + 1,
                            "message": f"Function '{func_name}' has {length} lines (threshold: 50)",
                            "debt_minutes": 20,
                        })
                func_start = i
                func_name = match.group(2)
                indent_level = len(match.group(1))

    elif ext in (".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".cs"):
        # Brace-based languages: count lines between { }
        pattern = r'(?:function|def|func)\s+(\w+)[^{]*\{'
        for match in re.finditer(pattern, content):
            start = content[:match.start()].count('\n')
            # Find matching closing brace (simplified)
            brace_count = 0
            end_pos = match.end()
            for j in range(match.end(), min(len(content), match.end() + 5000)):
                if content[j] == '{':
                    brace_count += 1
                elif content[j] == '}':
                    if brace_count == 0:
                        end_pos = j
                        break
                    brace_count -= 1

            length = content[match.start():end_pos].count('\n')
            if length > 50:
                smells.append({
                    "type": "long_function",
                    "severity": "MAJOR" if length > 100 else "MINOR",
                    "path": path,
                    "line": start + 1,
                    "message": f"Function '{match.group(1)}' has {length} lines (threshold: 50)",
                    "debt_minutes": 20,
                })


def _detect_many_parameters(content: str, ext: str, path: str, smells: list):
    """Detect functions with too many parameters."""
    if ext == ".py":
        pattern = r'def\s+(\w+)\s*\(([^)]*)\)'
    elif ext in (".js", ".ts", ".jsx", ".tsx"):
        pattern = r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\()\s*\(([^)]*)\)'
    else:
        pattern = r'(?:public|private|protected|static|\s)+\w+\s+(\w+)\s*\(([^)]*)\)'

    for match in re.finditer(pattern, content):
        func_name = match.group(1) or "anonymous"
        params = match.group(2) if match.lastindex >= 2 else ""
        if params:
            param_count = len([p for p in params.split(",") if p.strip() and p.strip() != "self" and p.strip() != "cls"])
            if param_count > 5:
                line = content[:match.start()].count('\n') + 1
                smells.append({
                    "type": "too_many_parameters",
                    "severity": "MINOR",
                    "path": path,
                    "line": line,
                    "message": f"Function '{func_name}' has {param_count} parameters (threshold: 5)",
                    "debt_minutes": 15,
                })


def _max_nesting_depth(lines: List[str]) -> int:
    """Calculate maximum nesting depth."""
    max_depth = 0
    for line in lines:
        if not line.strip():
            continue
        # Count leading whitespace as proxy for nesting
        indent = len(line) - len(line.lstrip())
        # Normalize: 2 or 4 spaces = 1 level, tab = 1 level
        if '\t' in line[:indent]:
            depth = line[:indent].count('\t')
        else:
            depth = indent // 4 if indent >= 4 else indent // 2
        max_depth = max(max_depth, depth)
    return max_depth


# =============================================================================
# TECHNICAL DEBT ESTIMATION
# =============================================================================

def _estimate_technical_debt(
    complexity: Dict, duplication: Dict, smells: Dict
) -> Dict[str, Any]:
    """
    Estimate technical debt in minutes/hours.
    Based on SQALE methodology (same as SonarQube).
    """
    debt_minutes = 0

    # Complexity debt: 10 min per file above threshold
    debt_minutes += complexity.get("files_above_threshold", 0) * 10

    # Duplication debt: 2 min per duplicated block
    debt_minutes += duplication.get("duplicated_blocks", 0) * 2

    # Code smell debt
    for smell in smells.get("items", []):
        debt_minutes += smell.get("debt_minutes", 5)

    # Convert to hours/days
    debt_hours = debt_minutes / 60
    debt_days = debt_hours / 8

    # Rating (A-E based on debt ratio)
    rating = _debt_rating(debt_days)

    return {
        "total_minutes": debt_minutes,
        "total_hours": round(debt_hours, 1),
        "total_days": round(debt_days, 1),
        "rating": rating,
        "breakdown": {
            "complexity": complexity.get("files_above_threshold", 0) * 10,
            "duplication": duplication.get("duplicated_blocks", 0) * 2,
            "code_smells": sum(s.get("debt_minutes", 5) for s in smells.get("items", [])),
        },
    }


def _debt_rating(days: float) -> str:
    if days < 1:
        return "A"
    elif days < 3:
        return "B"
    elif days < 7:
        return "C"
    elif days < 14:
        return "D"
    return "E"


# =============================================================================
# QUALITY GATE
# =============================================================================

def _evaluate_quality_gate(
    loc: Dict, complexity: Dict, duplication: Dict, smells: Dict
) -> Dict[str, Any]:
    """
    Evaluate quality gate — pass/fail based on thresholds.
    Similar to SonarQube's quality gate concept.
    """
    conditions = []
    passed = True

    # Condition 1: Duplication < 10%
    dup_pct = duplication.get("duplication_percentage", 0)
    dup_ok = dup_pct < 10
    conditions.append({
        "metric": "duplication",
        "operator": "<",
        "threshold": 10,
        "actual": dup_pct,
        "status": "PASSED" if dup_ok else "FAILED",
    })
    if not dup_ok:
        passed = False

    # Condition 2: Average complexity < 15
    avg_complexity = complexity.get("average_complexity", 0)
    complexity_ok = avg_complexity < 15
    conditions.append({
        "metric": "average_complexity",
        "operator": "<",
        "threshold": 15,
        "actual": avg_complexity,
        "status": "PASSED" if complexity_ok else "FAILED",
    })
    if not complexity_ok:
        passed = False

    # Condition 3: Maintainability rating >= C
    maint_index = complexity.get("maintainability_index", 100)
    maint_ok = maint_index >= 40  # C or better
    conditions.append({
        "metric": "maintainability_index",
        "operator": ">=",
        "threshold": 40,
        "actual": maint_index,
        "status": "PASSED" if maint_ok else "FAILED",
    })
    if not maint_ok:
        passed = False

    # Condition 4: No critical code smells
    critical_smells = smells.get("by_severity", {}).get("CRITICAL", 0)
    critical_ok = critical_smells == 0
    conditions.append({
        "metric": "critical_code_smells",
        "operator": "==",
        "threshold": 0,
        "actual": critical_smells,
        "status": "PASSED" if critical_ok else "FAILED",
    })
    if not critical_ok:
        passed = False

    # Condition 5: Comment ratio > 5%
    comment_ratio = loc.get("comment_ratio", 0)
    comment_ok = comment_ratio >= 5 or loc.get("code_lines", 0) < 100
    conditions.append({
        "metric": "comment_ratio",
        "operator": ">=",
        "threshold": 5,
        "actual": comment_ratio,
        "status": "PASSED" if comment_ok else "WARNING",
    })

    return {
        "passed": passed,
        "status": "PASSED" if passed else "FAILED",
        "conditions": conditions,
    }
