"""
Code Diff Generator for AI Fix Visualization.

Generates unified diffs showing exactly what the AI changed.
Uses Python's built-in difflib (no external dependencies).

Output formats:
- Unified diff (standard patch format)
- Side-by-side comparison data (for frontend rendering)
- Summary statistics (lines added/removed/changed)
"""

import difflib
from typing import Dict, Any, List


def generate_diff(
    original_code: str,
    fixed_code: str,
    file_path: str = "file",
) -> Dict[str, Any]:
    """
    Generate a comprehensive diff between original and fixed code.

    Returns:
        {
            "unified_diff": "--- a/file\n+++ b/file\n...",
            "hunks": [...],
            "stats": {"additions": 5, "deletions": 3, "changes": 2},
            "summary": "5 additions, 3 deletions across 2 hunks"
        }
    """
    original_lines = original_code.splitlines(keepends=True)
    fixed_lines = fixed_code.splitlines(keepends=True)

    # Generate unified diff
    unified = list(difflib.unified_diff(
        original_lines,
        fixed_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    ))

    # Parse into hunks for frontend rendering
    hunks = _parse_hunks(unified)

    # Calculate stats
    additions = sum(1 for line in unified if line.startswith("+") and not line.startswith("+++"))
    deletions = sum(1 for line in unified if line.startswith("-") and not line.startswith("---"))

    # Generate side-by-side data
    side_by_side = _generate_side_by_side(original_lines, fixed_lines)

    return {
        "unified_diff": "\n".join(unified),
        "hunks": hunks,
        "side_by_side": side_by_side[:100],  # Limit for large files
        "stats": {
            "additions": additions,
            "deletions": deletions,
            "total_changes": additions + deletions,
            "hunks": len(hunks),
        },
        "summary": f"{additions} addition{'s' if additions != 1 else ''}, "
                   f"{deletions} deletion{'s' if deletions != 1 else ''} "
                   f"across {len(hunks)} hunk{'s' if len(hunks) != 1 else ''}",
    }


def _parse_hunks(unified_lines: List[str]) -> List[Dict[str, Any]]:
    """Parse unified diff into structured hunks."""
    hunks = []
    current_hunk = None

    for line in unified_lines:
        if line.startswith("@@"):
            if current_hunk:
                hunks.append(current_hunk)
            current_hunk = {
                "header": line.strip(),
                "lines": [],
            }
        elif current_hunk is not None:
            if line.startswith("+") and not line.startswith("+++"):
                current_hunk["lines"].append({"type": "add", "content": line[1:]})
            elif line.startswith("-") and not line.startswith("---"):
                current_hunk["lines"].append({"type": "remove", "content": line[1:]})
            else:
                current_hunk["lines"].append({"type": "context", "content": line[1:] if line.startswith(" ") else line})

    if current_hunk:
        hunks.append(current_hunk)

    return hunks


def _generate_side_by_side(original: List[str], fixed: List[str]) -> List[Dict[str, Any]]:
    """Generate side-by-side comparison data."""
    matcher = difflib.SequenceMatcher(None, original, fixed)
    result = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for i in range(i1, i2):
                result.append({
                    "type": "equal",
                    "left_line": i + 1,
                    "right_line": j1 + (i - i1) + 1,
                    "left": original[i].rstrip(),
                    "right": fixed[j1 + (i - i1)].rstrip(),
                })
        elif tag == "replace":
            max_len = max(i2 - i1, j2 - j1)
            for k in range(max_len):
                left = original[i1 + k].rstrip() if (i1 + k) < i2 else ""
                right = fixed[j1 + k].rstrip() if (j1 + k) < j2 else ""
                result.append({
                    "type": "change",
                    "left_line": (i1 + k + 1) if (i1 + k) < i2 else None,
                    "right_line": (j1 + k + 1) if (j1 + k) < j2 else None,
                    "left": left,
                    "right": right,
                })
        elif tag == "delete":
            for i in range(i1, i2):
                result.append({
                    "type": "remove",
                    "left_line": i + 1,
                    "right_line": None,
                    "left": original[i].rstrip(),
                    "right": "",
                })
        elif tag == "insert":
            for j in range(j1, j2):
                result.append({
                    "type": "add",
                    "left_line": None,
                    "right_line": j + 1,
                    "left": "",
                    "right": fixed[j].rstrip(),
                })

    return result


def generate_fix_summary(diffs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate an overall summary of all fixes applied.
    Takes a list of diff results (one per file).
    """
    total_additions = sum(d["stats"]["additions"] for d in diffs)
    total_deletions = sum(d["stats"]["deletions"] for d in diffs)
    total_hunks = sum(d["stats"]["hunks"] for d in diffs)

    return {
        "files_changed": len(diffs),
        "total_additions": total_additions,
        "total_deletions": total_deletions,
        "total_hunks": total_hunks,
        "summary": f"{len(diffs)} file{'s' if len(diffs) != 1 else ''} changed, "
                   f"{total_additions} insertion{'s' if total_additions != 1 else ''}(+), "
                   f"{total_deletions} deletion{'s' if total_deletions != 1 else ''}(-)",
    }
