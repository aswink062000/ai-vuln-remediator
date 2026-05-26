"""
Secret & Sensitive Data Detector.

Scans code for accidentally committed secrets:
- API keys, tokens, passwords
- Private keys, certificates
- Database connection strings
- Cloud credentials (AWS, GCP, Azure)

Uses regex patterns + entropy analysis (no external dependencies).
Similar to tools like TruffleHog/GitLeaks but built-in.
"""

import re
import math
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Skip these files/dirs
SKIP_PATTERNS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "target", "vendor",
    ".lock", "package-lock.json", "yarn.lock",
}

# Secret patterns (regex + description)
SECRET_PATTERNS = [
    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Key"),

    # GitHub
    (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token"),
    (r'github_pat_[A-Za-z0-9_]{82}', "GitHub Fine-Grained Token"),
    (r'gho_[A-Za-z0-9]{36}', "GitHub OAuth Token"),

    # Google
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    (r'(?i)google_api_key\s*[=:]\s*["\']([^"\']+)', "Google API Key (assigned)"),

    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key"),
    (r'sk_test_[0-9a-zA-Z]{24,}', "Stripe Test Secret Key"),

    # Slack
    (r'xox[baprs]-[0-9a-zA-Z\-]{10,}', "Slack Token"),

    # Generic secrets
    (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "Hardcoded Password"),
    (r'(?i)(?:api_key|apikey|api-key)\s*[=:]\s*["\']([^"\']{16,})["\']', "Hardcoded API Key"),
    (r'(?i)(?:secret|token|auth)\s*[=:]\s*["\']([^"\']{16,})["\']', "Hardcoded Secret/Token"),
    (r'(?i)(?:database_url|db_url|connection_string)\s*[=:]\s*["\']([^"\']+)["\']', "Database Connection String"),

    # Database connection strings (MongoDB, PostgreSQL, MySQL, Redis, etc.)
    (r'mongodb(?:\+srv)?://[^\s"\']+', "MongoDB Connection String"),
    (r'postgres(?:ql)?://[^\s"\']+', "PostgreSQL Connection String"),
    (r'mysql://[^\s"\']+', "MySQL Connection String"),
    (r'redis://[^\s"\']+', "Redis Connection String"),
    (r'amqp://[^\s"\']+', "RabbitMQ Connection String"),
    (r'(?i)(?:db_?name|database|dbname)\s*[=:]\s*["\']([^"\']{2,})["\']', "Hardcoded Database Name"),
    (r'(?i)(?:var|let|const|self\.|this\.)\s*db\s*=\s*["\']([^"\']{2,})["\']', "Hardcoded Database Name"),
    (r'(?i)(?:db_?host|db_?server)\s*[=:]\s*["\']([^"\']+)["\']', "Hardcoded Database Host"),
    (r'(?i)(?:db_?user|db_?username)\s*[=:]\s*["\']([^"\']+)["\']', "Hardcoded Database Username"),
    (r'(?i)(?:db_?pass|db_?password)\s*[=:]\s*["\']([^"\']+)["\']', "Hardcoded Database Password"),

    # Hardcoded IPs and internal URLs (potential info leak)
    (r'(?i)(?:host|server|endpoint|url)\s*[=:]\s*["\'](?:https?://)?(?:\d{1,3}\.){3}\d{1,3}[^"\']*["\']', "Hardcoded IP Address"),

    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private Key"),
    (r'-----BEGIN CERTIFICATE-----', "Certificate (may contain private data)"),

    # JWT
    (r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "JWT Token"),

    # Azure
    (r'(?i)(?:azure|az)_(?:storage|account)_key\s*[=:]\s*["\']([^"\']+)', "Azure Storage Key"),

    # Generic high-entropy strings in assignments
    (r'(?i)(?:key|secret|token|password|credential)\s*[=:]\s*["\']([A-Za-z0-9+/=]{32,})["\']', "High-entropy credential"),
]


def run_secret_scan(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan repository for accidentally committed secrets.
    Returns findings in the standard format.
    """
    logger.info(f"Running secret detection on: {repo_path}")
    repo = Path(repo_path)
    findings = []

    # Collect scannable files
    scannable_extensions = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
        ".php", ".cs", ".env", ".yml", ".yaml", ".json", ".xml",
        ".cfg", ".conf", ".ini", ".properties", ".toml",
        ".sh", ".bash", ".zsh", ".dockerfile",
    }

    for f in repo.rglob("*"):
        if not f.is_file():
            continue
        if f.stat().st_size > 1_000_000:  # Skip files > 1MB
            continue

        # Skip excluded paths
        rel_parts = str(f.relative_to(repo)).lower()
        if any(skip in rel_parts for skip in SKIP_PATTERNS):
            continue

        # Only scan relevant file types
        if f.suffix.lower() not in scannable_extensions and f.name not in (".env", "Dockerfile"):
            continue

        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            rel_path = str(f.relative_to(repo))

            for line_num, line in enumerate(lines, 1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    # Still check — secrets in comments are still secrets
                    pass

                for pattern, description in SECRET_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        # Verify it's not a placeholder/example
                        matched_text = match.group(0)
                        if _is_placeholder(matched_text, line):
                            continue

                        # Check entropy for generic patterns
                        if "High-entropy" in description:
                            secret_value = match.group(1) if match.lastindex else matched_text
                            if _shannon_entropy(secret_value) < 3.5:
                                continue

                        # Mask the secret for reporting
                        masked = _mask_secret(matched_text)

                        # Generate fix guidance for the AI remediator
                        fix_guidance = _get_fix_guidance(description, rel_path)

                        findings.append({
                            "path": rel_path,
                            "line": line_num,
                            "end_line": line_num,
                            "rule_id": f"secret-detection-{description.lower().replace(' ', '-')}",
                            "message": f"Potential secret detected: {description}. Value: {masked}. Fix: {fix_guidance}",
                            "severity": "CRITICAL" if "Private Key" in description else "HIGH",
                            "metadata": {
                                "scanner": "secret-detector",
                                "category": "secret",
                                "secret_type": description,
                                "fix_guidance": fix_guidance,
                            },
                        })
                        break  # One finding per line

        except Exception:
            continue

    logger.info(f"Secret detection found {len(findings)} potential secrets")
    return findings


def _is_placeholder(value: str, line: str) -> bool:
    """Check if a matched value is just a placeholder/example."""
    placeholders = [
        "xxx", "your_", "example", "placeholder", "changeme",
        "TODO", "FIXME", "replace", "insert", "<your",
        "000000", "111111", "aaaaaa", "dummy",
    ]
    lower = value.lower()
    line_lower = line.lower()

    for p in placeholders:
        if p in lower or p in line_lower:
            return True

    # Check if it's in a comment explaining the format
    if "example" in line_lower or "format:" in line_lower or "e.g." in line_lower:
        return True

    # Don't treat "test_" as placeholder for DB names — test DBs are still hardcoded
    # Only skip if it's clearly a documentation/template value

    return False


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random = more likely a real secret."""
    if not data:
        return 0.0

    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def _mask_secret(value: str) -> str:
    """Mask a secret value for safe display."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _get_fix_guidance(secret_type: str, file_path: str) -> str:
    """
    Generate specific fix guidance based on the secret type and file language.
    This guidance is passed to the AI LLM to generate better fixes.
    """
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""

    # Determine env var syntax based on language
    if ext in ("js", "ts", "jsx", "tsx"):
        env_syntax = "process.env.VAR_NAME"
    elif ext == "py":
        env_syntax = "os.environ.get('VAR_NAME')"
    elif ext == "java":
        env_syntax = "System.getenv(\"VAR_NAME\")"
    elif ext in ("cs", "fs"):
        env_syntax = "Environment.GetEnvironmentVariable(\"VAR_NAME\")"
    elif ext == "go":
        env_syntax = "os.Getenv(\"VAR_NAME\")"
    elif ext == "rb":
        env_syntax = "ENV['VAR_NAME']"
    elif ext == "php":
        env_syntax = "getenv('VAR_NAME')"
    else:
        env_syntax = "environment variable"

    guidance_map = {
        "MongoDB Connection String": f"Move to {env_syntax} (e.g., MONGODB_URI). Never hardcode connection strings.",
        "PostgreSQL Connection String": f"Move to {env_syntax} (e.g., DATABASE_URL). Use connection pooling.",
        "MySQL Connection String": f"Move to {env_syntax} (e.g., MYSQL_URL).",
        "Redis Connection String": f"Move to {env_syntax} (e.g., REDIS_URL).",
        "Hardcoded Database Name": f"Move to {env_syntax} (e.g., DB_NAME). Use different names per environment.",
        "Hardcoded Database Host": f"Move to {env_syntax} (e.g., DB_HOST).",
        "Hardcoded Database Username": f"Move to {env_syntax} (e.g., DB_USER). Never commit credentials.",
        "Hardcoded Database Password": f"Move to {env_syntax} (e.g., DB_PASSWORD). Use secrets manager in production.",
        "Hardcoded Password": f"Move to {env_syntax}. Use a secrets manager (Vault, AWS Secrets Manager).",
        "Hardcoded API Key": f"Move to {env_syntax}. Rotate the exposed key immediately.",
        "Hardcoded Secret/Token": f"Move to {env_syntax}. Rotate the exposed secret.",
        "AWS Access Key ID": f"Move to {env_syntax} (AWS_ACCESS_KEY_ID). Use IAM roles instead of keys.",
        "AWS Secret Key": f"Move to {env_syntax} (AWS_SECRET_ACCESS_KEY). Rotate immediately if exposed.",
        "GitHub Personal Access Token": f"Move to {env_syntax} (GITHUB_TOKEN). Revoke and regenerate the token.",
        "Google API Key": f"Move to {env_syntax} (GOOGLE_API_KEY). Restrict key to specific APIs.",
        "Stripe Live Secret Key": "Move to environment variable. Rotate the key in Stripe dashboard immediately.",
        "Private Key": "Move to a secure file outside the repo. Use secrets manager. Never commit private keys.",
        "JWT Token": "JWTs should be generated at runtime, not hardcoded. Remove and generate dynamically.",
        "Hardcoded IP Address": f"Move to {env_syntax} (e.g., SERVICE_HOST). Use DNS names in production.",
    }

    return guidance_map.get(secret_type, f"Move to {env_syntax}. Never hardcode sensitive values in source code.")
