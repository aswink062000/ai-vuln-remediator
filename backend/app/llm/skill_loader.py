from pathlib import Path
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Skills directory
SKILLS_DIR = Path(__file__).parent.parent.parent / "skills"
SKILL_FILE = "vulnerability-remediation.md"


def _get_skill_path() -> Path:
    """Get the path to the skill file."""
    return SKILLS_DIR / SKILL_FILE


def load_skill() -> str:
    """Load the vulnerability remediation skill prompt. Returns empty string if not found."""
    path = _get_skill_path()

    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning(f"Skill file not found at {path}. Using empty skill prompt.")
        return ""
    except Exception as e:
        logger.warning(f"Could not load skill file: {e}")
        return ""


def save_skill(content: str) -> bool:
    """Save the skill prompt to disk."""
    path = _get_skill_path()

    try:
        # Ensure directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.info(f"Skill file saved to {path}")
        return True
    except Exception as e:
        logger.error(f"Failed to save skill file: {e}")
        return False


def build_language_skill(project_info: Dict[str, Any]) -> str:
    """
    Build a language-specific skill prompt based on the detected project languages.
    This replaces the generic all-language skill with a focused, token-efficient prompt.
    """
    languages = project_info.get("languages", [])
    frameworks = project_info.get("frameworks", [])
    build_tools = project_info.get("build_tools", [])

    if not languages:
        return ""

    sections = []

    # Header
    sections.append(f"Project: {', '.join(languages)} | Frameworks: {', '.join(frameworks) or 'none detected'} | Build: {', '.join(build_tools) or 'standard'}")
    sections.append("")

    # Language-specific fix rules
    for lang in languages:
        lang_lower = lang.lower()
        rules = _get_language_rules(lang_lower, frameworks, build_tools)
        if rules:
            sections.append(rules)

    # Dependency fix rules (based on detected manifest files)
    dep_rules = _get_dependency_rules(languages, build_tools)
    if dep_rules:
        sections.append(dep_rules)

    return "\n".join(sections)


def _get_language_rules(language: str, frameworks: List[str], build_tools: List[str]) -> str:
    """Get language-specific remediation rules."""

    rules_map = {
        "python": """PYTHON RULES:
- Use parameterized queries with %s placeholders or SQLAlchemy ORM
- Replace hardcoded secrets with os.environ.get('VAR_NAME', 'dev-fallback')
- Use subprocess with list args (no shell=True)
- Use pathlib for file paths, validate with resolve() and is_relative_to()
- Use secrets.compare_digest() for constant-time comparisons
- Use hashlib.pbkdf2_hmac or bcrypt for password hashing
- For Flask: use escape() for XSS, set secure cookie flags
- For Django: use ORM queries, {% autoescape %}, CSRF middleware
- Dependency files: requirements.txt, pyproject.toml, Pipfile""",

        "java": """JAVA RULES:
- Use PreparedStatement for SQL (never string concatenation)
- Replace hardcoded secrets with System.getenv("VAR_NAME")
- Use OWASP Encoder for XSS prevention
- Use java.nio.file.Path with normalize() and startsWith() for path validation
- Use MessageDigest with constant-time comparison for auth
- For Spring Boot: use @Value("${env.var}") for config, enable CSRF
- For Jakarta EE: use Bean Validation, JPA named parameters
- javax → jakarta migration: update imports if Spring Boot 3+
- Dependency files: pom.xml (Maven), build.gradle (Gradle)
- When bumping versions in pom.xml: update <version> tag for the dependency
- When bumping parent version: update <parent><version> tag""",

        "javascript": """JAVASCRIPT/NODE.JS RULES:
- Use parameterized queries (pg: $1 placeholders, mysql2: ? placeholders)
- Replace hardcoded secrets with process.env.VAR_NAME
- Use DOMPurify or textContent for XSS prevention
- Use path.resolve() + path.relative() for path traversal prevention
- Use crypto.timingSafeEqual() for constant-time comparisons
- Use bcrypt or argon2 for password hashing
- For Express: use helmet(), express-rate-limit, csurf
- For React/Next.js: avoid dangerouslySetInnerHTML, use sanitization
- Dependency files: package.json (update version in dependencies/devDependencies)
- When bumping versions: change "package": "^old" to "package": "^new" """,

        "typescript": """TYPESCRIPT RULES:
- Same as JavaScript rules, plus:
- Use strict type checking to prevent type confusion attacks
- Use branded types for sensitive values (UserId, Token, etc.)
- Avoid 'any' type for user input — use proper validation (zod, io-ts)
- Dependency files: package.json""",

        "csharp": """.NET/C# RULES:
- Use parameterized queries with SqlCommand.Parameters.AddWithValue()
- Replace hardcoded secrets with IConfiguration["VarName"] or Environment.GetEnvironmentVariable()
- Use HtmlEncoder.Default.Encode() for XSS prevention
- Use Path.GetFullPath() + StartsWith() for path validation
- Use [Authorize] attribute and ASP.NET Identity for auth
- Dependency files: .csproj (update PackageReference Version attribute)""",

        "go": """GO RULES:
- Use database/sql with ? or $1 placeholders for SQL
- Replace hardcoded secrets with os.Getenv("VAR_NAME")
- Use html/template (auto-escapes) instead of text/template for HTML
- Use filepath.Clean() + strings.HasPrefix() for path validation
- Use crypto/subtle.ConstantTimeCompare() for auth comparisons
- Use golang.org/x/crypto/bcrypt for password hashing
- Dependency files: go.mod (update require directive version)""",

        "rust": """RUST RULES:
- Use sqlx with query!() macro for compile-time checked SQL
- Replace hardcoded secrets with std::env::var("VAR_NAME")
- Use askama or tera templates (auto-escape by default)
- Use std::path::Path::canonicalize() for path validation
- Use constant_time_eq crate for timing-safe comparisons
- Use argon2 crate for password hashing
- Dependency files: Cargo.toml (update version in [dependencies])""",

        "ruby": """RUBY RULES:
- Use ActiveRecord parameterized queries: where("col = ?", val)
- Replace hardcoded secrets with ENV['VAR_NAME'] or Rails credentials
- Use ERB auto-escaping (<%=), raw() only when safe
- Use Pathname#realpath + start_with? for path validation
- Use bcrypt-ruby for password hashing
- Dependency files: Gemfile (update gem version)""",

        "php": """PHP RULES:
- Use PDO with prepared statements: $stmt->execute([$param])
- Replace hardcoded secrets with getenv('VAR_NAME') or $_ENV
- Use htmlspecialchars() with ENT_QUOTES for XSS prevention
- Use realpath() + strpos() for path validation
- Use password_hash() / password_verify() for passwords
- Dependency files: composer.json (update require version)""",

        "kotlin": """KOTLIN RULES:
- Same as Java rules (runs on JVM)
- Use Spring Data JPA @Query with named parameters
- Use string templates carefully — never for SQL
- Dependency files: build.gradle.kts (update version in dependencies)""",
    }

    return rules_map.get(language, "")


def _get_dependency_rules(languages: List[str], build_tools: List[str]) -> str:
    """Get dependency-specific fix rules based on detected build tools."""
    rules = ["DEPENDENCY FIX RULES:"]

    for lang in languages:
        lang_lower = lang.lower()
        if lang_lower == "python":
            rules.append("- requirements.txt: change 'package==old' to 'package==new'")
            rules.append("- pyproject.toml: update version in [project.dependencies]")
        elif lang_lower == "java":
            if "maven" in [t.lower() for t in build_tools] or any("pom" in t.lower() for t in build_tools):
                rules.append("- pom.xml: update <version>X.Y.Z</version> for the target dependency")
                rules.append("- If version uses property like ${spring.version}, update the property in <properties>")
            if "gradle" in [t.lower() for t in build_tools]:
                rules.append("- build.gradle: update version string in implementation/compile declaration")
        elif lang_lower in ("javascript", "typescript"):
            rules.append("- package.json: update version in \"dependencies\" or \"devDependencies\"")
            rules.append("- Keep the ^ or ~ prefix unless pinning is required")
        elif lang_lower == "csharp":
            rules.append("- .csproj: update Version attribute in <PackageReference>")
        elif lang_lower == "go":
            rules.append("- go.mod: update version in require() block")
        elif lang_lower == "rust":
            rules.append("- Cargo.toml: update version in [dependencies] section")
        elif lang_lower == "ruby":
            rules.append("- Gemfile: update gem 'name', '~> X.Y'")
        elif lang_lower == "php":
            rules.append("- composer.json: update version in require/require-dev")

    rules.append("- Always preserve the file's existing formatting and structure")
    rules.append("- Only change the version number, do not add/remove dependencies")

    return "\n".join(rules)
