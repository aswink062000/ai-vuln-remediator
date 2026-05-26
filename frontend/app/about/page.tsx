"use client";

import Link from "next/link";
import {
  ArrowLeft,
  ShieldCheck,
  SearchCode,
  BrainCircuit,
  GitBranch,
  FileText,
  Terminal,
  Globe,
  Ban,
  RefreshCw,
  BarChart3,
  Lock,
  Zap,
  Code,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function AboutPage() {
  return (
    <main className="min-h-screen bg-background">
      <div className="max-w-5xl mx-auto p-4 lg:p-8 space-y-8">
        {/* Header */}
        <div className="flex items-center gap-4">
          <Link href="/">
            <Button variant="ghost" size="icon"><ArrowLeft className="h-5 w-5" /></Button>
          </Link>
          <div>
            <h1 className="text-3xl font-bold">AI Vulnerability Remediator</h1>
            <p className="text-muted-foreground mt-1">
              Enterprise AI Security Platform — Complete Feature Guide
            </p>
          </div>
        </div>

        {/* Hero */}
        <Card className="p-6 lg:p-8 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-800 text-white border-0">
          <div className="flex items-start gap-4">
            <ShieldCheck className="h-10 w-10 text-cyan-400 flex-shrink-0 mt-1" />
            <div>
              <h2 className="text-2xl font-bold mb-2">What is this tool?</h2>
              <p className="text-slate-300 leading-relaxed">
                An all-in-one security scanning platform that finds vulnerabilities in your code,
                detects leaked secrets, measures code quality, and automatically generates AI-powered
                fixes with Pull Requests. Think of it as SonarQube + Snyk + GitHub Advanced Security
                combined — but fully open-source and free to use commercially.
              </p>
              <div className="flex flex-wrap gap-2 mt-4">
                <Badge className="bg-cyan-600 text-white">SAST Scanner</Badge>
                <Badge className="bg-green-600 text-white">Dependency CVE</Badge>
                <Badge className="bg-red-600 text-white">Secret Detection</Badge>
                <Badge className="bg-violet-600 text-white">Code Quality</Badge>
                <Badge className="bg-blue-600 text-white">AI Auto-Fix</Badge>
                <Badge className="bg-orange-600 text-white">Compliance</Badge>
              </div>
            </div>
          </div>
        </Card>

        {/* Feature Sections */}
        <div className="space-y-6">

          {/* 1. SAST Scanning */}
          <FeatureCard
            icon={<SearchCode className="h-6 w-6 text-blue-600" />}
            title="Static Application Security Testing (SAST)"
            badge="Core Feature"
            badgeColor="bg-blue-600"
            description="Scans your source code for security vulnerabilities without executing it. Finds SQL injection, XSS, command injection, insecure deserialization, and 1000+ vulnerability patterns."
            howItHelps={[
              "Catches vulnerabilities before they reach production",
              "Scans every file in the repository automatically",
              "Supports 12+ programming languages",
              "Zero false-positive tuning with Semgrep rules",
            ]}
            whyUseIt="Every security audit requires SAST scanning. This replaces expensive tools like Checkmarx, Fortify, or SonarQube's security module."
            output={[
              "Vulnerability type and severity (CRITICAL/HIGH/MEDIUM/LOW)",
              "Exact file path and line number",
              "Description of the vulnerability and how to fix it",
              "OWASP/CWE classification",
              "ML-adjusted risk score based on code context",
            ]}
            languages={["Python", "Java", "JavaScript", "TypeScript", "C#", "Go", "Rust", "Ruby", "PHP", "C/C++", "Kotlin", "Swift"]}
          />

          {/* 2. Dependency Scanning */}
          <FeatureCard
            icon={<AlertTriangle className="h-6 w-6 text-orange-600" />}
            title="Dependency Vulnerability Scanning (SCA)"
            badge="Core Feature"
            badgeColor="bg-orange-600"
            description="Detects known CVEs in your project's dependencies. Checks every package version against the OSV.dev vulnerability database, pip-audit, and npm audit."
            howItHelps={[
              "Finds vulnerable libraries before attackers exploit them",
              "Covers all major package ecosystems",
              "Shows exact fix versions to upgrade to",
              "No API key required — uses free OSV.dev database",
            ]}
            whyUseIt="80% of modern application code comes from dependencies. A single vulnerable package can compromise your entire application. This replaces Snyk, Dependabot, and WhiteSource."
            output={[
              "CVE ID and severity score",
              "Affected package name and version",
              "Recommended fix version",
              "Link to vulnerability advisory",
            ]}
            languages={["Python (pip)", "Java (Maven/Gradle)", "JavaScript (npm)", "C# (NuGet)", "Go (modules)", "Rust (Cargo)", "Ruby (Bundler)", "PHP (Composer)"]}
          />

          {/* 3. Secret Detection */}
          <FeatureCard
            icon={<Lock className="h-6 w-6 text-red-600" />}
            title="Secret & Credential Detection"
            badge="Security"
            badgeColor="bg-red-600"
            description="Finds accidentally committed secrets: API keys, tokens, passwords, private keys, database connection strings, and cloud credentials. Uses regex patterns + Shannon entropy analysis."
            howItHelps={[
              "Prevents credential leaks that lead to data breaches",
              "Detects AWS, GitHub, Google, Stripe, Slack tokens",
              "Finds hardcoded passwords and connection strings",
              "Entropy analysis catches custom/unknown secret formats",
            ]}
            whyUseIt="A single leaked API key can cost millions. This replaces TruffleHog, GitLeaks, and GitHub Secret Scanning."
            output={[
              "Secret type (AWS Key, GitHub Token, Password, etc.)",
              "File and line number where secret is exposed",
              "Masked secret value for safe reporting",
              "Severity: CRITICAL for private keys, HIGH for API keys",
            ]}
            languages={["All file types", ".env files", "YAML/JSON configs", "Docker files", "Shell scripts"]}
          />

          {/* 4. Code Quality */}
          <FeatureCard
            icon={<BarChart3 className="h-6 w-6 text-violet-600" />}
            title="Code Quality & Technical Debt"
            badge="Quality"
            badgeColor="bg-violet-600"
            description="Measures code complexity, duplication, maintainability, and technical debt. Provides a Quality Gate (pass/fail) similar to SonarQube. Detects code smells like long functions, deep nesting, and magic numbers."
            howItHelps={[
              "Quantifies technical debt in hours/days",
              "Quality Gate blocks low-quality code from shipping",
              "Tracks maintainability over time",
              "Identifies the most complex/risky files",
            ]}
            whyUseIt="Replaces SonarQube's code quality features. No license fees, no server to maintain. Same metrics: complexity, duplication, maintainability index."
            output={[
              "Maintainability rating (A-F)",
              "Duplication percentage",
              "Technical debt in hours",
              "Code smells count with descriptions",
              "Quality Gate: PASSED or FAILED with conditions",
              "Lines of code per language",
            ]}
            languages={["All 12+ supported languages"]}
          />

          {/* 5. AI Auto-Fix */}
          <FeatureCard
            icon={<BrainCircuit className="h-6 w-6 text-cyan-600" />}
            title="AI-Powered Auto-Remediation"
            badge="AI"
            badgeColor="bg-cyan-600"
            description="Uses multi-provider LLM routing (Gemini, Groq, NVIDIA, OpenRouter, HuggingFace) to automatically generate code fixes for detected vulnerabilities. Creates a Pull Request with all fixes applied."
            howItHelps={[
              "Fixes vulnerabilities automatically — no manual coding",
              "Multi-LLM fallback ensures fixes are always generated",
              "Confidence scoring verifies fixes actually resolve the issue",
              "Diff preview shows exactly what changed",
            ]}
            whyUseIt="Most tools only REPORT vulnerabilities. This tool FIXES them. Saves hours of developer time per vulnerability. The AI understands code context and generates production-ready patches."
            output={[
              "Fixed code with vulnerability removed",
              "Pull Request on GitHub with all changes",
              "Confidence score (%) per file",
              "Diff summary: lines added/removed",
              "Validation result (syntax check passed/failed)",
            ]}
            languages={["All languages supported by the LLM models"]}
          />

          {/* 6. Compliance Mapping */}
          <FeatureCard
            icon={<FileText className="h-6 w-6 text-green-600" />}
            title="Compliance Mapping (OWASP, CWE, PCI-DSS)"
            badge="Enterprise"
            badgeColor="bg-green-600"
            description="Automatically maps every finding to industry compliance frameworks. Shows which OWASP Top 10 categories, CWE weaknesses, and PCI-DSS requirements are violated."
            howItHelps={[
              "Audit-ready compliance reports",
              "Shows compliance score per framework (0-100%)",
              "Maps findings to specific CWE IDs",
              "Identifies PCI-DSS requirement violations",
            ]}
            whyUseIt="Enterprise buyers and auditors need compliance mapping. This generates the same reports that expensive GRC tools produce — automatically from scan results."
            output={[
              "OWASP Top 10 compliance score (%)",
              "PCI-DSS v4.0 compliance score (%)",
              "CWE weakness breakdown",
              "Per-category violation count",
              "Overall compliance score",
            ]}
            languages={[]}
          />

          {/* 7. Baseline & Suppress */}
          <FeatureCard
            icon={<Ban className="h-6 w-6 text-orange-600" />}
            title="Baseline & Suppress Findings"
            badge="Workflow"
            badgeColor="bg-orange-600"
            description="Mark findings as accepted risk or false positive. Set a baseline so future scans only show NEW vulnerabilities. Reduces alert fatigue and focuses teams on what matters."
            howItHelps={[
              "Eliminates noise from known/accepted issues",
              "Shows only NEW findings since last baseline",
              "Tracks suppression reasons for audit trail",
              "One-click suppress from scan results",
            ]}
            whyUseIt="Without baseline management, teams get overwhelmed by hundreds of findings and stop using the tool. This is the #1 feature that makes security scanning sustainable."
            output={[
              "Active findings (excluding suppressed)",
              "New findings since baseline count",
              "Suppression list with reasons",
              "Audit trail of who suppressed what and when",
            ]}
            languages={[]}
          />

          {/* 8. Multi-Repo Dashboard */}
          <FeatureCard
            icon={<Globe className="h-6 w-6 text-blue-600" />}
            title="Multi-Repo Dashboard"
            badge="Enterprise"
            badgeColor="bg-blue-600"
            description="Scan up to 10 repositories at once. Get an organization-level health score and per-repo breakdown. Identify which repos are most at risk."
            howItHelps={[
              "Portfolio view for security managers",
              "Org Health Score (0-100, A-F rating)",
              "Identifies worst repos to prioritize",
              "Tracks improvement across the organization",
            ]}
            whyUseIt="Security managers don't scan one repo at a time. They need to see the big picture across 10-100 repos. This provides that executive-level view."
            output={[
              "Organization Health Score (0-100)",
              "Health Rating (A-F)",
              "Per-repo: findings, critical/high count, quality gate",
              "Total findings across all repos",
              "Language detection per repo",
            ]}
            languages={[]}
          />

          {/* 9. Webhook / CI */}
          <FeatureCard
            icon={<RefreshCw className="h-6 w-6 text-purple-600" />}
            title="Webhook / CI Integration"
            badge="DevOps"
            badgeColor="bg-purple-600"
            description="Receives GitHub push events and triggers automatic scans. Posts results as commit status checks (✓ pass / ✗ fail). Makes security scanning 'always on' without manual intervention."
            howItHelps={[
              "Every push is automatically scanned",
              "Blocks merges if critical vulnerabilities found",
              "No manual scanning needed",
              "Respects baseline and suppressions",
            ]}
            whyUseIt="Shift-left security: catch vulnerabilities at the moment code is pushed, not weeks later in a quarterly audit. This is how modern DevSecOps works."
            output={[
              "GitHub commit status check (✓ success / ✗ failure)",
              "Status description with finding count",
              "Scan saved to history for trend tracking",
              "Only scans main/master branch (configurable)",
            ]}
            languages={[]}
          />

          {/* 10. Export Formats */}
          <FeatureCard
            icon={<FileText className="h-6 w-6 text-slate-600" />}
            title="Export: SARIF, CSV, PDF"
            badge="Integration"
            badgeColor="bg-slate-600"
            description="Export scan results in multiple formats for integration with other tools and reporting to stakeholders."
            howItHelps={[
              "SARIF: Import into GitHub Code Scanning, Azure DevOps, VS Code",
              "CSV: Open in Excel, import into JIRA, share with teams",
              "PDF: Professional report for management and auditors",
            ]}
            whyUseIt="Different stakeholders need different formats. Developers want SARIF in their IDE. Managers want PDF reports. Project managers want CSV for JIRA tickets."
            output={[
              "SARIF 2.1.0 (GitHub/Azure/VS Code compatible)",
              "CSV with all finding details (Excel/JIRA ready)",
              "PDF with executive summary, risk overview, detailed findings",
            ]}
            languages={[]}
          />
        </div>

        {/* Scan Pipeline */}
        <Card className="p-6 rounded-2xl">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Zap className="h-5 w-5 text-yellow-500" />
            How the Scan Pipeline Works
          </h2>
          <div className="space-y-3">
            {[
              { step: "1", title: "Clone Repository", desc: "Shallow clone (depth=1) for speed. Tracked with guaranteed cleanup." },
              { step: "2", title: "SAST Scan (Semgrep)", desc: "Static analysis with 1000+ security rules across all languages." },
              { step: "3", title: "Dependency Scan", desc: "Check all packages against CVE databases (OSV.dev, pip-audit, npm audit)." },
              { step: "4", title: "Secret Detection", desc: "Regex + entropy analysis finds leaked credentials and API keys." },
              { step: "5", title: "Custom Rules", desc: "User-defined Semgrep rules for organization-specific patterns." },
              { step: "6", title: "ML Severity Prediction", desc: "Adjusts priority based on code context (auth paths, user input, test files)." },
              { step: "7", title: "Code Quality Analysis", desc: "Complexity, duplication, tech debt, code smells, maintainability." },
              { step: "8", title: "Compliance Mapping", desc: "Maps findings to OWASP Top 10, CWE, PCI-DSS frameworks." },
              { step: "9", title: "Quality Gate", desc: "Pass/fail decision based on configurable thresholds." },
              { step: "10", title: "AI Fix (Scan & Fix mode)", desc: "LLM generates code patches, validates, creates PR." },
            ].map((item) => (
              <div key={item.step} className="flex gap-3 items-start">
                <div className="w-7 h-7 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs font-bold flex-shrink-0">
                  {item.step}
                </div>
                <div>
                  <p className="text-sm font-semibold">{item.title}</p>
                  <p className="text-xs text-muted-foreground">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Supported Languages */}
        <Card className="p-6 rounded-2xl">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Code className="h-5 w-5 text-green-600" />
            Supported Languages & Ecosystems
          </h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted">
                <tr>
                  <th className="text-left p-3 font-semibold">Language</th>
                  <th className="text-center p-3 font-semibold">SAST</th>
                  <th className="text-center p-3 font-semibold">Dependencies</th>
                  <th className="text-center p-3 font-semibold">Secrets</th>
                  <th className="text-center p-3 font-semibold">AI Fix</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { lang: "Python", sast: true, deps: true, secrets: true, fix: true, note: "pip-audit + OSV.dev" },
                  { lang: "Java (Maven)", sast: true, deps: true, secrets: true, fix: true, note: "OSV.dev (pom.xml)" },
                  { lang: "Java (Gradle)", sast: true, deps: true, secrets: true, fix: true, note: "OSV.dev (build.gradle)" },
                  { lang: "JavaScript", sast: true, deps: true, secrets: true, fix: true, note: "npm audit + OSV.dev" },
                  { lang: "TypeScript", sast: true, deps: true, secrets: true, fix: true, note: "npm audit + OSV.dev" },
                  { lang: "C# / .NET", sast: true, deps: true, secrets: true, fix: true, note: "OSV.dev (NuGet)" },
                  { lang: "Go", sast: true, deps: true, secrets: true, fix: true, note: "OSV.dev (go.mod)" },
                  { lang: "Rust", sast: true, deps: true, secrets: true, fix: true, note: "OSV.dev (Cargo)" },
                  { lang: "Ruby", sast: true, deps: true, secrets: true, fix: true, note: "OSV.dev (Gemfile)" },
                  { lang: "PHP", sast: true, deps: true, secrets: true, fix: true, note: "OSV.dev (Composer)" },
                  { lang: "Kotlin", sast: true, deps: true, secrets: true, fix: true, note: "Via Maven/Gradle" },
                  { lang: "C/C++", sast: true, deps: false, secrets: true, fix: true, note: "" },
                  { lang: "Swift", sast: true, deps: false, secrets: true, fix: true, note: "" },
                ].map((row) => (
                  <tr key={row.lang} className="border-t">
                    <td className="p-3 font-medium">{row.lang}</td>
                    <td className="p-3 text-center">{row.sast ? "✅" : "—"}</td>
                    <td className="p-3 text-center">{row.deps ? "✅" : "—"}</td>
                    <td className="p-3 text-center">{row.secrets ? "✅" : "—"}</td>
                    <td className="p-3 text-center">{row.fix ? "✅" : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {/* API Reference Quick Links */}
        <Card className="p-6 rounded-2xl">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Terminal className="h-5 w-5 text-slate-600" />
            API Reference
          </h2>
          <p className="text-sm text-muted-foreground mb-4">
            Full interactive API documentation available at the links below.
            All endpoints require the <code className="bg-muted px-1 rounded">X-API-Key</code> header when authentication is enabled.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <a href={`${API_URL}/docs`} target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-2 rounded-lg border p-3 hover:bg-muted/50 transition-colors">
              <ExternalLink className="h-4 w-4 text-blue-600" />
              <div>
                <p className="text-sm font-semibold">Swagger UI</p>
                <p className="text-xs text-muted-foreground">Interactive API explorer — try endpoints live</p>
              </div>
            </a>
            <a href={`${API_URL}/redoc`} target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-2 rounded-lg border p-3 hover:bg-muted/50 transition-colors">
              <ExternalLink className="h-4 w-4 text-green-600" />
              <div>
                <p className="text-sm font-semibold">ReDoc</p>
                <p className="text-xs text-muted-foreground">Clean API reference documentation</p>
              </div>
            </a>
          </div>

          <div className="mt-4 rounded-lg border overflow-hidden">
            <table className="w-full text-xs">
              <thead className="bg-muted">
                <tr>
                  <th className="text-left p-2 font-semibold">Endpoint</th>
                  <th className="text-left p-2 font-semibold">Method</th>
                  <th className="text-left p-2 font-semibold">Description</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { path: "/scan-only", method: "POST", desc: "Scan repo for vulnerabilities (no fix)" },
                  { path: "/scan", method: "POST", desc: "Scan + AI fix + create PR" },
                  { path: "/scan-multi", method: "POST", desc: "Scan multiple repos (dashboard)" },
                  { path: "/scan-secrets", method: "POST", desc: "Secret detection only" },
                  { path: "/compliance", method: "POST", desc: "Compliance mapping (OWASP/CWE/PCI)" },
                  { path: "/export/sarif", method: "POST", desc: "Export as SARIF" },
                  { path: "/export/csv", method: "POST", desc: "Export as CSV" },
                  { path: "/report/pdf", method: "POST", desc: "Generate PDF report" },
                  { path: "/diff", method: "POST", desc: "Generate code diff" },
                  { path: "/confidence", method: "POST", desc: "Fix confidence check" },
                  { path: "/rules", method: "GET/POST", desc: "Custom rules CRUD" },
                  { path: "/schedules", method: "GET/POST", desc: "Scheduled scans" },
                  { path: "/baseline/suppress", method: "POST", desc: "Suppress a finding" },
                  { path: "/baseline/set", method: "POST", desc: "Set scan baseline" },
                  { path: "/history", method: "GET/DELETE", desc: "Scan history" },
                  { path: "/webhook/github", method: "POST", desc: "GitHub webhook receiver" },
                  { path: "/health", method: "GET", desc: "Health check" },
                  { path: "/environment", method: "GET", desc: "System SDK status" },
                ].map((ep) => (
                  <tr key={ep.path} className="border-t">
                    <td className="p-2 font-mono">{ep.path}</td>
                    <td className="p-2"><Badge variant="outline" className="text-[10px]">{ep.method}</Badge></td>
                    <td className="p-2 text-muted-foreground">{ep.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Footer */}
        <div className="text-center text-xs text-muted-foreground py-4">
          AI Vulnerability Remediator v2.2 — Enterprise AI Security Platform
        </div>
      </div>
    </main>
  );
}


// Feature Card Component
function FeatureCard({
  icon,
  title,
  badge,
  badgeColor,
  description,
  howItHelps,
  whyUseIt,
  output,
  languages,
}: {
  icon: React.ReactNode;
  title: string;
  badge: string;
  badgeColor: string;
  description: string;
  howItHelps: string[];
  whyUseIt: string;
  output: string[];
  languages: string[];
}) {
  return (
    <Card className="p-5 lg:p-6 rounded-2xl">
      <div className="flex items-start gap-3 mb-4">
        <div className="flex-shrink-0 mt-0.5">{icon}</div>
        <div className="flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-lg font-bold">{title}</h3>
            <Badge className={`${badgeColor} text-white text-[10px]`}>{badge}</Badge>
          </div>
          <p className="text-sm text-muted-foreground mt-1">{description}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* How it helps */}
        <div className="space-y-2">
          <p className="text-xs font-semibold text-green-700 dark:text-green-400">How it helps</p>
          <ul className="space-y-1">
            {howItHelps.map((item, idx) => (
              <li key={idx} className="text-xs flex items-start gap-1.5">
                <CheckCircle2 className="h-3 w-3 text-green-500 flex-shrink-0 mt-0.5" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Why use it */}
        <div className="space-y-2">
          <p className="text-xs font-semibold text-blue-700 dark:text-blue-400">Why use it</p>
          <p className="text-xs text-muted-foreground leading-relaxed">{whyUseIt}</p>
          {languages.length > 0 && (
            <div className="mt-2">
              <p className="text-[10px] font-semibold text-muted-foreground mb-1">Supported:</p>
              <div className="flex flex-wrap gap-1">
                {languages.map((lang) => (
                  <span key={lang} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800">
                    {lang}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Output */}
        <div className="space-y-2">
          <p className="text-xs font-semibold text-violet-700 dark:text-violet-400">What it outputs</p>
          <ul className="space-y-1">
            {output.map((item, idx) => (
              <li key={idx} className="text-xs flex items-start gap-1.5">
                <span className="text-violet-500 flex-shrink-0">→</span>
                <span className="text-muted-foreground">{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Card>
  );
}
