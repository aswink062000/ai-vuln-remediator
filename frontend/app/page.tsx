"use client";

import { useState, useEffect } from "react";
import axios from "axios";

import {
  Copy,
  Moon,
  Sun,
  CheckCircle2,
  BrainCircuit,
  Download,
  History,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  XCircle,
  List,
  ExternalLink,
  GitBranch,
  SearchCode,
  Wrench,
  Eye,
  Settings,
  FileText,
} from "lucide-react";

import { useTheme } from "next-themes";
import Link from "next/link";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

type ScanMode = "scan-fix" | "scan-only";

export default function Home() {
  const { theme, setTheme } = useTheme();

  const [mounted, setMounted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showError, setShowError] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  const [url, setUrl] = useState("");
  const [result, setResult] = useState<any>(null);
  const [scanMode, setScanMode] = useState<ScanMode>("scan-only");

  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    const savedHistory = sessionStorage.getItem("scanHistory");
    if (savedHistory) {
      setScanHistory(JSON.parse(savedHistory));
    }
  }, []);

  async function runScan() {
    if (!url) {
      setErrorMessage("GitHub Repository URL is required before scanning.");
      setShowError(true);
      return;
    }

    setLoading(true);
    setErrorMessage("");
    setShowError(false);
    setResult(null);

    const endpoint =
      scanMode === "scan-fix"
        ? "http://localhost:8000/scan"
        : "http://localhost:8000/scan-only";

    try {
      const res = await axios.post(endpoint, { github_url: url });
      setResult(res.data);

      const historyEntry = {
        url,
        mode: scanMode,
        timestamp: new Date().toISOString(),
        result: res.data,
      };

      const updatedHistory = [historyEntry, ...scanHistory].slice(0, 10);
      setScanHistory(updatedHistory);
      sessionStorage.setItem("scanHistory", JSON.stringify(updatedHistory));
    } catch (error: any) {
      setErrorMessage(
        error.response?.data?.detail || error.message || "Failed to scan repository"
      );
      setShowError(true);
    } finally {
      setLoading(false);
    }
  }

  const copyResult = async () => {
    if (result) {
      await navigator.clipboard.writeText(JSON.stringify(result, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const downloadResult = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });
    const downloadUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = downloadUrl;
    const repoName = url.split("/").pop() || "repository";
    a.download = `${scanMode}_${repoName}_${new Date().getTime()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(downloadUrl);
  };

  const downloadPDF = async () => {
    if (!result) return;
    try {
      const res = await axios.post(
        "http://localhost:8000/report/pdf",
        { scan_data: result },
        { responseType: "blob" }
      );
      const blob = new Blob([res.data], { type: "application/pdf" });
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      const repoName = url.split("/").pop() || "repository";
      a.download = `vulnerability_report_${repoName}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadUrl);
    } catch (error) {
      console.error("PDF download failed:", error);
    }
  };

  const loadFromHistory = (entry: any) => {
    setUrl(entry.url);
    setScanMode(entry.mode || "scan-only");
    setResult(entry.result);
    setShowHistory(false);
  };

  const sampleRepos = [
    {
      name: "Django Vulnerable App",
      url: "https://github.com/nVisium/django.nV",
      type: "Python",
    },
    {
      name: "WebGoat Legacy (Java)",
      url: "https://github.com/WebGoat/WebGoat-Legacy",
      type: "Java",
    },
    {
      name: "NodeGoat (Node.js)",
      url: "https://github.com/OWASP/NodeGoat",
      type: "JavaScript",
    },
    {
      name: "FastAPI (Clean)",
      url: "https://github.com/tiangolo/fastapi",
      type: "Python",
    },
  ];

  // Helper to get severity color
  const severityColor = (severity: string) => {
    const s = severity?.toUpperCase();
    if (s === "CRITICAL") return "bg-red-600 text-white";
    if (s === "HIGH" || s === "ERROR") return "bg-orange-600 text-white";
    if (s === "MEDIUM" || s === "WARNING" || s === "MODERATE")
      return "bg-yellow-500 text-black";
    return "bg-blue-500 text-white";
  };

  // Render findings summary
  const renderSummary = () => {
    if (!result) return null;

    const summary = result.scan_summary;
    const findings = result.findings || [];
    const total = result.total_findings ?? findings.length;

    return (
      <div className="space-y-4">
        {/* Status Badge */}
        <div className="flex items-center gap-3">
          {result.status === "clean" ? (
            <Badge className="bg-green-600 text-white px-3 py-1">
              <ShieldCheck className="h-3 w-3 mr-1" /> Clean
            </Badge>
          ) : result.status === "success" ? (
            <Badge className="bg-blue-600 text-white px-3 py-1">
              <Wrench className="h-3 w-3 mr-1" /> Fix Applied
            </Badge>
          ) : result.status === "error" || result.status === "scan_failed" ? (
            <Badge className="bg-red-600 text-white px-3 py-1">
              <XCircle className="h-3 w-3 mr-1" /> Error
            </Badge>
          ) : (
            <Badge className="bg-orange-600 text-white px-3 py-1">
              <ShieldAlert className="h-3 w-3 mr-1" /> Vulnerabilities Found
            </Badge>
          )}
          <span className="text-sm text-muted-foreground">
            {total} total finding{total !== 1 ? "s" : ""}
          </span>
        </div>

        {/* Summary Stats */}
        {summary && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {Object.entries(summary.by_severity || {}).map(
              ([sev, count]) => (
                <div
                  key={sev}
                  className="rounded-lg border p-3 text-center"
                >
                  <Badge className={`${severityColor(sev)} text-xs`}>
                    {sev}
                  </Badge>
                  <p className="text-2xl font-bold mt-1">
                    {count as number}
                  </p>
                </div>
              )
            )}
          </div>
        )}

        {/* Scanner breakdown */}
        {summary?.by_scanner && (
          <div className="rounded-lg border p-3">
            <p className="text-xs font-semibold text-muted-foreground mb-2">
              Scanner Breakdown
            </p>
            <div className="flex flex-wrap gap-2">
              {Object.entries(summary.by_scanner).map(
                ([scanner, count]) => (
                  <Badge key={scanner} variant="outline" className="text-xs">
                    {scanner}: {count as number}
                  </Badge>
                )
              )}
            </div>
          </div>
        )}

        {/* Project Info & SDK Status */}
        {result.project_info && (
          <div className="rounded-lg border p-3 space-y-2">
            <p className="text-xs font-semibold text-muted-foreground">
              Project Detection
            </p>
            <div className="flex flex-wrap gap-2">
              {result.project_info.languages?.map((lang: string) => (
                <Badge key={lang} className="bg-violet-600 text-white text-xs">
                  {lang}
                </Badge>
              ))}
              {result.project_info.frameworks?.map((fw: string) => (
                <Badge key={fw} variant="outline" className="text-xs">
                  {fw}
                </Badge>
              ))}
            </div>
            {result.sdk_status && (
              <div className="mt-2 space-y-1">
                <p className="text-xs text-muted-foreground">SDK Status:</p>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(result.sdk_status.sdks || {}).map(
                    ([sdk, info]: [string, any]) => (
                      <Badge
                        key={sdk}
                        variant="outline"
                        className={`text-xs ${
                          info.installed
                            ? "border-green-500 text-green-700 dark:text-green-400"
                            : "border-red-500 text-red-700 dark:text-red-400"
                        }`}
                      >
                        {info.installed ? "✓" : "✗"} {sdk}
                      </Badge>
                    )
                  )}
                </div>
                {result.sdk_status.missing?.length > 0 && (
                  <p className="text-xs text-orange-600 dark:text-orange-400 mt-1">
                    ⚠ Missing: {result.sdk_status.missing.join(", ")} — validation skipped for these
                  </p>
                )}
              </div>
            )}
          </div>
        )}

        {/* PR Link if scan-fix */}
        {result.pull_request && (
          <div className="rounded-lg bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-800 p-4">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-green-600" />
              <div>
                <p className="font-semibold text-sm">Pull Request Created</p>
                <a
                  href={result.pull_request}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-600 hover:underline flex items-center gap-1"
                >
                  {result.pull_request}
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>
          </div>
        )}

        {/* Findings List */}
        {findings.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-semibold text-muted-foreground">
              Top Findings
            </p>
            <div className="max-h-80 overflow-y-auto space-y-2">
              {findings.slice(0, 20).map((f: any, idx: number) => (
                <div
                  key={idx}
                  className="rounded-lg border p-3 text-sm space-y-1"
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge
                      className={`${severityColor(f.severity)} text-xs`}
                    >
                      {f.severity}
                    </Badge>
                    <span className="font-mono text-xs text-muted-foreground">
                      {f.rule_id}
                    </span>
                    {f.metadata?.category && (
                      <Badge variant="outline" className="text-xs">
                        {f.metadata.category}
                      </Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {f.path}
                    {f.line ? `:${f.line}` : ""}
                  </p>
                  <p className="text-xs">{f.message?.slice(0, 200)}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <main className="min-h-screen bg-background">
      <div className="flex flex-col lg:flex-row min-h-screen lg:h-screen lg:overflow-hidden">
        {/* Sidebar */}
        <aside className="w-full lg:w-72 bg-slate-900 text-white border-b lg:border-r lg:border-b-0 flex flex-col">
          <div className="flex items-center justify-between p-3 lg:p-5 border-b border-slate-800">
            <div>
              <h1 className="font-bold text-lg lg:text-xl leading-tight">
                Enterprise
              </h1>
              <p className="text-xs lg:text-sm text-slate-300">
                AI Security Platform
              </p>
            </div>
            <Button
              size="icon"
              variant="ghost"
              className="text-white hover:bg-slate-800"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            >
              {mounted ? (
                theme === "dark" ? (
                  <Sun className="h-5 w-5" />
                ) : (
                  <Moon className="h-5 w-5" />
                )
              ) : (
                <div className="h-5 w-5" />
              )}
            </Button>
          </div>

          <div className="p-2 lg:p-3 space-y-2 lg:space-y-3 overflow-y-auto">
            <div className="flex items-center gap-2 lg:gap-3 rounded-xl bg-slate-800 px-3 lg:px-4 py-3 lg:py-4">
              <SearchCode className="h-4 w-4 lg:h-5 lg:w-5 text-blue-400" />
              <span className="font-medium text-sm lg:text-base">
                Repository Scanner
              </span>
            </div>

            {scanHistory.length > 0 && (
              <button
                onClick={() => setShowHistory(!showHistory)}
                className="w-full flex items-center gap-2 lg:gap-3 rounded-xl bg-slate-800/50 hover:bg-slate-800 px-3 lg:px-4 py-2 lg:py-3 transition-colors"
              >
                <History className="h-4 w-4 lg:h-5 lg:w-5" />
                <span className="font-medium text-sm lg:text-base">
                  Scan History ({scanHistory.length})
                </span>
              </button>
            )}

            {showHistory && (
              <div className="rounded-xl bg-slate-950/60 p-2 lg:p-3 border border-slate-800 max-h-48 lg:max-h-64 overflow-y-auto">
                <div className="space-y-2">
                  {scanHistory.map((entry, idx) => (
                    <button
                      key={idx}
                      onClick={() => loadFromHistory(entry)}
                      className="w-full text-left p-2 lg:p-3 rounded-lg bg-slate-900/50 hover:bg-slate-800 transition-colors"
                    >
                      <div className="flex items-center gap-2">
                        <Badge
                          variant="outline"
                          className="text-[10px] border-slate-600"
                        >
                          {entry.mode === "scan-fix" ? "Fix" : "Scan"}
                        </Badge>
                        <span className="text-xs lg:text-sm font-medium truncate">
                          {entry.url.split("/").slice(-2).join("/")}
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 mt-1">
                        {new Date(entry.timestamp).toLocaleString()}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="rounded-xl bg-slate-950/40 p-3 lg:p-4 border border-slate-800">
              <div className="flex items-center gap-2 mb-2 lg:mb-3">
                <BrainCircuit className="h-4 w-4 lg:h-5 lg:w-5 text-cyan-400" />
                <h3 className="font-semibold text-sm lg:text-base">
                  AI Remediation Engine
                </h3>
              </div>
              <div className="space-y-1 lg:space-y-2 text-xs lg:text-sm text-slate-300">
                <p>✔ Static Code Analysis</p>
                <p>✔ Dependency Scanning</p>
                <p>✔ Secret Detection</p>
                <p>✔ Contextual AI Fixes</p>
                <p>✔ Auto-PR Generation</p>
              </div>
            </div>

            {result && (
              <div className="rounded-xl p-3 lg:p-4 border bg-green-900/30 border-green-700">
                <div className="flex items-center gap-2 mb-2">
                  <ShieldCheck className="h-4 w-4 lg:h-5 lg:w-5 text-green-400" />
                  <h3 className="font-semibold text-sm lg:text-base">
                    Scan Completed
                  </h3>
                </div>
                <p className="text-xs text-slate-300">
                  Target repository has been successfully analyzed.
                </p>
              </div>
            )}
          </div>

          <div className="mt-auto p-3 lg:p-4 border-t border-slate-800">
            <Link href="/settings">
              <button className="w-full flex items-center gap-2 rounded-xl bg-slate-800/50 hover:bg-slate-800 px-3 py-2 transition-colors mb-2">
                <Settings className="h-4 w-4" />
                <span className="text-sm">Settings</span>
              </button>
            </Link>
            <div className="text-xs text-slate-400">
              Enterprise AI Scanner v2.0
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <section className="flex-1 overflow-auto p-3 lg:p-6">
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 lg:gap-6">
            {/* Left Column */}
            <div className="space-y-4 lg:space-y-6">
              <Card className="p-4 lg:p-6 rounded-2xl shadow-sm border-slate-200 dark:border-slate-800">
                <div className="space-y-4 lg:space-y-6">
                  <div>
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="h-5 w-5 lg:h-6 lg:w-6 text-blue-600 dark:text-blue-400" />
                      <h2 className="text-xl lg:text-2xl font-bold">
                        AI Vulnerability Remediator
                      </h2>
                    </div>
                    <p className="text-muted-foreground text-xs lg:text-sm mt-2">
                      Scan your GitHub repositories for security vulnerabilities
                      and receive AI-generated remediation strategies.
                    </p>

                    <Dialog>
                      <DialogTrigger asChild>
                        <button className="inline-flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 hover:underline mt-2">
                          <List className="h-3 w-3" />
                          View sample repositories
                          <ExternalLink className="h-3 w-3" />
                        </button>
                      </DialogTrigger>
                      <DialogContent className="max-w-2xl">
                        <DialogHeader>
                          <DialogTitle className="flex items-center gap-2">
                            <GitBranch className="h-5 w-5" />
                            Sample Repositories
                          </DialogTitle>
                          <DialogDescription>
                            Select a sample repository to test the scanner.
                          </DialogDescription>
                        </DialogHeader>

                        <div className="mt-4 rounded-lg border overflow-hidden">
                          <table className="w-full text-sm">
                            <thead className="bg-muted">
                              <tr>
                                <th className="text-left p-3 font-semibold">
                                  Repository
                                </th>
                                <th className="text-left p-3 font-semibold">
                                  Language
                                </th>
                                <th className="text-center p-3 font-semibold">
                                  Action
                                </th>
                              </tr>
                            </thead>
                            <tbody>
                              {sampleRepos.map((repo, idx) => (
                                <tr
                                  key={idx}
                                  className="border-t hover:bg-muted/50 transition-colors"
                                >
                                  <td className="p-3 font-medium">
                                    {repo.name}
                                  </td>
                                  <td className="p-3">
                                    <Badge
                                      variant="outline"
                                      className="text-xs"
                                    >
                                      {repo.type}
                                    </Badge>
                                  </td>
                                  <td className="p-3 text-center">
                                    <Button
                                      size="sm"
                                      variant="ghost"
                                      onClick={() => setUrl(repo.url)}
                                      className="h-8 text-xs gap-1"
                                    >
                                      Load
                                    </Button>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </DialogContent>
                    </Dialog>
                  </div>

                  {showError && (
                    <div className="rounded-lg bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-800 p-3 lg:p-4">
                      <div className="flex items-center gap-2">
                        <XCircle className="h-4 w-4 text-red-600 dark:text-red-400" />
                        <p className="text-sm text-red-900 dark:text-red-200">
                          {errorMessage}
                        </p>
                      </div>
                    </div>
                  )}

                  <div className="rounded-lg bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 p-3 lg:p-4">
                    <div className="flex gap-2 lg:gap-3">
                      <AlertTriangle className="h-4 w-4 lg:h-5 lg:w-5 text-blue-600 dark:text-blue-500 flex-shrink-0 mt-0.5" />
                      <div className="space-y-1">
                        <p className="text-xs lg:text-sm font-semibold text-blue-900 dark:text-blue-100">
                          Execution Environment Notice
                        </p>
                        <p className="text-xs text-blue-800 dark:text-blue-200">
                          Large repositories may take up to 60 seconds to scan.
                          Ensure your backend API (http://localhost:8000) is
                          running.
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Repository URL Input */}
                  <div className="space-y-2">
                    <Label htmlFor="repo-url">Repository URL</Label>
                    <div className="relative">
                      <GitBranch className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                      <Input
                        id="repo-url"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        placeholder="https://github.com/username/repository"
                        className="h-11 pl-10"
                      />
                    </div>
                  </div>

                  {/* Scan Mode Selection */}
                  <div className="space-y-2">
                    <Label>Scan Mode</Label>
                    <div className="grid grid-cols-2 gap-3">
                      <button
                        type="button"
                        onClick={() => setScanMode("scan-only")}
                        className={`flex items-center gap-2 rounded-xl border-2 p-3 lg:p-4 transition-all ${
                          scanMode === "scan-only"
                            ? "border-blue-600 bg-blue-50 dark:bg-blue-950/30"
                            : "border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600"
                        }`}
                      >
                        <Eye
                          className={`h-5 w-5 ${
                            scanMode === "scan-only"
                              ? "text-blue-600"
                              : "text-muted-foreground"
                          }`}
                        />
                        <div className="text-left">
                          <p
                            className={`text-sm font-semibold ${
                              scanMode === "scan-only"
                                ? "text-blue-900 dark:text-blue-100"
                                : ""
                            }`}
                          >
                            Scan Only
                          </p>
                          <p className="text-xs text-muted-foreground">
                            Detect vulnerabilities
                          </p>
                        </div>
                      </button>

                      <button
                        type="button"
                        onClick={() => setScanMode("scan-fix")}
                        className={`flex items-center gap-2 rounded-xl border-2 p-3 lg:p-4 transition-all ${
                          scanMode === "scan-fix"
                            ? "border-green-600 bg-green-50 dark:bg-green-950/30"
                            : "border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600"
                        }`}
                      >
                        <Wrench
                          className={`h-5 w-5 ${
                            scanMode === "scan-fix"
                              ? "text-green-600"
                              : "text-muted-foreground"
                          }`}
                        />
                        <div className="text-left">
                          <p
                            className={`text-sm font-semibold ${
                              scanMode === "scan-fix"
                                ? "text-green-900 dark:text-green-100"
                                : ""
                            }`}
                          >
                            Scan & Fix
                          </p>
                          <p className="text-xs text-muted-foreground">
                            Fix & create PR
                          </p>
                        </div>
                      </button>
                    </div>
                  </div>

                  {/* Action Button */}
                  <Button
                    className={`w-full h-10 lg:h-11 gap-2 text-sm lg:text-base text-white ${
                      scanMode === "scan-fix"
                        ? "bg-green-600 hover:bg-green-700"
                        : "bg-blue-600 hover:bg-blue-700"
                    }`}
                    onClick={runScan}
                    disabled={loading}
                  >
                    {loading ? (
                      <SearchCode className="h-4 w-4 animate-pulse" />
                    ) : scanMode === "scan-fix" ? (
                      <Wrench className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                    {loading
                      ? "Analyzing Repository..."
                      : scanMode === "scan-fix"
                      ? "Scan & Fix Repository"
                      : "Scan Repository"}
                  </Button>

                  {/* Mode description */}
                  <p className="text-xs text-muted-foreground text-center">
                    {scanMode === "scan-fix"
                      ? "Scans for vulnerabilities, applies AI fix to the first SAST finding, and creates a Pull Request."
                      : "Scans for all vulnerabilities (SAST + Dependencies) and returns a detailed report without modifying code."}
                  </p>
                </div>
              </Card>

              {/* Scan Summary Card */}
              <Card className="p-4 lg:p-6 rounded-2xl shadow-sm border-slate-200 dark:border-slate-800">
                <div className="flex items-center gap-2 mb-4 lg:mb-5">
                  <BrainCircuit className="h-4 w-4 lg:h-5 lg:w-5 text-violet-600" />
                  <h2 className="text-lg lg:text-xl font-bold">
                    Scan Analysis
                  </h2>
                </div>

                {loading ? (
                  <div className="space-y-3">
                    <div className="h-4 w-3/4 bg-slate-100 dark:bg-slate-800 rounded animate-pulse"></div>
                    <div className="h-4 w-1/2 bg-slate-100 dark:bg-slate-800 rounded animate-pulse"></div>
                    <div className="h-4 w-5/6 bg-slate-100 dark:bg-slate-800 rounded animate-pulse"></div>
                  </div>
                ) : result ? (
                  renderSummary()
                ) : (
                  <div className="text-muted-foreground text-xs lg:text-sm text-center py-6 border-2 border-dashed rounded-lg border-slate-200 dark:border-slate-800">
                    Run a scan to view the AI analysis summary.
                  </div>
                )}
              </Card>
            </div>

            {/* Right Column - Raw JSON Results */}
            <Card className="flex flex-col p-0 rounded-2xl shadow-sm overflow-hidden border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 min-h-[400px] xl:min-h-0 xl:h-[calc(100vh-4rem)]">
              <div className="flex items-center justify-between p-4 lg:p-6 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-background">
                <div>
                  <h2 className="text-xl lg:text-2xl font-bold">
                    Scan Report
                  </h2>
                  <p className="text-muted-foreground text-xs lg:text-sm mt-1">
                    Raw JSON output of identified vulnerabilities and
                    remediation steps.
                  </p>
                </div>

                {result && (
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={copyResult}
                      title={copied ? "Copied!" : "Copy to clipboard"}
                      className="h-9 w-9"
                    >
                      {copied ? (
                        <CheckCircle2 className="h-4 w-4 text-green-600" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={downloadResult}
                      title="Download as JSON"
                      className="h-9 w-9"
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="outline"
                      size="icon"
                      onClick={downloadPDF}
                      title="Download as PDF"
                      className="h-9 w-9"
                    >
                      <FileText className="h-4 w-4" />
                    </Button>
                  </div>
                )}
              </div>

              <div className="flex-1 overflow-auto p-4 lg:p-6">
                {loading ? (
                  <div className="flex flex-col items-center justify-center h-full space-y-4 text-muted-foreground">
                    <SearchCode className="h-8 w-8 animate-pulse text-blue-500" />
                    <p className="text-sm">
                      {scanMode === "scan-fix"
                        ? "Scanning, fixing, and generating PR..."
                        : "Scanning codebase for vulnerabilities..."}
                    </p>
                  </div>
                ) : result ? (
                  <pre className="text-xs lg:text-sm font-mono text-slate-800 dark:text-slate-300 whitespace-pre-wrap break-all">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full text-muted-foreground space-y-3">
                    <ShieldCheck className="h-12 w-12 opacity-20" />
                    <p className="text-sm">No report generated yet.</p>
                  </div>
                )}
              </div>
            </Card>
          </div>
        </section>
      </div>
    </main>
  );
}
