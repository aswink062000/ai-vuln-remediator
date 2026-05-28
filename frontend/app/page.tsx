"use client";

import { useState, useEffect, useRef, useCallback } from "react";
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
  Terminal,
  Monitor,
  Package,
  BarChart3,
  GitBranch as GitBranchIcon,
  Check,
  AlertCircle,
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
import { ReviewPanel } from "@/components/diff-viewer/ReviewPanel";

type ScanMode = "scan-fix" | "scan-only";
type LogEntry = {
  type: string;
  message: string;
  level?: string;
  data?: any;
  timestamp?: string;
};

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const API_BASE = `${API_URL}/api/v1`;
const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000";
const API_KEY = process.env.NEXT_PUBLIC_API_KEY || "";

/** Trim a scan result to only keep lightweight metadata for history storage */
function trimResultForHistory(result: any): any {
  if (!result) return result;
  return {
    status: result.status,
    message: result.message,
    total_findings: result.total_findings,
    fixable_findings: result.fixable_findings,
    scan_summary: result.scan_summary,
    project_info: result.project_info,
    sdk_status: result.sdk_status,
    // Keep only first 10 findings without heavy metadata
    findings: (result.findings || []).slice(0, 10).map((f: any) => ({
      rule_id: f.rule_id,
      severity: f.severity,
      message: (f.message || "").slice(0, 150),
      path: f.path,
      line: f.line,
    })),
    // Strip preview_files (contains full source code) — keep only paths and counts
    preview_files: (result.preview_files || []).map((f: any) => ({
      path: f.path,
      findings_count: f.findings_count,
      error: f.error,
    })),
    // Strip fixed_files code, keep summary
    fixed_files: (result.fixed_files || []).map((f: any) => ({
      path: f.path,
      findings_fixed: f.findings_fixed,
      confidence: f.confidence,
    })),
  };
}

/** Safely save scan history to sessionStorage with auto-cleanup on quota exceeded */
function saveHistoryToStorage(history: any[]) {
  try {
    sessionStorage.setItem("scanHistory", JSON.stringify(history));
  } catch (e: any) {
    if (e?.name === "QuotaExceededError" || e?.code === 22) {
      // Auto-clean: remove oldest entries until it fits or list is empty
      let trimmed = [...history];
      while (trimmed.length > 0) {
        trimmed.pop(); // remove oldest (last item since newest is first)
        try {
          sessionStorage.setItem("scanHistory", JSON.stringify(trimmed));
          return; // success
        } catch {
          // keep trimming
        }
      }
      // If even empty array fails, just clear it
      sessionStorage.removeItem("scanHistory");
    }
  }
}

export default function Home() {
  const { theme, setTheme } = useTheme();

  const [mounted, setMounted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showError, setShowError] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  const [url, setUrl] = useState("");
  const [result, setResult] = useState<any>(null);
  const [scanMode, setScanMode] = useState<ScanMode>("scan-only");
  const [branch, setBranch] = useState("");  // Branch to scan
  const [branches, setBranches] = useState<string[]>([]);  // Available branches
  const [defaultBranch, setDefaultBranch] = useState("");  // Repo's default branch
  const [branchesLoading, setBranchesLoading] = useState(false);
  const [prBranchName, setPrBranchName] = useState("");  // Custom PR branch name
  const [skillPrompt, setSkillPrompt] = useState("");  // Per-scan AI instructions
  const [showAdvanced, setShowAdvanced] = useState(false);  // Toggle advanced options

  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [copied, setCopied] = useState(false);

  // Review panel state (for scan-fix-preview mode)
  const [showReview, setShowReview] = useState(false);
  const [previewFiles, setPreviewFiles] = useState<any[]>([]);
  const [applyingFixes, setApplyingFixes] = useState(false);

  // Terminal / WebSocket state
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [showTerminal, setShowTerminal] = useState(false);
  const [currentPhase, setCurrentPhase] = useState("");
  const [missingSDKs, setMissingSDKs] = useState<any[]>([]);
  const [showInstallPrompt, setShowInstallPrompt] = useState(false);
  const [reportView, setReportView] = useState<"report" | "json">("report");
  const terminalRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const loadingRef = useRef(false);

  // Prerequisites state
  const [prereqsReady, setPrereqsReady] = useState(false);
  const [prereqsLoading, setPrereqsLoading] = useState(true);
  const [prereqStatus, setPrereqStatus] = useState<any>(null);

  useEffect(() => {
    loadingRef.current = loading;
  }, [loading]);

  useEffect(() => {
    setMounted(true);
    // Set API key header for all axios requests
    if (API_KEY) {
      axios.defaults.headers.common["X-API-Key"] = API_KEY;
    }
    // Check prerequisites on load
    checkPrerequisites();
  }, []);

  const checkPrerequisites = async () => {
    setPrereqsLoading(true);
    try {
      const res = await axios.get(`${API_URL}/health/prerequisites`);
      setPrereqStatus(res.data);
      // Ready if git + sast scanner are installed
      const gitOk = res.data?.git?.installed;
      const sastOk = res.data?.sast_scanner?.installed;
      setPrereqsReady(gitOk && sastOk);
    } catch {
      // Backend not running — disable scan buttons
      setPrereqsReady(false);
      setPrereqStatus(null);
    } finally {
      setPrereqsLoading(false);
    }
  };

  useEffect(() => {
    const savedHistory = sessionStorage.getItem("scanHistory");
    if (savedHistory) {
      setScanHistory(JSON.parse(savedHistory));
    }
  }, []);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  // Auto-detect branch from URL and fetch available branches
  useEffect(() => {
    if (!url) {
      setBranches([]);
      setDefaultBranch("");
      return;
    }

    // Extract branch from /tree/branch-name URLs
    const treeMatch = url.match(/github\.com\/[^/]+\/[^/]+\/tree\/([^/?#]+)/);
    if (treeMatch) {
      setBranch(treeMatch[1]);
      const cleanUrl = url.replace(/\/tree\/[^/?#]+/, "");
      setUrl(cleanUrl);
      setShowAdvanced(true);
      return; // Will re-trigger with clean URL
    }

    // Only fetch branches for valid GitHub URLs
    if (!url.startsWith("https://github.com/") || url.split("/").filter(Boolean).length < 4) {
      return;
    }

    // Debounce: fetch branches after user stops typing
    const timer = setTimeout(() => {
      fetchBranches(url);
    }, 800);

    return () => clearTimeout(timer);
  }, [url]);

  const fetchBranches = async (repoUrl: string) => {
    setBranchesLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/branches`, { github_url: repoUrl });
      setBranches(res.data.branches || []);
      setDefaultBranch(res.data.default_branch || "");
      // Pre-select default branch if none selected
      if (!branch) {
        setBranch(res.data.default_branch || "");
      }
    } catch {
      // Token might not be set or repo doesn't exist — just clear
      setBranches([]);
      setDefaultBranch("");
    } finally {
      setBranchesLoading(false);
    }
  };

  const addLog = useCallback((entry: LogEntry) => {
    const timestamped = { ...entry, timestamp: new Date().toLocaleTimeString() };
    setLogs((prev) => [...prev, timestamped]);
  }, []);

  // WebSocket-based scan
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
    setShowReview(false);
    setPreviewFiles([]);
    setLogs([]);
    setShowTerminal(true);
    setCurrentPhase("Connecting...");
    setMissingSDKs([]);
    setShowInstallPrompt(false);

    // For "Scan & Fix" mode — always use HTTP with preview (review before PR)
    if (scanMode === "scan-fix") {
      runScanFixPreview();
      return;
    }

    // For "Scan Only" mode — use WebSocket for real-time progress
    const wsUrl = `${WS_URL}/ws/scan`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        addLog({ type: "log", message: "Connected to server", level: "info" });
        ws.send(JSON.stringify({
          github_url: url,
          mode: "scan-only",
          branch,
        }));
      };

      ws.onmessage = (event) => {
        try {
          const msg: LogEntry = JSON.parse(event.data);
          addLog(msg);

          switch (msg.type) {
            case "phase":
              setCurrentPhase(msg.message);
              break;
            case "install":
              // Installation progress
              break;
            case "missing_sdk":
              if (msg.data?.missing) {
                setMissingSDKs(msg.data.missing);
                setShowInstallPrompt(true);
              }
              break;
            case "result":
              setResult(msg.data);
              setLoading(false);
              setCurrentPhase("Complete");
              // Save to history
              if (msg.data) {
                const historyEntry = {
                  url,
                  mode: scanMode,
                  timestamp: new Date().toISOString(),
                  result: trimResultForHistory(msg.data),
                };
                setScanHistory((prev) => {
                  const updated = [historyEntry, ...prev].slice(0, 10);
                  saveHistoryToStorage(updated);
                  return updated;
                });
              }
              break;
            case "error":
              setErrorMessage(msg.message);
              setShowError(true);
              break;
          }
        } catch (e) {
          addLog({ type: "log", message: event.data, level: "info" });
        }
      };

      ws.onerror = () => {
        addLog({ type: "error", message: "WebSocket connection failed. Falling back to HTTP..." });
        ws.close();
        runScanHTTP();
      };

      ws.onclose = () => {
        if (loadingRef.current) {
          setLoading(false);
        }
      };
    } catch {
      // Fallback to HTTP if WebSocket fails
      runScanHTTP();
    }
  }

  // Scan & Fix with Preview (starts background task, polls for progress)
  async function runScanFixPreview() {
    addLog({ type: "phase", message: "Starting scan & fix..." });
    setCurrentPhase("Starting...");

    try {
      // Start the background task
      const res = await axios.post(`${API_BASE}/scan-fix-preview`, {
        github_url: url,
        branch,
        skill_prompt: skillPrompt,
      });

      const taskId = res.data.task_id;
      if (!taskId) {
        // Fallback: result returned directly (shouldn't happen with new API)
        setResult(res.data);
        setLoading(false);
        return;
      }

      addLog({ type: "log", message: `Task started: ${taskId}`, level: "info" });

      // Poll for progress
      let completed = false;
      while (!completed) {
        await new Promise((resolve) => setTimeout(resolve, 1000)); // Poll every 1s

        try {
          const progressRes = await axios.get(`${API_BASE}/progress/${taskId}`);
          const progress = progressRes.data;

          if (progress.phase) {
            setCurrentPhase(progress.phase);
          }

          // Show new log messages
          if (progress.logs && progress.logs.length > 0) {
            const lastLog = progress.logs[progress.logs.length - 1];
            if (lastLog.message) {
              addLog({ type: "log", message: lastLog.message, level: "info" });
            }
          }

          // Check if complete
          if (progress.status === "complete" || progress.status === "error") {
            completed = true;

            if (progress.result) {
              setResult(progress.result);

              // Show review panel if fixes were generated
              if (progress.result.status === "preview_ready" && progress.result.preview_files?.length > 0) {
                setPreviewFiles(progress.result.preview_files);
                setShowReview(true);
                setShowTerminal(false);
                addLog({ type: "phase", message: "Fixes ready for review!" });
              } else {
                addLog({ type: "phase", message: progress.result.message || "Complete" });
              }

              // Save to history
              setScanHistory((prev) => {
                const historyEntry = {
                  url,
                  mode: scanMode,
                  timestamp: new Date().toISOString(),
                  result: trimResultForHistory(progress.result),
                };
                const updated = [historyEntry, ...prev].slice(0, 10);
                saveHistoryToStorage(updated);
                return updated;
              });
            }

            if (progress.status === "error") {
              setErrorMessage(progress.result?.message || "Scan failed");
              setShowError(true);
            }
          }
        } catch {
          // Polling failed — might be network issue, keep trying
        }
      }
    } catch (error: any) {
      const msg = error.response?.data?.message || error.response?.data?.detail || error.message || "Failed to start scan";
      setErrorMessage(msg);
      setShowError(true);
      addLog({ type: "error", message: msg });
    } finally {
      setLoading(false);
    }
  }

  // HTTP fallback (for scan-only when WebSocket fails)
  async function runScanHTTP() {
    setShowTerminal(true);
    addLog({ type: "log", message: "Using HTTP fallback mode", level: "info" });
    setCurrentPhase("Scanning (HTTP mode)...");

    try {
      const res = await axios.post(`${API_BASE}/scan-only`, {
        github_url: url,
        branch,
      });
      setResult(res.data);
      addLog({ type: "phase", message: "Scan complete!" });
      setCurrentPhase("Complete");

      const historyEntry = {
        url,
        mode: scanMode,
        timestamp: new Date().toISOString(),
        result: trimResultForHistory(res.data),
      };
      setScanHistory((prev) => {
        const updatedHistory = [historyEntry, ...prev].slice(0, 10);
        saveHistoryToStorage(updatedHistory);
        return updatedHistory;
      });
    } catch (error: any) {
      const msg = error.response?.data?.message || error.response?.data?.detail || error.message || "Failed to scan";
      setErrorMessage(msg);
      setShowError(true);
      addLog({ type: "error", message: msg });
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
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
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
        `${API_BASE}/report/pdf`,
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

  const downloadSARIF = async () => {
    if (!result) return;
    try {
      const res = await axios.post(
        `${API_BASE}/export/sarif`,
        { scan_data: result },
        { responseType: "blob" }
      );
      const blob = new Blob([res.data], { type: "application/json" });
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      const repoName = url.split("/").pop() || "repository";
      a.download = `${repoName}-scan.sarif`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadUrl);
    } catch (error) {
      console.error("SARIF export failed:", error);
    }
  };

  const downloadCSV = async () => {
    if (!result) return;
    try {
      const res = await axios.post(
        `${API_BASE}/export/csv`,
        { scan_data: result },
        { responseType: "blob" }
      );
      const blob = new Blob([res.data], { type: "text/csv" });
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      const repoName = url.split("/").pop() || "repository";
      a.download = `vulnerability-report-${repoName}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadUrl);
    } catch (error) {
      console.error("CSV export failed:", error);
    }
  };

  const loadFromHistory = (entry: any) => {
    setUrl(entry.url);
    setScanMode(entry.mode || "scan-only");
    setResult(entry.result);
    setShowHistory(false);
    setShowTerminal(false);
  };

  const clearHistory = async () => {
    // Clear from backend
    try {
      await axios.delete(`${API_BASE}/history`);
    } catch {
      // Backend might not have history yet, that's fine
    }
    // Clear local
    setScanHistory([]);
    sessionStorage.removeItem("scanHistory");
    setShowHistory(false);
  };

  const suppressFinding = async (ruleId: string, path: string) => {
    try {
      await axios.post(`${API_BASE}/baseline/suppress`, {
        rule_id: ruleId,
        path: path || "",
        reason: "accepted_risk",
      });
      // Remove from current results display
      if (result?.findings) {
        const updated = {
          ...result,
          findings: result.findings.filter((f: any) => !(f.rule_id === ruleId && f.path === path)),
          suppressed_count: (result.suppressed_count || 0) + 1,
        };
        updated.total_findings = updated.findings.length;
        setResult(updated);
      }
    } catch {
      // silently fail
    }
  };

  const handleApplyFixes = async (approvedFiles: Array<{ path: string; fixed_code: string }>) => {
    console.log("[handleApplyFixes] Received approved files:", approvedFiles.map(f => f.path));
    console.log("[handleApplyFixes] Total files:", approvedFiles.length);
    setApplyingFixes(true);
    try {
      const res = await axios.post(`${API_BASE}/apply-fixes`, {
        github_url: url,
        branch,
        pr_branch_name: prBranchName,
        approved_files: approvedFiles,
      });

      // Map the response to match what the UI expects
      const resultData = {
        ...res.data,
        // Map pr_url → pull_request (what the UI renders)
        pull_request: res.data.pr_url || res.data.pull_request || null,
        repo: url,
        total_findings: result?.total_findings || 0,
        fixable_findings: result?.fixable_findings || 0,
        scan_summary: result?.scan_summary || {},
        findings_breakdown: result?.findings_breakdown || {},
        project_info: result?.project_info || {},
        files_fixed: approvedFiles.map((f) => ({
          path: f.path,
          findings_fixed: 1,
          confidence: -1,
        })),
      };

      setResult(resultData);
      setShowReview(false);
      setPreviewFiles([]);
      setShowTerminal(false);

      if (res.data.status === "success") {
        addLog({ type: "phase", message: `✓ PR created with ${res.data.files_count || approvedFiles.length} approved fixes!` });
        // Warn if any files were skipped by the safety check
        if (res.data.skipped_files && res.data.skipped_files.length > 0) {
          const skippedPaths = res.data.skipped_files.map((f: any) => f.path).join(", ");
          addLog({ type: "log", message: `⚠️ ${res.data.skipped_files.length} file(s) skipped by secret safety check: ${skippedPaths}`, level: "warning" });
        }
        setCurrentPhase("PR Created");
      } else {
        setErrorMessage(res.data.message || "Failed to apply fixes");
        setShowError(true);
      }
    } catch (error: any) {
      const msg = error.response?.data?.message || error.response?.data?.detail || error.message || "Failed to apply fixes";
      setErrorMessage(msg);
      setShowError(true);
    } finally {
      setApplyingFixes(false);
    }
  };

  const sampleRepos = [
    { name: "Django Vulnerable App", url: "https://github.com/nVisium/django.nV", type: "Python" },
    { name: "WebGoat Legacy (Java)", url: "https://github.com/WebGoat/WebGoat-Legacy", type: "Java" },
    { name: "NodeGoat (Node.js)", url: "https://github.com/OWASP/NodeGoat", type: "JavaScript" },
    { name: "FastAPI (Clean)", url: "https://github.com/tiangolo/fastapi", type: "Python" },
  ];

  const severityColor = (severity: string) => {
    const s = severity?.toUpperCase();
    if (s === "CRITICAL") return "bg-red-600 text-white";
    if (s === "HIGH" || s === "ERROR") return "bg-orange-600 text-white";
    if (s === "MEDIUM" || s === "WARNING" || s === "MODERATE") return "bg-yellow-500 text-black";
    return "bg-blue-500 text-white";
  };

  const getLogColor = (entry: LogEntry) => {
    if (entry.type === "error") return "text-red-400";
    if (entry.type === "phase") return "text-cyan-400 font-semibold";
    if (entry.type === "install") return "text-yellow-400";
    if (entry.type === "missing_sdk") return "text-orange-400";
    if (entry.level === "warning") return "text-yellow-400";
    if (entry.level === "error") return "text-red-400";
    return "text-green-400";
  };

  const getLogPrefix = (entry: LogEntry) => {
    if (entry.type === "phase") return "▶";
    if (entry.type === "install") return "📦";
    if (entry.type === "error") return "✗";
    if (entry.type === "missing_sdk") return "⚠";
    if (entry.type === "sdk_check") return "🔍";
    return "›";
  };

  const ratingColor = (rating: string) => {
    switch (rating) {
      case "A": return "text-green-600";
      case "B": return "text-blue-600";
      case "C": return "text-yellow-600";
      case "D": return "text-orange-600";
      case "E": case "F": return "text-red-600";
      default: return "text-muted-foreground";
    }
  };

  // Render findings summary
  const renderSummary = () => {
    if (!result) return null;
    const summary = result.scan_summary;
    const findings = result.findings || [];
    const total = result.total_findings ?? findings.length;

    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          {result.status === "clean" ? (
            <Badge className="bg-green-600 text-white px-3 py-1"><ShieldCheck className="h-3 w-3 mr-1" /> Clean</Badge>
          ) : result.status === "success" ? (
            <Badge className="bg-blue-600 text-white px-3 py-1"><Wrench className="h-3 w-3 mr-1" /> Fix Applied</Badge>
          ) : result.status === "error" ? (
            <Badge className="bg-red-600 text-white px-3 py-1"><XCircle className="h-3 w-3 mr-1" /> Error</Badge>
          ) : (
            <Badge className="bg-orange-600 text-white px-3 py-1"><ShieldAlert className="h-3 w-3 mr-1" /> Vulnerabilities Found</Badge>
          )}
          <span className="text-sm text-muted-foreground">{total} finding{total !== 1 ? "s" : ""}</span>
        </div>

        {summary && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {Object.entries(summary.by_severity || {}).map(([sev, count]) => (
              <div key={sev} className="rounded-lg border p-3 text-center">
                <Badge className={`${severityColor(sev)} text-xs`}>{sev}</Badge>
                <p className="text-2xl font-bold mt-1">{count as number}</p>
              </div>
            ))}
          </div>
        )}

        {summary?.by_scanner && (
          <div className="rounded-lg border p-3">
            <p className="text-xs font-semibold text-muted-foreground mb-2">Scanner Breakdown</p>
            <div className="flex flex-wrap gap-2">
              {Object.entries(summary.by_scanner).map(([scanner, count]) => (
                <Badge key={scanner} variant="outline" className="text-xs">{scanner}: {count as number}</Badge>
              ))}
            </div>
          </div>
        )}

        {result.project_info && (
          <div className="rounded-lg border p-3 space-y-2">
            <p className="text-xs font-semibold text-muted-foreground">Project Detection</p>
            <div className="flex flex-wrap gap-2">
              {result.project_info.languages?.map((lang: string) => (
                <Badge key={lang} className="bg-violet-600 text-white text-xs">{lang}</Badge>
              ))}
              {result.project_info.frameworks?.map((fw: string) => (
                <Badge key={fw} variant="outline" className="text-xs">{fw}</Badge>
              ))}
            </div>
          </div>
        )}

        {/* Code Quality Dashboard */}
        {result.code_quality?.metrics && (
          <div className="space-y-3">
            {/* Quality Gate Banner */}
            <div className={`rounded-lg p-4 border ${
              result.code_quality.quality_gate_details?.passed
                ? "bg-green-50 dark:bg-green-950/20 border-green-200 dark:border-green-800"
                : "bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-800"
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {result.code_quality.quality_gate_details?.passed ? (
                    <CheckCircle2 className="h-5 w-5 text-green-600" />
                  ) : (
                    <XCircle className="h-5 w-5 text-red-600" />
                  )}
                  <div>
                    <p className="font-semibold text-sm">Quality Gate</p>
                    <p className="text-xs text-muted-foreground">
                      {result.code_quality.quality_gate_details?.passed ? "All conditions met" : "Some conditions failed"}
                    </p>
                  </div>
                </div>
                <Badge className={`text-sm px-3 py-1 ${
                  result.code_quality.quality_gate_details?.passed
                    ? "bg-green-600 text-white"
                    : "bg-red-600 text-white"
                }`}>
                  {result.code_quality.quality_gate_details?.passed ? "PASSED" : "FAILED"}
                </Badge>
              </div>

              {/* Gate Conditions */}
              {result.code_quality.quality_gate_details?.conditions && (
                <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {result.code_quality.quality_gate_details.conditions.map((cond: any, idx: number) => (
                    <div key={idx} className="flex items-center gap-2 text-xs">
                      <span className={cond.status === "PASSED" ? "text-green-600" : cond.status === "WARNING" ? "text-yellow-600" : "text-red-600"}>
                        {cond.status === "PASSED" ? "✓" : cond.status === "WARNING" ? "⚠" : "✗"}
                      </span>
                      <span className="text-muted-foreground">{cond.metric.replace(/_/g, " ")}</span>
                      <span className="font-mono">{typeof cond.actual === "number" ? cond.actual.toFixed(1) : cond.actual}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              {/* Maintainability */}
              <div className="rounded-lg border p-3 text-center">
                <p className="text-xs text-muted-foreground mb-1">Maintainability</p>
                <p className={`text-2xl font-bold ${ratingColor(result.code_quality.metrics.complexity?.maintainability_rating)}`}>
                  {result.code_quality.metrics.complexity?.maintainability_rating || "—"}
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  Index: {result.code_quality.metrics.complexity?.maintainability_index?.toFixed(0)}
                </p>
              </div>

              {/* Duplication */}
              <div className="rounded-lg border p-3 text-center">
                <p className="text-xs text-muted-foreground mb-1">Duplication</p>
                <p className={`text-2xl font-bold ${ratingColor(result.code_quality.metrics.duplication?.rating)}`}>
                  {result.code_quality.metrics.duplication?.rating || "—"}
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  {result.code_quality.metrics.duplication?.duplication_percentage?.toFixed(1)}%
                </p>
              </div>

              {/* Technical Debt */}
              <div className="rounded-lg border p-3 text-center">
                <p className="text-xs text-muted-foreground mb-1">Tech Debt</p>
                <p className={`text-2xl font-bold ${ratingColor(result.code_quality.metrics.technical_debt?.rating)}`}>
                  {result.code_quality.metrics.technical_debt?.rating || "—"}
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  {result.code_quality.metrics.technical_debt?.total_hours?.toFixed(1)}h
                </p>
              </div>

              {/* Code Smells */}
              <div className="rounded-lg border p-3 text-center">
                <p className="text-xs text-muted-foreground mb-1">Code Smells</p>
                <p className="text-2xl font-bold text-orange-600">
                  {result.code_quality.code_smells?.total || 0}
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  issues found
                </p>
              </div>
            </div>

            {/* LOC & Complexity Summary */}
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-lg border p-3">
                <p className="text-xs font-semibold text-muted-foreground mb-2">Lines of Code</p>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Code</span>
                    <span className="font-mono">{result.code_quality.metrics.lines_of_code?.code_lines?.toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Comments</span>
                    <span className="font-mono">{result.code_quality.metrics.lines_of_code?.comment_lines?.toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Comment %</span>
                    <span className="font-mono">{result.code_quality.metrics.lines_of_code?.comment_ratio}%</span>
                  </div>
                </div>
              </div>

              <div className="rounded-lg border p-3">
                <p className="text-xs font-semibold text-muted-foreground mb-2">Complexity</p>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Average</span>
                    <span className="font-mono">{result.code_quality.metrics.complexity?.average_complexity?.toFixed(1)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Max</span>
                    <span className="font-mono">{result.code_quality.metrics.complexity?.max_complexity}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Complex files</span>
                    <span className="font-mono">{result.code_quality.metrics.complexity?.files_above_threshold}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Languages Breakdown */}
            {result.code_quality.metrics.lines_of_code?.languages && Object.keys(result.code_quality.metrics.lines_of_code.languages).length > 0 && (
              <div className="rounded-lg border p-3">
                <p className="text-xs font-semibold text-muted-foreground mb-2">Language Distribution</p>
                <div className="space-y-2">
                  {Object.entries(result.code_quality.metrics.lines_of_code.languages)
                    .sort(([, a]: any, [, b]: any) => b - a)
                    .map(([lang, lines]: [string, any]) => {
                      const total = result.code_quality.metrics.lines_of_code.code_lines || 1;
                      const pct = ((lines / total) * 100).toFixed(1);
                      return (
                        <div key={lang} className="space-y-1">
                          <div className="flex justify-between text-xs">
                            <span>{lang}</span>
                            <span className="text-muted-foreground">{lines.toLocaleString()} lines ({pct}%)</span>
                          </div>
                          <div className="h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-violet-500 rounded-full"
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                </div>
              </div>
            )}

            {/* Top Code Smells */}
            {result.code_quality.code_smells?.items?.length > 0 && (
              <div className="rounded-lg border p-3">
                <p className="text-xs font-semibold text-muted-foreground mb-2">
                  Code Smells ({result.code_quality.code_smells.total})
                </p>
                <div className="max-h-48 overflow-y-auto space-y-2">
                  {result.code_quality.code_smells.items.slice(0, 10).map((smell: any, idx: number) => (
                    <div key={idx} className="flex items-start gap-2 text-xs">
                      <Badge className={`text-[10px] px-1.5 ${
                        smell.severity === "MAJOR" ? "bg-orange-500 text-white" :
                        smell.severity === "CRITICAL" ? "bg-red-600 text-white" :
                        "bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300"
                      }`}>
                        {smell.severity}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <p className="truncate text-muted-foreground">{smell.path}</p>
                        <p className="text-foreground">{smell.message}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {result.pull_request && (
          <div className="rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
            {/* Report Header */}
            <div className="bg-slate-800 dark:bg-slate-900 text-white px-5 py-4">
              <h2 className="text-base font-bold tracking-wide">VULNERABILITY SCAN REPORT</h2>
              <p className="text-[10px] text-slate-300 mt-0.5">AI Vulnerability Remediator • Automated Security Analysis</p>
            </div>

            {/* Executive Summary */}
            <div className="px-5 py-4 border-b">
              <h3 className="text-xs font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider mb-3 border-b-2 border-blue-600 pb-1 inline-block">Executive Summary</h3>
              <div className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-xs">
                <span className="font-semibold text-slate-700 dark:text-slate-300">Target Repository:</span>
                <span className="font-mono text-slate-600 dark:text-slate-400">{result.repo || ""}</span>
                <span className="font-semibold text-slate-700 dark:text-slate-300">Scan Status:</span>
                <span className="font-semibold text-green-600">SUCCESS</span>
                <span className="font-semibold text-slate-700 dark:text-slate-300">Total Vulnerabilities:</span>
                <span className="font-bold">{result.total_findings || 0}</span>
                {result.project_info?.languages && (
                  <>
                    <span className="font-semibold text-slate-700 dark:text-slate-300">Languages Detected:</span>
                    <span>{result.project_info.languages.join(", ")}</span>
                  </>
                )}
                {result.project_info?.frameworks && result.project_info.frameworks.length > 0 && (
                  <>
                    <span className="font-semibold text-slate-700 dark:text-slate-300">Frameworks:</span>
                    <span>{result.project_info.frameworks.join(", ")}</span>
                  </>
                )}
              </div>
            </div>

            {/* Risk Overview Table */}
            {result.scan_summary?.by_severity && Object.keys(result.scan_summary.by_severity).length > 0 && (
              <div className="px-5 py-4 border-b">
                <h3 className="text-xs font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider mb-3 border-b-2 border-blue-600 pb-1 inline-block">Risk Overview</h3>
                <div className="border rounded overflow-hidden text-xs">
                  {/* Table Header */}
                  <div className="grid grid-cols-3 bg-slate-100 dark:bg-slate-800 font-bold text-slate-700 dark:text-slate-300">
                    <div className="px-3 py-2 border-r border-slate-200 dark:border-slate-700">SEVERITY</div>
                    <div className="px-3 py-2 border-r border-slate-200 dark:border-slate-700 text-center">COUNT</div>
                    <div className="px-3 py-2 text-center">RISK LEVEL</div>
                  </div>
                  {/* Table Rows */}
                  {[
                    { key: "CRITICAL", color: "bg-red-600", label: "Immediate action required" },
                    { key: "HIGH", color: "bg-orange-500", label: "High priority fix needed" },
                    { key: "ERROR", color: "bg-orange-400", label: "High priority fix needed" },
                    { key: "MEDIUM", color: "bg-yellow-500", label: "Should be addressed" },
                    { key: "WARNING", color: "bg-yellow-400", label: "Should be addressed" },
                    { key: "MODERATE", color: "bg-yellow-400", label: "Should be addressed" },
                    { key: "LOW", color: "bg-green-500", label: "Low priority" },
                    { key: "INFO", color: "bg-blue-400", label: "Informational" },
                  ]
                    .filter(({ key }) => (result.scan_summary.by_severity[key] || 0) > 0)
                    .map(({ key, color, label }) => (
                      <div key={key} className="grid grid-cols-3 border-t border-slate-200 dark:border-slate-700">
                        <div className="px-3 py-2 border-r border-slate-200 dark:border-slate-700 flex items-center gap-2">
                          <span className={`w-3 h-3 rounded-sm ${color}`} />
                          <span className="font-bold">{key}</span>
                        </div>
                        <div className="px-3 py-2 border-r border-slate-200 dark:border-slate-700 text-center font-mono font-bold">
                          {result.scan_summary.by_severity[key] || 0}
                        </div>
                        <div className="px-3 py-2 text-center text-muted-foreground">{label}</div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Scanner Coverage */}
            {result.scan_summary?.by_scanner && Object.keys(result.scan_summary.by_scanner).length > 0 && (
              <div className="px-5 py-4 border-b">
                <h3 className="text-xs font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider mb-3 border-b-2 border-blue-600 pb-1 inline-block">Scanner Coverage</h3>
                <div className="space-y-1.5 text-xs pl-4">
                  {Object.entries(result.scan_summary.by_scanner)
                    .sort(([, a]: any, [, b]: any) => b - a)
                    .map(([scanner, count]: [string, any]) => (
                      <div key={scanner} className="text-slate-700 dark:text-slate-300">
                        {scanner}: <span className="font-bold">{count}</span> finding(s)
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Remediation Applied */}
            {result.files_fixed && result.files_fixed.length > 0 && (
              <div className="px-5 py-4 border-b">
                <h3 className="text-xs font-bold text-slate-800 dark:text-slate-200 uppercase tracking-wider mb-3 border-b-2 border-green-600 pb-1 inline-block">Remediation Applied</h3>

                {/* PR Info */}
                <div className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-xs mb-4">
                  <span className="font-semibold text-slate-700 dark:text-slate-300">Pull Request:</span>
                  <a href={result.pull_request} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline font-mono truncate">
                    {result.pull_request}
                  </a>
                  <span className="font-semibold text-slate-700 dark:text-slate-300">Files Modified:</span>
                  <span className="font-bold">{result.files_fixed.length}</span>
                  <span className="font-semibold text-slate-700 dark:text-slate-300">Total Issues Resolved:</span>
                  <span className="font-bold">{result.files_fixed.reduce((sum: number, f: any) => sum + (f.findings_fixed || 1), 0)}</span>
                </div>

                {/* Fixed Files Table */}
                <div className="border rounded overflow-hidden text-xs">
                  {/* Table Header */}
                  <div className="grid grid-cols-[2rem_1fr_auto_1fr] bg-slate-800 dark:bg-slate-900 text-white font-bold">
                    <div className="px-2 py-2 text-center">#</div>
                    <div className="px-3 py-2">Issue Found</div>
                    <div className="px-3 py-2 text-center">Status</div>
                    <div className="px-3 py-2">File</div>
                  </div>
                  {/* Table Rows */}
                  {result.files_fixed.map((f: any, idx: number) => (
                    <div key={idx} className={`grid grid-cols-[2rem_1fr_auto_1fr] border-t border-slate-200 dark:border-slate-700 ${
                      idx % 2 === 0 ? "bg-white dark:bg-slate-900" : "bg-slate-50 dark:bg-slate-800/50"
                    }`}>
                      <div className="px-2 py-2 text-center text-muted-foreground">{idx + 1}</div>
                      <div className="px-3 py-2">{f.findings_fixed || 1} vulnerability(s)</div>
                      <div className="px-3 py-2 text-center">
                        <span className="text-green-600 dark:text-green-400 italic text-[11px]">Fixed by AI Remediator</span>
                      </div>
                      <div className="px-3 py-2 font-mono text-muted-foreground truncate">{f.path}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Skipped Files */}
            {result.skipped_files && result.skipped_files.length > 0 && (
              <div className="px-5 py-4 border-b">
                <h3 className="text-xs font-bold text-orange-700 dark:text-orange-400 uppercase tracking-wider mb-2">⚠️ Skipped Files ({result.skipped_files.length})</h3>
                <div className="space-y-1 text-xs pl-4">
                  {result.skipped_files.map((f: any, idx: number) => (
                    <div key={idx} className="text-muted-foreground">
                      <span className="font-mono">{f.path}</span> — <span className="text-orange-600 dark:text-orange-400">{f.reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Build & Test Validation */}
            {result.validation && result.validation.steps && result.validation.steps.length > 0 && (
              <div className="px-5 py-4 border-b">
                <h3 className={`text-xs font-bold uppercase tracking-wider mb-3 border-b-2 pb-1 inline-block ${
                  result.validation.success
                    ? "text-green-800 dark:text-green-200 border-green-600"
                    : "text-orange-800 dark:text-orange-200 border-orange-600"
                }`}>
                  Build & Test Validation
                </h3>
                <div className="border rounded overflow-hidden text-xs">
                  {/* Table Header */}
                  <div className="grid grid-cols-[1fr_auto_1fr] bg-slate-100 dark:bg-slate-800 font-bold text-slate-700 dark:text-slate-300">
                    <div className="px-3 py-2 border-r border-slate-200 dark:border-slate-700">Step</div>
                    <div className="px-3 py-2 border-r border-slate-200 dark:border-slate-700 text-center w-20">Status</div>
                    <div className="px-3 py-2">Details</div>
                  </div>
                  {result.validation.steps.map((step: any, idx: number) => (
                    <div key={idx} className={`grid grid-cols-[1fr_auto_1fr] border-t border-slate-200 dark:border-slate-700 ${
                      idx % 2 === 0 ? "bg-white dark:bg-slate-900" : "bg-slate-50 dark:bg-slate-800/50"
                    }`}>
                      <div className="px-3 py-2 font-mono border-r border-slate-200 dark:border-slate-700">{step.name}</div>
                      <div className="px-3 py-2 text-center w-20 border-r border-slate-200 dark:border-slate-700">
                        {step.status === "pass" ? (
                          <span className="text-green-600 font-bold">✓ PASS</span>
                        ) : step.status === "fail" ? (
                          <span className="text-red-600 font-bold">✗ FAIL</span>
                        ) : (
                          <span className="text-slate-400">— SKIP</span>
                        )}
                      </div>
                      <div className="px-3 py-2 text-muted-foreground truncate" title={step.output}>
                        {step.status === "fail" ? step.output?.slice(0, 80) : step.status === "skipped" ? step.output?.slice(0, 60) : ""}
                      </div>
                    </div>
                  ))}
                </div>
                {result.validation.success ? (
                  <p className="text-[11px] text-green-600 dark:text-green-400 mt-2 font-medium">✓ All validation steps passed</p>
                ) : (
                  <p className="text-[11px] text-orange-600 dark:text-orange-400 mt-2 font-medium">⚠️ Some steps failed — review PR carefully before merging</p>
                )}
              </div>
            )}

            {/* Footer — View PR */}
            <div className="px-5 py-3 bg-slate-50 dark:bg-slate-800/50 flex items-center justify-between">
              <p className="text-[10px] text-muted-foreground">
                Generated by AI Vulnerability Remediator
              </p>
              <a
                href={result.pull_request}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
              >
                <GitBranchIcon className="h-3 w-3" />
                View PR on GitHub
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </div>
        )}

        {findings.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-semibold text-muted-foreground">Top Findings</p>
            <div className="max-h-80 overflow-y-auto space-y-2">
              {findings.slice(0, 20).map((f: any, idx: number) => (
                <div key={idx} className="rounded-lg border p-3 text-sm space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge className={`${severityColor(f.adjusted_severity || f.severity)} text-xs`}>
                      {f.adjusted_severity || f.severity}
                    </Badge>
                    {f.risk_score !== undefined && (
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        f.risk_score >= 80 ? "bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300" :
                        f.risk_score >= 60 ? "bg-orange-100 dark:bg-orange-950 text-orange-700 dark:text-orange-300" :
                        "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400"
                      }`}>
                        Risk: {f.risk_score}
                      </span>
                    )}
                    <span className="font-mono text-xs text-muted-foreground">{f.rule_id}</span>
                    {f.metadata?.category && (
                      <Badge variant="outline" className={`text-xs ${
                        f.metadata.category === "secret" ? "border-red-500 text-red-600 dark:text-red-400" : ""
                      }`}>
                        {f.metadata.category === "secret" ? "🔑 " : ""}{f.metadata.category}
                      </Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground">{f.path}{f.line ? `:${f.line}` : ""}</p>
                  <p className="text-xs">{f.message?.slice(0, 200)}</p>
                  {f.risk_factors && f.risk_factors.length > 0 && f.risk_factors[0] !== "Standard risk level" && (
                    <div className="flex flex-wrap gap-1 mt-1">
                      {f.risk_factors.map((factor: string, fi: number) => (
                        <span key={fi} className="text-[10px] px-1.5 py-0.5 rounded bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
                          {factor}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Secrets Summary (if any found) */}
        {findings.filter((f: any) => f.metadata?.category === "secret").length > 0 && (
          <div className="rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/20 p-3 space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-sm">🔑</span>
              <p className="text-xs font-semibold text-red-700 dark:text-red-300">
                Secrets Detected ({findings.filter((f: any) => f.metadata?.category === "secret").length})
              </p>
            </div>
            <div className="space-y-1 max-h-32 overflow-y-auto">
              {findings.filter((f: any) => f.metadata?.category === "secret").slice(0, 5).map((f: any, idx: number) => (
                <div key={idx} className="text-xs flex items-center gap-2">
                  <Badge className="bg-red-600 text-white text-[10px]">SECRET</Badge>
                  <span className="text-muted-foreground truncate">{f.path}:{f.line}</span>
                  <span className="truncate">{f.metadata?.secret_type}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Diff Summary (for scan-fix results) */}
        {result.files_fixed && result.files_fixed.length > 0 && (
          <div className="rounded-lg border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-950/20 p-3 space-y-3">
            <p className="text-xs font-semibold text-green-700 dark:text-green-300">
              ✅ Issues Fixed by AI Vulnerability Remediator
            </p>

            {/* Fix details list */}
            {result.files_fixed.some((f: any) => f.fix_details?.length > 0) && (
              <div className="space-y-1.5 max-h-40 overflow-y-auto">
                {result.files_fixed.flatMap((f: any) =>
                  (f.fix_details || []).map((detail: any, dIdx: number) => (
                    <div key={`${f.path}-${dIdx}`} className="flex items-start gap-2 text-xs">
                      <span className="text-green-600 flex-shrink-0 mt-0.5">✓</span>
                      <div className="flex-1 min-w-0">
                        <p className="text-foreground truncate">{detail.issue}</p>
                        <p className="text-green-600 text-[10px]">Fixed in {f.path}</p>
                      </div>
                    </div>
                  ))
                ).slice(0, 15)}
              </div>
            )}

            {/* File summary with confidence */}
            <div className="space-y-1.5 pt-2 border-t border-green-200 dark:border-green-800">
              {result.files_fixed.map((f: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between text-xs">
                  <span className="font-mono text-muted-foreground truncate">{f.path}</span>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-muted-foreground">{f.findings_fixed} fixed</span>
                    {f.confidence >= 0 && (
                      <Badge className={`text-[10px] px-1.5 ${
                        f.confidence >= 90 ? "bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-300" :
                        f.confidence >= 70 ? "bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-300" :
                        "bg-yellow-100 text-yellow-700 dark:bg-yellow-950 dark:text-yellow-300"
                      }`}>
                        {f.confidence}%
                      </Badge>
                    )}
                    {f.diff && (
                      <span className="text-[10px] text-muted-foreground">+{f.diff.additions} -{f.diff.deletions}</span>
                    )}
                  </div>
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
              <h1 className="font-bold text-lg lg:text-xl leading-tight">Enterprise</h1>
              <p className="text-xs lg:text-sm text-slate-300">AI Security Platform</p>
            </div>
            <Button size="icon" variant="ghost" className="text-white hover:bg-slate-800"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
              {mounted ? (theme === "dark" ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />) : <div className="h-5 w-5" />}
            </Button>
          </div>

          <div className="p-2 lg:p-3 space-y-2 lg:space-y-3 overflow-y-auto">
            <div className="flex items-center gap-2 lg:gap-3 rounded-xl bg-slate-800 px-3 lg:px-4 py-3 lg:py-4">
              <SearchCode className="h-4 w-4 lg:h-5 lg:w-5 text-blue-400" />
              <span className="font-medium text-sm lg:text-base">Repository Scanner</span>
            </div>

            {scanHistory.length > 0 && (
              <button onClick={() => setShowHistory(!showHistory)}
                className="w-full flex items-center gap-2 lg:gap-3 rounded-xl bg-slate-800/50 hover:bg-slate-800 px-3 lg:px-4 py-2 lg:py-3 transition-colors">
                <History className="h-4 w-4 lg:h-5 lg:w-5" />
                <span className="font-medium text-sm lg:text-base">Scan History ({scanHistory.length})</span>
              </button>
            )}

            {showHistory && (
              <div className="rounded-xl bg-slate-950/60 p-2 lg:p-3 border border-slate-800 max-h-48 lg:max-h-64 overflow-y-auto">
                <div className="space-y-2">
                  {scanHistory.map((entry, idx) => (
                    <button key={idx} onClick={() => loadFromHistory(entry)}
                      className="w-full text-left p-2 lg:p-3 rounded-lg bg-slate-900/50 hover:bg-slate-800 transition-colors">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[10px] border-slate-600">
                          {entry.mode === "scan-fix" ? "Fix" : "Scan"}
                        </Badge>
                        <span className="text-xs lg:text-sm font-medium truncate">
                          {entry.url.split("/").slice(-2).join("/")}
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 mt-1">{new Date(entry.timestamp).toLocaleString()}</div>
                    </button>
                  ))}
                </div>
                {scanHistory.length > 0 && (
                  <button
                    onClick={clearHistory}
                    className="w-full mt-2 flex items-center justify-center gap-1 rounded-lg bg-red-900/30 hover:bg-red-900/50 border border-red-800/50 px-3 py-2 text-xs text-red-300 transition-colors"
                  >
                    <XCircle className="h-3 w-3" />
                    Clear All History
                  </button>
                )}
              </div>
            )}

            <div className="rounded-xl bg-slate-950/40 p-3 lg:p-4 border border-slate-800">
              <div className="flex items-center gap-2 mb-2 lg:mb-3">
                <BrainCircuit className="h-4 w-4 lg:h-5 lg:w-5 text-cyan-400" />
                <h3 className="font-semibold text-sm lg:text-base">AI Remediation Engine</h3>
              </div>
              <div className="space-y-1 lg:space-y-2 text-xs lg:text-sm text-slate-300">
                <p>✔ SAST Scanning (Semgrep)</p>
                <p>✔ Dependency CVE Detection</p>
                <p>✔ Secret & Credential Detection</p>
                <p>✔ Code Quality & Tech Debt</p>
                <p>✔ ML Severity Prediction</p>
                <p>✔ AI-Powered Auto-Fix</p>
                <p>✔ Fix Confidence Scoring</p>
                <p>✔ Custom Rule Engine</p>
                <p>✔ SARIF / CSV / PDF Export</p>
                <p>✔ Auto-PR Generation</p>
              </div>

              {/* Supported Languages */}
              <div className="mt-3 pt-3 border-t border-slate-800">
                <p className="text-xs font-semibold text-slate-400 mb-2">Supported Ecosystems</p>
                <div className="flex flex-wrap gap-1">
                  {["Python", "Java", "JavaScript", "TypeScript", "C#/.NET", "Go", "Rust", "Ruby", "PHP", "C/C++", "Kotlin", "Swift"].map((lang) => (
                    <span key={lang} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">{lang}</span>
                  ))}
                </div>
              </div>

              <div className="mt-3 pt-3 border-t border-slate-800">
                <a
                  href={`${API_URL}/docs`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                >
                  <ExternalLink className="h-3 w-3" />
                  API Documentation (Swagger)
                </a>
                <a
                  href={`${API_URL}/redoc`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-xs text-slate-400 hover:text-slate-300 transition-colors mt-1"
                >
                  <ExternalLink className="h-3 w-3" />
                  API Reference (ReDoc)
                </a>
              </div>
            </div>

            {result && (
              <div className="rounded-xl p-3 lg:p-4 border bg-green-900/30 border-green-700">
                <div className="flex items-center gap-2 mb-2">
                  <ShieldCheck className="h-4 w-4 lg:h-5 lg:w-5 text-green-400" />
                  <h3 className="font-semibold text-sm lg:text-base">Scan Completed</h3>
                </div>
                <p className="text-xs text-slate-300">Target repository has been successfully analyzed.</p>
              </div>
            )}
          </div>

          <div className="mt-auto p-3 lg:p-4 border-t border-slate-800">
            <Link href="/dashboard">
              <button className="w-full flex items-center gap-2 rounded-xl bg-slate-800/50 hover:bg-slate-800 px-3 py-2 transition-colors mb-2">
                <BarChart3 className="h-4 w-4" /><span className="text-sm">Dashboard</span>
              </button>
            </Link>
            <Link href="/about">
              <button className="w-full flex items-center gap-2 rounded-xl bg-slate-800/50 hover:bg-slate-800 px-3 py-2 transition-colors mb-2">
                <FileText className="h-4 w-4" /><span className="text-sm">Features & Docs</span>
              </button>
            </Link>
            <Link href="/settings">
              <button className="w-full flex items-center gap-2 rounded-xl bg-slate-800/50 hover:bg-slate-800 px-3 py-2 transition-colors mb-2">
                <Settings className="h-4 w-4" /><span className="text-sm">Settings</span>
              </button>
            </Link>
            <div className="text-xs text-slate-400">Enterprise AI Scanner v2.2</div>
          </div>
        </aside>

        {/* Main Content */}
        <section className="flex-1 overflow-auto p-3 lg:p-6">
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 lg:gap-6 h-full">
            {/* Left Column - Scan Form + Terminal */}
            <div className="space-y-4 lg:space-y-6">
              <Card className="p-4 lg:p-6 rounded-2xl shadow-sm border-slate-200 dark:border-slate-800">
                <div className="space-y-4 lg:space-y-6">
                  <div>
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="h-5 w-5 lg:h-6 lg:w-6 text-blue-600 dark:text-blue-400" />
                      <h2 className="text-xl lg:text-2xl font-bold">AI Vulnerability Remediator</h2>
                    </div>
                    <p className="text-muted-foreground text-xs lg:text-sm mt-2">
                      Scan your GitHub repositories for security vulnerabilities and receive AI-generated remediation strategies.
                    </p>
                    <Dialog>
                      <DialogTrigger asChild>
                        <button className="inline-flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 hover:underline mt-2">
                          <List className="h-3 w-3" />View sample repositories<ExternalLink className="h-3 w-3" />
                        </button>
                      </DialogTrigger>
                      <DialogContent className="max-w-2xl">
                        <DialogHeader>
                          <DialogTitle className="flex items-center gap-2"><GitBranch className="h-5 w-5" />Sample Repositories</DialogTitle>
                          <DialogDescription>Select a sample repository to test the scanner.</DialogDescription>
                        </DialogHeader>
                        <div className="mt-4 rounded-lg border overflow-hidden">
                          <table className="w-full text-sm">
                            <thead className="bg-muted">
                              <tr>
                                <th className="text-left p-3 font-semibold">Repository</th>
                                <th className="text-left p-3 font-semibold">Language</th>
                                <th className="text-center p-3 font-semibold">Action</th>
                              </tr>
                            </thead>
                            <tbody>
                              {sampleRepos.map((repo, idx) => (
                                <tr key={idx} className="border-t hover:bg-muted/50 transition-colors">
                                  <td className="p-3 font-medium">{repo.name}</td>
                                  <td className="p-3"><Badge variant="outline" className="text-xs">{repo.type}</Badge></td>
                                  <td className="p-3 text-center">
                                    <Button size="sm" variant="ghost" onClick={() => setUrl(repo.url)} className="h-8 text-xs gap-1">Load</Button>
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
                        <p className="text-sm text-red-900 dark:text-red-200">{errorMessage}</p>
                      </div>
                    </div>
                  )}

                  {/* Repository URL Input */}
                  <div className="space-y-2">
                    <Label htmlFor="repo-url">Repository URL</Label>
                    <div className="relative">
                      <GitBranch className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                      <Input id="repo-url" value={url} onChange={(e) => setUrl(e.target.value)}
                        placeholder="https://github.com/username/repository" className="h-11 pl-10" />
                    </div>
                  </div>

                  {/* Scan Mode Selection */}
                  <div className="space-y-2">
                    <Label>Scan Mode</Label>
                    <div className="grid grid-cols-2 gap-3">
                      <button type="button" onClick={() => setScanMode("scan-only")}
                        className={`flex items-center gap-2 rounded-xl border-2 p-3 lg:p-4 transition-all ${
                          scanMode === "scan-only" ? "border-blue-600 bg-blue-50 dark:bg-blue-950/30" : "border-slate-200 dark:border-slate-700 hover:border-slate-300"
                        }`}>
                        <Eye className={`h-5 w-5 ${scanMode === "scan-only" ? "text-blue-600" : "text-muted-foreground"}`} />
                        <div className="text-left">
                          <p className={`text-sm font-semibold ${scanMode === "scan-only" ? "text-blue-900 dark:text-blue-100" : ""}`}>Scan Only</p>
                          <p className="text-xs text-muted-foreground">Detect vulnerabilities</p>
                        </div>
                      </button>
                      <button type="button" onClick={() => setScanMode("scan-fix")}
                        className={`flex items-center gap-2 rounded-xl border-2 p-3 lg:p-4 transition-all ${
                          scanMode === "scan-fix" ? "border-green-600 bg-green-50 dark:bg-green-950/30" : "border-slate-200 dark:border-slate-700 hover:border-slate-300"
                        }`}>
                        <Wrench className={`h-5 w-5 ${scanMode === "scan-fix" ? "text-green-600" : "text-muted-foreground"}`} />
                        <div className="text-left">
                          <p className={`text-sm font-semibold ${scanMode === "scan-fix" ? "text-green-900 dark:text-green-100" : ""}`}>Scan & Fix</p>
                          <p className="text-xs text-muted-foreground">Fix & create PR</p>
                        </div>
                      </button>
                    </div>
                  </div>

                  {/* Advanced Options (Branch, PR name, Instructions) */}
                  <div className="space-y-2">
                    <button
                      type="button"
                      onClick={() => setShowAdvanced(!showAdvanced)}
                      className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                    >
                      <Settings className="h-3 w-3" />
                      {showAdvanced ? "Hide" : "Show"} Advanced Options
                      <span className="text-[10px]">{showAdvanced ? "▲" : "▼"}</span>
                    </button>

                    {showAdvanced && (
                      <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-3 space-y-3 bg-muted/30">
                        {/* Branch to scan */}
                        <div className="space-y-1">
                          <Label className="text-xs">Branch to Scan</Label>
                          {branches.length > 0 ? (
                            <select
                              value={branch}
                              onChange={(e) => setBranch(e.target.value)}
                              className="w-full h-8 rounded-lg border border-input bg-background px-2.5 text-xs"
                            >
                              {branches.map((b) => (
                                <option key={b} value={b}>
                                  {b}{b === defaultBranch ? " (default)" : ""}
                                </option>
                              ))}
                            </select>
                          ) : (
                            <div className="relative">
                              <Input
                                value={branch}
                                onChange={(e) => setBranch(e.target.value)}
                                placeholder={branchesLoading ? "Loading branches..." : "main (leave empty for default)"}
                                className="text-xs h-8"
                                disabled={branchesLoading}
                              />
                              {branchesLoading && (
                                <div className="absolute right-2 top-1/2 -translate-y-1/2">
                                  <SearchCode className="h-3 w-3 animate-spin text-muted-foreground" />
                                </div>
                              )}
                            </div>
                          )}
                          <p className="text-[10px] text-muted-foreground">
                            {branches.length > 0
                              ? `${branches.length} branches found. Default: ${defaultBranch}`
                              : "Enter a valid GitHub URL to auto-load branches, or type a branch name."}
                          </p>
                        </div>

                        {/* PR Branch Name (only for scan-fix) */}
                        {scanMode === "scan-fix" && (
                          <div className="space-y-1">
                            <Label className="text-xs">PR Branch Name</Label>
                            <Input
                              value={prBranchName}
                              onChange={(e) => setPrBranchName(e.target.value)}
                              placeholder="fix/vuln-remediation-abc123 (auto-generated if empty)"
                              className="text-xs h-8 font-mono"
                            />
                            <p className="text-[10px] text-muted-foreground">
                              Custom name for the fix branch. Leave empty for auto-generated name.
                            </p>
                          </div>
                        )}

                        {/* Per-scan skill instructions */}
                        <div className="space-y-1">
                          <Label className="text-xs">Additional AI Instructions</Label>
                          <textarea
                            value={skillPrompt}
                            onChange={(e) => setSkillPrompt(e.target.value)}
                            placeholder={"e.g.\n- Use Django 4.2 patterns\n- Database is PostgreSQL\n- Follow our coding standards at docs/STYLE.md\n- Replace deprecated APIs with new equivalents"}
                            className="w-full h-24 rounded-lg border border-input bg-background px-2.5 py-1.5 text-xs resize-y focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                          />
                          <p className="text-[10px] text-muted-foreground">
                            Custom instructions for the AI when generating fixes. Project-specific rules, coding standards, migration notes.
                          </p>
                        </div>
                      </div>
                    )}
                  </div>

                  <Button className={`w-full h-10 lg:h-11 gap-2 text-sm lg:text-base text-white ${
                    scanMode === "scan-fix" ? "bg-green-600 hover:bg-green-700" : "bg-blue-600 hover:bg-blue-700"
                  }`} onClick={runScan} disabled={loading || !prereqsReady}>
                    {loading ? <SearchCode className="h-4 w-4 animate-pulse" /> : scanMode === "scan-fix" ? <Wrench className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    {loading ? "Analyzing Repository..." : scanMode === "scan-fix" ? "Scan & Fix Repository" : "Scan Repository"}
                  </Button>

                  {/* Prerequisites Warning */}
                  {!prereqsLoading && !prereqsReady && (
                    <div className="rounded-lg bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-800 p-3 space-y-2">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-red-600" />
                        <p className="text-xs font-semibold text-red-700 dark:text-red-300">
                          {prereqStatus === null ? "Backend not running" : "Missing required tools"}
                        </p>
                      </div>
                      {prereqStatus === null ? (
                        <p className="text-xs text-red-600 dark:text-red-400">
                          Cannot connect to the backend server at {API_URL}. Start the backend first.
                        </p>
                      ) : (
                        <div className="space-y-1 text-xs">
                          {!prereqStatus?.git?.installed && (
                            <div className="flex items-center gap-2">
                              <XCircle className="h-3 w-3 text-red-500" />
                              <span>Git not installed — </span>
                              <code className="bg-red-100 dark:bg-red-900 px-1 rounded text-[10px]">
                                {navigator.platform?.includes("Mac") ? "brew install git" : "sudo apt install git"}
                              </code>
                            </div>
                          )}
                          {!prereqStatus?.sast_scanner?.installed && (
                            <div className="flex items-center gap-2">
                              <XCircle className="h-3 w-3 text-red-500" />
                              <span>SAST Scanner not installed — </span>
                              <code className="bg-red-100 dark:bg-red-900 px-1 rounded text-[10px]">
                                curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
                              </code>
                            </div>
                          )}
                        </div>
                      )}
                      <Button variant="outline" size="sm" className="text-xs gap-1 mt-1" onClick={checkPrerequisites}>
                        <SearchCode className="h-3 w-3" /> Re-check
                      </Button>
                    </div>
                  )}

                  {/* Prerequisites OK indicator */}
                  {!prereqsLoading && prereqsReady && prereqStatus && (
                    <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                      <CheckCircle2 className="h-3 w-3 text-green-500" />
                      <span>
                        {prereqStatus.sast_scanner?.tool === "opengrep" ? "OpenGrep" : "Semgrep"} ready
                      </span>
                      <span className="text-slate-300 dark:text-slate-600">•</span>
                      <span>Git ready</span>
                      {prereqStatus.sast_scanner?.tool && (
                        <>
                          <span className="text-slate-300 dark:text-slate-600">•</span>
                          <span className="font-mono">{prereqStatus.sast_scanner.tool}</span>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </Card>

              {/* Terminal View - Shows during scan, hides when report is ready */}
              {showTerminal && (loading || !result) && (
                <Card className="rounded-2xl shadow-sm overflow-hidden border-slate-200 dark:border-slate-800 bg-slate-950">
                  <div className="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700">
                    <div className="flex items-center gap-2">
                      <Terminal className="h-4 w-4 text-green-400" />
                      <span className="text-sm font-mono text-slate-300">Scan Progress</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {loading && (
                        <Badge className="bg-green-600/20 text-green-400 border-green-600/30 text-xs animate-pulse">
                          {currentPhase}
                        </Badge>
                      )}
                      <div className="flex gap-1">
                        <div className="w-3 h-3 rounded-full bg-red-500"></div>
                        <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                        <div className="w-3 h-3 rounded-full bg-green-500"></div>
                      </div>
                    </div>
                  </div>
                  <div ref={terminalRef} className="p-4 font-mono text-xs max-h-72 overflow-y-auto space-y-1">
                    {logs.map((entry, idx) => (
                      <div key={idx} className={`flex gap-2 ${getLogColor(entry)}`}>
                        <span className="text-slate-600 select-none">{entry.timestamp}</span>
                        <span className="select-none">{getLogPrefix(entry)}</span>
                        <span className="break-all">{entry.message}</span>
                      </div>
                    ))}
                    {loading && (
                      <div className="flex gap-2 text-slate-500">
                        <span className="animate-pulse">▌</span>
                      </div>
                    )}
                  </div>
                </Card>
              )}

              {/* Missing SDK Install Prompt */}
              {showInstallPrompt && missingSDKs.length > 0 && (
                <Card className="rounded-2xl shadow-sm border-orange-200 dark:border-orange-800 bg-orange-50 dark:bg-orange-950/20 p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Package className="h-5 w-5 text-orange-600" />
                    <h3 className="font-semibold text-sm">Missing Dependencies</h3>
                  </div>
                  <p className="text-xs text-muted-foreground mb-3">
                    The following tools are not installed on the server. Some scan features may be limited.
                  </p>
                  <div className="space-y-2">
                    {missingSDKs.map((sdk, idx) => (
                      <div key={idx} className="flex items-center justify-between rounded-lg border border-orange-200 dark:border-orange-800 bg-white dark:bg-slate-900 p-3">
                        <div className="flex items-center gap-2">
                          <Monitor className="h-4 w-4 text-orange-500" />
                          <span className="text-sm font-medium">{sdk.name}</span>
                        </div>
                        <code className="text-xs bg-slate-100 dark:bg-slate-800 px-2 py-1 rounded font-mono">
                          {sdk.install_cmd}
                        </code>
                      </div>
                    ))}
                  </div>
                  <Button variant="outline" size="sm" className="mt-3 text-xs"
                    onClick={() => setShowInstallPrompt(false)}>
                    Dismiss
                  </Button>
                </Card>
              )}

              {/* Scan Summary Card - Shows when result is ready */}
              {result && (
                <Card className="p-4 lg:p-6 rounded-2xl shadow-sm border-slate-200 dark:border-slate-800">
                  <div className="flex items-center justify-between mb-4 lg:mb-5">
                    <div className="flex items-center gap-2">
                      <BrainCircuit className="h-4 w-4 lg:h-5 lg:w-5 text-violet-600" />
                      <h2 className="text-lg lg:text-xl font-bold">Scan Analysis</h2>
                    </div>
                    {showTerminal && (
                      <Button variant="ghost" size="sm" className="text-xs gap-1"
                        onClick={() => setShowTerminal(!showTerminal)}>
                        <Terminal className="h-3 w-3" />
                        {showTerminal ? "Hide" : "Show"} Logs
                      </Button>
                    )}
                  </div>
                  {renderSummary()}
                </Card>
              )}

              {/* Terminal replay when result is ready but user wants to see logs */}
              {showTerminal && result && logs.length > 0 && (
                <Card className="rounded-2xl shadow-sm overflow-hidden border-slate-200 dark:border-slate-800 bg-slate-950">
                  <div className="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700">
                    <div className="flex items-center gap-2">
                      <Terminal className="h-4 w-4 text-green-400" />
                      <span className="text-sm font-mono text-slate-300">Scan Logs</span>
                    </div>
                    <Button variant="ghost" size="sm" className="text-xs text-slate-400 hover:text-white h-6"
                      onClick={() => setShowTerminal(false)}>Hide</Button>
                  </div>
                  <div className="p-4 font-mono text-xs max-h-48 overflow-y-auto space-y-1">
                    {logs.map((entry, idx) => (
                      <div key={idx} className={`flex gap-2 ${getLogColor(entry)}`}>
                        <span className="text-slate-600 select-none">{entry.timestamp}</span>
                        <span className="select-none">{getLogPrefix(entry)}</span>
                        <span className="break-all">{entry.message}</span>
                      </div>
                    ))}
                  </div>
                </Card>
              )}
            </div>

            {/* Right Column - Report Panel */}
            <Card className="flex flex-col p-0 rounded-2xl shadow-sm overflow-hidden border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 min-h-[400px] xl:min-h-0 xl:h-[calc(100vh-4rem)]">
              <div className="flex items-center justify-between p-4 lg:p-6 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-background">
                <div>
                  <h2 className="text-xl lg:text-2xl font-bold">Scan Report</h2>
                  <p className="text-muted-foreground text-xs lg:text-sm mt-1">
                    {result ? "Vulnerability scan results and remediation details." : "Generate a scan to view the report."}
                  </p>
                </div>
                {result && (
                  <div className="flex gap-2 flex-wrap">
                    {/* View Toggle */}
                    <div className="flex rounded-lg border overflow-hidden">
                      <button onClick={() => setReportView("report")}
                        className={`px-2 py-1 text-xs ${reportView === "report" ? "bg-blue-600 text-white" : "bg-white dark:bg-slate-800 text-muted-foreground"}`}>
                        Report
                      </button>
                      <button onClick={() => setReportView("json")}
                        className={`px-2 py-1 text-xs ${reportView === "json" ? "bg-blue-600 text-white" : "bg-white dark:bg-slate-800 text-muted-foreground"}`}>
                        JSON
                      </button>
                    </div>
                    <Button variant="outline" size="icon" onClick={copyResult}
                      title={copied ? "Copied!" : "Copy to clipboard"} className="h-9 w-9">
                      {copied ? <CheckCircle2 className="h-4 w-4 text-green-600" /> : <Copy className="h-4 w-4" />}
                    </Button>
                    <Button variant="outline" size="icon" onClick={downloadResult}
                      title="Download as JSON" className="h-9 w-9">
                      <Download className="h-4 w-4" />
                    </Button>
                    <Button variant="outline" size="icon" onClick={downloadPDF}
                      title="Download as PDF" className="h-9 w-9">
                      <FileText className="h-4 w-4" />
                    </Button>
                    <Button variant="outline" size="sm" onClick={downloadSARIF}
                      title="Export SARIF (GitHub/Azure)" className="h-9 text-xs px-2">
                      SARIF
                    </Button>
                    <Button variant="outline" size="sm" onClick={downloadCSV}
                      title="Export CSV (Excel/JIRA)" className="h-9 text-xs px-2">
                      CSV
                    </Button>
                  </div>
                )}
              </div>

              <div className="flex-1 overflow-auto p-4 lg:p-6">
                {/* Review Panel — shown when fixes are ready for approval */}
                {showReview && previewFiles.length > 0 ? (
                  <ReviewPanel
                    files={previewFiles}
                    onApprove={handleApplyFixes}
                    onCancel={() => { setShowReview(false); setPreviewFiles([]); }}
                    loading={applyingFixes}
                  />
                ) : loading && !result ? (
                  <div className="flex flex-col items-center justify-center h-full space-y-4 text-muted-foreground">
                    <Terminal className="h-8 w-8 animate-pulse text-green-500" />
                    <p className="text-sm font-mono">{currentPhase || "Initializing..."}</p>
                    <div className="w-48 h-1 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                      <div className="h-full bg-green-500 rounded-full animate-pulse" style={{ width: "60%" }}></div>
                    </div>
                  </div>
                ) : result ? (
                  reportView === "json" ? (
                    <pre className="text-xs lg:text-sm font-mono text-slate-800 dark:text-slate-300 whitespace-pre-wrap break-all leading-relaxed">
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  ) : (
                    <div className="space-y-6">
                      {/* Report Header */}
                      <div className="border-b pb-4">
                        <h3 className="text-lg font-bold">Vulnerability Scan Report</h3>
                        <p className="text-xs text-muted-foreground mt-1">
                          Repository: <span className="font-mono">{result.repo || url}</span>
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Scanned: {new Date().toLocaleDateString()} at {new Date().toLocaleTimeString()}
                        </p>
                      </div>

                      {/* Executive Summary */}
                      <div>
                        <h4 className="text-sm font-semibold mb-3">Executive Summary</h4>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          <div className="rounded-lg bg-white dark:bg-slate-800 border p-3 text-center">
                            <p className="text-2xl font-bold">{result.total_findings || 0}</p>
                            <p className="text-xs text-muted-foreground">Total Findings</p>
                          </div>
                          <div className="rounded-lg bg-white dark:bg-slate-800 border p-3 text-center">
                            <p className="text-2xl font-bold text-red-600">
                              {(result.scan_summary?.by_severity?.CRITICAL || 0) + (result.scan_summary?.by_severity?.HIGH || 0)}
                            </p>
                            <p className="text-xs text-muted-foreground">Critical/High</p>
                          </div>
                          <div className="rounded-lg bg-white dark:bg-slate-800 border p-3 text-center">
                            <p className="text-2xl font-bold text-yellow-600">
                              {result.scan_summary?.by_severity?.MEDIUM || result.scan_summary?.by_severity?.WARNING || 0}
                            </p>
                            <p className="text-xs text-muted-foreground">Medium</p>
                          </div>
                          <div className="rounded-lg bg-white dark:bg-slate-800 border p-3 text-center">
                            <p className="text-2xl font-bold text-blue-600">
                              {(result.scan_summary?.by_severity?.LOW || 0) + (result.scan_summary?.by_severity?.INFO || 0)}
                            </p>
                            <p className="text-xs text-muted-foreground">Low/Info</p>
                          </div>
                        </div>
                      </div>

                      {/* Status */}
                      <div className={`rounded-lg p-4 ${
                        result.status === "clean" ? "bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-800" :
                        result.status === "success" && result.pull_request ? "bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800" :
                        result.status === "error" ? "bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-800" :
                        "bg-orange-50 dark:bg-orange-950/20 border border-orange-200 dark:border-orange-800"
                      }`}>
                        <p className="text-sm font-semibold">
                          {result.status === "clean" ? "✅ No vulnerabilities found" :
                           result.status === "success" && result.pull_request ? "✅ Vulnerabilities fixed — PR created" :
                           result.status === "success" && !result.pull_request ? `⚠️ ${result.total_findings || 0} vulnerabilities detected` :
                           result.status === "error" ? "❌ Scan failed" :
                           `⚠️ ${result.total_findings || 0} vulnerabilities detected`}
                        </p>
                        {result.message && !result.pull_request && (
                          <p className="text-xs text-muted-foreground mt-1">{result.message}</p>
                        )}
                        {result.pull_request && (
                          <a href={result.pull_request} target="_blank" rel="noopener noreferrer"
                            className="text-xs text-blue-600 hover:underline mt-1 inline-block">
                            View Pull Request →
                          </a>
                        )}
                      </div>

                      {/* Project Info */}
                      {result.project_info && (
                        <div>
                          <h4 className="text-sm font-semibold mb-2">Project Information</h4>
                          <div className="rounded-lg bg-white dark:bg-slate-800 border p-3 text-sm space-y-1">
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Languages</span>
                              <span>{result.project_info.languages?.join(", ") || "Unknown"}</span>
                            </div>
                            {result.project_info.frameworks?.length > 0 && (
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Frameworks</span>
                                <span>{result.project_info.frameworks.join(", ")}</span>
                              </div>
                            )}
                            {result.project_info.build_tools?.length > 0 && (
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Build Tools</span>
                                <span>{result.project_info.build_tools.join(", ")}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Quality Gate */}
                      {result.code_quality?.quality_gate_details && (
                        <div>
                          <h4 className="text-sm font-semibold mb-2">Quality Gate</h4>
                          <div className={`rounded-lg border p-3 ${
                            result.code_quality.quality_gate_details.passed
                              ? "border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-950/20"
                              : "border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/20"
                          }`}>
                            <div className="flex items-center gap-2 mb-2">
                              {result.code_quality.quality_gate_details.passed
                                ? <CheckCircle2 className="h-4 w-4 text-green-600" />
                                : <XCircle className="h-4 w-4 text-red-600" />}
                              <span className="text-sm font-semibold">
                                {result.code_quality.quality_gate_details.passed ? "PASSED" : "FAILED"}
                              </span>
                            </div>
                            <div className="grid grid-cols-2 gap-2 text-xs">
                              {result.code_quality.quality_gate_details.conditions?.map((c: any, i: number) => (
                                <div key={i} className="flex items-center gap-1">
                                  <span>{c.status === "PASSED" ? "✓" : "✗"}</span>
                                  <span className="text-muted-foreground">{c.metric.replace(/_/g, " ")}: </span>
                                  <span className="font-mono">{typeof c.actual === "number" ? c.actual.toFixed(1) : c.actual}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Code Quality Metrics */}
                      {result.code_quality?.metrics && (
                        <div>
                          <h4 className="text-sm font-semibold mb-2">Code Quality Metrics</h4>
                          <div className="rounded-lg bg-white dark:bg-slate-800 border p-3 text-sm">
                            <div className="grid grid-cols-2 gap-3">
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Maintainability</span>
                                <span className={`font-bold ${ratingColor(result.code_quality.metrics.complexity?.maintainability_rating)}`}>
                                  {result.code_quality.metrics.complexity?.maintainability_rating || "—"}
                                </span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Duplication</span>
                                <span className="font-mono">{result.code_quality.metrics.duplication?.duplication_percentage?.toFixed(1)}%</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Tech Debt</span>
                                <span className="font-mono">{result.code_quality.metrics.technical_debt?.total_hours?.toFixed(1)}h</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Code Smells</span>
                                <span className="font-mono">{result.code_quality.code_smells?.total || 0}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Lines of Code</span>
                                <span className="font-mono">{result.code_quality.metrics.lines_of_code?.code_lines?.toLocaleString()}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Avg Complexity</span>
                                <span className="font-mono">{result.code_quality.metrics.complexity?.average_complexity?.toFixed(1)}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Compliance Dashboard */}
                      {result.compliance && (
                        <div>
                          <h4 className="text-sm font-semibold mb-2">Compliance Status</h4>
                          <div className="grid grid-cols-3 gap-3 mb-3">
                            <div className="rounded-lg border p-3 text-center">
                              <p className="text-xs text-muted-foreground">OWASP Top 10</p>
                              <p className={`text-xl font-bold ${
                                result.compliance.owasp_top_10.compliance_score >= 80 ? "text-green-600" :
                                result.compliance.owasp_top_10.compliance_score >= 50 ? "text-yellow-600" : "text-red-600"
                              }`}>{result.compliance.owasp_top_10.compliance_score}%</p>
                              <p className="text-[10px] text-muted-foreground">
                                {result.compliance.owasp_top_10.violations}/10 categories violated
                              </p>
                            </div>
                            <div className="rounded-lg border p-3 text-center">
                              <p className="text-xs text-muted-foreground">PCI-DSS</p>
                              <p className={`text-xl font-bold ${
                                result.compliance.pci_dss.compliance_score >= 80 ? "text-green-600" :
                                result.compliance.pci_dss.compliance_score >= 50 ? "text-yellow-600" : "text-red-600"
                              }`}>{result.compliance.pci_dss.compliance_score}%</p>
                              <p className="text-[10px] text-muted-foreground">
                                {result.compliance.pci_dss.violations} requirements failed
                              </p>
                            </div>
                            <div className="rounded-lg border p-3 text-center">
                              <p className="text-xs text-muted-foreground">Overall</p>
                              <p className={`text-xl font-bold ${
                                result.compliance.overall_compliance_score >= 80 ? "text-green-600" :
                                result.compliance.overall_compliance_score >= 50 ? "text-yellow-600" : "text-red-600"
                              }`}>{result.compliance.overall_compliance_score}%</p>
                              <p className="text-[10px] text-muted-foreground">compliance score</p>
                            </div>
                          </div>

                          {/* OWASP Details */}
                          {result.compliance.owasp_top_10.details.some((d: any) => d.violations > 0) && (
                            <div className="rounded-lg border p-3 text-xs space-y-1">
                              <p className="font-semibold text-muted-foreground mb-2">OWASP Top 10 Violations</p>
                              {result.compliance.owasp_top_10.details
                                .filter((d: any) => d.violations > 0)
                                .map((d: any, i: number) => (
                                  <div key={i} className="flex items-center justify-between">
                                    <span>{d.code}: {d.name}</span>
                                    <Badge className="bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300 text-[10px]">
                                      {d.violations} findings
                                    </Badge>
                                  </div>
                                ))}
                            </div>
                          )}

                          {/* CWE List */}
                          {result.compliance.cwe?.details?.length > 0 && (
                            <div className="rounded-lg border p-3 text-xs mt-2">
                              <p className="font-semibold text-muted-foreground mb-2">
                                CWE Weaknesses ({result.compliance.cwe.unique_weaknesses})
                              </p>
                              <div className="space-y-1 max-h-24 overflow-y-auto">
                                {result.compliance.cwe.details.slice(0, 8).map((c: any, i: number) => (
                                  <div key={i} className="flex justify-between">
                                    <span className="font-mono">{c.id}</span>
                                    <span className="text-muted-foreground">{c.name} ({c.count})</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Baseline Info */}
                      {(result.new_since_baseline !== undefined || result.suppressed_count > 0) && (
                        <div className="rounded-lg border p-3 space-y-2">
                          <p className="text-xs font-semibold text-muted-foreground">Baseline & Suppressions</p>
                          <div className="grid grid-cols-2 gap-3 text-xs">
                            {result.new_since_baseline !== undefined && (
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">New since baseline</span>
                                <span className={`font-bold ${result.new_since_baseline > 0 ? "text-red-600" : "text-green-600"}`}>
                                  {result.new_since_baseline > 0 ? `+${result.new_since_baseline}` : "0 new"}
                                </span>
                              </div>
                            )}
                            {result.suppressed_count > 0 && (
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Suppressed</span>
                                <span className="text-slate-500">{result.suppressed_count} hidden</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Findings Table */}
                      {result.findings?.length > 0 && (
                        <div>
                          <h4 className="text-sm font-semibold mb-2">
                            Vulnerability Details ({result.findings.length})
                          </h4>
                          <div className="rounded-lg border overflow-hidden">
                            <table className="w-full text-xs">
                              <thead className="bg-muted">
                                <tr>
                                  <th className="text-left p-2 font-semibold">Severity</th>
                                  <th className="text-left p-2 font-semibold">File</th>
                                  <th className="text-left p-2 font-semibold hidden sm:table-cell">Rule</th>
                                  <th className="text-left p-2 font-semibold">Description</th>
                                  <th className="text-center p-2 font-semibold w-16">Action</th>
                                </tr>
                              </thead>
                              <tbody>
                                {result.findings.slice(0, 50).map((f: any, idx: number) => (
                                  <tr key={idx} className="border-t hover:bg-muted/30">
                                    <td className="p-2">
                                      <Badge className={`${severityColor(f.adjusted_severity || f.severity)} text-[10px]`}>
                                        {f.adjusted_severity || f.severity}
                                      </Badge>
                                    </td>
                                    <td className="p-2 font-mono text-muted-foreground max-w-[120px] truncate">
                                      {f.path}{f.line ? `:${f.line}` : ""}
                                    </td>
                                    <td className="p-2 font-mono text-muted-foreground hidden sm:table-cell max-w-[100px] truncate">
                                      {f.rule_id}
                                    </td>
                                    <td className="p-2 max-w-[200px]">
                                      <p className="truncate">{f.message?.slice(0, 120)}</p>
                                      {f.metadata?.category === "secret" && (
                                        <span className="text-[10px] text-red-600 font-semibold">🔑 SECRET</span>
                                      )}
                                    </td>
                                    <td className="p-2 text-center">
                                      <button
                                        onClick={() => suppressFinding(f.rule_id, f.path)}
                                        className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 hover:bg-orange-100 dark:hover:bg-orange-950 text-muted-foreground hover:text-orange-600 transition-colors"
                                        title="Suppress this finding"
                                      >
                                        Suppress
                                      </button>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                            {result.findings.length > 50 && (
                              <div className="p-2 text-center text-xs text-muted-foreground bg-muted/30">
                                Showing 50 of {result.findings.length} findings. Export full report for all details.
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Fix Results (for scan-fix mode) */}
                      {result.files_fixed?.length > 0 && (
                        <div>
                          <h4 className="text-sm font-semibold mb-2">Issues Fixed by AI Vulnerability Remediator</h4>

                          {/* Fix Details Table */}
                          {result.files_fixed.some((f: any) => f.fix_details?.length > 0) && (
                            <div className="rounded-lg border overflow-hidden mb-3">
                              <table className="w-full text-xs">
                                <thead className="bg-muted">
                                  <tr>
                                    <th className="text-left p-2 font-semibold">#</th>
                                    <th className="text-left p-2 font-semibold">Issue Found</th>
                                    <th className="text-left p-2 font-semibold">Status</th>
                                    <th className="text-left p-2 font-semibold">File</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {result.files_fixed.flatMap((f: any, fIdx: number) =>
                                    (f.fix_details || []).map((detail: any, dIdx: number) => (
                                      <tr key={`${fIdx}-${dIdx}`} className="border-t">
                                        <td className="p-2 text-muted-foreground">{fIdx + dIdx + 1}</td>
                                        <td className="p-2">
                                          <span className="text-orange-600">⚠️</span> {detail.issue?.slice(0, 80)}
                                        </td>
                                        <td className="p-2">
                                          <span className="text-green-600">✅ Fixed</span>
                                        </td>
                                        <td className="p-2 font-mono text-muted-foreground">{f.path}</td>
                                      </tr>
                                    ))
                                  ).slice(0, 20)}
                                </tbody>
                              </table>
                            </div>
                          )}

                          {/* Files Summary */}
                          <div className="rounded-lg border overflow-hidden">
                            <table className="w-full text-xs">
                              <thead className="bg-muted">
                                <tr>
                                  <th className="text-left p-2 font-semibold">File</th>
                                  <th className="text-center p-2 font-semibold">Issues Fixed</th>
                                  <th className="text-center p-2 font-semibold">Confidence</th>
                                  <th className="text-center p-2 font-semibold">Changes</th>
                                </tr>
                              </thead>
                              <tbody>
                                {result.files_fixed.map((f: any, idx: number) => (
                                  <tr key={idx} className="border-t">
                                    <td className="p-2 font-mono text-muted-foreground">{f.path}</td>
                                    <td className="p-2 text-center">{f.findings_fixed}</td>
                                    <td className="p-2 text-center">
                                      {f.confidence >= 0 ? (
                                        <span className={`font-semibold ${
                                          f.confidence >= 90 ? "text-green-600" :
                                          f.confidence >= 70 ? "text-blue-600" : "text-yellow-600"
                                        }`}>{f.confidence}%</span>
                                      ) : "—"}
                                    </td>
                                    <td className="p-2 text-center text-muted-foreground">
                                      {f.diff ? `+${f.diff.additions} -${f.diff.deletions}` : "—"}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}

                      {/* Errors */}
                      {result.errors?.length > 0 && (
                        <div>
                          <h4 className="text-sm font-semibold mb-2 text-red-600">Scan Errors</h4>
                          <div className="rounded-lg border border-red-200 dark:border-red-800 p-3 space-y-1">
                            {result.errors.map((err: any, idx: number) => (
                              <p key={idx} className="text-xs text-red-700 dark:text-red-300">
                                • {typeof err === "string" ? err : err.message || JSON.stringify(err)}
                              </p>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )
                ) : (
                  <div className="flex flex-col items-center justify-center h-full text-muted-foreground space-y-3">
                    <ShieldCheck className="h-12 w-12 opacity-20" />
                    <p className="text-sm">No report generated yet.</p>
                    <p className="text-xs text-center max-w-xs">
                      Enter a GitHub repository URL and click scan to generate a vulnerability report.
                    </p>
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
