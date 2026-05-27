"use client";

import { useState, useEffect } from "react";
import ReactDiffViewer, { DiffMethod } from "react-diff-viewer-continued";
import {
  CheckCircle2,
  XCircle,
  FileText,
  ShieldAlert,
  GitBranch,
  Loader2,
  Eye,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";

interface PreviewFile {
  path: string;
  original_code: string;
  fixed_code: string;
  findings_count: number;
  findings?: Array<{
    rule_id: string;
    severity: string;
    message: string;
    line?: number;
  }>;
  diff?: {
    stats: { additions: number; deletions: number };
    summary: string;
  };
  error?: string;
}

interface ReviewPanelProps {
  files: PreviewFile[];
  onApprove: (approvedFiles: Array<{ path: string; fixed_code: string }>) => void;
  onCancel: () => void;
  loading?: boolean;
}

export function ReviewPanel({ files, onApprove, onCancel, loading }: ReviewPanelProps) {
  // Reactive dark mode detection
  const [isDark, setIsDark] = useState(false);
  // Dialog state
  const [viewingFile, setViewingFile] = useState<PreviewFile | null>(null);

  useEffect(() => {
    const checkDark = () => setIsDark(document.documentElement.classList.contains("dark"));
    checkDark();
    const observer = new MutationObserver(checkDark);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => observer.disconnect();
  }, []);

  // Track which files are approved (all approved by default)
  const [approvals, setApprovals] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    files.forEach((f) => {
      if (f.fixed_code && !f.error) {
        initial[f.path] = true;
      }
    });
    return initial;
  });

  const toggleApproval = (path: string) => {
    setApprovals((prev) => {
      const newState = { ...prev, [path]: !prev[path] };
      console.log("[ReviewPanel] Toggle approval:", path, "→", newState[path]);
      return newState;
    });
  };

  const approveAll = () => {
    const all: Record<string, boolean> = {};
    files.forEach((f) => {
      if (f.fixed_code && !f.error) all[f.path] = true;
    });
    setApprovals(all);
  };

  const rejectAll = () => {
    setApprovals({});
  };

  const handleSubmit = () => {
    const approved = files
      .filter((f) => approvals[f.path] === true && f.fixed_code)
      .map((f) => ({ path: f.path, fixed_code: f.fixed_code }));
    console.log("[ReviewPanel] Submitting approved files:", approved.map(f => f.path));
    console.log("[ReviewPanel] Approvals state:", approvals);
    onApprove(approved);
  };

  const approvedCount = Object.values(approvals).filter(Boolean).length;
  const fixableCount = files.filter((f) => f.fixed_code && !f.error).length;

  const severityColor = (severity: string) => {
    const s = severity?.toUpperCase();
    if (s === "CRITICAL") return "bg-red-600 text-white";
    if (s === "HIGH" || s === "ERROR") return "bg-orange-600 text-white";
    if (s === "MEDIUM" || s === "WARNING") return "bg-yellow-500 text-black";
    return "bg-blue-500 text-white";
  };

  return (
    <>
      <div className="space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold flex items-center gap-2">
              <GitBranch className="h-5 w-5 text-blue-600" />
              Review AI Fixes
            </h3>
            <p className="text-xs text-muted-foreground mt-1">
              Click &quot;View Diff&quot; to inspect changes. Approve or reject files before creating the PR.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-xs">
              {approvedCount}/{fixableCount} approved
            </Badge>
            <Button variant="ghost" size="sm" className="text-xs" onClick={approveAll}>
              Approve All
            </Button>
            <Button variant="ghost" size="sm" className="text-xs text-red-500" onClick={rejectAll}>
              Reject All
            </Button>
          </div>
        </div>

        {/* File List */}
        <div className="space-y-2 max-h-[60vh] overflow-y-auto">
          {files.map((file) => (
            <div
              key={file.path}
              className={`rounded-xl border transition-colors ${
                file.error
                  ? "border-red-200 dark:border-red-800 bg-red-50/50 dark:bg-red-950/10"
                  : approvals[file.path]
                  ? "border-green-200 dark:border-green-800 bg-green-50/30 dark:bg-green-950/10"
                  : "border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-900/30"
              }`}
            >
              <div className="flex items-center gap-3 p-3">
                {/* Approve/Reject Toggle */}
                {file.fixed_code && !file.error && (
                  <button
                    onClick={() => toggleApproval(file.path)}
                    className="flex-shrink-0"
                    title={approvals[file.path] ? "Click to reject" : "Click to approve"}
                  >
                    {approvals[file.path] ? (
                      <CheckCircle2 className="h-5 w-5 text-green-600" />
                    ) : (
                      <XCircle className="h-5 w-5 text-slate-300 dark:text-slate-600" />
                    )}
                  </button>
                )}
                {file.error && <ShieldAlert className="h-5 w-5 text-red-500 flex-shrink-0" />}

                {/* File path */}
                <div className="flex-1 flex items-center gap-2 min-w-0">
                  <FileText className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                  <span className="font-mono text-xs truncate">{file.path}</span>
                </div>

                {/* Stats + View button */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  {file.diff?.stats && (
                    <span className="text-[10px] font-mono text-muted-foreground">
                      <span className="text-green-600">+{file.diff.stats.additions}</span>
                      {" "}
                      <span className="text-red-600">-{file.diff.stats.deletions}</span>
                    </span>
                  )}
                  <Badge variant="outline" className="text-[10px]">
                    {file.findings_count} issue{file.findings_count !== 1 ? "s" : ""}
                  </Badge>
                  {file.fixed_code && !file.error && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs gap-1.5"
                      onClick={() => setViewingFile(file)}
                    >
                      <Eye className="h-3.5 w-3.5" />
                      View Diff
                    </Button>
                  )}
                  {file.error && (
                    <span className="text-[10px] text-red-500">Failed</span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-between pt-3 border-t">
          <p className="text-xs text-muted-foreground">
            {approvedCount} file{approvedCount !== 1 ? "s" : ""} will be included in the PR
          </p>
          <div className="flex gap-2">
            <Button variant="outline" onClick={onCancel} disabled={loading}>
              Cancel
            </Button>
            <Button
              onClick={handleSubmit}
              disabled={loading || approvedCount === 0}
              className="gap-2 bg-green-600 hover:bg-green-700 text-white"
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <GitBranch className="h-4 w-4" />
              )}
              {loading ? "Creating PR..." : `Create PR (${approvedCount} files)`}
            </Button>
          </div>
        </div>
      </div>

      {/* Diff Popup Dialog */}
      <Dialog open={!!viewingFile} onOpenChange={(open) => !open && setViewingFile(null)}>
        <DialogContent
          className="max-w-[95vw] w-full max-h-[90vh] h-full sm:max-w-[95vw] p-0 gap-0 overflow-hidden"
          showCloseButton={true}
        >
          {viewingFile && (
            <>
              {/* Dialog Header */}
              <DialogHeader className="px-5 pt-4 pb-3 border-b">
                <div className="flex items-center justify-between pr-8">
                  <div className="flex items-center gap-3 min-w-0">
                    <FileText className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                    <DialogTitle className="font-mono text-sm truncate">
                      {viewingFile.path}
                    </DialogTitle>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0">
                    {viewingFile.diff?.stats && (
                      <span className="text-xs font-mono">
                        <span className="text-green-600">+{viewingFile.diff.stats.additions}</span>
                        {" "}
                        <span className="text-red-600">-{viewingFile.diff.stats.deletions}</span>
                      </span>
                    )}
                    <Badge variant="outline" className="text-xs">
                      {viewingFile.findings_count} issue{viewingFile.findings_count !== 1 ? "s" : ""}
                    </Badge>
                    <Button
                      variant={approvals[viewingFile.path] ? "default" : "outline"}
                      size="sm"
                      className={`h-7 text-xs gap-1.5 ${
                        approvals[viewingFile.path]
                          ? "bg-green-600 hover:bg-green-700 text-white"
                          : ""
                      }`}
                      onClick={() => toggleApproval(viewingFile.path)}
                    >
                      {approvals[viewingFile.path] ? (
                        <CheckCircle2 className="h-3.5 w-3.5" />
                      ) : (
                        <XCircle className="h-3.5 w-3.5" />
                      )}
                      {approvals[viewingFile.path] ? "Approved" : "Rejected"}
                    </Button>
                  </div>
                </div>
                {/* Findings summary */}
                {viewingFile.findings && viewingFile.findings.length > 0 && (
                  <DialogDescription className="flex flex-wrap gap-1.5 mt-2">
                    {viewingFile.findings.slice(0, 5).map((f, idx) => (
                      <Badge key={idx} className={`${severityColor(f.severity)} text-[10px] px-1.5 py-0`}>
                        {f.severity}: {f.message.slice(0, 60)}{f.message.length > 60 ? "…" : ""}
                      </Badge>
                    ))}
                  </DialogDescription>
                )}
              </DialogHeader>

              {/* Diff Content */}
              <div className="flex-1 overflow-auto">
                <ReactDiffViewer
                  oldValue={viewingFile.original_code}
                  newValue={viewingFile.fixed_code}
                  splitView={true}
                  useDarkTheme={isDark}
                  leftTitle="Original"
                  rightTitle="Fixed"
                  compareMethod={DiffMethod.WORDS}
                  hideLineNumbers={false}
                  styles={{
                    variables: {
                      light: {
                        diffViewerBackground: "#fafbfc",
                        diffViewerColor: "#24292e",
                        addedBackground: "#e6ffec",
                        addedColor: "#22863a",
                        removedBackground: "#ffebe9",
                        removedColor: "#cf222e",
                        wordAddedBackground: "#abf2bc",
                        wordRemovedBackground: "#ff818266",
                        addedGutterBackground: "#ccffd8",
                        removedGutterBackground: "#ffd7d5",
                        gutterBackground: "#f6f8fa",
                        gutterBackgroundDark: "#f0f1f3",
                        highlightBackground: "#fffbdd",
                        highlightGutterBackground: "#fff5b1",
                        codeFoldGutterBackground: "#dbedff",
                        codeFoldBackground: "#f1f8ff",
                        emptyLineBackground: "#fafbfc",
                      },
                      dark: {
                        diffViewerBackground: "#0d1117",
                        diffViewerColor: "#e6edf3",
                        addedBackground: "#12261e",
                        addedColor: "#3fb950",
                        removedBackground: "#2d1215",
                        removedColor: "#f85149",
                        wordAddedBackground: "#1a4721",
                        wordRemovedBackground: "#5d1216",
                        addedGutterBackground: "#0d3117",
                        removedGutterBackground: "#3c1418",
                        gutterBackground: "#161b22",
                        gutterBackgroundDark: "#1c2128",
                        highlightBackground: "#2d2000",
                        highlightGutterBackground: "#3b2300",
                        codeFoldGutterBackground: "#1d2d3e",
                        codeFoldBackground: "#161b22",
                        emptyLineBackground: "#0d1117",
                      },
                    },
                    contentText: {
                      fontSize: "13px",
                      lineHeight: "1.5",
                      fontFamily: "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace",
                    },
                    line: {
                      fontSize: "13px",
                      padding: "2px 12px",
                    },
                    gutter: {
                      fontSize: "11px",
                      minWidth: "45px",
                      padding: "0 10px",
                    },
                    wordDiff: {
                      padding: "1px 4px",
                      borderRadius: "3px",
                    },
                    diffContainer: {
                      borderRadius: "0",
                      overflow: "hidden",
                      width: "100%",
                      tableLayout: "fixed" as const,
                    },
                    titleBlock: {
                      fontSize: "13px",
                      fontWeight: "600",
                      padding: "10px 16px",
                      borderBottom: "1px solid",
                      borderColor: isDark ? "#30363d" : "#d0d7de",
                      background: isDark ? "#161b22" : "#f6f8fa",
                      width: "50%",
                      display: "table-cell",
                      textAlign: "left" as const,
                    },
                  }}
                />
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
