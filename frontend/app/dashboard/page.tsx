"use client";

import { useState, useEffect } from "react";
import axios from "axios";
import Link from "next/link";
import {
  ArrowLeft,
  Plus,
  Trash2,
  Play,
  ShieldCheck,
  ShieldAlert,
  XCircle,
  CheckCircle2,
  GitBranch,
  BarChart3,
  Globe,
  Loader2,
  Ban,
  RefreshCw,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const API_KEY = process.env.NEXT_PUBLIC_API_KEY || "";

export default function DashboardPage() {
  // Multi-repo state
  const [repos, setRepos] = useState<string[]>([""]);
  const [multiResult, setMultiResult] = useState<any>(null);
  const [multiLoading, setMultiLoading] = useState(false);

  // Baseline state
  const [suppressions, setSuppressions] = useState<any[]>([]);
  const [suppressRule, setSuppressRule] = useState("");
  const [suppressPath, setSuppressPath] = useState("");
  const [suppressReason, setSuppressReason] = useState("accepted_risk");

  // Webhook state
  const [webhookUrl, setWebhookUrl] = useState("");

  useEffect(() => {
    if (API_KEY) {
      axios.defaults.headers.common["X-API-Key"] = API_KEY;
    }
    fetchSuppressions();
    // Build webhook URL
    setWebhookUrl(`${API_URL}/webhook/github`);
  }, []);

  const fetchSuppressions = async () => {
    try {
      const res = await axios.get(`${API_URL}/baseline/suppressions`);
      setSuppressions(res.data.suppressions || []);
    } catch {
      // Endpoint might not exist yet
    }
  };

  // Multi-repo scan
  const addRepoField = () => setRepos([...repos, ""]);
  const removeRepoField = (idx: number) => setRepos(repos.filter((_, i) => i !== idx));
  const updateRepo = (idx: number, value: string) => {
    const updated = [...repos];
    updated[idx] = value;
    setRepos(updated);
  };

  const runMultiScan = async () => {
    const validRepos = repos.filter((r) => r.trim().startsWith("https://github.com/"));
    if (validRepos.length === 0) return;

    setMultiLoading(true);
    setMultiResult(null);
    try {
      const res = await axios.post(`${API_URL}/scan-multi`, { repos: validRepos });
      setMultiResult(res.data);
    } catch (error: any) {
      setMultiResult({ status: "error", message: error.response?.data?.detail || error.message });
    } finally {
      setMultiLoading(false);
    }
  };

  // Suppress finding
  const handleSuppress = async () => {
    if (!suppressRule.trim()) return;
    try {
      await axios.post(`${API_URL}/baseline/suppress`, {
        rule_id: suppressRule.trim(),
        path: suppressPath.trim(),
        reason: suppressReason,
      });
      setSuppressRule("");
      setSuppressPath("");
      fetchSuppressions();
    } catch {
      // handle error
    }
  };

  const handleUnsuppress = async (ruleId: string) => {
    try {
      await axios.delete(`${API_URL}/baseline/suppress/${encodeURIComponent(ruleId)}`);
      fetchSuppressions();
    } catch {
      // handle error
    }
  };

  const healthColor = (score: number) => {
    if (score >= 80) return "text-green-600";
    if (score >= 60) return "text-blue-600";
    if (score >= 40) return "text-yellow-600";
    return "text-red-600";
  };

  return (
    <main className="min-h-screen bg-background p-4 lg:p-8">
      <div className="max-w-5xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-4">
          <Link href="/">
            <Button variant="ghost" size="icon"><ArrowLeft className="h-5 w-5" /></Button>
          </Link>
          <div>
            <h1 className="text-2xl font-bold">Security Dashboard</h1>
            <p className="text-sm text-muted-foreground">
              Multi-repo scanning, baseline management, and CI integration
            </p>
          </div>
        </div>

        {/* Multi-Repo Scanner */}
        <Card className="p-5 rounded-2xl">
          <div className="flex items-center gap-2 mb-4">
            <Globe className="h-5 w-5 text-blue-600" />
            <h2 className="text-lg font-semibold">Multi-Repo Scanner</h2>
          </div>
          <p className="text-sm text-muted-foreground mb-4">
            Scan multiple repositories at once. Get an organization-level health score.
          </p>

          <div className="space-y-2 mb-4">
            {repos.map((repo, idx) => (
              <div key={idx} className="flex gap-2">
                <div className="relative flex-1">
                  <GitBranch className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    value={repo}
                    onChange={(e) => updateRepo(idx, e.target.value)}
                    placeholder="https://github.com/owner/repo"
                    className="pl-9 text-sm"
                  />
                </div>
                {repos.length > 1 && (
                  <Button variant="ghost" size="icon" onClick={() => removeRepoField(idx)} className="h-9 w-9 text-red-500">
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
            ))}
          </div>

          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={addRepoField} className="gap-1">
              <Plus className="h-3 w-3" /> Add Repo
            </Button>
            <Button
              onClick={runMultiScan}
              disabled={multiLoading}
              className="gap-2 bg-blue-600 hover:bg-blue-700 text-white"
            >
              {multiLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {multiLoading ? "Scanning..." : "Scan All"}
            </Button>
          </div>

          {/* Multi-Repo Results */}
          {multiResult && multiResult.status !== "error" && (
            <div className="mt-6 space-y-4">
              {/* Org Health Score */}
              <div className="rounded-lg border p-4 text-center">
                <p className="text-xs text-muted-foreground mb-1">Organization Health Score</p>
                <p className={`text-5xl font-bold ${healthColor(multiResult.org_health_score)}`}>
                  {multiResult.org_health_score}
                </p>
                <Badge className={`mt-2 ${
                  multiResult.health_rating === "A" ? "bg-green-600" :
                  multiResult.health_rating === "B" ? "bg-blue-600" :
                  multiResult.health_rating === "C" ? "bg-yellow-600" : "bg-red-600"
                } text-white`}>
                  Rating: {multiResult.health_rating}
                </Badge>
                <div className="flex justify-center gap-6 mt-3 text-xs text-muted-foreground">
                  <span>{multiResult.repos_scanned} repos scanned</span>
                  <span>{multiResult.total_findings} total findings</span>
                  <span className="text-red-600">{multiResult.total_critical_high} critical/high</span>
                </div>
              </div>

              {/* Per-Repo Results */}
              <div className="rounded-lg border overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-muted">
                    <tr>
                      <th className="text-left p-3 font-semibold">Repository</th>
                      <th className="text-center p-3 font-semibold">Findings</th>
                      <th className="text-center p-3 font-semibold">Critical/High</th>
                      <th className="text-center p-3 font-semibold">Quality Gate</th>
                    </tr>
                  </thead>
                  <tbody>
                    {multiResult.results?.map((r: any, idx: number) => (
                      <tr key={idx} className="border-t">
                        <td className="p-3">
                          <div className="flex items-center gap-2">
                            {r.status === "success" ? (
                              <ShieldCheck className="h-4 w-4 text-green-500" />
                            ) : (
                              <XCircle className="h-4 w-4 text-red-500" />
                            )}
                            <span className="font-mono text-xs truncate max-w-[200px]">
                              {r.repo.replace("https://github.com/", "")}
                            </span>
                          </div>
                          {r.languages && (
                            <div className="flex gap-1 mt-1">
                              {r.languages.map((l: string) => (
                                <span key={l} className="text-[10px] px-1 rounded bg-slate-100 dark:bg-slate-800">{l}</span>
                              ))}
                            </div>
                          )}
                        </td>
                        <td className="p-3 text-center font-mono">
                          {r.status === "success" ? r.total_findings : "—"}
                        </td>
                        <td className="p-3 text-center">
                          {r.status === "success" ? (
                            <span className={r.critical_high > 0 ? "text-red-600 font-bold" : "text-green-600"}>
                              {r.critical_high}
                            </span>
                          ) : "—"}
                        </td>
                        <td className="p-3 text-center">
                          {r.status === "success" ? (
                            r.quality_gate ? (
                              <Badge className="bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-300 text-[10px]">PASS</Badge>
                            ) : (
                              <Badge className="bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300 text-[10px]">FAIL</Badge>
                            )
                          ) : (
                            <span className="text-xs text-red-500">{r.message?.slice(0, 30)}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {multiResult?.status === "error" && (
            <div className="mt-4 rounded-lg bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-800 p-3">
              <p className="text-sm text-red-700 dark:text-red-300">{multiResult.message}</p>
            </div>
          )}
        </Card>

        {/* Baseline / Suppress Findings */}
        <Card className="p-5 rounded-2xl">
          <div className="flex items-center gap-2 mb-4">
            <Ban className="h-5 w-5 text-orange-600" />
            <h2 className="text-lg font-semibold">Suppress Findings</h2>
          </div>
          <p className="text-sm text-muted-foreground mb-4">
            Mark findings as accepted risk or false positive. Suppressed findings are hidden from future scan results.
          </p>

          {/* Add Suppression Form */}
          <div className="rounded-lg border p-4 space-y-3 mb-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="space-y-1">
                <Label className="text-xs">Rule ID</Label>
                <Input
                  value={suppressRule}
                  onChange={(e) => setSuppressRule(e.target.value)}
                  placeholder="e.g. python.lang.security.sql-injection"
                  className="text-xs"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">File Path (optional)</Label>
                <Input
                  value={suppressPath}
                  onChange={(e) => setSuppressPath(e.target.value)}
                  placeholder="e.g. src/utils.py (blank = all files)"
                  className="text-xs"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Reason</Label>
                <select
                  value={suppressReason}
                  onChange={(e) => setSuppressReason(e.target.value)}
                  className="w-full h-9 rounded-md border border-input bg-background px-3 text-xs"
                >
                  <option value="accepted_risk">Accepted Risk</option>
                  <option value="false_positive">False Positive</option>
                  <option value="wont_fix">Won&apos;t Fix</option>
                  <option value="mitigated">Mitigated Elsewhere</option>
                </select>
              </div>
            </div>
            <Button onClick={handleSuppress} size="sm" className="gap-1 bg-orange-600 hover:bg-orange-700 text-white">
              <Ban className="h-3 w-3" /> Suppress Finding
            </Button>
          </div>

          {/* Current Suppressions */}
          {suppressions.length > 0 ? (
            <div className="rounded-lg border overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-muted">
                  <tr>
                    <th className="text-left p-2 font-semibold">Rule ID</th>
                    <th className="text-left p-2 font-semibold">Path</th>
                    <th className="text-left p-2 font-semibold">Reason</th>
                    <th className="text-center p-2 font-semibold">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {suppressions.map((s: any, idx: number) => (
                    <tr key={idx} className="border-t">
                      <td className="p-2 font-mono">{s.rule_id}</td>
                      <td className="p-2 text-muted-foreground">{s.path === "*" ? "All files" : s.path}</td>
                      <td className="p-2">
                        <Badge variant="outline" className="text-[10px]">{s.reason}</Badge>
                      </td>
                      <td className="p-2 text-center">
                        <Button variant="ghost" size="sm" onClick={() => handleUnsuppress(s.rule_id)}
                          className="h-6 text-xs text-red-500 hover:text-red-700">
                          Remove
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-xs text-muted-foreground text-center py-4 border-2 border-dashed rounded-lg">
              No suppressions configured. Suppress findings from scan results to reduce noise.
            </p>
          )}
        </Card>

        {/* Webhook / CI Integration */}
        <Card className="p-5 rounded-2xl">
          <div className="flex items-center gap-2 mb-4">
            <RefreshCw className="h-5 w-5 text-purple-600" />
            <h2 className="text-lg font-semibold">CI/CD Integration</h2>
          </div>
          <p className="text-sm text-muted-foreground mb-4">
            Connect your GitHub repositories for automatic scanning on every push.
            Results are posted as commit status checks.
          </p>

          <div className="space-y-4">
            {/* Webhook URL */}
            <div className="rounded-lg border p-4 bg-muted/30">
              <p className="text-xs font-semibold mb-2">Webhook URL</p>
              <div className="flex gap-2">
                <code className="flex-1 text-xs bg-slate-900 text-green-400 p-2 rounded font-mono overflow-x-auto">
                  {webhookUrl}
                </code>
                <Button variant="outline" size="sm" className="text-xs"
                  onClick={() => { navigator.clipboard.writeText(webhookUrl); }}>
                  Copy
                </Button>
              </div>
            </div>

            {/* Setup Instructions */}
            <div className="rounded-lg border p-4 space-y-3">
              <p className="text-xs font-semibold">Setup Instructions</p>
              <ol className="text-xs text-muted-foreground space-y-2 list-decimal list-inside">
                <li>Go to your GitHub repository → <strong>Settings</strong> → <strong>Webhooks</strong></li>
                <li>Click <strong>Add webhook</strong></li>
                <li>Paste the Webhook URL above into <strong>Payload URL</strong></li>
                <li>Set Content type to <code className="bg-muted px-1 rounded">application/json</code></li>
                <li>Set a <strong>Secret</strong> (same as <code className="bg-muted px-1 rounded">WEBHOOK_SECRET</code> in your backend .env)</li>
                <li>Select <strong>Just the push event</strong></li>
                <li>Click <strong>Add webhook</strong></li>
              </ol>
            </div>

            {/* How it works */}
            <div className="rounded-lg bg-purple-50 dark:bg-purple-950/20 border border-purple-200 dark:border-purple-800 p-4">
              <p className="text-xs font-semibold text-purple-700 dark:text-purple-300 mb-2">How it works</p>
              <div className="text-xs text-purple-600 dark:text-purple-400 space-y-1">
                <p>1. Developer pushes code to main/master branch</p>
                <p>2. GitHub sends webhook to your server</p>
                <p>3. Server runs full security scan automatically</p>
                <p>4. Results posted as commit status check (✓ pass / ✗ fail)</p>
                <p>5. Scan saved to history for trend tracking</p>
              </div>
            </div>

            {/* Status indicators */}
            <div className="flex gap-3 text-xs">
              <div className="flex items-center gap-1">
                <CheckCircle2 className="h-3 w-3 text-green-500" />
                <span>Respects suppressions</span>
              </div>
              <div className="flex items-center gap-1">
                <CheckCircle2 className="h-3 w-3 text-green-500" />
                <span>Compares to baseline</span>
              </div>
              <div className="flex items-center gap-1">
                <CheckCircle2 className="h-3 w-3 text-green-500" />
                <span>Only scans main branch</span>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </main>
  );
}
