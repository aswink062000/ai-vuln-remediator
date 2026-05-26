"use client";

import { useState, useEffect } from "react";
import axios from "axios";
import Link from "next/link";
import {
  ArrowLeft,
  Key,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Shield,
  Eye,
  EyeOff,
  Save,
  TestTube,
  Loader2,
  BrainCircuit,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const API_KEY = process.env.NEXT_PUBLIC_API_KEY || "";

export default function SettingsPage() {
  const [token, setToken] = useState("");
  const [testRepoUrl, setTestRepoUrl] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  // Token status from backend
  const [tokenStatus, setTokenStatus] = useState<any>(null);
  // Test result
  const [testResult, setTestResult] = useState<any>(null);
  // Alert state
  const [alert, setAlert] = useState<{
    type: "success" | "error" | "warning";
    title: string;
    message: string;
  } | null>(null);

  // LLM provider state
  const [geminiKey, setGeminiKey] = useState("");
  const [groqKey, setGroqKey] = useState("");
  const [nvidiaKey, setNvidiaKey] = useState("");
  const [openrouterKey, setOpenrouterKey] = useState("");
  const [huggingfaceKey, setHuggingfaceKey] = useState("");
  const [defaultModel, setDefaultModel] = useState("");
  const [savingLLM, setSavingLLM] = useState(false);
  const [llmStatus, setLlmStatus] = useState<any>(null);

  // Load current token status on mount
  useEffect(() => {
    if (API_KEY) {
      axios.defaults.headers.common["X-API-Key"] = API_KEY;
    }
    fetchTokenStatus();
    fetchLLMStatus();
  }, []);

  const fetchTokenStatus = async () => {
    try {
      const res = await axios.get(`${API_URL}/settings/token/status`);
      setTokenStatus(res.data);
    } catch {
      setTokenStatus(null);
    }
  };

  const fetchLLMStatus = async () => {
    try {
      const res = await axios.get(`${API_URL}/environment`);
      setLlmStatus(res.data.llm_providers);
    } catch {
      setLlmStatus(null);
    }
  };

  const saveLLMKeys = async () => {
    setSavingLLM(true);
    setAlert(null);

    try {
      const keys: Record<string, string> = {};
      if (geminiKey.trim()) keys["GEMINI_API_KEY"] = geminiKey.trim();
      if (groqKey.trim()) keys["GROQ_API_KEY"] = groqKey.trim();
      if (nvidiaKey.trim()) keys["NVIDIA_API_KEY"] = nvidiaKey.trim();
      if (openrouterKey.trim()) keys["OPENROUTER_API_KEY"] = openrouterKey.trim();
      if (huggingfaceKey.trim()) keys["HUGGINGFACE_API_KEY"] = huggingfaceKey.trim();
      if (defaultModel.trim()) keys["DEFAULT_LLM_PROVIDER"] = defaultModel.trim();

      if (Object.keys(keys).length === 0) {
        setAlert({
          type: "warning",
          title: "No Keys Provided",
          message: "Enter at least one API key to save.",
        });
        setSavingLLM(false);
        return;
      }

      await axios.post(`${API_URL}/settings/llm/save`, { keys });

      setAlert({
        type: "success",
        title: "LLM Keys Saved",
        message: `Saved ${Object.keys(keys).length} key(s) securely. Active immediately.`,
      });

      // Clear inputs and refresh status
      setGeminiKey("");
      setGroqKey("");
      setNvidiaKey("");
      setOpenrouterKey("");
      setHuggingfaceKey("");
      await fetchLLMStatus();
    } catch (error: any) {
      setAlert({
        type: "error",
        title: "Save Failed",
        message: error.response?.data?.detail || error.message || "Failed to save LLM keys.",
      });
    } finally {
      setSavingLLM(false);
    }
  };

  const testToken = async () => {
    if (!token.trim()) {
      setAlert({
        type: "error",
        title: "Token Required",
        message: "Please enter a GitHub token to test.",
      });
      return;
    }

    setLoading(true);
    setTestResult(null);
    setAlert(null);

    try {
      const res = await axios.post(`${API_URL}/settings/token/test`, {
        token: token.trim(),
        github_url: testRepoUrl.trim(),
      });

      setTestResult(res.data);

      if (!res.data.valid) {
        setAlert({
          type: "error",
          title: "Invalid Token",
          message: res.data.error || "Token authentication failed.",
        });
      } else if (!res.data.permissions_ok) {
        setAlert({
          type: "warning",
          title: "Missing Permissions",
          message: res.data.error || "Token is missing required scopes.",
        });
      } else {
        setAlert({
          type: "success",
          title: "Token Valid",
          message: `Authenticated as ${res.data.username}. All required permissions are present.`,
        });
      }
    } catch (error: any) {
      setAlert({
        type: "error",
        title: "Test Failed",
        message: error.response?.data?.detail || error.message || "Failed to test token.",
      });
    } finally {
      setLoading(false);
    }
  };

  const saveToken = async () => {
    if (!token.trim()) {
      setAlert({
        type: "error",
        title: "Token Required",
        message: "Please enter a GitHub token to save.",
      });
      return;
    }

    setSaving(true);
    setAlert(null);

    try {
      await axios.post(`${API_URL}/settings/token/save`, {
        token: token.trim(),
      });

      setAlert({
        type: "success",
        title: "Token Saved",
        message: "GitHub token has been saved to the backend .env file.",
      });

      // Refresh status
      await fetchTokenStatus();
      setToken("");
    } catch (error: any) {
      setAlert({
        type: "error",
        title: "Save Failed",
        message: error.response?.data?.detail || error.message || "Failed to save token.",
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <main className="min-h-screen bg-background p-4 lg:p-8">
      <div className="max-w-2xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-4">
          <Link href="/">
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-5 w-5" />
            </Button>
          </Link>
          <div>
            <h1 className="text-2xl font-bold">Settings</h1>
            <p className="text-sm text-muted-foreground">
              Configure GitHub token and permissions
            </p>
          </div>
        </div>

        {/* Alert */}
        {alert && (
          <Alert variant={alert.type === "error" || alert.type === "warning" ? "destructive" : "default"}>
            {alert.type === "error" ? (
              <XCircle className="h-4 w-4" />
            ) : alert.type === "warning" ? (
              <AlertTriangle className="h-4 w-4" />
            ) : (
              <CheckCircle2 className="h-4 w-4" />
            )}
            <AlertTitle>{alert.title}</AlertTitle>
            <AlertDescription>{alert.message}</AlertDescription>
          </Alert>
        )}

        {/* Current Token Status */}
        <Card className="p-5 rounded-2xl">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="h-5 w-5 text-blue-600" />
            <h2 className="text-lg font-semibold">Current Token Status</h2>
          </div>

          {tokenStatus ? (
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                {tokenStatus.configured ? (
                  <Badge className="bg-green-600 text-white">Configured</Badge>
                ) : (
                  <Badge variant="destructive">Not Configured</Badge>
                )}
                {tokenStatus.token_type && (
                  <Badge variant="outline" className="text-xs">
                    {tokenStatus.token_type}
                  </Badge>
                )}
              </div>
              {tokenStatus.masked_token && (
                <p className="text-sm font-mono text-muted-foreground">
                  {tokenStatus.masked_token}
                </p>
              )}
              {!tokenStatus.configured && (
                <p className="text-sm text-muted-foreground">
                  No GitHub token is configured. The Scan & Fix feature requires
                  a token with <code className="text-xs bg-muted px-1 py-0.5 rounded">repo</code> scope.
                </p>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              Unable to check token status. Is the backend running?
            </p>
          )}
        </Card>

        {/* Configure Token */}
        <Card className="p-5 rounded-2xl">
          <div className="flex items-center gap-2 mb-4">
            <Key className="h-5 w-5 text-violet-600" />
            <h2 className="text-lg font-semibold">Configure GitHub Token</h2>
          </div>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="github-token">Personal Access Token</Label>
              <div className="relative">
                <Input
                  id="github-token"
                  type={showToken ? "text" : "password"}
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                  className="pr-10 font-mono text-sm"
                />
                <button
                  type="button"
                  onClick={() => setShowToken(!showToken)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showToken ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
              <p className="text-xs text-muted-foreground">
                Generate at{" "}
                <a
                  href="https://github.com/settings/tokens"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:underline"
                >
                  github.com/settings/tokens
                </a>
                . Required scope: <code className="bg-muted px-1 py-0.5 rounded">repo</code>
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="test-repo">Test Repository URL (optional)</Label>
              <Input
                id="test-repo"
                value={testRepoUrl}
                onChange={(e) => setTestRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repo"
                className="text-sm"
              />
              <p className="text-xs text-muted-foreground">
                Optionally provide a repo URL to check push access.
              </p>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-3">
              <Button
                onClick={testToken}
                disabled={loading || !token.trim()}
                variant="outline"
                className="gap-2"
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <TestTube className="h-4 w-4" />
                )}
                Test Token
              </Button>

              <Button
                onClick={saveToken}
                disabled={saving || !token.trim()}
                className="gap-2 bg-blue-600 hover:bg-blue-700 text-white"
              >
                {saving ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Save className="h-4 w-4" />
                )}
                Save Token
              </Button>
            </div>
          </div>
        </Card>

        {/* Test Results */}
        {testResult && (
          <Card className="p-5 rounded-2xl">
            <div className="flex items-center gap-2 mb-4">
              <TestTube className="h-5 w-5 text-green-600" />
              <h2 className="text-lg font-semibold">Test Results</h2>
            </div>

            <div className="space-y-3">
              {/* Auth status */}
              <div className="flex items-center gap-2">
                {testResult.valid ? (
                  <CheckCircle2 className="h-4 w-4 text-green-600" />
                ) : (
                  <XCircle className="h-4 w-4 text-red-600" />
                )}
                <span className="text-sm font-medium">
                  {testResult.valid
                    ? `Authenticated as ${testResult.username}`
                    : "Authentication failed"}
                </span>
              </div>

              {/* Scopes */}
              {testResult.scopes && (
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-1">
                    Token Scopes
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {testResult.scopes.map((scope: string) => (
                      <Badge
                        key={scope}
                        variant="outline"
                        className={`text-xs ${
                          scope === "repo"
                            ? "border-green-500 text-green-700 dark:text-green-400"
                            : ""
                        }`}
                      >
                        {scope === "repo" ? "✓ " : ""}
                        {scope}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Required permissions check */}
              {testResult.valid && (
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    {testResult.has_repo_scope ? (
                      <CheckCircle2 className="h-3 w-3 text-green-600" />
                    ) : (
                      <XCircle className="h-3 w-3 text-red-600" />
                    )}
                    <span className="text-xs">
                      repo scope (push branches, create PRs)
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    {testResult.has_workflow_scope ? (
                      <CheckCircle2 className="h-3 w-3 text-green-600" />
                    ) : (
                      <AlertTriangle className="h-3 w-3 text-yellow-600" />
                    )}
                    <span className="text-xs">
                      workflow scope (optional, for CI triggers)
                    </span>
                  </div>
                </div>
              )}

              {/* Repo access */}
              {testResult.repo_access && (
                <div className="rounded-lg border p-3 mt-2">
                  <p className="text-xs font-semibold text-muted-foreground mb-2">
                    Repository Access: {testResult.repo_access.repo}
                  </p>
                  {testResult.repo_access.error ? (
                    <p className="text-xs text-red-600">
                      {testResult.repo_access.error}
                    </p>
                  ) : (
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        {testResult.repo_access.can_push ? (
                          <CheckCircle2 className="h-3 w-3 text-green-600" />
                        ) : (
                          <AlertTriangle className="h-3 w-3 text-yellow-600" />
                        )}
                        <span className="text-xs">
                          {testResult.repo_access.note}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Default branch: {testResult.repo_access.default_branch}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </Card>
        )}

        {/* LLM Providers Section */}
        <Card className="p-5 rounded-2xl">
          <div className="flex items-center gap-2 mb-4">
            <BrainCircuit className="h-5 w-5 text-cyan-600" />
            <h2 className="text-lg font-semibold">LLM Providers</h2>
          </div>

          <p className="text-sm text-muted-foreground mb-4">
            Configure AI model providers. The app uses a fallback chain — if one provider
            hits rate limits, it automatically tries the next. Set a default to prioritize your preferred model.
          </p>

          {llmStatus && (
            <div className="flex flex-wrap gap-2 mb-4">
              {Object.entries(llmStatus).map(([name, info]: [string, any]) => (
                <Badge
                  key={name}
                  variant="outline"
                  className={`text-xs ${
                    info.configured
                      ? "border-green-500 text-green-700 dark:text-green-400"
                      : "border-slate-300 text-muted-foreground"
                  }`}
                >
                  {info.configured ? "✓" : "○"} {name}
                </Badge>
              ))}
            </div>
          )}

          <div className="space-y-4">
            {/* Default Model Selector */}
            <div className="space-y-1 rounded-lg border p-3 bg-muted/30">
              <Label className="text-xs font-semibold">Default AI Model</Label>
              <select
                value={defaultModel}
                onChange={(e) => setDefaultModel(e.target.value)}
                className="w-full h-9 rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="">Auto (fallback chain)</option>
                <option value="gemini">Google Gemini 2.0 Flash</option>
                <option value="gemini-1.5-flash">Google Gemini 1.5 Flash</option>
                <option value="groq">Groq (Llama 3.1 8B)</option>
                <option value="nvidia">NVIDIA NIM (Llama 3.1)</option>
                <option value="openrouter">OpenRouter</option>
                <option value="huggingface">HuggingFace (Qwen 2.5 Coder)</option>
              </select>
              <p className="text-xs text-muted-foreground">
                Choose which model to try first. Falls through to others if it fails.
              </p>
            </div>

            {/* Gemini */}
            <div className="space-y-1">
              <Label className="text-xs font-semibold">
                1. Google Gemini (Recommended)
              </Label>
              <Input
                type="password"
                value={geminiKey}
                onChange={(e) => setGeminiKey(e.target.value)}
                placeholder="AIzaSy..."
                className="font-mono text-xs"
              />
              <p className="text-xs text-muted-foreground">
                Free tier: 15 RPM.{" "}
                <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                  Get key →
                </a>
              </p>
            </div>

            {/* Groq */}
            <div className="space-y-1">
              <Label className="text-xs font-semibold">
                2. Groq (Fastest inference)
              </Label>
              <Input
                type="password"
                value={groqKey}
                onChange={(e) => setGroqKey(e.target.value)}
                placeholder="gsk_..."
                className="font-mono text-xs"
              />
              <p className="text-xs text-muted-foreground">
                Free: 30 req/min, 14400/day.{" "}
                <a href="https://console.groq.com/keys" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                  Get key →
                </a>
              </p>
            </div>

            {/* NVIDIA */}
            <div className="space-y-1">
              <Label className="text-xs font-semibold">
                3. NVIDIA NIM
              </Label>
              <Input
                type="password"
                value={nvidiaKey}
                onChange={(e) => setNvidiaKey(e.target.value)}
                placeholder="nvapi-..."
                className="font-mono text-xs"
              />
              <p className="text-xs text-muted-foreground">
                Free tier available.{" "}
                <a href="https://build.nvidia.com/" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                  Get key →
                </a>
              </p>
            </div>

            {/* OpenRouter */}
            <div className="space-y-1">
              <Label className="text-xs font-semibold">
                4. OpenRouter (Many free models)
              </Label>
              <Input
                type="password"
                value={openrouterKey}
                onChange={(e) => setOpenrouterKey(e.target.value)}
                placeholder="sk-or-..."
                className="font-mono text-xs"
              />
              <p className="text-xs text-muted-foreground">
                Free models available.{" "}
                <a href="https://openrouter.ai/keys" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                  Get key →
                </a>
              </p>
            </div>

            {/* HuggingFace */}
            <div className="space-y-1">
              <Label className="text-xs font-semibold">
                5. HuggingFace (Qwen 2.5 Coder)
              </Label>
              <Input
                type="password"
                value={huggingfaceKey}
                onChange={(e) => setHuggingfaceKey(e.target.value)}
                placeholder="hf_..."
                className="font-mono text-xs"
              />
              <p className="text-xs text-muted-foreground">
                Free inference API.{" "}
                <a href="https://huggingface.co/settings/tokens" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                  Get key →
                </a>
              </p>
            </div>

            <Button
              onClick={saveLLMKeys}
              disabled={savingLLM}
              className="gap-2 bg-cyan-600 hover:bg-cyan-700 text-white"
            >
              {savingLLM ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              Save LLM Keys
            </Button>
          </div>
        </Card>

        {/* Help Section */}
        <Card className="p-5 rounded-2xl">
          <h2 className="text-lg font-semibold mb-3">Required Permissions</h2>
          <div className="space-y-3 text-sm">
            <p className="text-muted-foreground">
              The GitHub token needs the following permissions for Scan & Fix to work:
            </p>
            <div className="rounded-lg bg-muted/50 p-4 space-y-2">
              <div className="flex items-center gap-2">
                <Badge className="bg-green-600 text-white text-xs">Required</Badge>
                <code className="text-xs">repo</code>
                <span className="text-xs text-muted-foreground">
                  — Push branches and create Pull Requests
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="text-xs">Optional</Badge>
                <code className="text-xs">workflow</code>
                <span className="text-xs text-muted-foreground">
                  — Trigger CI/CD workflows on the PR
                </span>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              If you don&apos;t have push access to the target repository, the app will
              automatically fork it to your account and create a cross-repo Pull Request.
            </p>
          </div>
        </Card>

        {/* Custom Rules Section */}
        <Card className="p-5 rounded-2xl">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="h-5 w-5 text-orange-600" />
            <h2 className="text-lg font-semibold">Custom Scan Rules</h2>
          </div>
          <p className="text-sm text-muted-foreground mb-4">
            Create custom Semgrep rules to detect patterns specific to your codebase.
            Rules run alongside the default security scans.
          </p>
          <div className="space-y-3">
            <div className="rounded-lg bg-muted/50 p-4 space-y-2 text-xs">
              <p className="font-semibold">Example: Detect hardcoded localhost URLs</p>
              <pre className="bg-slate-900 text-green-400 p-2 rounded text-[11px] overflow-x-auto">
{`Pattern: requests.get("http://localhost...")
Language: python
Severity: WARNING
Message: Hardcoded localhost URL found`}</pre>
            </div>
            <p className="text-xs text-muted-foreground">
              Manage rules via the API: <code className="bg-muted px-1 rounded">GET /rules</code>, <code className="bg-muted px-1 rounded">POST /rules</code>
            </p>
            <a
              href={`${API_URL}/docs#/Custom%20Rules`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs text-blue-600 hover:underline"
            >
              Open Rules API →
            </a>
          </div>
        </Card>

        {/* Scheduled Scans Section */}
        <Card className="p-5 rounded-2xl">
          <div className="flex items-center gap-2 mb-4">
            <Key className="h-5 w-5 text-purple-600" />
            <h2 className="text-lg font-semibold">Scheduled Scans</h2>
          </div>
          <p className="text-sm text-muted-foreground mb-4">
            Set up recurring scans to monitor repositories over time.
            Track trends and catch new vulnerabilities as dependencies update.
          </p>
          <div className="rounded-lg bg-muted/50 p-4 space-y-2 text-xs">
            <p><strong>Frequencies:</strong> Daily, Weekly, Monthly</p>
            <p><strong>Features:</strong> Auto-saves to history, trend tracking, quality gate monitoring</p>
          </div>
          <p className="text-xs text-muted-foreground mt-3">
            Manage via API: <code className="bg-muted px-1 rounded">GET /schedules</code>, <code className="bg-muted px-1 rounded">POST /schedules</code>
          </p>
          <a
            href={`${API_URL}/docs#/API%20v1/list_schedules_api_v1_schedules_get`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-blue-600 hover:underline mt-2"
          >
            Open Schedules API →
          </a>
        </Card>
      </div>
    </main>
  );
}
