"use client";

import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function RemediatePage() {
  return (
    <main className="min-h-screen bg-background p-4 lg:p-8">
      <div className="max-w-3xl mx-auto space-y-6">
        <div className="flex items-center gap-4">
          <Link href="/">
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-5 w-5" />
            </Button>
          </Link>
          <div>
            <h1 className="text-2xl font-bold">Remediation</h1>
            <p className="text-sm text-muted-foreground">
              Use the main scanner in Scan &amp; Fix mode to automatically remediate vulnerabilities.
            </p>
          </div>
        </div>

        <div className="rounded-2xl border p-8 text-center space-y-4">
          <p className="text-muted-foreground">
            The remediation workflow is integrated into the main scanner. Select
            &quot;Scan &amp; Fix&quot; mode on the home page to scan a repository and
            automatically generate AI-powered fixes with a Pull Request.
          </p>
          <Link href="/">
            <Button className="bg-green-600 hover:bg-green-700 text-white">
              Go to Scanner
            </Button>
          </Link>
        </div>
      </div>
    </main>
  );
}
