"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";

/** Technical hash: monospace, truncated; hover (or focus) reveals a copy icon. */
export function HashChip({ value, className = "", tone = "dark" }: { value: string; className?: string; tone?: "dark" | "light" }) {
  const [copied, setCopied] = useState(false);
  const short = value.length > 14 ? `${value.slice(0, 6)}…${value.slice(-4)}` : value;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <button
      type="button"
      onClick={copy}
      title={value}
      aria-label={`Copy ${value}`}
      className={`group inline-flex items-center gap-1.5 font-mono text-[12px] ${tone === "light" ? "text-paper-ink" : "text-ink"} ${className}`}
    >
      {short}
      <span className="opacity-0 transition-opacity duration-200 group-hover:opacity-100 group-focus-visible:opacity-100">
        {copied ? <Check aria-hidden="true" className="h-3 w-3 text-cobalt-bright" /> : <Copy aria-hidden="true" className="h-3 w-3 opacity-60" />}
      </span>
    </button>
  );
}
