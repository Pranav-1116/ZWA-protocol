"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";

type Tab = { id: string; label: string; badge?: string; lang: "ts" | "sh"; code: string };

const KW = /\b(const|await|async|import|from|export|return|new|function|let|if|type)\b/;

function highlight(line: string, lang: Tab["lang"]) {
  if (lang === "sh") {
    if (line.trim().startsWith("#")) return <span className="text-muted">{line}</span>;
    const [cmd, ...rest] = line.split(" ");
    return (
      <>
        <span className="text-electric">{cmd}</span> <span className="text-ink/90">{rest.join(" ")}</span>
      </>
    );
  }
  if (line.trim().startsWith("//")) return <span className="text-muted">{line}</span>;
  const parts = line.split(/("[^"]*"|'[^']*'|\b\w+\b)/g);
  return parts.map((p, i) => {
    if (/^["']/.test(p)) return <span key={i} className="text-[#a5b4fc]">{p}</span>;
    if (KW.test(p) && p.match(KW)?.[0] === p) return <span key={i} className="text-cobalt-bright">{p}</span>;
    if (/^(zwa|prove|verify|settle)$/.test(p)) return <span key={i} className="text-electric">{p}</span>;
    return <span key={i} className="text-ink/90">{p}</span>;
  });
}

export function CodeBlock({ tabs }: { tabs: Tab[] }) {
  const [active, setActive] = useState(tabs[0].id);
  const [copied, setCopied] = useState(false);
  const tab = tabs.find((t) => t.id === active) ?? tabs[0];

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(tab.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <div className="overflow-hidden rounded-[14px] border border-line bg-[#0a0f1c] shadow-[0_30px_80px_-40px_rgba(37,99,235,0.45)]">
      <div className="flex items-center justify-between border-b border-line px-3">
        {tabs.length === 1 ? (
          <span className="mono-label px-4 py-3.5 text-research">{tab.label}</span>
        ) : (
        <div role="tablist" aria-label="Code examples" className="flex">
          {tabs.map((t) => (
            <button
              key={t.id}
              role="tab"
              type="button"
              aria-selected={t.id === active}
              onClick={() => setActive(t.id)}
              className={`relative px-4 py-3.5 text-[13px] font-medium transition-colors ${t.id === active ? "text-ink" : "text-muted hover:text-ink"}`}
            >
              {t.label}
              {t.id === active && <span className="absolute inset-x-3 -bottom-px h-px bg-cobalt-bright" />}
            </button>
          ))}
        </div>
        )}
        <button type="button" onClick={copy} className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[12px] text-muted hover:text-ink" aria-label="Copy code">
          {copied ? <Check className="h-3.5 w-3.5 text-electric" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      {tab.badge && (
        <div className="border-b border-line/70 bg-research/[0.06] px-5 py-2.5">
          <span className="mono-label text-research">{tab.badge}</span>
        </div>
      )}
      <pre role={tabs.length > 1 ? "tabpanel" : undefined} className="overflow-x-auto p-5 text-[13.5px] leading-[1.75]">
        <code className="font-mono">
          {tab.code.split("\n").map((l, i) => (
            <span key={i} className="block min-h-[1.75em]">
              <span aria-hidden="true" className="mr-5 inline-block w-5 select-none text-right text-muted/60">
                {i + 1}
              </span>
              {highlight(l, tab.lang)}
            </span>
          ))}
        </code>
      </pre>
    </div>
  );
}
