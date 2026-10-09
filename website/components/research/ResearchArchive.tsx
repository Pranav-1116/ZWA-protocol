"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { ArrowUpRight } from "lucide-react";
import { researchItems, type Topic } from "@/lib/research";
import { ResearchStatus } from "./ResearchStatus";

const filters: { id: "all" | Topic; label: string }[] = [
  { id: "all", label: "All" },
  { id: "lineage", label: "Lineage" },
  { id: "settlement", label: "Settlement" },
  { id: "circuits", label: "Circuits" },
  { id: "consensus", label: "Consensus" },
  { id: "protocol", label: "Protocol" },
];

export function ResearchArchive() {
  const params = useSearchParams();
  const router = useRouter();
  const raw = params.get("topic");
  const active = (filters.find((f) => f.id === raw)?.id ?? "all") as "all" | Topic;
  const items = active === "all" ? researchItems : researchItems.filter((r) => r.topic === active);

  return (
    <div>
      <div role="toolbar" aria-label="Filter research by topic" className="scrollbar-none -mx-5 flex gap-2 overflow-x-auto px-5 sm:mx-0 sm:px-0">
        {filters.map((f) => {
          const on = f.id === active;
          return (
            <button
              key={f.id}
              type="button"
              aria-pressed={on}
              onClick={() => router.replace(f.id === "all" ? "/research" : `/research?topic=${f.id}`, { scroll: false })}
              className={`mono-label shrink-0 rounded-full border px-4 py-2 transition-colors ${
                on ? "border-cobalt bg-cobalt/15 text-ink" : "border-line text-muted hover:border-[#3a4866] hover:text-ink"
              }`}
            >
              {f.label}
            </button>
          );
        })}
      </div>

      <ul className="mt-10 divide-y divide-line border-y border-line" aria-live="polite">
        {items.map((r) => (
          <li key={r.id}>
            <a
              href={r.href}
              target="_blank"
              rel="noreferrer noopener"
              className="group grid gap-4 py-8 transition-colors hover:bg-surface/40 sm:px-4 lg:grid-cols-[220px_1fr_200px] lg:gap-10"
            >
              <div className="space-y-3">
                <p className="mono-label text-muted">{r.code}</p>
                <ResearchStatus status={r.status} />
              </div>
              <div>
                <h3 className="text-[22px] tracking-[-0.02em] transition-colors group-hover:text-electric">{r.title}</h3>
                <p className="mt-2 max-w-[44rem] text-[16px]">{r.summary}</p>
              </div>
              <div className="flex items-start justify-between gap-4 lg:flex-col lg:items-end">
                <span className="mono-label text-muted">Updated {r.updated}</span>
                <span className="inline-flex items-center gap-1.5 text-[15px] font-semibold text-ink group-hover:text-electric">
                  Read research <ArrowUpRight aria-hidden="true" className="h-4 w-4" />
                </span>
              </div>
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}
