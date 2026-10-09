"use client";

/**
 * Architecture — four horizontal layers. Hover/focus activates a layer;
 * click/Enter opens a side drawer (native <dialog>: focus trap + Esc for free)
 * so visitors never leave the homepage for detail.
 */

import { Fragment, useEffect, useRef, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { ArrowRight, X } from "lucide-react";
import { ResearchStatus } from "@/components/research/ResearchStatus";
import type { Status } from "@/lib/research";

type Layer = {
  id: string;
  name: string;
  items: string[];
  accent?: boolean;
  summary: string;
  detail: { title: string; body: string; status?: Status; statusLabel?: string }[];
};

const layers: Layer[] = [
  {
    id: "apps",
    name: "Applications",
    items: ["Issuers", "Markets", "Custodians"],
    summary: "Institutions integrate ZWA where they already operate. ZWA is infrastructure, not a marketplace or exchange.",
    detail: [
      { title: "Issuers", body: "Create assets through an authorized issuance path and attach policy." },
      { title: "Markets", body: "Coordinate eligible counterparties without publishing private positions or terms." },
      { title: "Custodians", body: "Keep spending authority with the party's own wallet. ZWA never holds it." },
    ],
  },
  {
    id: "zwa",
    name: "ZWA",
    items: ["Policy", "Credentials", "Trade commitments", "Private lineage", "Settlement"],
    accent: true,
    summary: "The protocol layer: what must be proven, how it is committed to, and how approval becomes settlement.",
    detail: [
      { title: "Credentials", body: "Issuer-rooted credentials with domain-separated encodings.", status: "established", statusLabel: "Frozen · M1" },
      { title: "Trade commitments", body: "TradeCommitmentV1 binds an approved trade to its exact terms.", status: "established", statusLabel: "Frozen · M1" },
      { title: "Matching", body: "Eligibility-gated matching with single-use approvals and replay protection.", status: "established", statusLabel: "Accepted · M2" },
      { title: "Settlement authorization", body: "Credential-authority-attested party consent for the exact approved trade.", status: "research", statusLabel: "In review · M3" },
      { title: "Private lineage", body: "Supported ancestry for non-split paths under stated assumptions.", status: "conditional" },
    ],
  },
  {
    id: "proof",
    name: "Proof system",
    items: ["Circuits", "Commitments", "Verification"],
    summary: "Circom predicates and Groth16 verification over Poseidon commitments.",
    detail: [
      { title: "Circuits", body: "Eligibility and provenance predicates written in Circom.", status: "established" },
      { title: "Commitments", body: "Poseidon over BN254 with fixed, domain-separated encodings and test vectors.", status: "established" },
      {
        title: "Verification keys",
        body: "Current keys come from a development ceremony variant. Production keys require owner re-issuance or approval.",
        status: "open",
        statusLabel: "Open gate",
      },
    ],
  },
  {
    id: "zcash",
    name: "Zcash",
    items: ["Orchard / ZSA", "Shielded state", "Consensus"],
    summary: "Private settlement targets Zcash shielded assets. Zcash consensus does not enforce ZWA compliance.",
    detail: [
      { title: "Orchard / ZSA", body: "Zcash Shielded Assets are experimental and not available on mainnet.", status: "research", statusLabel: "Experimental" },
      { title: "Wallet authorization", body: "In settlement, each party's wallet authorizes its own Zcash spend.", status: "open", statusLabel: "Not started · M4" },
      { title: "Consensus boundary", body: "Chain rules validate transactions; ZWA policy checks happen above consensus.", status: "open" },
    ],
  },
];

export function ArchitectureStack() {
  const [hover, setHover] = useState<string | null>(null);
  const [selected, setSelected] = useState<Layer | null>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const reduce = useReducedMotion();

  useEffect(() => {
    const d = dialogRef.current;
    if (!d) return;
    if (selected && !d.open) d.showModal();
    if (!selected && d.open) d.close();
  }, [selected]);

  return (
    <>
      <ol className="relative" aria-label="ZWA architecture layers, top to bottom">
        {layers.map((l, i) => {
          const active = hover === l.id;
          return (
            <Fragment key={l.id}>
            {i > 0 && (
              <li aria-hidden="true" className="relative flex h-10 justify-center">
                {/* AnimatedBeam-style vertical connector: a faint rail with a travelling pulse */}
                <span className="h-full w-px bg-gradient-to-b from-line via-cobalt/50 to-line" />
                {!reduce && (
                  <motion.span
                    className="absolute left-1/2 h-4 w-[2px] -translate-x-1/2 rounded-full bg-gradient-to-b from-transparent via-electric to-transparent shadow-[0_0_8px_rgba(96,165,250,0.8)]"
                    initial={{ top: "-30%" }}
                    animate={{ top: ["-30%", "110%"] }}
                    transition={{ duration: 1.6, ease: "easeInOut", repeat: Infinity, repeatDelay: 1.2, delay: i * 0.45 }}
                  />
                )}
              </li>
            )}
            <li>
              <button
                type="button"
                onMouseEnter={() => setHover(l.id)}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover(l.id)}
                onBlur={() => setHover(null)}
                onClick={() => setSelected(l)}
                aria-haspopup="dialog"
                className={`group relative grid w-full gap-4 overflow-hidden rounded-[14px] border px-5 py-5 text-left transition-all duration-300 ease-proof sm:px-7 lg:grid-cols-[220px_1fr_auto] lg:items-center lg:gap-8 ${
                  l.accent
                    ? "border-cobalt/60 bg-gradient-to-r from-cobalt/[0.14] to-surface"
                    : active
                      ? "border-[#3a4866] bg-elevated"
                      : "border-line bg-surface/60"
                }`}
              >
                <span className="flex items-center gap-4">
                  <span className={`text-[20px] font-semibold tracking-[-0.01em] ${l.accent ? "text-ink" : "text-ink/90"}`}>{l.name}</span>
                </span>
                <span className="flex flex-wrap gap-2">
                  {l.items.map((it) => (
                    <span
                      key={it}
                      className={`rounded-[8px] border px-3 py-1.5 font-mono text-[12.5px] transition-colors duration-300 ${
                        l.accent || active ? "border-cobalt/40 text-ink" : "border-line text-body"
                      }`}
                    >
                      {it}
                    </span>
                  ))}
                </span>
                <span className="mono-label inline-flex items-center gap-2 text-muted transition-colors group-hover:text-electric">
                  Details <ArrowRight aria-hidden="true" className="h-3.5 w-3.5 transition-transform group-hover:translate-x-1" />
                </span>
                {active && <span aria-hidden="true" className="pointer-events-none absolute inset-y-0 left-0 w-[3px] bg-cobalt-bright" />}
              </button>
            </li>
            </Fragment>
          );
        })}
      </ol>

      <dialog
        ref={dialogRef}
        onClose={() => setSelected(null)}
        onClick={(e) => e.target === e.currentTarget && setSelected(null)}
        aria-labelledby="arch-drawer-title"
        className="fixed inset-y-0 right-0 left-auto m-0 h-full max-h-none w-full max-w-[480px] border-l border-line bg-deep p-0 text-body backdrop:bg-void/70 backdrop:backdrop-blur-sm open:animate-[drawer_.35s_cubic-bezier(.22,1,.36,1)]"
      >
        {selected && (
          <div className="flex h-full flex-col">
            <div className="flex items-start justify-between border-b border-line px-7 py-6">
              <div>
                <h3 id="arch-drawer-title" className="text-[28px]">
                  {selected.name}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="-mr-2 inline-flex h-10 w-10 items-center justify-center rounded-md text-body hover:text-ink"
                aria-label="Close"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-7 py-6">
              <p className="text-[16px] leading-relaxed text-ink/90">{selected.summary}</p>
              <ul className="mt-8 divide-y divide-line border-y border-line">
                {selected.detail.map((d) => (
                  <li key={d.title} className="py-5">
                    <div className="flex items-center justify-between gap-4">
                      <h4 className="text-[16px] font-semibold">{d.title}</h4>
                      {d.status && <ResearchStatus status={d.status} label={d.statusLabel} />}
                    </div>
                    <p className="mt-2 text-[15px] leading-relaxed">{d.body}</p>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </dialog>
    </>
  );
}
