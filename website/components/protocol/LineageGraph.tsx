"use client";

/**
 * Section 05 visual (spec):
 *
 *   AUTHORIZED
 *   ISSUANCE
 *   ● ───── ● ───── ● ───── ●
 *             ╲       ╲
 *            hidden intermediate state
 *                            ↓
 *                       TERMINAL
 *                     AUTHENTICATED
 *
 * A horizontally moving chain (animation class D: pulses travel along the
 * path). Intermediate nodes are blurred by default; hover / focus expands a
 * node to Commitment · Nullifier · Proof. Abstract identifiers only — never
 * personal data.
 */

import { motion, useInView, useReducedMotion } from "motion/react";
import { useRef, useState } from "react";
import { HashChip } from "@/components/ui/HashChip";

const hidden = [
  { id: "h1", cm: "0x1c9e5f02b7a4a04f", nf: "0x77d2c0f19ae3e1b8", pf: "0x3b6e0a9d4c21f7aa" },
  { id: "h2", cm: "0x5a31e8d4720b0c6d", nf: "0x2fe07ab3c6d194a7", pf: "0x9c04f2e1b7a3d812" },
  { id: "h3", cm: "0xb40d93a6ce5f7e12", nf: "0xc8a91e0b5d723f05", pf: "0x61f3a8c0e9d2b47c" },
];

export function LineageGraph() {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "0px 0px -20% 0px" });
  const reduce = useReducedMotion();
  const [open, setOpen] = useState<string | null>(null);
  const shown = inView || !!reduce;

  return (
    <div ref={ref} className="relative">
      <p className="sr-only">
        Diagram: an authorized issuance connects through hidden intermediate state to a terminal that is authenticated.
        Each intermediate node exposes only a commitment, a nullifier and a proof.
      </p>
      <div className="scrollbar-none -mx-5 overflow-x-auto px-5 pb-2 sm:mx-0 sm:px-0">
        <div className="relative min-h-[300px] min-w-[760px] pt-2">
          {/* chain rail */}
          <div aria-hidden="true" className="absolute left-[10%] right-[10%] top-[44px] h-[2px] overflow-hidden bg-paper-line">
            <motion.div
              className="h-full origin-left bg-cobalt"
              initial={{ scaleX: reduce ? 1 : 0 }}
              animate={{ scaleX: shown ? 1 : 0 }}
              transition={{ duration: 1.8, ease: [0.65, 0, 0.35, 1], delay: 0.2 }}
            />
            {/* horizontally moving pulses */}
            {!reduce &&
              [0, 1.4, 2.8].map((d) => (
                <motion.span
                  key={d}
                  className="absolute top-0 h-full w-24 bg-gradient-to-r from-transparent via-electric to-transparent"
                  initial={{ left: "-10%" }}
                  animate={shown ? { left: "105%" } : { left: "-10%" }}
                  transition={{ duration: 4.2, ease: "linear", repeat: Infinity, delay: 2 + d }}
                />
              ))}
          </div>

          <ol className="relative grid grid-cols-5">
            {/* AUTHORIZED ISSUANCE */}
            <li className="flex flex-col items-center text-center">
              <motion.span
                initial={{ opacity: reduce ? 1 : 0, scale: reduce ? 1 : 0.85 }}
                animate={{ opacity: shown ? 1 : 0, scale: shown ? 1 : 0.85 }}
                transition={{ delay: 0.2, duration: 0.5 }}
                className="flex h-[88px] w-[88px] items-center justify-center"
              >
                <span className="flex h-[52px] w-[52px] items-center justify-center rounded-full border-2 border-cobalt bg-white shadow-[0_8px_24px_-8px_rgba(37,99,235,0.6)]">
                  <span className="h-3 w-3 rotate-45 bg-research" />
                </span>
              </motion.span>
              <span className="mono-label text-paper-ink">
                Authorized
                <br />
                Issuance
              </span>
            </li>

            {/* hidden intermediate nodes */}
            {hidden.map((n, i) => {
              const isOpen = open === n.id;
              return (
                <li key={n.id} className="relative flex flex-col items-center text-center">
                  <motion.button
                    type="button"
                    onMouseEnter={() => setOpen(n.id)}
                    onMouseLeave={() => setOpen(null)}
                    onFocus={() => setOpen(n.id)}
                    onBlur={(e) => !e.currentTarget.parentElement?.contains(e.relatedTarget as Node) && setOpen(null)}
                    onClick={() => setOpen(isOpen ? null : n.id)}
                    aria-expanded={isOpen}
                    aria-controls={`node-${n.id}`}
                    aria-label={`Intermediate node ${i + 1}: show commitment, nullifier and proof`}
                    initial={{ opacity: reduce ? 1 : 0, scale: reduce ? 1 : 0.85 }}
                    animate={{ opacity: shown ? 1 : 0, scale: shown ? 1 : 0.85 }}
                    transition={{ delay: 0.6 + i * 0.4, duration: 0.5 }}
                    className="flex h-[88px] w-[88px] cursor-pointer items-center justify-center rounded-full"
                  >
                    <span
                      className={`flex h-[40px] w-[40px] items-center justify-center rounded-full border bg-white transition-all duration-300 ${
                        isOpen ? "scale-110 border-cobalt blur-0" : "border-paper-line blur-[2px]"
                      }`}
                    >
                      <span className={`h-2.5 w-2.5 rounded-full transition-colors ${isOpen ? "bg-cobalt" : "bg-slate-400"}`} />
                    </span>
                  </motion.button>
                  <div
                    id={`node-${n.id}`}
                    onMouseEnter={() => setOpen(n.id)}
                    onMouseLeave={() => setOpen(null)}
                    className={`absolute left-1/2 top-[92px] z-10 w-[164px] -translate-x-1/2 overflow-hidden rounded-[10px] border text-left transition-all duration-300 ease-proof ${
                      isOpen ? "max-h-48 border-paper-line bg-white opacity-100 shadow-[0_12px_32px_-16px_rgba(7,10,18,0.35)]" : "max-h-0 border-transparent opacity-0"
                    }`}
                  >
                    <dl className="space-y-2 p-3">
                      {[
                        ["Commitment", n.cm],
                        ["Nullifier", n.nf],
                        ["Proof", n.pf],
                      ].map(([k, v]) => (
                        <div key={k}>
                          <dt className="font-mono text-[10.5px] tracking-[0.12em] text-paper-body/70 uppercase">{k}</dt>
                          <dd>
                            <HashChip value={v} tone="light" />
                          </dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                </li>
              );
            })}

            {/* TERMINAL AUTHENTICATED */}
            <li className="flex flex-col items-center text-center">
              <motion.span
                initial={{ opacity: reduce ? 1 : 0, scale: reduce ? 1 : 0.85 }}
                animate={{ opacity: shown ? 1 : 0, scale: shown ? 1 : 0.85 }}
                transition={{ delay: 1.9, duration: 0.5 }}
                className="flex h-[88px] w-[88px] items-center justify-center"
              >
                <span className="flex h-[52px] w-[52px] items-center justify-center rounded-full bg-cobalt shadow-[0_8px_28px_-6px_rgba(37,99,235,0.8)]">
                  <svg viewBox="0 0 16 16" className="h-5 w-5" aria-hidden="true">
                    <path d="M3.5 8.5l3 3 6-7" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </span>
              </motion.span>
              <span className="mono-label text-paper-ink">
                Terminal
                <br />
                Authenticated
              </span>
            </li>
          </ol>

          <div aria-hidden="true" className="pointer-events-none mt-3 grid grid-cols-5">
            <span />
            <span className="col-span-3 mx-8 border-t border-dashed border-paper-line pt-2 text-center font-mono text-[11px] tracking-[0.1em] text-paper-body/80 uppercase">
              hidden intermediate state
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
