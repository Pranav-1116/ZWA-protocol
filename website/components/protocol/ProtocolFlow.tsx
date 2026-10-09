"use client";

/**
 * How ZWA works — ISSUE → PROVE → MATCH → SETTLE.
 * A cobalt line progresses with scroll and activates each stage in turn.
 * Hover or keyboard focus reveals one deeper technical layer per stage.
 */

import { motion, useMotionValueEvent, useReducedMotion, useScroll, useSpring } from "motion/react";
import { useRef, useState } from "react";

const stages = [
  {
    n: "01",
    title: "Issue",
    body: "An asset enters ZWA through an authorized issuance path.",
    layer: ["Asset", "Authorization", "Commitment"],
  },
  {
    n: "02",
    title: "Prove",
    body: "Private credentials and protocol conditions produce cryptographic evidence.",
    layer: ["Private witness", "ZK relation", "Proof"],
  },
  {
    n: "03",
    title: "Match",
    body: "Eligible counterparties can coordinate without publishing the underlying private state.",
    layer: ["Eligibility proof", "Trade commitment", "Single-use approval"],
  },
  {
    n: "04",
    title: "Settle",
    body: "Validated conditions resolve into private onchain settlement.",
    layer: ["Party consent", "Wallet authorization", "Shielded transfer"],
  },
];

export function ProtocolFlow() {
  const ref = useRef<HTMLDivElement>(null);
  const reduce = useReducedMotion();
  const { scrollYProgress } = useScroll({ target: ref, offset: ["start 75%", "end 55%"] });
  const progress = useSpring(scrollYProgress, { stiffness: 120, damping: 30, mass: 0.4 });
  const [active, setActive] = useState(reduce ? 4 : 0);
  const [focus, setFocus] = useState<number | null>(null);

  useMotionValueEvent(scrollYProgress, "change", (v) => {
    if (reduce) return;
    setActive(Math.min(4, Math.floor(v * 4 + 0.35)));
  });

  return (
    <div ref={ref} className="relative">
      {/* progress rail — horizontal on desktop, vertical on mobile */}
      <div aria-hidden="true" className="absolute left-0 right-0 top-[27px] hidden h-px bg-line lg:block">
        <motion.div className="h-px origin-left bg-gradient-to-r from-cobalt to-electric" style={{ scaleX: reduce ? 1 : progress }} />
      </div>
      <div aria-hidden="true" className="absolute bottom-6 left-[27px] top-6 w-px bg-line lg:hidden">
        <motion.div className="w-px origin-top bg-gradient-to-b from-cobalt to-electric" style={{ scaleY: reduce ? 1 : progress, height: "100%" }} />
      </div>

      <ol className="relative grid gap-10 lg:grid-cols-4 lg:gap-8">
        {stages.map((s, i) => {
          const on = i < active;
          const open = focus === i;
          return (
            <li key={s.n} className="relative pl-[76px] lg:pl-0">
              <button
                type="button"
                onMouseEnter={() => setFocus(i)}
                onMouseLeave={() => setFocus(null)}
                onFocus={() => setFocus(i)}
                onBlur={() => setFocus(null)}
                aria-expanded={open}
                aria-describedby={`stage-layer-${i}`}
                className="group block w-full cursor-default text-left focus-visible:outline-none"
              >
                <span
                  className={`absolute left-0 top-0 flex h-[55px] w-[55px] items-center justify-center rounded-full border font-mono text-[13px] transition-all duration-500 lg:relative ${
                    on
                      ? "border-cobalt-bright bg-[#101b3a] text-ink shadow-[0_0_24px_-4px_rgba(59,130,246,0.6)]"
                      : "border-line bg-[#0d1426] text-muted"
                  } group-focus-visible:ring-2 group-focus-visible:ring-electric`}
                >
                  {s.n}
                </span>
                <span className={`mono-label mt-0 block transition-colors duration-500 lg:mt-7 ${on ? "text-electric" : "text-muted"}`}>
                  {s.title}
                </span>
                <span className={`mt-3 block text-[17px] leading-relaxed transition-colors duration-500 ${on ? "text-ink" : "text-body"}`}>
                  {s.body}
                </span>

                <span
                  id={`stage-layer-${i}`}
                  className={`mt-5 block overflow-hidden rounded-[12px] border transition-all duration-500 ease-proof ${
                    open ? "max-h-56 border-line bg-surface/80 opacity-100" : "max-h-0 border-transparent opacity-0 lg:max-h-0"
                  }`}
                >
                  <span className="block p-4">
                    {s.layer.map((l, k) => (
                      <span key={l} className="block">
                        <span className="font-mono text-[13px] text-ink">{l}</span>
                        {k < s.layer.length - 1 && <span className="my-1 block pl-3 font-mono text-[12px] text-cobalt-bright">↓</span>}
                      </span>
                    ))}
                  </span>
                </span>
              </button>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
