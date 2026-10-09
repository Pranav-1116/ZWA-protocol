"use client";

/**
 * Section 02 visual (spec): "a vertically scrolling stack of fields".
 *
 *   LEGAL NAME / ACCREDITATION / COUNTRY / PORTFOLIO / ASSET / TERMS
 *     → animate them being transformed into →
 *   ELIGIBLE ✓ / AUTHORIZED ✓ / VALID ✓
 *
 * "The values disappear. The guarantees remain."
 *
 * Cycle while in view: scroll (3.2s) → values redact (1.6s) → guarantees (4.2s) → repeat.
 * Reduced motion: the guarantees, static.
 */

import { motion, useInView, useReducedMotion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { Check } from "lucide-react";

const fields = [
  { k: "Legal name", w: 64 },
  { k: "Accreditation", w: 52 },
  { k: "Country", w: 38 },
  { k: "Portfolio", w: 72 },
  { k: "Asset", w: 58 },
  { k: "Terms", w: 80 },
];
const guarantees = ["Eligible", "Authorized", "Valid"];

const ROW = 52; // px per field row
type Phase = 0 | 1 | 2;

function FieldRow({ k, w, phase, i }: { k: string; w: number; phase: Phase; i: number }) {
  return (
    <li className="flex items-center justify-between border-b border-line/60" style={{ height: ROW }}>
      <span className="mono-label text-body">{k}</span>
      <span className="relative block h-3" style={{ width: `${w * 1.6}px` }}>
        {/* abstract encoded value — never real personal data */}
        <motion.span
          className="absolute inset-0 rounded-[2px] bg-gradient-to-r from-slate-400/40 to-slate-400/20"
          animate={{ opacity: phase >= 1 ? 0.2 : 1 }}
          transition={{ delay: phase === 1 ? (i % 6) * 0.1 : 0, duration: 0.45 }}
        />
        <motion.span
          className="redacted absolute inset-0"
          initial={false}
          animate={{ scaleX: phase >= 1 ? 1 : 0 }}
          style={{ originX: 0 }}
          transition={{ delay: phase === 1 ? 0.15 + (i % 6) * 0.1 : 0, duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
        />
      </span>
    </li>
  );
}

export function FieldStack() {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { margin: "0px 0px -20% 0px" });
  const reduce = useReducedMotion();
  const [phase, setPhase] = useState<Phase>(0);
  const [cycle, setCycle] = useState(0);

  useEffect(() => {
    if (reduce) {
      setPhase(2);
      return;
    }
    if (!inView) return;
    setPhase(0);
    const a = setTimeout(() => setPhase(1), 3200);
    const b = setTimeout(() => setPhase(2), 4800);
    const c = setTimeout(() => setCycle((n) => n + 1), 9000);
    return () => {
      clearTimeout(a);
      clearTimeout(b);
      clearTimeout(c);
    };
  }, [inView, reduce, cycle]);

  // Two copies of the list so the vertical scroll loops seamlessly.
  const loop = [...fields, ...fields];

  return (
    <div ref={ref}>
      <div className="relative h-[364px] overflow-hidden rounded-[16px] border border-line bg-void/70 px-6 sm:px-8">
        {/* scrolling field stack */}
        <motion.div
          aria-hidden={phase === 2}
          className="absolute inset-x-6 top-0 sm:inset-x-8 [mask-image:linear-gradient(to_bottom,transparent,black_14%,black_86%,transparent)]"
          animate={{ opacity: phase < 2 ? 1 : 0, filter: phase < 2 ? "blur(0px)" : "blur(6px)" }}
          transition={{ duration: 0.45 }}
        >
          <motion.ul
            key={cycle}
            initial={{ y: 0 }}
            animate={reduce ? { y: 0 } : { y: phase === 0 ? -ROW * fields.length : -ROW * fields.length }}
            transition={phase === 0 ? { duration: 3.2, ease: "linear" } : { duration: 0 }}
          >
            {loop.map((f, i) => (
              <FieldRow key={`${f.k}-${i}`} k={f.k} w={f.w} phase={phase} i={i} />
            ))}
          </motion.ul>
        </motion.div>

        {/* guarantees */}
        <ul aria-hidden={phase < 2} className="pointer-events-none absolute inset-x-6 top-1/2 -translate-y-1/2 space-y-3 sm:inset-x-8">
          {guarantees.map((g, i) => (
            <motion.li
              key={g}
              initial={false}
              animate={phase === 2 ? { opacity: 1, y: 0 } : { opacity: 0, y: 12 }}
              transition={{ delay: phase === 2 ? 0.3 + i * 0.22 : 0, duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
              className="flex items-center justify-between rounded-[12px] border border-cobalt/35 bg-cobalt/[0.07] px-5 py-4"
            >
              <span className="text-[19px] font-semibold tracking-[0.06em] text-ink uppercase">{g}</span>
              <span className="inline-flex h-7 w-7 items-center justify-center rounded-full border border-cobalt-bright/70 bg-cobalt/20">
                <Check aria-hidden="true" className="h-4 w-4 text-electric" />
              </span>
            </motion.li>
          ))}
        </ul>
      </div>
      <p className="sr-only">
        Legal name, accreditation, country, portfolio, asset and terms are transformed into three guarantees: eligible,
        authorized and valid. The values disappear. The guarantees remain.
      </p>
    </div>
  );
}
