"use client";

/**
 * The signature ZWA moment — the Privacy Boundary.
 *
 * As the user scrolls, private information moves toward a thin vertical
 * boundary. Values progressively disappear; nothing crosses. On the other side
 * only three statements survive, then PROOF VERIFIED.
 *
 * Desktop: sticky stage driven by scroll position (no scroll-jacking — the
 * page scrolls normally, the stage just stays pinned while it plays).
 * Mobile and reduced motion: a static, vertical rendering of the end state.
 */

import { motion, useReducedMotion, useScroll, useTransform, type MotionValue } from "motion/react";
import { useRef } from "react";
import { Check } from "lucide-react";

const items = [
  { label: "Identity", value: "7f3a 91c2 e04b" },
  { label: "Asset", value: "zsa:4be1 · 25,000" },
  { label: "Position", value: "b88d 0c17 a5f2" },
  { label: "Policy", value: "accredited · jurisdiction" },
];
const outputs = ["Authorized", "Eligible", "Valid"];

function PrivateItem({ p, i, label, value }: { p: MotionValue<number>; i: number; label: string; value: string }) {
  const s = 0.06 + i * 0.05;
  const x = useTransform(p, [s, s + 0.36], ["0%", "78%"]);
  const valueOpacity = useTransform(p, [s + 0.04, s + 0.26], [1, 0]);
  const valueBlur = useTransform(p, [s + 0.02, s + 0.24], ["blur(0px)", "blur(8px)"]);
  const maskScale = useTransform(p, [s + 0.08, s + 0.24], [0, 1]);
  const rowOpacity = useTransform(p, [s + 0.3, s + 0.37], [1, 0]);

  return (
    <motion.li style={{ x, opacity: rowOpacity }} className="flex items-center justify-between gap-6 rounded-[12px] border border-line bg-surface/80 px-5 py-4">
      <span className="text-[18px] font-semibold text-ink">{label}</span>
      <span className="relative font-mono text-[13px] text-body">
        <motion.span style={{ opacity: valueOpacity, filter: valueBlur }} className="block whitespace-nowrap">
          {value}
        </motion.span>
        <motion.span aria-hidden="true" style={{ scaleX: maskScale, originX: 0 }} className="redacted absolute inset-y-[3px] left-0 right-0" />
      </span>
    </motion.li>
  );
}

function Output({ p, i, label }: { p: MotionValue<number>; i: number; label: string }) {
  const s = 0.5 + i * 0.07;
  const opacity = useTransform(p, [s, s + 0.06], [0, 1]);
  const y = useTransform(p, [s, s + 0.08], [14, 0]);
  const blur = useTransform(p, [s, s + 0.07], ["blur(6px)", "blur(0px)"]);
  return (
    <motion.li style={{ opacity, y, filter: blur }} className="flex items-center gap-4">
      <span className="inline-flex h-8 w-8 items-center justify-center rounded-full border border-cobalt-bright/70 bg-cobalt/15">
        <Check aria-hidden="true" className="h-4 w-4 text-electric" />
      </span>
      <span className="text-[28px] font-semibold tracking-[0.08em] text-ink uppercase xl:text-[32px]">{label}</span>
    </motion.li>
  );
}

function StaticBoundary() {
  return (
    <div className="grid gap-6">
      <ul className="space-y-3">
        {items.map((it) => (
          <li key={it.label} className="flex items-center justify-between rounded-[12px] border border-line bg-surface/70 px-5 py-4">
            <span className="text-[17px] font-semibold text-ink">{it.label}</span>
            <span aria-label="redacted" className="redacted h-3 w-24" />
          </li>
        ))}
      </ul>
      <div aria-hidden="true" className="relative flex items-center justify-center py-2">
        <span className="h-px w-full bg-gradient-to-r from-transparent via-cobalt-bright to-transparent" />
      </div>
      <ul className="space-y-3">
        {outputs.map((o) => (
          <li key={o} className="flex items-center gap-3 text-[22px] font-semibold tracking-[0.08em] text-ink uppercase">
            <Check aria-hidden="true" className="h-5 w-5 text-electric" /> {o}
          </li>
        ))}
      </ul>
      <p className="mono-label text-electric">Proof verified</p>
    </div>
  );
}

export function PrivacyBoundary() {
  const ref = useRef<HTMLDivElement>(null);
  const reduce = useReducedMotion();
  const { scrollYProgress: p } = useScroll({ target: ref, offset: ["start start", "end end"] });

  const lineGlow = useTransform(p, [0.25, 0.5, 0.9], [0.25, 1, 0.7]);
  const lineScale = useTransform(p, [0, 0.2], [0.4, 1]);
  const verified = useTransform(p, [0.78, 0.86], [0, 1]);
  const verifiedY = useTransform(p, [0.78, 0.86], [10, 0]);

  return (
    <div>
      <p className="sr-only">
        Animated illustration: identity, asset, position and policy move toward the ZWA proof boundary and their values
        disappear. Only authorized, eligible and valid are visible on the other side, followed by proof verified.
      </p>

      {/* Mobile, tablet and reduced motion */}
      <div className={reduce ? "" : "lg:hidden"} aria-hidden="true">
        <StaticBoundary />
      </div>

      {/* Desktop scroll stage */}
      {!reduce && (
        <div ref={ref} className="relative hidden h-[240vh] lg:block" aria-hidden="true">
          <div className="sticky top-0 flex h-screen items-center">
            <div className="relative grid w-full grid-cols-[1fr_1px_1fr] items-center gap-0">
              <div className="pr-16">
                <ul className="max-w-[440px] space-y-3">
                  {items.map((it, i) => (
                    <PrivateItem key={it.label} p={p} i={i} label={it.label} value={it.value} />
                  ))}
                </ul>
              </div>

              <div className="relative h-[62vh] w-px">
              <motion.div style={{ scaleY: lineScale }} className="relative h-full w-px origin-center">
                <motion.span style={{ opacity: lineGlow }} className="absolute inset-0 bg-gradient-to-b from-transparent via-cobalt-bright to-transparent" />
                <motion.span
                  style={{ opacity: lineGlow }}
                  className="absolute inset-y-[20%] -left-6 w-12 bg-[radial-gradient(closest-side,rgba(59,130,246,0.22),transparent)]"
                />
              </motion.div>
              </div>

              <div className="pl-16">
                <ul className="space-y-6">
                  {outputs.map((o, i) => (
                    <Output key={o} p={p} i={i} label={o} />
                  ))}
                </ul>
                <motion.div
                  style={{ opacity: verified, y: verifiedY }}
                  className="mt-10 inline-flex items-center gap-3 rounded-full border border-cobalt/50 bg-cobalt/10 px-4 py-2"
                >
                  <span className="h-2 w-2 rounded-full bg-electric shadow-[0_0_12px_rgba(96,165,250,0.9)]" />
                  <span className="mono-label text-ink">Proof verified</span>
                </motion.div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
