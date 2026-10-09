"use client";

/**
 * Hero visual — hidden state → proof boundary → public guarantee.
 *
 * One ~8s cycle, drawn entirely in SVG (scales cleanly, no canvas, no WebGL):
 *   0.0–3.2s  encoded values leave the private rows and travel to ZWA
 *   3.2–4.6s  inside the boundary they compress into a single commitment
 *   4.6–7.0s  guarantees resolve one by one on the public side
 *   7.0–8.0s  rest, then repeat
 * Nothing that enters from the left ever exits on the right: only check
 * marks and a commitment leave the boundary.
 *
 * Under prefers-reduced-motion the final state is rendered statically.
 */

import { useReducedMotion } from "motion/react";
import { Check } from "lucide-react";

const DUR = "8s";
const privateRows = [
  { label: "Asset", y: 112 },
  { label: "Investor", y: 164 },
  { label: "Position", y: 216 },
  { label: "Terms", y: 268 },
];
const publicRows = [
  { label: "Authorized", y: 138, at: 0.6 },
  { label: "Eligible", y: 190, at: 0.68 },
  { label: "Settlement valid", y: 242, at: 0.76 },
];

const BOX = { x: 246, y: 120, w: 128, h: 140 };
const IN = { x: BOX.x, y: BOX.y + BOX.h / 2 };
const OUT = { x: BOX.x + BOX.w, y: BOX.y + BOX.h / 2 };
const CORE = { x: BOX.x + BOX.w / 2, y: BOX.y + 58 };

function t(v: number) {
  return Math.max(0, Math.min(1, v)).toFixed(3);
}

export function ProofBoundary({ className = "" }: { className?: string }) {
  const reduce = useReducedMotion();
  const animate = !reduce;

  return (
    <figure className={className}>
      {/* Desktop / tablet: full boundary diagram */}
      <svg
        viewBox="0 0 620 380"
        className="hidden h-auto w-full md:block"
        role="img"
        aria-labelledby="pb-title pb-desc"
      >
        <title id="pb-title">ZWA proof boundary</title>
        <desc id="pb-desc">
          Private asset, investor, position and terms data flows into the ZWA proof layer and compresses into
          commitments. Only three guarantees leave the boundary: authorized, eligible and settlement valid. Nothing
          private crosses the boundary.
        </desc>
        <defs>
          <linearGradient id="pb-in" x1="0" x2="1">
            <stop offset="0" stopColor="#94A3B8" stopOpacity="0" />
            <stop offset="1" stopColor="#94A3B8" stopOpacity="0.28" />
          </linearGradient>
          <linearGradient id="pb-out" x1="0" x2="1">
            <stop offset="0" stopColor="#3B82F6" stopOpacity="0.5" />
            <stop offset="1" stopColor="#3B82F6" stopOpacity="0.05" />
          </linearGradient>
          <radialGradient id="pb-core" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0" stopColor="#3B82F6" stopOpacity="0.35" />
            <stop offset="1" stopColor="#3B82F6" stopOpacity="0" />
          </radialGradient>
          <pattern id="pb-redact" width="8" height="10" patternUnits="userSpaceOnUse">
            <rect width="6" height="10" fill="#94A3B8" fillOpacity="0.3" />
          </pattern>
        </defs>

        {/* Boundary line: the thing private data never crosses */}
        <line x1={OUT.x + 16} y1="36" x2={OUT.x + 16} y2="344" stroke="#253047" strokeDasharray="2 6" />

        {/* ---------- PRIVATE ---------- */}
        <text x="0" y="52" fill="#64748B" fontFamily="var(--font-mono)" fontSize="11" letterSpacing="2">
          PRIVATE
        </text>
        <line x1="0" y1="64" x2="186" y2="64" stroke="#253047" />
        {privateRows.map((r, i) => (
          <g key={r.label}>
            <text x="0" y={r.y + 4} fill="#CBD5E1" fontFamily="var(--font-sans)" fontSize="14" fontWeight="500">
              {r.label}
            </text>
            <rect x="96" y={r.y - 5} width="80" height="10" fill="url(#pb-redact)" rx="1">
              {animate && (
                <animate
                  attributeName="opacity"
                  values="1;0.45;1"
                  dur={`${2.6 + i * 0.4}s`}
                  repeatCount="indefinite"
                />
              )}
            </rect>
            <path
              d={`M184 ${r.y} C 214 ${r.y}, 220 ${IN.y}, ${IN.x} ${IN.y}`}
              fill="none"
              stroke="url(#pb-in)"
              strokeWidth="1"
            />
          </g>
        ))}

        {/* Particles travelling into the boundary */}
        {animate &&
          privateRows.flatMap((r, i) =>
            [0, 1].map((k) => {
              const s = 0.02 + i * 0.07 + k * 0.12;
              const e = s + 0.22;
              const path = `M184 ${r.y} C 214 ${r.y}, 220 ${IN.y}, ${IN.x} ${IN.y} L ${CORE.x} ${CORE.y}`;
              return (
                <circle key={`${i}-${k}`} r="2" fill="#94A3B8" opacity="0">
                  <animateMotion
                    dur={DUR}
                    repeatCount="indefinite"
                    path={path}
                    keyPoints="0;0;1;1"
                    keyTimes={`0;${t(s)};${t(e)};1`}
                    calcMode="linear"
                  />
                  <animate
                    attributeName="opacity"
                    dur={DUR}
                    repeatCount="indefinite"
                    values="0;0;0.9;0.9;0;0"
                    keyTimes={`0;${t(s)};${t(s + 0.02)};${t(e - 0.02)};${t(e)};1`}
                  />
                  <animate
                    attributeName="fill"
                    dur={DUR}
                    repeatCount="indefinite"
                    values="#94A3B8;#94A3B8;#60A5FA;#60A5FA"
                    keyTimes={`0;${t(e - 0.08)};${t(e - 0.02)};1`}
                  />
                </circle>
              );
            }),
          )}

        {/* ---------- ZWA PROOF LAYER ---------- */}
        <rect
          x={BOX.x - 14}
          y={BOX.y - 14}
          width={BOX.w + 28}
          height={BOX.h + 28}
          rx="24"
          fill="none"
          stroke="#2563EB"
          strokeOpacity="0.14"
        />
        <rect x={BOX.x} y={BOX.y} width={BOX.w} height={BOX.h} rx="18" fill="#0B1020" stroke="#2563EB" strokeOpacity="0.7" />
        <circle cx={CORE.x} cy={CORE.y} r="34" fill="url(#pb-core)">
          {animate && (
            <animate
              attributeName="opacity"
              dur={DUR}
              repeatCount="indefinite"
              values="0.3;0.3;1;1;0.3;0.3"
              keyTimes="0;0.36;0.5;0.62;0.8;1"
            />
          )}
        </circle>
        {/* compression: scattered points collapse into one commitment */}
        {[
          [-16, -10],
          [14, -12],
          [-10, 12],
          [16, 9],
          [0, -18],
          [-20, 2],
        ].map(([dx, dy], i) => (
          <circle key={i} cx={CORE.x + dx} cy={CORE.y + dy} r="1.6" fill="#60A5FA" opacity="0">
            {animate && (
              <>
                <animate
                  attributeName="opacity"
                  dur={DUR}
                  repeatCount="indefinite"
                  values="0;0;0.9;0.9;0;0"
                  keyTimes="0;0.38;0.42;0.54;0.58;1"
                />
                <animate
                  attributeName="cx"
                  dur={DUR}
                  repeatCount="indefinite"
                  values={`${CORE.x + dx};${CORE.x + dx};${CORE.x + dx};${CORE.x};${CORE.x}`}
                  keyTimes="0;0.38;0.44;0.56;1"
                />
                <animate
                  attributeName="cy"
                  dur={DUR}
                  repeatCount="indefinite"
                  values={`${CORE.y + dy};${CORE.y + dy};${CORE.y + dy};${CORE.y};${CORE.y}`}
                  keyTimes="0;0.38;0.44;0.56;1"
                />
              </>
            )}
          </circle>
        ))}
        <circle cx={CORE.x} cy={CORE.y} r="3.2" fill="#60A5FA">
          {animate && (
            <animate
              attributeName="r"
              dur={DUR}
              repeatCount="indefinite"
              values="2.4;2.4;4.4;3.2;3.2"
              keyTimes="0;0.55;0.58;0.64;1"
            />
          )}
        </circle>
        <text
          x={CORE.x}
          y={BOX.y + 100}
          textAnchor="middle"
          fill="#F8FAFC"
          fontFamily="var(--font-sans)"
          fontSize="17"
          fontWeight="700"
          letterSpacing="2.5"
        >
          ZWA
        </text>
        <text
          x={CORE.x}
          y={BOX.y + 118}
          textAnchor="middle"
          fill="#94A3B8"
          fontFamily="var(--font-mono)"
          fontSize="8.5"
          letterSpacing="1.6"
        >
          PROOF LAYER
        </text>

        {/* ---------- PUBLIC / VERIFIED ---------- */}
        <text x="430" y="52" fill="#60A5FA" fontFamily="var(--font-mono)" fontSize="11" letterSpacing="2">
          VERIFIED
        </text>
        <line x1="430" y1="64" x2="620" y2="64" stroke="#253047" />
        {publicRows.map((r) => {
          const path = `M${OUT.x} ${OUT.y} C ${OUT.x + 30} ${OUT.y}, 396 ${r.y}, 426 ${r.y}`;
          return (
            <g key={r.label}>
              <path d={path} fill="none" stroke="url(#pb-out)" strokeWidth="1" />
              {animate && (
                <circle r="2.2" fill="#60A5FA" opacity="0">
                  <animateMotion
                    dur={DUR}
                    repeatCount="indefinite"
                    path={path}
                    keyPoints="0;0;1;1"
                    keyTimes={`0;${t(r.at - 0.06)};${t(r.at)};1`}
                    calcMode="linear"
                  />
                  <animate
                    attributeName="opacity"
                    dur={DUR}
                    repeatCount="indefinite"
                    values="0;0;1;1;0;0"
                    keyTimes={`0;${t(r.at - 0.06)};${t(r.at - 0.05)};${t(r.at - 0.005)};${t(r.at)};1`}
                  />
                </circle>
              )}
              <g opacity={animate ? 0.25 : 1}>
                {animate && (
                  <animate
                    attributeName="opacity"
                    dur={DUR}
                    repeatCount="indefinite"
                    values="0.25;0.25;1;1;0.25"
                    keyTimes={`0;${t(r.at - 0.005)};${t(r.at + 0.02)};0.9;1`}
                  />
                )}
                <circle cx="442" cy={r.y} r="9" fill="#2563EB" fillOpacity="0.16" stroke="#3B82F6" strokeOpacity="0.7" />
                <path
                  d={`M437.5 ${r.y} l3 3 l5.5 -6`}
                  fill="none"
                  stroke="#60A5FA"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <text x="462" y={r.y + 5} fill="#F8FAFC" fontFamily="var(--font-sans)" fontSize="14.5" fontWeight="600">
                  {r.label}
                </text>
              </g>
            </g>
          );
        })}
      </svg>

      {/* Mobile: vertical, lightweight */}
      <div className="md:hidden" aria-hidden="true">
        <div className="rounded-[14px] border border-line bg-surface/70 p-5">
          <p className="mono-label text-muted">Private data</p>
          <ul className="mt-3 space-y-2.5">
            {privateRows.map((r) => (
              <li key={r.label} className="flex items-center justify-between text-[15px] text-ink">
                {r.label}
                <span className="redacted h-2.5 w-20" />
              </li>
            ))}
          </ul>
        </div>
        <div className="flex flex-col items-center py-3">
          <span className="h-6 w-px bg-gradient-to-b from-line to-cobalt" />
          <div className="rounded-[12px] border border-cobalt/70 bg-deep px-6 py-3 text-center">
            <span className="block text-[15px] font-bold tracking-[0.18em] text-ink">ZWA</span>
            <span className="mono-label text-[10px] text-body">Proof layer</span>
          </div>
          <span className="h-6 w-px bg-gradient-to-b from-cobalt to-line" />
        </div>
        <div className="rounded-[14px] border border-cobalt/40 bg-surface/70 p-5">
          <p className="mono-label text-electric">Verified</p>
          <ul className="mt-3 space-y-2.5">
            {publicRows.map((r) => (
              <li key={r.label} className="flex items-center gap-2.5 text-[15px] font-semibold text-ink">
                <Check className="h-4 w-4 text-electric" /> {r.label}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </figure>
  );
}
