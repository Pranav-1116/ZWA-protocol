"use client";

/**
 * /demo — simulated private asset settlement.
 * Purely illustrative: no proof is generated, nothing leaves the browser,
 * no transaction is built or sent.
 */

import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { useEffect, useState } from "react";
import { ArrowRight, Check, EyeOff, Loader2, RotateCcw } from "lucide-react";

const steps = [{ t: "Issue asset" }, { t: "Add private credential" }, { t: "Build trade" }, { t: "Verify conditions" }, { t: "Settle" }];

const inputs = [
  { k: "Investor", from: 1 },
  { k: "Credential", from: 1 },
  { k: "Asset state", from: 0 },
];

const checks = [
  { k: "Eligibility valid", at: 3 },
  { k: "Issuance authorized", at: 3 },
  { k: "Settlement permitted", at: 4 },
];

export function DemoWalkthrough() {
  const [step, setStep] = useState(0);
  const [proving, setProving] = useState(false);
  const reduce = useReducedMotion();

  useEffect(() => {
    if (step !== 3) return;
    setProving(true);
    const id = setTimeout(() => setProving(false), reduce ? 0 : 1800);
    return () => clearTimeout(id);
  }, [step, reduce]);

  const done = step === steps.length - 1 && !proving;
  const proofState = step < 3 ? "Waiting for inputs" : proving ? "Generating…" : "Verified";

  return (
    <div className="grid gap-8 lg:grid-cols-12">
      {/* Steps */}
      <div className="lg:col-span-5">
        <ol className="space-y-2" aria-label="Walkthrough steps">
          {steps.map((s, i) => {
            const state = i < step ? "done" : i === step ? "current" : "todo";
            return (
              <li key={s.t}>
                <button
                  type="button"
                  onClick={() => setStep(i)}
                  aria-current={state === "current" ? "step" : undefined}
                  className={`flex w-full items-center gap-4 rounded-[12px] border p-4 text-left transition-colors ${
                    state === "current" ? "border-cobalt/60 bg-cobalt/[0.08]" : "border-transparent hover:bg-surface/60"
                  }`}
                >
                  <span
                    className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full border font-mono text-[12px] ${
                      state === "done"
                        ? "border-cobalt-bright bg-cobalt/25 text-electric"
                        : state === "current"
                          ? "border-cobalt-bright text-ink"
                          : "border-line text-muted"
                    }`}
                  >
                    {state === "done" ? <Check className="h-3.5 w-3.5" aria-label="done" /> : i + 1}
                  </span>
                  <span>
                    <span className={`block text-[16px] font-semibold ${state === "todo" ? "text-body" : "text-ink"}`}>{s.t}</span>
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
        <div className="mt-6 flex gap-3">
          {step < steps.length - 1 ? (
            <button
              type="button"
              disabled={proving}
              onClick={() => setStep((s) => Math.min(steps.length - 1, s + 1))}
              className="group inline-flex items-center gap-2 rounded-[10px] bg-cobalt px-5 py-3 text-[15px] font-semibold text-white transition-colors hover:bg-cobalt-bright disabled:opacity-50"
            >
              Next
              <ArrowRight aria-hidden="true" className="h-4 w-4 transition-transform group-hover:translate-x-1" />
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setStep(0)}
              className="inline-flex items-center gap-2 rounded-[10px] border border-line px-5 py-3 text-[15px] font-semibold text-ink hover:bg-elevated"
            >
              <RotateCcw aria-hidden="true" className="h-4 w-4" /> Restart
            </button>
          )}
        </div>
      </div>

      {/* Visualization */}
      <div className="lg:col-span-7" aria-live="polite">
        <div className="overflow-hidden rounded-[16px] border border-line bg-void">
          <div className="grid divide-y divide-line">
            <div className="p-6 sm:p-7">
              <p className="mono-label text-muted">Private input</p>
              <ul className="mt-4 grid gap-2 sm:grid-cols-3">
                {inputs.map((x) => {
                  const present = step >= x.from;
                  return (
                    <li key={x.k} className={`flex items-center justify-between rounded-[10px] border px-4 py-3 transition-colors ${present ? "border-line bg-surface/70" : "border-dashed border-line/60"}`}>
                      <span className={`text-[15px] ${present ? "text-ink" : "text-muted"}`}>{x.k}</span>
                      <span className="mono-label inline-flex items-center gap-1.5 text-muted">
                        {present ? (
                          <>
                            <EyeOff aria-hidden="true" className="h-3.5 w-3.5" /> Hidden
                          </>
                        ) : (
                          "—"
                        )}
                      </span>
                    </li>
                  );
                })}
              </ul>
            </div>

            <div className="relative p-6 sm:p-7">
              <div className="flex items-center justify-between">
                <p className="mono-label text-muted">Proof</p>
                <span className={`mono-label inline-flex items-center gap-2 ${proofState === "Verified" ? "text-electric" : "text-body"}`}>
                  {proving && <Loader2 aria-hidden="true" className="h-3.5 w-3.5 animate-spin" />}
                  {proofState}
                </span>
              </div>
              <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-surface">
                <motion.div
                  className="h-full rounded-full bg-gradient-to-r from-cobalt to-electric"
                  animate={{ width: step < 3 ? `${(step / 3) * 40}%` : proving ? "75%" : "100%" }}
                  transition={{ duration: proving ? 1.6 : 0.5, ease: [0.22, 1, 0.36, 1] }}
                />
              </div>
            </div>

            <div className={`p-6 transition-colors sm:p-7 ${done ? "bg-cobalt/[0.07]" : ""}`}>
              <p className="mono-label text-muted">Public output</p>
              <ul className="mt-4 space-y-2.5">
                {checks.map((c) => {
                  const ok = step >= c.at && !(proving && c.at === 3) && !(c.at === 4 && step < 4);
                  return (
                    <li key={c.k} className="flex items-center gap-3">
                      <span className={`flex h-6 w-6 items-center justify-center rounded-full border transition-colors ${ok ? "border-cobalt-bright bg-cobalt/20" : "border-line"}`}>
                        <AnimatePresence>
                          {ok && (
                            <motion.span initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }}>
                              <Check aria-hidden="true" className="h-3.5 w-3.5 text-electric" />
                            </motion.span>
                          )}
                        </AnimatePresence>
                      </span>
                      <span className={`text-[15px] ${ok ? "text-ink" : "text-muted"}`}>{c.k}</span>
                      <span className="sr-only">{ok ? "verified" : "pending"}</span>
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
