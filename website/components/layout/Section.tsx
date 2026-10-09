import type { ReactNode } from "react";

type Tone = "void" | "deep" | "paper";

const tones: Record<Tone, string> = {
  void: "bg-void",
  deep: "bg-deep",
  paper: "bg-paper text-paper-body",
};

export function Section({
  id,
  tone = "void",
  className = "",
  children,
  labelledBy,
}: {
  id?: string;
  tone?: Tone;
  className?: string;
  children: ReactNode;
  labelledBy?: string;
}) {
  return (
    <section
      id={id}
      aria-labelledby={labelledBy}
      className={`relative py-24 sm:py-32 lg:py-40 ${tones[tone]} ${className}`}
    >
      {children}
    </section>
  );
}
