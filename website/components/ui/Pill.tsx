import type { ReactNode } from "react";

export function Pill({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={`mono-label inline-flex items-center gap-2 rounded-full border border-line bg-surface/70 px-3 py-1.5 text-body ${className}`}
    >
      {children}
    </span>
  );
}
