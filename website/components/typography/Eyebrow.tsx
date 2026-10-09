import type { ReactNode } from "react";

export function Eyebrow({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <p className={`mono-label flex items-center gap-3 text-electric ${className}`}>
      <span aria-hidden="true" className="h-px w-6 bg-cobalt-bright/70" />
      {children}
    </p>
  );
}
