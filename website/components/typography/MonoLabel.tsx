import type { ReactNode } from "react";

export function MonoLabel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`mono-label text-muted ${className}`}>{children}</span>;
}
