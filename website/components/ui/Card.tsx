import type { ReactNode } from "react";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={`rounded-[14px] border border-line bg-surface transition-[border-color,transform] duration-300 ease-proof hover:-translate-y-px hover:border-[#33415c] ${className}`}
    >
      {children}
    </div>
  );
}
