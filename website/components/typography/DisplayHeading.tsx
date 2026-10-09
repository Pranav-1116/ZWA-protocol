import type { ReactNode } from "react";

/** Hero-scale heading: 40px mobile, ~48px tablet, ~72px desktop. Max two lines. */
export function DisplayHeading({ children, className = "", id }: { children: ReactNode; className?: string; id?: string }) {
  return (
    <h1
      id={id}
      className={`text-[40px] leading-[1.04] font-semibold tracking-[-0.035em] sm:text-[48px] lg:text-[64px] xl:text-[72px] ${className}`}
    >
      {children}
    </h1>
  );
}
