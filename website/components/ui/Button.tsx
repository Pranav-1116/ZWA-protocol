import Link from "next/link";
import type { ReactNode } from "react";
import { ArrowRight, ArrowUpRight } from "lucide-react";

type Variant = "primary" | "secondary" | "ghost";

const base =
  "group inline-flex items-center justify-center gap-2 rounded-[10px] px-5 py-3 text-[15px] font-semibold tracking-[-0.005em] transition-[background-color,border-color,color,box-shadow] duration-300 ease-proof";

const variants: Record<Variant, string> = {
  primary:
    "bg-cobalt text-white shadow-[0_0_0_1px_rgba(96,165,250,0.35)_inset,0_8px_30px_-8px_rgba(37,99,235,0.6)] hover:bg-cobalt-bright",
  secondary: "border border-line bg-surface/60 text-ink hover:border-[#3a4866] hover:bg-elevated",
  ghost: "text-ink hover:text-electric px-0",
};

export function Button({
  href,
  children,
  variant = "primary",
  arrow = "right",
  className = "",
}: {
  href: string;
  children: ReactNode;
  variant?: Variant;
  arrow?: "right" | "external" | "none";
  className?: string;
}) {
  const external = arrow === "external" || href.startsWith("http");
  const icon =
    arrow === "none" ? null : external ? (
      <ArrowUpRight aria-hidden="true" className="h-4 w-4 transition-transform duration-300 ease-proof group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
    ) : (
      <ArrowRight aria-hidden="true" className="h-4 w-4 transition-transform duration-300 ease-proof group-hover:translate-x-1" />
    );
  const cls = `${base} ${variants[variant]} ${className}`;
  if (external) {
    return (
      <a href={href} target="_blank" rel="noreferrer noopener" className={cls}>
        {children}
        {icon}
        <span className="sr-only">(opens in a new tab)</span>
      </a>
    );
  }
  return (
    <Link href={href} className={cls}>
      {children}
      {icon}
    </Link>
  );
}
