import { ArrowRight, ArrowUpRight } from "lucide-react";
import SpotlightCard from "@/components/reactbits/SpotlightCard";

export function ResearchCard({ title, body, cta, href }: { title: string; body: string; cta: string; href: string }) {
  const external = href.startsWith("http");
  return (
    <SpotlightCard className="h-full">
      <a
        href={href}
        {...(external ? { target: "_blank", rel: "noreferrer noopener" } : {})}
        className="group flex h-full flex-col p-7 focus-visible:outline-none"
      >
        <h3 className="text-[24px] tracking-[-0.02em]">{title}</h3>
        <p className="mt-3 flex-1 text-[16px] leading-relaxed">{body}</p>
        <span className="mt-8 inline-flex items-center gap-2 text-[15px] font-semibold text-ink transition-colors group-hover:text-electric">
          {cta}
          {external ? (
            <ArrowUpRight aria-hidden="true" className="h-4 w-4 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
          ) : (
            <ArrowRight aria-hidden="true" className="h-4 w-4 transition-transform group-hover:translate-x-1" />
          )}
        </span>
      </a>
    </SpotlightCard>
  );
}
