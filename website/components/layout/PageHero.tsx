import type { ReactNode } from "react";
import { Container } from "./Container";
import { Reveal } from "@/components/motion/Reveal";

export function PageHero({ title, children }: { title: ReactNode; children?: ReactNode }) {
  return (
    <section className="relative isolate overflow-hidden border-b border-line/60 bg-void pb-20 pt-[152px] sm:pb-24 lg:pt-[184px]">
      <div aria-hidden="true" className="glow-top absolute inset-0 -z-10" />
      <div aria-hidden="true" className="bg-coordinate-grid absolute inset-0 -z-10 [mask-image:radial-gradient(ellipse_at_30%_0%,black,transparent_70%)]" />
      <Container>
        <Reveal y={14}>
          <h1 className="max-w-[18ch] text-[40px] leading-[1.04] tracking-[-0.035em] sm:text-[52px] lg:text-[64px]">{title}</h1>
        </Reveal>
        {children && (
          <Reveal y={14} delay={0.12}>
            <div className="mt-7 max-w-[40rem] text-[18px] leading-relaxed lg:text-[19px]">{children}</div>
          </Reveal>
        )}
      </Container>
    </section>
  );
}
