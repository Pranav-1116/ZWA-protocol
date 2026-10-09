import type { Metadata } from "next";
import { PageHero } from "@/components/layout/PageHero";
import { Container } from "@/components/layout/Container";
import { Section } from "@/components/layout/Section";

export const metadata: Metadata = {
  title: "About",
  description: "ZWA Protocol: privacy infrastructure for compliant digital assets.",
};

const traits = ["Precise", "Institutional", "Private", "Technical", "Calm", "Research-led"];

export default function AboutPage() {
  return (
    <>
      <PageHero title="Privacy infrastructure for compliant digital assets." />
      <Section>
        <Container>
          <ul className="grid gap-px overflow-hidden rounded-[16px] border border-line bg-line sm:grid-cols-2 lg:grid-cols-3">
            {traits.map((t) => (
              <li key={t} className="bg-void px-7 py-10 text-[24px] font-semibold tracking-[-0.02em] text-ink">
                {t}
              </li>
            ))}
          </ul>
        </Container>
      </Section>
    </>
  );
}
