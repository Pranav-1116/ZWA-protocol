import type { Metadata } from "next";
import { PageHero } from "@/components/layout/PageHero";
import { Container } from "@/components/layout/Container";
import { Section } from "@/components/layout/Section";
import { DemoWalkthrough } from "@/components/lazy";

export const metadata: Metadata = {
  title: "Demo",
  description: "A simulated walkthrough of private asset settlement with ZWA.",
};

export default function DemoPage() {
  return (
    <>
      <PageHero title="Private Asset Settlement" />
      <Section className="!pt-14">
        <Container>
          <DemoWalkthrough />
          <p className="mono-label mt-10 text-muted">Simulated walkthrough · no proofs generated · nothing leaves your browser</p>
        </Container>
      </Section>
    </>
  );
}
