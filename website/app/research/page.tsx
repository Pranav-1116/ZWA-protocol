import type { Metadata } from "next";
import { Suspense } from "react";
import { PageHero } from "@/components/layout/PageHero";
import { Container } from "@/components/layout/Container";
import { Section } from "@/components/layout/Section";
import { ResearchArchive } from "@/components/research/ResearchArchive";

export const metadata: Metadata = {
  title: "Research",
  description: "The assumptions, experiments and boundaries behind ZWA Protocol.",
};

export default function ResearchPage() {
  return (
    <>
      <PageHero title="Cryptography should come with evidence.">
        <p>ZWA Research documents the assumptions, experiments and boundaries behind the protocol.</p>
      </PageHero>

      <Section className="!pt-16">
        <Container>
          <Suspense fallback={<div className="h-96" />}>
            <ResearchArchive />
          </Suspense>
        </Container>
      </Section>

    </>
  );
}
