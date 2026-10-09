import type { Metadata } from "next";
import { PageHero } from "@/components/layout/PageHero";
import { Container } from "@/components/layout/Container";
import { Section } from "@/components/layout/Section";
import { CodeBlock } from "@/components/ui/CodeBlock";

export const metadata: Metadata = {
  title: "Developers",
  description: "Build private asset workflows with ZWA.",
};

const example = `const proof = await zwa.prove({ asset, policy, credential })
await zwa.verify(proof)`;

export default function DevelopersPage() {
  return (
    <>
      <PageHero title="Build private asset workflows." />
      <Section className="!pt-16">
        <Container>
          <div className="max-w-[760px]">
            <CodeBlock tabs={[{ id: "ts", label: "Illustrative interface", lang: "ts", code: example }]} />
          </div>
        </Container>
      </Section>
    </>
  );
}
