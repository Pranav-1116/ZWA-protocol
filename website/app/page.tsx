import { Check } from "lucide-react";
import { Container } from "@/components/layout/Container";
import { Section } from "@/components/layout/Section";
import { Eyebrow } from "@/components/typography/Eyebrow";
import { DisplayHeading } from "@/components/typography/DisplayHeading";
import { SectionHeading } from "@/components/typography/SectionHeading";
import { Button } from "@/components/ui/Button";
import { Reveal } from "@/components/motion/Reveal";
import { EncryptedField } from "@/components/backgrounds/EncryptedField";
import { ProofBoundary } from "@/components/protocol/ProofBoundary";
import { FieldStack } from "@/components/protocol/FieldStack";
import { ProtocolFlow } from "@/components/protocol/ProtocolFlow";
import { PrivacyBoundary } from "@/components/protocol/PrivacyBoundary";
import { ArchitectureStack, LineageGraph } from "@/components/lazy";
import { ResearchCard } from "@/components/research/ResearchCard";
import { ResearchStatus } from "@/components/research/ResearchStatus";
import BlurText from "@/components/reactbits/BlurText";
import Magnet from "@/components/reactbits/Magnet";
import { lineageStatus } from "@/lib/research";
import { site } from "@/lib/site";

export default function Home() {
  return (
    <>
      {/* ───────────── 01 HERO — What is ZWA? ───────────── */}
      <section aria-labelledby="hero-title" className="relative isolate flex min-h-[85vh] items-center overflow-hidden bg-void pt-[72px]">
        <div aria-hidden="true" className="glow-hero absolute inset-0 -z-10" />
        <div aria-hidden="true" className="absolute inset-0 -z-10 [mask-image:radial-gradient(ellipse_at_60%_45%,black_20%,transparent_75%)]">
          <EncryptedField />
        </div>
        <div aria-hidden="true" className="absolute inset-x-0 bottom-0 -z-10 h-40 bg-gradient-to-b from-transparent to-void" />

        <Container className="py-14 lg:py-16">
          <Reveal y={12}>
            <Eyebrow>Private infrastructure for tokenized assets</Eyebrow>
          </Reveal>
          <Reveal y={14} delay={0.05}>
            <DisplayHeading id="hero-title" className="mt-7">
              <span className="block">Prove what is permitted.</span>
              <span className="block text-body/90">Keep everything else private.</span>
            </DisplayHeading>
          </Reveal>
          <div className="mt-12 grid items-center gap-14 lg:grid-cols-12 lg:gap-10">
            <div className="lg:col-span-5">
              <Reveal y={14} delay={0.12}>
                <p className="max-w-[32rem] text-[18px] leading-relaxed text-ink lg:text-[19px]">
                  ZWA is privacy infrastructure for compliant digital assets.
                </p>
                <p className="mt-4 max-w-[32rem] text-[17px] leading-relaxed text-body lg:text-[18px]">
                  Prove authorized issuance, investor eligibility, and settlement conditions without exposing the
                  private information behind them.
                </p>
              </Reveal>
              <Reveal y={14} delay={0.18}>
                <div className="mt-10 flex flex-wrap items-center gap-4">
                  <Magnet>
                    <Button href="/protocol">Explore the Protocol</Button>
                  </Magnet>
                  <Button href="/research" variant="secondary" arrow="none">
                    Read the Research
                  </Button>
                </div>
              </Reveal>
              <Reveal y={10} delay={0.26}>
                <p className="mono-label mt-10 flex items-center gap-3 text-muted">
                  <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-research" />
                  Built on Zcash privacy infrastructure
                </p>
              </Reveal>
            </div>
            <div className="lg:col-span-7">
              <Reveal y={18} delay={0.2}>
                <ProofBoundary className="mx-auto max-w-[640px]" />
              </Reveal>
            </div>
          </div>
        </Container>
      </section>

      {/* ───────────── 02 PROBLEM — Why does this need to exist? ───────────── */}
      <Section tone="deep" labelledBy="problem-title" className="border-t border-line/50">
        <div aria-hidden="true" className="bg-coordinate-grid absolute inset-0 [mask-image:linear-gradient(to_bottom,transparent,black_30%,black_70%,transparent)]" />
        <Container className="relative">
          <div className="grid items-center gap-16 lg:grid-cols-12">
            <div className="lg:col-span-6">
              <BlurText
                as="h2"
                text="Public rails. Private financial reality."
                delay={90}
                className="max-w-[14ch] text-[38px] leading-[1.05] font-semibold tracking-[-0.03em] sm:text-[46px] lg:text-[54px]"
              />
              <Reveal delay={0.1}>
                <p className="mt-8 max-w-[34rem]">
                  Real-world assets carry information that should not become public simply because settlement moves
                  onchain.
                </p>
                <ul className="mt-6 space-y-1.5 text-[17px] text-ink/85">
                  {["Identity.", "Eligibility.", "Asset provenance.", "Positions.", "Commercial terms."].map((t) => (
                    <li key={t}>{t}</li>
                  ))}
                </ul>
                <p className="mt-6 max-w-[34rem] text-ink">
                  ZWA separates what must be proven from what must remain private.
                </p>
              </Reveal>
            </div>
            <div className="lg:col-span-5 lg:col-start-8">
              <Reveal delay={0.1}>
                <FieldStack />
              </Reveal>
            </div>
          </div>
        </Container>
      </Section>

      {/* ───────────── 03 HOW ZWA WORKS — How does it work? ───────────── */}
      <Section labelledBy="how-title" className="bg-[#0d1426]">
        <div aria-hidden="true" className="glow-top absolute inset-0" />
        <Container className="relative">
          <div className="max-w-3xl">
            <Reveal>
              <SectionHeading id="how-title">
                Private state in.
                <span className="block text-body/90">Verifiable settlement out.</span>
              </SectionHeading>
            </Reveal>
          </div>
          <div className="mt-20">
            <ProtocolFlow />
          </div>
        </Container>
      </Section>

      {/* ───────────── 04 PRIVACY MODEL — What stays private? ───────────── */}
      <Section labelledBy="privacy-title" className="pb-10 sm:pb-16 lg:pb-8">
        <Container>
          <div className="grid gap-px overflow-hidden rounded-[16px] border border-line bg-line md:grid-cols-2">
            <div className="bg-void p-8 sm:p-10">
              <h3 id="privacy-title" className="text-[26px] tracking-[-0.02em] lg:text-[32px]">What stays private</h3>
              <ul className="mt-8 space-y-4">
                {[
                  "Investor identity",
                  "Private credentials",
                  "Intermediate state",
                  "Sensitive transaction context",
                  "Asset lineage details",
                ].map((t, i) => (
                  <Reveal as="li" key={t} delay={i * 0.06} className="flex items-center justify-between gap-6">
                    <span className="text-[17px]">{t}</span>
                    <span aria-hidden="true" className="redacted h-2.5 w-24 shrink-0 opacity-80" />
                  </Reveal>
                ))}
              </ul>
            </div>
            <div className="bg-void p-8 sm:p-10">
              <h3 className="text-[26px] tracking-[-0.02em] lg:text-[32px]">What becomes verifiable</h3>
              <ul className="mt-8 space-y-4">
                {[
                  "Issuance was authorized",
                  "Required conditions hold",
                  "Asset lineage satisfies the supported relation",
                  "Settlement corresponds to permitted state",
                ].map((t, i) => (
                  <Reveal as="li" key={t} delay={0.2 + i * 0.08} className="flex items-start gap-3">
                    <Check aria-hidden="true" className="mt-1 h-4 w-4 shrink-0 text-electric" />
                    <span className="text-[17px] text-ink">{t}</span>
                  </Reveal>
                ))}
              </ul>
            </div>
          </div>

          <div className="mt-24 lg:mt-10">
            <PrivacyBoundary />
          </div>
        </Container>
      </Section>

      {/* ───────────── 05 LINEAGE — What makes ZWA technically interesting? ───────────── */}
      <Section tone="paper" labelledBy="lineage-title" className="!bg-[#ECEDE7]">
        <Container>
          <div className="grid gap-12 lg:grid-cols-12">
            <div className="lg:col-span-7">
              <h2 id="lineage-title" className="text-[34px] leading-[1.06] tracking-[-0.03em] text-paper-ink sm:text-[44px] lg:text-[50px]">
                Provenance without publishing the path.
              </h2>
              <p className="mt-6 max-w-[38rem] text-paper-body">
                ZWA&apos;s lineage research explores how an asset can prove supported ancestry while keeping sensitive
                intermediate state private.
              </p>
            </div>
            <aside aria-labelledby="lineage-status" className="lg:col-span-4 lg:col-start-9">
              <div className="rounded-[14px] border border-paper-line bg-white/70 p-6">
                <h3 id="lineage-status" className="mono-label text-paper-ink">
                  Lineage research
                </h3>
                <ul className="mt-5 space-y-4">
                  {lineageStatus.map((s) => (
                    <li key={s.label} className="flex flex-col gap-1">
                      <span className="text-[15px] font-semibold text-paper-ink">{s.label}</span>
                      <ResearchStatus status={s.status} label={s.note} tone="light" />
                    </li>
                  ))}
                </ul>
              </div>
            </aside>
          </div>

          <div className="mt-16 rounded-[18px] border border-paper-line bg-white/50 px-5 py-10 sm:px-10">
            <LineageGraph />
          </div>
        </Container>
      </Section>

      {/* ───────────── 06 ARCHITECTURE — Where does it sit? ───────────── */}
      <Section id="architecture" labelledBy="arch-title">
        <div aria-hidden="true" className="bg-coordinate-grid absolute inset-0 opacity-70 [mask-image:radial-gradient(ellipse_at_50%_40%,black,transparent_70%)]" />
        <div aria-hidden="true" className="bg-hex-contour absolute inset-0 opacity-[0.045]" />
        <Container className="relative">
          <div className="grid gap-12 lg:grid-cols-12">
            <div className="lg:col-span-4">
              <Reveal>
                <SectionHeading id="arch-title">Built as protocol infrastructure.</SectionHeading>
              </Reveal>
            </div>
            <div className="lg:col-span-8">
              <ArchitectureStack />
            </div>
          </div>
        </Container>
      </Section>

      {/* ───────────── 07 RESEARCH — Why should I trust the work? ───────────── */}
      <Section tone="deep" labelledBy="research-title" className="border-y border-line/50">
        <Container>
          <div className="max-w-3xl">
            <Reveal>
              <SectionHeading id="research-title">Research you can inspect.</SectionHeading>
            </Reveal>
            <Reveal delay={0.1}>
              <p className="mt-6 max-w-[34rem]">ZWA is being developed from:</p>
              <ul className="mt-3 space-y-1.5 text-ink/90">
                {["explicit protocol assumptions", "adversarial testing", "reproducible cryptographic experiments"].map((t) => (
                  <li key={t} className="flex items-center gap-3">
                    <span aria-hidden="true" className="h-px w-4 bg-cobalt-bright" />
                    {t}
                  </li>
                ))}
              </ul>
            </Reveal>
          </div>

          <div className="mt-16 grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
            {[
              {
                title: "Private Lineage",
                body: "Supported ancestry for non-split ZSA paths.",
                cta: "View research",
                href: "/research?topic=lineage",
              },
              {
                title: "Settlement",
                body: "Private asset delivery and settlement primitives.",
                cta: "View architecture",
                href: "/#architecture",
              },
              {
                title: "Protocol Security",
                body: "Explicit assumptions, negative testing and reproducible evidence.",
                cta: "Read methodology",
                href: "/research?topic=protocol",
              },
              {
                title: "Cryptographic Foundations",
                body: "Commitments, proof relations and consensus boundaries.",
                cta: "Explore",
                href: "/research?topic=circuits",
              },
            ].map((c, i) => (
              <Reveal key={c.title} delay={i * 0.06} className="h-full">
                <ResearchCard {...c} />
              </Reveal>
            ))}
          </div>
        </Container>
      </Section>

      {/* ───────────── 08 FINAL CTA — Where do I go next? ───────────── */}
      <section aria-labelledby="cta-title" className="relative isolate overflow-hidden bg-void py-32 sm:py-40">
        <div
          aria-hidden="true"
          className="absolute inset-0 -z-10 bg-[radial-gradient(ellipse_at_50%_100%,rgba(37,99,235,0.28),transparent_55%)]"
        />
        <div aria-hidden="true" className="absolute inset-x-0 bottom-0 -z-10 h-px bg-gradient-to-r from-transparent via-cobalt-bright/60 to-transparent" />
        <Container className="text-center">
          <h2 id="cta-title" className="sr-only">
            Private infrastructure should prove more and reveal less.
          </h2>
          <div aria-hidden="true" className="text-[34px] leading-[1.08] font-semibold tracking-[-0.03em] text-ink sm:text-[46px] lg:text-[58px]">
            <BlurText as="p" text="Private infrastructure should prove more" delay={70}  />
            <BlurText as="p" text="and reveal less." delay={70} className="text-body/90" />
          </div>
          <div className="mt-12 flex flex-wrap items-center justify-center gap-4">
            <Magnet>
              <Button href="/protocol">Explore the Protocol</Button>
            </Magnet>
            <Button href={site.github} variant="secondary" arrow="external">
              View on GitHub
            </Button>
          </div>
          <p className="mt-16 text-[15px] font-semibold text-ink">ZWA Protocol</p>
          <p className="mt-1 text-[15px]">{site.tagline}</p>
        </Container>
      </section>
    </>
  );
}
