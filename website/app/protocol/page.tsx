import type { Metadata } from "next";
import { ArrowUpRight, Check } from "lucide-react";
import { PageHero } from "@/components/layout/PageHero";
import { Container } from "@/components/layout/Container";
import { Section } from "@/components/layout/Section";
import { Reveal } from "@/components/motion/Reveal";
import { site } from "@/lib/site";

export const metadata: Metadata = {
  title: "Protocol",
  description: "What ZWA is: privacy infrastructure for regulated assets across issuance, compliance, private market coordination and settlement.",
};

type Chapter = {
  n: string;
  name: string;
  problem: string;
  primitive: string;
  primitiveBody: string;
  diagram: { in: string[]; core: string; out: string[] };
  link: { label: string; href: string };
};

const chapters: Chapter[] = [
  {
    n: "01",
    name: "Issuance",
    problem: "An issuer needs to show that an asset was created through an authorized path — without publishing the issuer's internal records or investor list.",
    primitive: "Authorized issuance root",
    primitiveBody: "Issuer-rooted credentials with domain-separated encodings anchor an asset to an authorization that can be verified later.",
    diagram: { in: ["Asset", "Issuer key", "Policy"], core: "Root authorization", out: ["Issuance authorized"] },
    link: { label: "Credentials crate", href: `${site.github}/tree/main/crates/credentials` },
  },
  {
    n: "02",
    name: "Compliance",
    problem: "Regulated assets can only move to eligible holders, but eligibility data — identity, accreditation, jurisdiction — should not be public.",
    primitive: "Eligibility predicate",
    primitiveBody: "A zero-knowledge predicate proves a credential satisfies the asset's policy without revealing the credential's fields.",
    diagram: { in: ["Credential", "Policy", "Private witness"], core: "ZK relation", out: ["Eligible"] },
    link: { label: "Circuits", href: `${site.github}/tree/main/circuits` },
  },
  {
    n: "03",
    name: "Private market coordination",
    problem: "Counterparties need to agree on a trade without publishing positions, prices or who is trading with whom.",
    primitive: "Trade commitment + matcher",
    primitiveBody: "TradeCommitmentV1 binds the exact terms. The matcher checks eligibility and issues a single-use, replay-protected approval for that commitment.",
    diagram: { in: ["Seller intent", "Buyer intent", "Eligibility"], core: "Trade commitment", out: ["Approved trade"] },
    link: { label: "Matcher", href: `${site.github}/tree/main/matcher` },
  },
  {
    n: "04",
    name: "Settlement",
    problem: "An approved trade must settle exactly as approved, with each party in control of its own funds.",
    primitive: "Attested consent → wallet authorization",
    primitiveBody:
      "ZWA verifies credential-authority-attested party consent for the exact approved trade and holds no spending authority. Each party's wallet authorizes its own Zcash spend.",
    diagram: { in: ["Approved trade", "Seller consent", "Buyer consent"], core: "Settlement handoff", out: ["Settlement permitted"] },
    link: { label: "Architecture", href: "/#architecture" },
  },
];

function MiniDiagram({ d }: { d: Chapter["diagram"] }) {
  return (
    <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-4 rounded-[14px] border border-line bg-void/70 p-6" aria-hidden="true">
      <ul className="space-y-2">
        {d.in.map((x) => (
          <li key={x} className="flex items-center justify-between gap-3 rounded-[8px] border border-line px-3 py-2">
            <span className="font-mono text-[12px] text-body">{x}</span>
            <span className="redacted h-2 w-8" />
          </li>
        ))}
      </ul>
      <div className="flex flex-col items-center">
        <span className="h-px w-8 bg-gradient-to-r from-line to-cobalt" />
        <span className="my-3 rounded-[10px] border border-cobalt/70 bg-deep px-3 py-3 text-center font-mono text-[11px] uppercase tracking-[0.12em] text-ink">
          {d.core}
        </span>
        <span className="h-px w-8 bg-gradient-to-r from-cobalt to-line" />
      </div>
      <ul className="space-y-2">
        {d.out.map((x) => (
          <li key={x} className="flex items-center gap-2 rounded-[8px] border border-cobalt/40 bg-cobalt/[0.08] px-3 py-2.5">
            <Check className="h-3.5 w-3.5 text-electric" />
            <span className="text-[13px] font-semibold text-ink">{x}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function ProtocolPage() {
  return (
    <>
      <PageHero title="Privacy infrastructure for regulated assets." />

      {chapters.map((c, i) => (
        <Section key={c.n} id={`ch-${c.n}`} tone={i % 2 ? "deep" : "void"} labelledBy={`ch-${c.n}-title`} className="!py-24 lg:!py-32">
          <Container>
            <div className="grid gap-12 lg:grid-cols-12">
              <div className="lg:col-span-5">
                <Reveal>
                  <h2 id={`ch-${c.n}-title`} className="text-[32px] tracking-[-0.03em] sm:text-[40px]">
                    {c.name}
                  </h2>
                  <p className="mt-6">{c.problem}</p>
                </Reveal>
              </div>
              <div className="lg:col-span-6 lg:col-start-7">
                <Reveal delay={0.08}>
                  <p className="mono-label text-muted">ZWA primitive</p>
                  <h3 className="mt-3 text-[22px]">{c.primitive}</h3>
                  <p className="mt-3 text-[16px]">{c.primitiveBody}</p>
                  <div className="mt-8">
                    <MiniDiagram d={c.diagram} />
                  </div>
                  <a
                    href={c.link.href}
                    {...(c.link.href.startsWith("http") ? { target: "_blank", rel: "noreferrer noopener" } : {})}
                    className="group mt-6 inline-flex items-center gap-2 text-[15px] font-semibold text-ink hover:text-electric"
                  >
                    Technical detail: {c.link.label}
                    <ArrowUpRight aria-hidden="true" className="h-4 w-4 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
                  </a>
                </Reveal>
              </div>
            </div>
          </Container>
        </Section>
      ))}

    </>
  );
}
