/**
 * Research and build status shown on the site.
 *
 * Claim discipline: every entry states its status narrowly. Nothing here
 * claims production security, mainnet ZSA functionality, consensus-enforced
 * compliance or complete ownership history.
 */

export type Status = "established" | "conditional" | "research" | "open";

export const statusMeta: Record<Status, { label: string; description: string }> = {
  established: {
    label: "Established",
    description: "Implemented and validated against its stated scope.",
  },
  conditional: {
    label: "Conditional",
    description: "Holds under explicitly stated assumptions.",
  },
  research: {
    label: "Research",
    description: "Active research. Not a protocol guarantee.",
  },
  open: {
    label: "Open",
    description: "Known open question or unresolved gate.",
  },
};

export type Topic = "lineage" | "settlement" | "circuits" | "consensus" | "protocol";

export type ResearchItem = {
  id: string;
  code: string;
  topic: Topic;
  title: string;
  status: Status;
  summary: string;
  updated: string;
  href: string;
};

const repo = "https://github.com/Maheshsiddu29/ZWA-Protocol";

export const researchItems: ResearchItem[] = [
  {
    id: "rooted-lineage",
    code: "LINEAGE / H1",
    topic: "lineage",
    title: "Rooted lineage",
    status: "conditional",
    summary:
      "Authenticated ancestry from an authorized issuance root to an authenticated terminal, under explicitly stated assumptions.",
    updated: "Oct 2026",
    href: `${repo}/tree/main/docs`,
  },
  {
    id: "design-a",
    code: "LINEAGE / DESIGN-A",
    topic: "lineage",
    title: "Design-A composition",
    status: "conditional",
    summary:
      "Composition of root and terminal authentication for supported non-split ZSA paths. Conditionally established.",
    updated: "Oct 2026",
    href: `${repo}/tree/main/docs`,
  },
  {
    id: "recursive-compression",
    code: "LINEAGE / R1",
    topic: "lineage",
    title: "Recursive compression",
    status: "research",
    summary:
      "Compressing long ancestry into constant-size evidence. Research only. Full recursive ownership lineage does not exist today.",
    updated: "Oct 2026",
    href: `${repo}/tree/main/docs`,
  },
  {
    id: "trade-commitment",
    code: "PROTOCOL / M1",
    topic: "protocol",
    title: "TradeCommitmentV1 and credentials",
    status: "established",
    summary:
      "Poseidon trade commitments, domain-separated encodings and issuer-rooted credentials. Frozen protocol primitives with fixed test vectors.",
    updated: "Oct 2026",
    href: `${repo}/tree/main/crates`,
  },
  {
    id: "matcher",
    code: "PROTOCOL / M2",
    topic: "protocol",
    title: "Private matcher and replay protection",
    status: "established",
    summary:
      "Eligibility-gated matching that binds an approved trade to its commitment, with single-use approvals and replay protection.",
    updated: "Oct 2026",
    href: `${repo}/tree/main/matcher`,
  },
  {
    id: "party-consent",
    code: "SETTLEMENT / M3",
    topic: "settlement",
    title: "Attested party consent",
    status: "research",
    summary:
      "Credential-authority-attested party consent for the exact approved trade. Under review; M3 holds no spending authority.",
    updated: "Oct 2026",
    href: repo,
  },
  {
    id: "zsa-settlement",
    code: "SETTLEMENT / M4",
    topic: "settlement",
    title: "Private ZSA settlement",
    status: "open",
    summary:
      "Each party's wallet authorizes its own Zcash spend. Not started. ZSA is experimental and not available on mainnet.",
    updated: "Oct 2026",
    href: repo,
  },
  {
    id: "groth16-vk",
    code: "CIRCUITS / G1",
    topic: "circuits",
    title: "Groth16 verification-key provenance",
    status: "open",
    summary:
      "Current verification keys come from a development ceremony variant. Production keys require owner re-issuance or approval.",
    updated: "Oct 2026",
    href: `${repo}/tree/main/circuits`,
  },
  {
    id: "eligibility-circuit",
    code: "CIRCUITS / P1B",
    topic: "circuits",
    title: "Eligibility predicate",
    status: "established",
    summary:
      "Circom predicate proving a credential satisfies a policy without revealing the credential's fields.",
    updated: "Oct 2026",
    href: `${repo}/tree/main/circuits`,
  },
  {
    id: "consensus-boundary",
    code: "CONSENSUS / B1",
    topic: "consensus",
    title: "Consensus boundary",
    status: "open",
    summary:
      "Zcash consensus does not enforce ZWA compliance. This item documents exactly where protocol checks end and chain rules begin.",
    updated: "Oct 2026",
    href: `${repo}/tree/main/docs`,
  },
];

export const lineageStatus: { label: string; status: Status; note: string }[] = [
  { label: "Design-A composition", status: "conditional", note: "Conditionally established" },
  { label: "Root authentication", status: "established", note: "Validated in research" },
  { label: "Terminal authentication", status: "established", note: "Validated in research" },
  { label: "Recursive compression", status: "research", note: "Research" },
];
