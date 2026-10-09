export const site = {
  name: "ZWA Protocol",
  tagline: "Privacy infrastructure for compliant digital assets.",
  description:
    "ZWA is privacy infrastructure for compliant digital assets. Prove authorized issuance, investor eligibility and settlement conditions without exposing the private information behind them.",
  github: "https://github.com/Maheshsiddu29/ZWA-Protocol",
  docs: "https://github.com/Maheshsiddu29/ZWA-Protocol/tree/main/docs",
  commits: "https://github.com/Maheshsiddu29/ZWA-Protocol/commits/main",
} as const;

export const primaryNav = [
  { label: "Protocol", href: "/protocol" },
  { label: "Research", href: "/research" },
  { label: "Developers", href: "/developers" },
  { label: "About", href: "/about" },
] as const;

export const footerNav = [
  {
    title: "Protocol",
    links: [
      { label: "Overview", href: "/protocol" },
      { label: "Architecture", href: "/#architecture" },
      { label: "Research", href: "/research" },
    ],
  },
  {
    title: "Build",
    links: [
      { label: "Documentation", href: site.docs, external: true },
      { label: "GitHub", href: site.github, external: true },
      { label: "Demo", href: "/demo" },
    ],
  },
  {
    title: "Project",
    links: [
      { label: "About", href: "/about" },
      { label: "Updates", href: site.commits, external: true },
    ],
  },
  {
    title: "Legal",
    links: [
      { label: "Privacy", href: "/privacy" },
      { label: "Terms", href: "/terms" },
    ],
  },
] as const;
