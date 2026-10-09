"use client";

/** Heavy interactive visuals, code-split and loaded on the client only. Fixed-height placeholders avoid layout shift. */

import dynamic from "next/dynamic";

export const ArchitectureStack = dynamic(() => import("./protocol/ArchitectureStack").then((m) => m.ArchitectureStack), {
  ssr: false,
  loading: () => <div className="h-[520px]" aria-hidden="true" />,
});

export const LineageGraph = dynamic(() => import("./protocol/LineageGraph").then((m) => m.LineageGraph), {
  ssr: false,
  loading: () => <div className="min-h-[300px]" aria-hidden="true" />,
});

export const DemoWalkthrough = dynamic(() => import("./protocol/DemoWalkthrough").then((m) => m.DemoWalkthrough), {
  ssr: false,
  loading: () => <div className="h-[560px]" aria-hidden="true" />,
});
