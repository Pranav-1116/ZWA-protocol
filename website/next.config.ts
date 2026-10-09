import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // The repo root has its own package-lock.json (circuit tooling); pin tracing to this app.
  outputFileTracingRoot: path.join(__dirname),
};

export default nextConfig;
