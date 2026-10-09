import type { Metadata } from "next";
import { PageHero } from "@/components/layout/PageHero";

export const metadata: Metadata = { title: "Terms" };

export default function TermsPage() {
  return (
    <PageHero title="Terms">
      <p>
        ZWA Protocol is research software provided as is, without warranty. It has not been audited for production use
        and must not be used to custody or move real assets.
      </p>
    </PageHero>
  );
}
