import type { Metadata } from "next";
import { PageHero } from "@/components/layout/PageHero";

export const metadata: Metadata = { title: "Privacy" };

export default function PrivacyPage() {
  return (
    <PageHero title="Privacy">
      <p>
        This website sets no cookies, runs no analytics and loads no third-party scripts. The demo runs entirely in
        your browser and sends nothing anywhere.
      </p>
    </PageHero>
  );
}
