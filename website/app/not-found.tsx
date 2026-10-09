import { Container } from "@/components/layout/Container";
import { Button } from "@/components/ui/Button";

export default function NotFound() {
  return (
    <section className="flex min-h-[80vh] items-center bg-void pt-[72px]">
      <Container>
        <p className="mono-label text-electric">404 · Not disclosed</p>
        <h1 className="mt-6 text-[44px] tracking-[-0.03em] sm:text-[60px]">This page stays private.</h1>
        <p className="mt-5 max-w-[30rem]">Or it doesn&apos;t exist. Either way, nothing to verify here.</p>
        <div className="mt-10">
          <Button href="/">Back to home</Button>
        </div>
      </Container>
    </section>
  );
}
