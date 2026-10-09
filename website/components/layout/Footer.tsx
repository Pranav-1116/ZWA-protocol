import Link from "next/link";
import { footerNav } from "@/lib/site";

export function Footer() {
  return (
    <footer className="border-t border-line/70 bg-void">
      <div className="mx-auto max-w-[1320px] px-5 pb-10 pt-16 sm:px-8 lg:px-14 xl:px-16">
        <nav aria-label="Footer" className="grid grid-cols-2 gap-10 sm:grid-cols-4">
            {footerNav.map((col) => (
              <div key={col.title}>
                <h2 className="mono-label text-muted">{col.title}</h2>
                <ul className="mt-4 space-y-3">
                  {col.links.map((l) => (
                    <li key={l.label}>
                      {"external" in l && l.external ? (
                        <a href={l.href} target="_blank" rel="noreferrer noopener" className="text-[15px] text-body transition-colors hover:text-ink">
                          {l.label} <span aria-hidden="true">↗</span>
                        </a>
                      ) : (
                        <Link href={l.href} className="text-[15px] text-body transition-colors hover:text-ink">
                          {l.label}
                        </Link>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
        </nav>
        <div className="mt-16 border-t border-line/60 pt-6">
          <p className="text-[13px] text-muted">© 2026 ZWA Protocol</p>
        </div>
      </div>
    </footer>
  );
}
