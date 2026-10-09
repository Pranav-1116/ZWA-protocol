"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowRight, Menu, X } from "lucide-react";
import { Logo } from "@/components/ui/Logo";
import { primaryNav, site } from "@/lib/site";

export function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => setOpen(false), [pathname]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 transition-[background-color,border-color,backdrop-filter] duration-300 ${
        scrolled || open ? "border-b border-line/70 bg-void/85 backdrop-blur-xl" : "border-b border-transparent"
      }`}
    >
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-3 focus:rounded-md focus:bg-cobalt focus:px-3 focus:py-2 focus:text-white">
        Skip to content
      </a>
      <nav aria-label="Primary" className="mx-auto flex h-[72px] max-w-[1320px] items-center justify-between px-5 sm:px-8 lg:px-14 xl:px-16">
        <Link href="/" aria-label="ZWA Protocol home" className="rounded-md">
          <Logo />
        </Link>

        <ul className="hidden items-center gap-1 md:flex">
          {primaryNav.map((item) => {
            const active = pathname === item.href;
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={`rounded-md px-3.5 py-2 text-[14.5px] font-medium transition-colors ${
                    active ? "text-ink" : "text-body hover:text-ink"
                  }`}
                >
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>

        <div className="hidden items-center gap-5 md:flex">
          <a href={site.docs} target="_blank" rel="noreferrer noopener" className="text-[14.5px] font-medium text-body transition-colors hover:text-ink">
            Docs <span aria-hidden="true">↗</span>
          </a>
          <a href={site.github} target="_blank" rel="noreferrer noopener" className="text-[14.5px] font-medium text-body transition-colors hover:text-ink">
            GitHub <span aria-hidden="true">↗</span>
          </a>
          <Link
            href="/protocol"
            className="group inline-flex items-center gap-1.5 rounded-[9px] border border-cobalt/60 bg-cobalt/15 px-3.5 py-2 text-[14px] font-semibold text-ink transition-colors hover:border-cobalt-bright hover:bg-cobalt/30"
          >
            Explore Protocol
            <ArrowRight aria-hidden="true" className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-1" />
          </Link>
        </div>

        <button
          type="button"
          className="-mr-2 inline-flex h-10 w-10 items-center justify-center rounded-md text-ink md:hidden"
          aria-expanded={open}
          aria-controls="mobile-menu"
          aria-label={open ? "Close menu" : "Open menu"}
          onClick={() => setOpen((v) => !v)}
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </nav>

      {open && (
        <div id="mobile-menu" className="border-t border-line/70 px-5 pb-8 pt-4 md:hidden">
          <ul className="flex flex-col">
            {primaryNav.map((item) => (
              <li key={item.href}>
                <Link href={item.href} className="block border-b border-line/50 py-4 text-[20px] font-semibold text-ink">
                  {item.label}
                </Link>
              </li>
            ))}
            <li>
              <a href={site.docs} target="_blank" rel="noreferrer noopener" className="block border-b border-line/50 py-4 text-[20px] font-semibold text-ink">
                Docs ↗
              </a>
            </li>
            <li>
              <a href={site.github} target="_blank" rel="noreferrer noopener" className="block py-4 text-[20px] font-semibold text-ink">
                GitHub ↗
              </a>
            </li>
          </ul>
          <Link href="/protocol" className="mt-4 flex items-center justify-center gap-2 rounded-[10px] bg-cobalt py-3.5 text-[15px] font-semibold text-white">
            Explore Protocol <ArrowRight aria-hidden="true" className="h-4 w-4" />
          </Link>
        </div>
      )}
    </header>
  );
}
