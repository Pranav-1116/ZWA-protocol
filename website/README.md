# ZWA Protocol — website

Marketing site for ZWA Protocol: *Prove what is permitted. Keep everything else private.*

Next.js 15 (App Router, static pages) · React 19 · TypeScript · Tailwind CSS 4 · Motion · React Bits · Lucide.

```bash
cd website
npm ci
npm run dev      # http://localhost:3000
npm run build && npm run start
npm run lint     # tsc --noEmit
```

This is separate from `frontend/`, which is reserved for the Colosseum demo.

## Pages

| Route | What it answers |
|---|---|
| `/` | The 8-section homepage: hero, problem, how it works, privacy model (with the scroll-driven Privacy Boundary), lineage, architecture, research, final call to action |
| `/protocol` | What ZWA is, in four chapters: issuance, compliance, private market coordination, settlement |
| `/research` | Research archive with topic filters |
| `/developers` | Illustrative interface (two-line code block, clearly labelled) |
| `/demo` | Simulated settlement walkthrough. No proofs, no network calls, no transactions |
| `/about` | Brand personality traits |
| `/privacy`, `/terms` | Legal pages linked from the footer |

## Design tokens

| Role | Colour | Use |
|---|---|---|
| Void Navy | `#070A12` | Main page background |
| Deep Navy | `#0B1020` | Alternate sections |
| Surface | `#111827` | Cards / panels |
| Elevated Surface | `#172033` | Interactive components |
| Border | `#253047` | Hairlines / card borders |
| Cobalt Blue | `#2563EB` | Primary brand accent |
| Bright Cobalt | `#3B82F6` | Hover / active / animated states |
| Electric Blue | `#60A5FA` | Highlights / proof flows |
| Primary White | `#F8FAFC` | Main headings |
| Secondary Gray | `#94A3B8` | Body copy |
| Muted Gray | `#64748B` | Labels / metadata |

Research status colours (Established `#60A5FA`, Conditional `#A5B4FC`, Research `#D8B568`, Open `#64748B`) are always shown with a text label, never as colour alone. Tokens live in `app/globals.css` (`@theme`).

Type: Manrope for UI and headings, IBM Plex Mono for hashes, labels and status. Both are self-hosted through Fontsource, so there are no external font requests.

## Logo

`components/ui/Logo.tsx` holds the ZWA mark as a vector, redrawn from the supplied artwork. Brand blue is `#0055FF`. Standalone files are `public/zwa-mark.svg` and `public/zwa-mark-white.svg`; the favicon is `app/icon.svg`.

## Motion

There are four animation classes: **Reveal** (`components/motion/Reveal`), **Proof** (the hero `ProofBoundary`), **Privacy** (`FieldStack`, `PrivacyBoundary`) and **Chain** (`LineageGraph`, `ProtocolFlow`).

- Everything respects `prefers-reduced-motion` and renders a meaningful static state.
- The hero background (`EncryptedField`) is Canvas 2D, pauses when off-screen, and uses no WebGL.

React Bits components used (adapted, see `THIRD_PARTY_NOTICES.md`):
- `BlurText`: two headings only;
- `SpotlightCard`: research cards, low intensity;
- `Magnet`: primary call to action, disabled on touch and reduced motion;

## Claim discipline

The copy follows the repository's `AGENTS.md`:
- no production or mainnet ZSA claims;
- no claim that consensus enforces compliance;
- no claim of full recursive lineage;
- no SDK presented as published.

Statuses come from `lib/research.ts`. Update them there when a milestone changes.
