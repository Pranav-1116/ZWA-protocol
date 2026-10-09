/**
 * ZWA mark. Vector reconstruction of the supplied logo artwork
 * (three angular bands forming the Z / W / A monogram), drawn on a 523 × 685 grid.
 */
const BRAND_BLUE = "#0055FF";

export const LOGO_PATHS = [
  "M0 220 Q0 209 10 204 L441 0 V129 L0 336 Z",
  "M0 402 L187 314 V412 Q187 425 199 432 L406 552 V685 L163 544 V445 L0 521 Z",
  "M523 164 V282 L368 355 L523 445 V560 L255 405 Q243 398 243 386 V305 Q243 295 254 290 Z",
];

export function LogoGlyph({
  className = "",
  title,
  color = BRAND_BLUE,
}: {
  className?: string;
  title?: string;
  color?: string;
}) {
  return (
    <svg
      viewBox="0 0 523 685"
      fill={color}
      className={className}
      role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
    >
      {LOGO_PATHS.map((d) => (
        <path key={d} d={d} />
      ))}
    </svg>
  );
}

export function Logo({ className = "", withProtocol = false }: { className?: string; withProtocol?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-3 ${className}`}>
      <LogoGlyph className="h-8 w-auto" />
      <span className="text-[17px] font-bold tracking-[0.08em] text-ink">
        ZWA
        {withProtocol && <span className="ml-1.5 font-medium tracking-[0.02em] text-body">Protocol</span>}
      </span>
    </span>
  );
}
