import type { ReactNode } from "react";

/** Section title: 34px mobile → 50px desktop. */
export function SectionHeading({
  children,
  className = "",
  id,
  as: Tag = "h2",
}: {
  children: ReactNode;
  className?: string;
  id?: string;
  as?: "h1" | "h2" | "h3";
}) {
  return (
    <Tag id={id} className={`text-[34px] leading-[1.06] font-semibold tracking-[-0.03em] sm:text-[44px] lg:text-[50px] ${className}`}>
      {children}
    </Tag>
  );
}
