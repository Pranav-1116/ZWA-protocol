import { statusMeta, type Status } from "@/lib/research";

const dot: Record<Status, string> = {
  established: "bg-established shadow-[0_0_10px_rgba(96,165,250,0.6)]",
  conditional: "bg-conditional shadow-[0_0_10px_rgba(165,180,252,0.5)]",
  research: "bg-research shadow-[0_0_10px_rgba(216,181,104,0.45)]",
  open: "bg-open",
};

const text: Record<Status, string> = {
  established: "text-established",
  conditional: "text-conditional",
  research: "text-research",
  open: "text-body",
};

/** Status is never encoded by colour alone: the dot always comes with a label. */
export function ResearchStatus({
  status,
  label,
  className = "",
  tone = "dark",
}: {
  status: Status;
  label?: string;
  className?: string;
  tone?: "dark" | "light";
}) {
  const lightText: Record<Status, string> = {
    established: "text-cobalt",
    conditional: "text-[#4f46e5]",
    research: "text-[#8a6a1f]",
    open: "text-paper-body",
  };
  return (
    <span className={`mono-label inline-flex items-center gap-2 ${tone === "light" ? lightText[status] : text[status]} ${className}`}>
      <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${dot[status]}`} />
      {label ?? statusMeta[status].label}
    </span>
  );
}
