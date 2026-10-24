import { cn } from "@/lib/utils";

export function HoneypotBadge({ score, evidence }: { score?: number; evidence?: string }) {
  if (!score || !Number.isFinite(score) || score <= 0) return <span className="text-xs text-muted-foreground">—</span>;
  let details = evidence || "";
  try {
    const parsed: unknown = JSON.parse(evidence || "[]");
    if (Array.isArray(parsed)) details = parsed.filter((v) => typeof v === "string").join("\n");
  } catch {
    /* legacy evidence remains plain text */
  }
  const high = score >= 0.9;
  const title = `静态蜜罐评分 ${score.toFixed(2)}（单信号，只表示疑似）\n${details}\n处置：降级为只读，不投递、不爆破、不利用；无信号不代表安全。`;
  return (
    <span
      title={title}
      aria-label={title}
      className={cn(
        "inline-block rounded px-1.5 py-0.5 text-[10px] font-semibold leading-none",
        high
          ? "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300"
          : "bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300",
      )}
    >
      {high ? "高度疑似" : "疑似蜜罐"}
    </span>
  );
}
