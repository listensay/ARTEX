import type { AnchorHTMLAttributes } from "react";
import { safeHref } from "@/lib/safe-href";

export function ExternalLink({ href, children, ...props }: AnchorHTMLAttributes<HTMLAnchorElement>) {
  const safe = safeHref(href);
  return safe ? <a {...props} href={safe} target="_blank" rel="noopener noreferrer">{children}</a> : <span className={props.className}>{children}</span>;
}
