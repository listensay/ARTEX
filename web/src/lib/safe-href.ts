// Dynamic external links use the same parsed URL that was validated.
export function safeHref(value: unknown): string | undefined {
  if (typeof value !== "string" || /[\u0000-\u0020\u007f-\u009f]/.test(value)) return undefined;
  if (!/^https?:\/\//i.test(value) || value.includes("\\")) return undefined;
  try {
    const url = new URL(value);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || !url.hostname || url.username || url.password) return undefined;
    return url.href;
  } catch { return undefined; }
}
