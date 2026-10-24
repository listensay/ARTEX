// Scope this loader to one transcript's task/conversation. Deduplicate requests
// while a record is loading and bound completed bodies so long sessions do not
// retain every expanded tool output indefinitely. Failed requests remain retryable.
export function createActivityDetailCache(
  fetchDetail: (seq: number) => Promise<string>,
  limit = 128,
  maxChars = 2_000_000,
) {
  const completed = new Map<number, string>();
  const pending = new Map<number, Promise<string>>();
  let retainedChars = 0;
  return (seq: number): Promise<string> => {
    if (completed.has(seq)) {
      const detail = completed.get(seq)!;
      completed.delete(seq);
      completed.set(seq, detail);
      return Promise.resolve(detail);
    }
    const existing = pending.get(seq);
    if (existing) return existing;
    const request = Promise.resolve()
      .then(() => fetchDetail(seq))
      .then((detail) => {
        // A single command may produce megabytes of output. Keep it in the
        // expanded row, but let it be released instead of retaining it in the cache.
        if (detail.length <= maxChars) {
          completed.set(seq, detail);
          retainedChars += detail.length;
          while (completed.size > limit || retainedChars > maxChars) {
            const oldest = completed.keys().next().value!;
            retainedChars -= completed.get(oldest)!.length;
            completed.delete(oldest);
          }
        }
        return detail;
      })
      .finally(() => pending.delete(seq));
    pending.set(seq, request);
    return request;
  };
}
