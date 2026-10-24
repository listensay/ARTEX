import type { Activity } from "./types";

// History and live responses can overlap or arrive out of order. A persisted
// activity's seq is its identity; replay must not duplicate rows or token totals.
export function mergeActivities(current: Activity[], incoming: Activity[]): Activity[] {
  if (!incoming.length) return current;
  const bySeq = new Map<number, Activity>();
  for (const activity of current) bySeq.set(activity.seq, activity);
  for (const activity of incoming) {
    const existing = bySeq.get(activity.seq);
    // Poll/replay serializes fresh objects even when the persisted row is the
    // same. Keep that row's reference so unchanged transcript blocks can skip work.
    const same = existing && Object.keys({ ...existing, ...activity }).every((key) => {
      const field = key as keyof Activity;
      return field === "metadata"
        ? JSON.stringify(existing[field]) === JSON.stringify(activity[field])
        : existing[field] === activity[field];
    });
    if (!same) bySeq.set(activity.seq, activity);
  }
  const merged = [...bySeq.values()].sort((left, right) => left.seq - right.seq);
  return merged.length === current.length && merged.every((item, index) => item === current[index]) ? current : merged;
}
