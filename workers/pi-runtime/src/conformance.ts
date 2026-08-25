import type { PiWorkerdConformanceStatus } from "./types.ts";

const UNAVAILABLE_REASON =
  "Pi Agent Core 0.84.3 and stock workerd 1.20260825.1 have not passed the real dynamic-worker, outbound-denial, and isolate-separation gate";

export function getPiWorkerdConformanceStatus(): PiWorkerdConformanceStatus {
  return { status: "UNAVAILABLE", reason: UNAVAILABLE_REASON };
}
