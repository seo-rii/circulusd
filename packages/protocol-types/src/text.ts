import { validationError } from "./errors.ts";
import { UNICODE_15_UNASSIGNED_RANGES } from "./unicode15-table.ts";

export function assertUnicodeScalarString(value: string, path: string): string {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const following = value.charCodeAt(index + 1);
      if (!(following >= 0xdc00 && following <= 0xdfff)) {
        validationError(path, "must contain only valid Unicode scalar values");
      }
      index += 1;
      continue;
    }
    if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      validationError(path, "must contain only valid Unicode scalar values");
    }
  }
  return value;
}

// U+10EFD (combining class 220) is new in Unicode 15.0.0; an older normalizer
// treats it as unassigned and leaves it after U+0300.
const runtimeNormalizesUnicode15 =
  "\u0300\u{10EFD}".normalize("NFC") === "\u{10EFD}\u0300";
// Planes 0 and 1 hold nearly all text, so they get a bitmap; higher planes use
// binary search over the generated ranges.
const unicode15UnassignedLowPlanes = new Uint32Array(0x20000 / 32);
for (let index = 0; index < UNICODE_15_UNASSIGNED_RANGES.length; index += 2) {
  const first = UNICODE_15_UNASSIGNED_RANGES[index] ?? 0;
  const last = Math.min(UNICODE_15_UNASSIGNED_RANGES[index + 1] ?? 0, 0x1ffff);
  for (let codePoint = first; codePoint <= last;) {
    const word = codePoint >>> 5;
    const bit = codePoint & 31;
    const span = Math.min(32 - bit, last - codePoint + 1);
    const mask = span === 32 ? 0xffffffff : ((1 << span) - 1) << bit;
    unicode15UnassignedLowPlanes[word] = (unicode15UnassignedLowPlanes[word] ?? 0) | mask;
    codePoint += span;
  }
}
// The first code point unassigned in Unicode 15.0.0 is U+0378; this native scan
// skips the per-code-point loop for text without anything at or above it.
const atOrAboveFirstUnassigned = /[^\0-\u{377}]/u;

function unassignedInUnicode15(codePoint: number): boolean {
  if (codePoint <= 0x1ffff) {
    return ((unicode15UnassignedLowPlanes[codePoint >>> 5] ?? 0) & (1 << (codePoint & 31))) !== 0;
  }
  let low = 0;
  let high = UNICODE_15_UNASSIGNED_RANGES.length / 2;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if ((UNICODE_15_UNASSIGNED_RANGES[middle * 2 + 1] ?? 0) < codePoint) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }
  return (UNICODE_15_UNASSIGNED_RANGES[low * 2] ?? Number.POSITIVE_INFINITY) <= codePoint;
}

/**
 * Returns text in canonical form: NFC as defined by Unicode 15.0.0, whatever
 * Unicode version the runtime's normalizer implements.
 *
 * A code point unassigned in Unicode 15.0.0 has combining class 0, no
 * decomposition and no composition there, so it is a normalization boundary.
 * Splitting at those code points and normalizing each segment with the
 * runtime gives the Unicode 15.0.0 result on any runtime of version 15.0.0 or
 * later: the segments contain only characters assigned in 15.0.0, whose
 * normalization the Unicode Normalization Stability Policy freezes. Go applies
 * the same rule (internal/canonical text.go).
 */
export function normalizeCanonicalText(value: string): string {
  if (!runtimeNormalizesUnicode15) {
    throw new Error("canonical text requires a Unicode 15.0.0 or later normalizer");
  }
  if (!atOrAboveFirstUnassigned.test(value)) {
    return value.normalize("NFC");
  }
  let pieces: string[] | undefined;
  let segmentStart = 0;
  for (let index = 0; index < value.length; index += 1) {
    let codePoint = value.charCodeAt(index);
    let width = 1;
    if (codePoint >= 0xd800 && codePoint <= 0xdbff) {
      const following = value.charCodeAt(index + 1);
      if (following >= 0xdc00 && following <= 0xdfff) {
        codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (following - 0xdc00);
        width = 2;
      }
    }
    if (unassignedInUnicode15(codePoint)) {
      pieces ??= [];
      pieces.push(value.slice(segmentStart, index).normalize("NFC"), value.slice(index, index + width));
      segmentStart = index + width;
    }
    index += width - 1;
  }
  if (pieces === undefined) {
    return value.normalize("NFC");
  }
  pieces.push(value.slice(segmentStart).normalize("NFC"));
  return pieces.join("");
}

/** Reports whether text is already in the form normalizeCanonicalText returns. */
export function isCanonicalText(value: string): boolean {
  return normalizeCanonicalText(value) === value;
}
