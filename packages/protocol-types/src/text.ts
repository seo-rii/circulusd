import { validationError } from "./errors.ts";

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
