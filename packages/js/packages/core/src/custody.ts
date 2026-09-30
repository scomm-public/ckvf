import { fail } from "./errors.js";
import type { Extension } from "./types.js";

/** Payload extension for content-key exportability. The VEK is unchanged. */
export const KEY_CUSTODY_EXTENSION_ID = "std:key-custody";

const CUSTODY = new Set(["portable", "device-bound", "external"]);

export function validateKeyCustodyData(data: unknown, critical: boolean): void {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    fail("ERR_EXTENSION", "key custody data");
  }
  const o = data as Record<string, unknown>;
  for (const key of Object.keys(o)) {
    if (!["absolute_key_id", "custody", "provider", "key_ref"].includes(key)) {
      fail("ERR_EXTENSION", `key custody field ${key}`);
    }
  }
  if (typeof o.absolute_key_id !== "string" || !o.absolute_key_id) {
    fail("ERR_EXTENSION", "key custody absolute_key_id");
  }
  if (typeof o.custody !== "string" || !CUSTODY.has(o.custody)) {
    fail("ERR_EXTENSION", "key custody value");
  }
  const nonExportable = o.custody === "device-bound" || o.custody === "external";
  if (critical !== nonExportable) fail("ERR_EXTENSION", "key custody critical flag");
  if (nonExportable && (typeof o.key_ref !== "string" || !o.key_ref)) {
    fail("ERR_EXTENSION", "key custody key_ref");
  }
}

export function isUnderstoodCriticalExtension(extension: Extension): boolean {
  return extension.id === KEY_CUSTODY_EXTENSION_ID;
}

export function nonExportableKeyIds(criticalExtensions: Extension[]): Set<string> {
  const ids = new Set<string>();
  for (const extension of criticalExtensions) {
    if (extension.id !== KEY_CUSTODY_EXTENSION_ID) continue;
    const data = extension.data;
    if (!data || typeof data !== "object") continue;
    const o = data as Record<string, unknown>;
    if (o.custody === "device-bound" || o.custody === "external") {
      if (typeof o.absolute_key_id === "string") ids.add(o.absolute_key_id);
    }
  }
  return ids;
}

export function assertCustodyBindings(payload: Record<string, unknown>): void {
  const keys = Array.isArray(payload.keys) ? payload.keys : [];
  const byId = new Map<string, Record<string, unknown>>();
  for (const raw of keys) {
    if (raw && typeof raw === "object") {
      const key = raw as Record<string, unknown>;
      if (typeof key.absolute_key_id === "string") byId.set(key.absolute_key_id, key);
    }
  }
  const check = (raw: unknown) => {
    if (!Array.isArray(raw)) return;
    for (const entry of raw) {
      if (!entry || typeof entry !== "object") continue;
      const ext = entry as Record<string, unknown>;
      if (ext.id !== KEY_CUSTODY_EXTENSION_ID) continue;
      const data = ext.data as Record<string, unknown> | undefined;
      if (!data) continue;
      const key = typeof data.absolute_key_id === "string" ? byId.get(data.absolute_key_id) : undefined;
      if (!key) fail("ERR_EXTENSION", "key custody key missing");
      if (
        (data.custody === "device-bound" || data.custody === "external") &&
        key.private_key != null
      ) {
        fail("ERR_EXTENSION", "non-exportable key has private bytes");
      }
    }
  };
  check(payload.extensions);
  check(payload.critical_extensions);
}
