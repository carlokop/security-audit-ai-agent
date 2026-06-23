/**
 * Loads `.env` files from the current working directory and package root.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

let loaded = false;

/**
 * Loads environment variables from `.env` without overriding existing process values.
 */
export function loadEnv() {
  if (loaded) {
    return;
  }

  loaded = true;
  const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

  for (const envPath of [join(process.cwd(), ".env"), join(packageRoot, ".env")]) {
    if (!existsSync(envPath)) {
      continue;
    }

    for (const line of readFileSync(envPath, "utf8").split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) {
        continue;
      }

      const separator = trimmed.indexOf("=");
      if (separator === -1) {
        continue;
      }

      const key = trimmed.slice(0, separator).trim();
      let value = trimmed.slice(separator + 1).trim();

      if (
        (value.startsWith('"') && value.endsWith('"'))
        || (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }

      if (process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  }
}

loadEnv();
