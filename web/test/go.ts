import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const internal = fileURLToPath(new URL("../../internal/", import.meta.url));

function goSources(): string[] {
    return (readdirSync(internal, { recursive: true }) as string[])
        .filter((f) => f.endsWith(".go") && !f.endsWith("_test.go"))
        .map((f) => readFileSync(join(internal, f), "utf8"));
}

function matches(sources: string[], pattern: RegExp): string[] {
    const found = new Set<string>();
    for (const src of sources) {
        for (const m of src.matchAll(pattern)) found.add(m[1]);
    }
    return [...found].sort();
}

// Every error code the API can answer with, from internal/api/codes.go.
export function apiErrorCodes(): string[] {
    const src = readFileSync(join(internal, "api", "codes.go"), "utf8");
    return matches([src], /^\s*Err\w+\s*=\s*"([a-z0-9_]+)"/gm);
}

// Every event type the daemon writes to the timeline: the named constants in
// the store, and the handful recorded with a literal type.
export function eventTypes(): string[] {
    const sources = goSources();
    return [
        ...new Set([
            ...matches(sources, /\bEvent[A-Z]\w*\s*=\s*"([a-z_]+)"/g),
            ...matches(sources, /\bType:\s*"([a-z_]+)"/g),
        ]),
    ].sort();
}
