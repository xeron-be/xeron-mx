import { beforeEach, describe, expect, it } from "vitest";
import { LANGUAGES, setLang, translate, translateApiError, type Lang } from "../src/i18n";
import { en, type TranslationKey } from "../src/locales/en";
import { fr } from "../src/locales/fr";
import { es } from "../src/locales/es";
import { nl } from "../src/locales/nl";
import { de } from "../src/locales/de";
import { apiErrorCodes } from "./go";

const catalogs = { en, fr, es, nl, de };
const keys = Object.keys(en) as TranslationKey[];

function placeholders(text: string): string[] {
    return [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
}

describe("catalogues", () => {
    it("covers every language offered in the picker", () => {
        expect(Object.keys(catalogs).sort()).toEqual(LANGUAGES.map((l) => l.code).sort());
    });

    for (const [lang, catalog] of Object.entries(catalogs)) {
        it(`${lang} keeps every placeholder the English string has`, () => {
            const wrong = keys.filter(
                (k) => placeholders(catalog[k]).join() !== placeholders(en[k]).join(),
            );
            expect(wrong).toEqual([]);
        });

        it(`${lang} has no empty strings`, () => {
            expect(keys.filter((k) => catalog[k].trim() === "")).toEqual([]);
        });
    }
});

describe("translate", () => {
    it("substitutes variables", () => {
        expect(translate("en", "time.ago", { value: "5m" })).toBe("5m ago");
    });

    it("leaves a placeholder alone when its variable is missing", () => {
        expect(translate("en", "time.ago", {})).toBe("{value} ago");
    });

    it("translates", () => {
        expect(translate("fr", "nav.domains")).toBe("Domaines");
    });
});

describe("translateApiError", () => {
    beforeEach(() => setLang("en" as Lang));

    it("maps a code to its message in the current language", () => {
        expect(translateApiError("not_found")).toBe(en["apiErr.not_found"]);
        setLang("fr");
        expect(translateApiError("not_found")).toBe(fr["apiErr.not_found"]);
    });

    it("falls back to the raw code rather than hiding it", () => {
        expect(translateApiError("no_such_code")).toBe("no_such_code");
        expect(translateApiError(undefined)).toBe("");
    });

    it("has a message for every error code the API can return", () => {
        const codes = apiErrorCodes();
        expect(codes.length).toBeGreaterThan(50);
        expect(codes.filter((c) => !(`apiErr.${c}` in en))).toEqual([]);
    });

    it("has no message for a code the API no longer returns", () => {
        const codes = new Set(apiErrorCodes());
        const stale = keys
            .filter((k) => k.startsWith("apiErr."))
            .map((k) => k.slice("apiErr.".length))
            .filter((c) => !codes.has(c));
        expect(stale).toEqual([]);
    });
});
