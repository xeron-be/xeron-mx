import { useSyncExternalStore } from "react";
import { en, type Catalog, type TranslationKey } from "./locales/en";
import { fr } from "./locales/fr";
import { es } from "./locales/es";
import { nl } from "./locales/nl";
import { de } from "./locales/de";

export type Lang = "en" | "fr" | "es" | "nl" | "de";

export const LANGUAGES: { code: Lang; label: string }[] = [
    { code: "en", label: "English" },
    { code: "fr", label: "Français" },
    { code: "es", label: "Español" },
    { code: "nl", label: "Nederlands" },
    { code: "de", label: "Deutsch" },
];

const CATALOGS: Record<Lang, Catalog> = { en, fr, es, nl, de };

const STORAGE_KEY = "xeronmx.lang";

function isLang(v: string): v is Lang {
    return LANGUAGES.some((l) => l.code === v);
}

// The choice lives in the browser rather than on the account: it is a display
// preference, it needs no schema migration, and a panel is usually run by one
// person anyway. Storage can throw in a private window, so every access is
// guarded and simply falls back to detection.
function detect(): Lang {
    try {
        const saved = localStorage.getItem(STORAGE_KEY);
        if (saved && isLang(saved)) return saved;
    } catch {
        /* storage unavailable */
    }
    const offered = navigator.languages?.length ? navigator.languages : [navigator.language];
    for (const tag of offered) {
        const base = (tag ?? "").slice(0, 2).toLowerCase();
        if (isLang(base)) return base;
    }
    return "en";
}

let current: Lang = detect();
const listeners = new Set<() => void>();

export function getLang(): Lang {
    return current;
}

export function setLang(lang: Lang): void {
    if (lang === current) return;
    current = lang;
    try {
        localStorage.setItem(STORAGE_KEY, lang);
    } catch {
        /* storage unavailable; the choice lasts for this page only */
    }
    document.documentElement.lang = lang;
    listeners.forEach((notify) => notify());
}

function subscribe(notify: () => void): () => void {
    listeners.add(notify);
    return () => listeners.delete(notify);
}

export function useLang(): Lang {
    return useSyncExternalStore(subscribe, getLang, getLang);
}

export type Vars = Record<string, string | number>;

export function translate(lang: Lang, key: TranslationKey, vars?: Vars): string {
    // English is the fallback rather than the key itself: a missing translation
    // should read as slightly wrong, not as machinery leaking into the page.
    const text = CATALOGS[lang][key] ?? en[key] ?? key;
    if (!vars) return text;
    return text.replace(/\{(\w+)\}/g, (whole, name: string) =>
        name in vars ? String(vars[name]) : whole,
    );
}

export type TFunction = (key: TranslationKey, vars?: Vars) => string;

export function useT(): TFunction {
    const lang = useLang();
    return (key, vars) => translate(lang, key, vars);
}

export function t(key: TranslationKey, vars?: Vars): string {
    return translate(current, key, vars);
}

// The BCP 47 tag for Intl. Only the base language is tracked, which is enough
// for dates and numbers to come out in the right shape.
export function locale(): string {
    return current;
}

export function translateApiError(code: string | undefined): string {
    if (!code) return "";
    const key = `apiErr.${code}` as TranslationKey;
    const cat = CATALOGS[current];
    if (cat && key in cat) return cat[key];
    if (key in en) return en[key];
    return code;
}

document.documentElement.lang = current;
