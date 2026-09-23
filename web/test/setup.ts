// i18n.ts sets the page language when it loads and whenever the language
// changes. The tests run in Node, and this is all of the DOM that needs.
globalThis.document = { documentElement: { lang: "" } } as unknown as Document;
