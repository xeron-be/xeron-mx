import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { bytes, duration, eventLabel, eventTone, relative, statusLabel, statusTone } from "../src/format";
import { setLang, translate } from "../src/i18n";
import { eventTypes } from "./go";

beforeEach(() => setLang("en"));

describe("bytes", () => {
    it.each([
        [0, "0 B"],
        [1023, "1023 B"],
        [1024, "1.0 KB"],
        [1536, "1.5 KB"],
        [10 * 1024, "10 KB"],
        [1024 ** 2, "1.0 MB"],
        [1.5 * 1024 ** 3, "1.5 GB"],
        [1024 ** 4, "1.0 TB"],
        [2048 * 1024 ** 4, "2048 TB"],
    ])("%d bytes reads as %s", (n, want) => {
        expect(bytes(n)).toBe(want);
    });
});

describe("duration", () => {
    it.each([
        [0, "0s"],
        [59, "59s"],
        [60, "1m"],
        [3599, "60m"],
        [3600, "1.0h"],
        [5400, "1.5h"],
        [86400, "1.0d"],
    ])("%d seconds reads as %s", (s, want) => {
        expect(duration(s)).toBe(want);
    });
});

describe("relative", () => {
    const now = new Date("2026-09-23T12:00:00Z");
    beforeEach(() => {
        vi.useFakeTimers();
        vi.setSystemTime(now);
    });
    afterEach(() => vi.useRealTimers());

    const ago = (seconds: number) => new Date(now.getTime() - seconds * 1000).toISOString();

    it.each([
        ["missing", null, "never"],
        ["unparseable", "not a date", "unknown"],
        ["a few seconds ago", ago(10), "just now"],
        ["a few seconds ahead", ago(-10), "now"],
        ["a minute ago", ago(60), "1m ago"],
        ["half an hour ago", ago(1800), "30m ago"],
        ["three hours ago", ago(3 * 3600), "3h ago"],
        ["two days ago", ago(2 * 86400), "2d ago"],
        ["in an hour", ago(-3600), "in 1h"],
    ])("%s", (_name, iso, want) => {
        expect(relative(iso)).toBe(want);
    });
});

describe("events", () => {
    it("labels every event type the daemon records", () => {
        const types = eventTypes();
        expect(types).toContain("primary_down");
        const fallback = types.filter((t) => eventLabel(t) === t.replace(/_/g, " "));
        expect(fallback).toEqual([]);
    });

    it("follows the panel language", () => {
        setLang("fr");
        expect(eventLabel("primary_down")).toBe(translate("fr", "ev.primary_down"));
    });

    it("falls back to a readable form of an unknown type", () => {
        expect(eventLabel("something_new")).toBe("something new");
    });

    it("colours outages and failures as bad and recoveries as ok", () => {
        expect(eventTone("primary_down")).toBe("bad");
        expect(eventTone("mail_failed")).toBe("bad");
        expect(eventTone("queue_full")).toBe("warn");
        expect(eventTone("primary_up")).toBe("ok");
        expect(eventTone("login")).toBe("mute");
    });
});

describe("queue status", () => {
    it.each([
        ["queued", "warn"],
        ["delivering", "warn"],
        ["delivered", "ok"],
        ["failed", "bad"],
        ["expired", "bad"],
        ["something_else", "mute"],
    ])("%s is %s", (status, tone) => {
        expect(statusTone(status)).toBe(tone);
    });

    it("labels known statuses and passes unknown ones through", () => {
        expect(statusLabel("queued")).toBe(translate("en", "queue.waiting"));
        expect(statusLabel("something_else")).toBe("something_else");
    });
});
