import { beforeEach, describe, expect, it } from "vitest";
import { describeEvent, detailRows, timelineLabel } from "../src/pages/Events";
import { setLang } from "../src/i18n";

beforeEach(() => setLang("en"));

const at = "2026-09-25T12:00:00Z";

describe("timeline summaries", () => {
    it("names the account, the token and the address behind an admin action", () => {
        expect(
            describeEvent({
                id: 1, type: "domain_deleted", created_at: at, user: "admin@example.com",
                data: { name: "example.org", by: "admin@example.com", via_token: "billing", ip: "203.0.113.7" },
            }),
        ).toBe("example.org · by admin@example.com · via the token “billing” · from 203.0.113.7");
    });

    it("falls back to the resolved account on events recorded before the actor was stored", () => {
        expect(
            describeEvent({ id: 2, type: "login", created_at: at, user: "admin@example.com", data: { ip: "203.0.113.7" } }),
        ).toBe("by admin@example.com · from 203.0.113.7");
    });

    it("says why a login failed and for which address", () => {
        expect(
            describeEvent({
                id: 3, type: "login_failed", created_at: at,
                data: { email: "someone@example.com", reason: "wrong_password", ip: "198.51.100.2" },
            }),
        ).toBe("someone@example.com · wrong password · from 198.51.100.2");
    });

    it("tells who was refused by a blocklist and which one", () => {
        expect(
            describeEvent({
                id: 4, type: "mail_rejected", created_at: at,
                data: { reason: "dnsbl", remote: "192.0.2.9", zone: "zen.spamhaus.org", record: "127.0.0.4" },
            }),
        ).toBe("address on a blocklist · listed on zen.spamhaus.org · from 192.0.2.9");
    });

    it("gives the sender, the recipients and the sending host of a spam rejection", () => {
        expect(
            describeEvent({
                id: 5, type: "mail_rejected", created_at: at,
                data: { reason: "spam", score: 18.5, from: "x@spam.test", to: ["a@example.com"], remote: "192.0.2.9", helo: "mx.spam.test" },
            }),
        ).toBe("spam · score 18.5 · from x@spam.test · to a@example.com · from 192.0.2.9 (mx.spam.test)");
    });
});

describe("timeline details", () => {
    it("shows the domain and the account once", () => {
        const rows = detailRows({
            id: 10, type: "mail_delivered", created_at: at, domain_name: "xeron.be", queue_id: "abc",
            user: "admin@example.com",
            data: { domain: "xeron.be", by: "admin@example.com", to: ["a@far.example"] },
        });
        expect(rows.filter(([, v]) => v === "xeron.be")).toHaveLength(1);
        expect(rows.filter(([, v]) => v === "admin@example.com")).toHaveLength(1);
        expect(rows.map(([k]) => k)).toEqual(["Domain", "Message", "By", "Recipients"]);
    });

    it("keeps a domain field that differs from the resolved one", () => {
        const rows = detailRows({
            id: 11, type: "domain_deleted", created_at: at, domain_name: "old.example",
            data: { domain: "other.example" },
        });
        expect(rows.map(([, v]) => v)).toEqual(["old.example", "other.example"]);
    });
});

describe("timeline labels", () => {
    it("tells outbound deliveries from deliveries to the primary", () => {
        expect(timelineLabel({ id: 12, type: "mail_delivered", created_at: at, data: { direction: "outbound" } }))
            .toBe("Sent to the recipient");
        expect(timelineLabel({ id: 13, type: "mail_delivered", created_at: at, data: {} }))
            .not.toBe("Sent to the recipient");
    });
});
