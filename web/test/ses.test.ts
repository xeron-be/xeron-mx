import { beforeEach, describe, expect, it } from "vitest";
import { sendingTone, sesTone } from "../src/pages/Domains";
import { describeEvent } from "../src/pages/Events";
import { eventLabel, eventTone } from "../src/format";
import { setLang } from "../src/i18n";

beforeEach(() => setLang("en"));

describe("SES status", () => {
    it("only shows a verified identity as good", () => {
        expect(sesTone("verified")).toBe("ok");
        expect(sesTone("pending")).toBe("warn");
        expect(sesTone("failed")).toBe("bad");
        expect(sesTone("error")).toBe("bad");
        expect(sesTone("unknown")).toBe("mute");
    });

    it("labels the identity events on the timeline", () => {
        expect(eventLabel("ses_identity_verified")).toBe("SES identity verified");
        expect(eventTone("ses_identity_failed")).toBe("bad");
        expect(eventTone("ses_identity_verified")).toBe("ok");
        setLang("fr");
        expect(eventLabel("ses_identity_deleted")).toBe("Identité SES supprimée");
    });
});

describe("sending reputation", () => {
    it("shows a suspension as bad and a warning as a warning", () => {
        expect(sendingTone("suspended")).toBe("bad");
        expect(sendingTone("warning")).toBe("warn");
        expect(sendingTone("ok")).toBe("ok");
    });

    it("tells why a domain was suspended on the timeline", () => {
        expect(eventLabel("sending_suspended")).toBe("Sending suspended");
        expect(eventTone("sending_suspended")).toBe("bad");
        expect(eventTone("sending_reputation_warning")).toBe("warn");
        expect(
            describeEvent({
                id: 1, type: "sending_suspended", created_at: "2026-11-10T12:00:00Z",
                data: { domain: "client.example", reason: "complaints", sent: 40, complaints: 2 },
            }),
        ).toBe("client.example · too many complaints");
    });
});
