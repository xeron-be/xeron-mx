import { beforeEach, describe, expect, it } from "vitest";
import { sesTone } from "../src/pages/Domains";
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
