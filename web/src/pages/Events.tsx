import { useState } from "react";
import { api, type TimelineEvent } from "../api";
import { absolute, eventLabel, eventTone, relative } from "../format";
import { Alert, Card, Empty, PageHead, Pill } from "../components/ui";
import { useAsync } from "../useAsync";
import { t as translate, useT } from "../i18n";
import { en, type TranslationKey } from "../locales/en";

export function Events({ refreshKey }: { refreshKey: number }) {
    const t = useT();
    const list = useAsync<{ events: TimelineEvent[] }>(() => api.listEvents(200), [refreshKey]);
    const [open, setOpen] = useState<number | null>(null);

    return (
        <>
            <PageHead
                title={t("events.title")}
                subtitle={t("events.subtitle")}
            />

            {list.error && <Alert>{list.error}</Alert>}

            <Card>
                {!list.data?.events?.length ? (
                    <Empty title={t("events.nothingRecorded")} />
                ) : (
                    <ul className="timeline">
                        {list.data.events.map((e) => (
                            <li key={e.id} style={{ flexWrap: "wrap" }}>
                                <time title={absolute(e.created_at)}>{relative(e.created_at)}</time>
                                <Pill tone={eventTone(e.type)}>{eventLabel(e.type)}</Pill>
                                <span style={{ color: "var(--muted)", fontSize: ".85rem", flex: 1, minWidth: 0 }}>
                                    {describeEvent(e)}
                                </span>
                                <button
                                    className="btn-sm"
                                    aria-expanded={open === e.id}
                                    onClick={() => setOpen(open === e.id ? null : e.id)}
                                >
                                    {open === e.id ? t("events.hideDetails") : t("events.details")}
                                </button>
                                {open === e.id && <Details e={e} />}
                            </li>
                        ))}
                    </ul>
                )}
            </Card>
        </>
    );
}

function known(key: string): key is TranslationKey {
    return key in en;
}

function label(prefix: string, value: string): string {
    const key = `${prefix}.${value}`;
    return known(key) ? translate(key) : value;
}

function text(v: unknown): string {
    if (v === null || v === undefined) return "";
    if (Array.isArray(v)) return v.map(text).join(", ");
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
}

export function describeEvent(e: TimelineEvent): string {
    const d = e.data ?? {};
    const str = (k: string) => (typeof d[k] === "string" && d[k] ? (d[k] as string) : "");
    const parts: string[] = [];

    const subject = e.domain_name || str("domain") || str("name");
    if (subject) parts.push(subject);
    if (e.type === "login_failed" || !str("by")) {
        if (str("email")) parts.push(str("email"));
    }
    if (str("reason")) parts.push(label("events.reason", str("reason")));
    if (str("zone")) parts.push(translate("events.listedOn", { value: str("zone") }));
    if (str("filter")) parts.push(translate("events.filter", { value: str("filter") }));
    if (str("virus")) parts.push(translate("events.virus", { value: str("virus") }));
    if (typeof d.score === "number") parts.push(translate("events.score", { value: d.score }));
    if (str("from")) parts.push(translate("events.from", { value: str("from") }));
    if (Array.isArray(d.to) && d.to.length) parts.push(translate("events.to", { value: d.to.join(", ") }));
    if (str("host")) parts.push(str("host"));
    if (str("error")) parts.push(str("error"));
    if (str("last_error")) parts.push(str("last_error"));
    if (typeof d.attempts === "number" && d.attempts > 0) parts.push(translate("events.attempts", { n: d.attempts }));
    if (typeof d.discarded === "number" && d.discarded > 0) parts.push(translate("events.discarded", { n: d.discarded }));
    if (typeof d.pending === "number") parts.push(translate("events.pending", { n: d.pending }));

    const by = str("by") || e.user || "";
    if (by) parts.push(translate("events.by", { value: by }));
    if (str("via_token")) parts.push(translate("events.viaToken", { value: str("via_token") }));
    if (str("second_factor")) parts.push(label("events.2fa", str("second_factor")));
    if (str("during") === "account_change") parts.push(translate("events.duringAccountChange"));
    const where = str("remote") || str("ip");
    if (where) parts.push(translate("events.fromIp", { value: str("helo") ? `${where} (${str("helo")})` : where }));

    return parts.join(" · ");
}

function Details({ e }: { e: TimelineEvent }) {
    const rows: [string, string][] = [];
    const add = (key: string, value: unknown) => {
        const v = text(value);
        if (v !== "") rows.push([label("events.field", key), v]);
    };
    add("user", e.user);
    add("domain_name", e.domain_name);
    add("queue_id", e.queue_id);
    for (const [k, v] of Object.entries(e.data ?? {})) {
        add(k, k === "reason" && typeof v === "string" ? `${label("events.reason", v)} (${v})` : v);
    }

    return (
        <dl
            style={{
                flexBasis: "100%",
                display: "grid",
                gridTemplateColumns: "max-content 1fr",
                gap: ".25rem 1rem",
                margin: ".5rem 0 .25rem",
                padding: ".6rem .8rem",
                background: "var(--bg)",
                border: "1px solid var(--border)",
                borderRadius: ".5rem",
                fontSize: ".82rem",
            }}
        >
            {rows.map(([k, v]) => (
                <div key={k} style={{ display: "contents" }}>
                    <dt style={{ color: "var(--muted)" }}>{k}</dt>
                    <dd style={{ margin: 0, wordBreak: "break-word", fontFamily: "var(--mono, monospace)" }}>{v}</dd>
                </div>
            ))}
        </dl>
    );
}
