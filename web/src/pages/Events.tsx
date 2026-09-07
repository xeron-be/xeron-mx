import { api, type TimelineEvent } from "../api";
import { absolute, eventLabel, eventTone, relative } from "../format";
import { Alert, Card, Empty, PageHead, Pill } from "../components/ui";
import { useAsync } from "../useAsync";
import { t as translate, useT } from "../i18n";

export function Events({ refreshKey }: { refreshKey: number }) {
    const t = useT();
    const list = useAsync<{ events: TimelineEvent[] }>(() => api.listEvents(200), [refreshKey]);

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
                            <li key={e.id}>
                                <time title={absolute(e.created_at)}>{relative(e.created_at)}</time>
                                <Pill tone={eventTone(e.type)}>{eventLabel(e.type)}</Pill>
                                <span style={{ color: "var(--muted)", fontSize: ".85rem" }}>
                                    {describe(e)}
                                </span>
                            </li>
                        ))}
                    </ul>
                )}
            </Card>
        </>
    );
}

function describe(e: TimelineEvent): string {
    const d = e.data ?? {};
    const parts: string[] = [];

    if (typeof d.domain === "string") parts.push(d.domain);
    if (typeof d.name === "string") parts.push(d.name);
    if (typeof d.from === "string" && d.from) parts.push(translate("events.from", { value: d.from }));
    if (Array.isArray(d.to) && d.to.length)
        parts.push(translate("events.to", { value: d.to.join(", ") }));
    if (typeof d.host === "string") parts.push(d.host);
    if (typeof d.email === "string") parts.push(d.email);
    if (typeof d.ip === "string") parts.push(translate("events.from", { value: d.ip }));
    if (typeof d.reason === "string") parts.push(d.reason);
    if (typeof d.error === "string" && d.error) parts.push(d.error);
    if (typeof d.discarded === "number" && d.discarded > 0) {
        parts.push(translate("events.discarded", { n: d.discarded }));
    }
    if (typeof d.pending === "number") parts.push(translate("events.pending", { n: d.pending }));

    return parts.join(" · ");
}
