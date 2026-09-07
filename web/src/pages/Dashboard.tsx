import { api, type Status, type TimelineEvent } from "../api";
import { bytes, eventLabel, eventTone, relative } from "../format";
import { Alert, Card, Empty, PageHead, Pill, Stat } from "../components/ui";
import { useAsync } from "../useAsync";
import { useT } from "../i18n";

export function Dashboard({ refreshKey }: { refreshKey: number }) {
    const t = useT();
    const status = useAsync<Status>(api.status, [refreshKey]);
    const events = useAsync<{ events: TimelineEvent[] }>(() => api.listEvents(12), [refreshKey]);

    if (status.error) return <Alert>{status.error}</Alert>;
    if (!status.data) return <div className="empty">{t("common.loading")}</div>;

    const s = status.data;
    const down = s.domains.filter((d) => d.enabled && !d.is_up);

    return (
        <>
            <PageHead
                title={t("dash.title")}
                subtitle={
                    s.domains.length === 0
                        ? t("dash.noDomains")
                        : down.length === 0
                          ? t("dash.allUp")
                          : t("dash.someDown", { down: down.length, total: s.domains.length })
                }
            />

            {s.draining && (
                <Alert tone="warn">
                    <strong>{t("dash.drainingTitle")}</strong>{" "}
                    {t("dash.drainingBody")}
                </Alert>
            )}

            {s.tls?.source === "self-signed" && (
                <Alert tone="warn">
                    <strong>{t("dash.selfSignedTitle")}</strong>{" "}
                    {t("dash.selfSignedBody", { domain: s.tls.domain })}
                    {s.tls.last_error && (
                        <div style={{ marginTop: ".4rem", opacity: 0.85 }}>
                            {t("dash.lastAttempt", { error: s.tls.last_error })}
                        </div>
                    )}
                </Alert>
            )}

            {down.length > 0 && (
                <Alert tone="warn">
                    <strong>{t("dash.holdingTitle")}</strong>{" "}
                    {t("dash.holdingBody", {
                        names: down.map((d) => d.name).join(", "),
                        verb: down.length === 1 ? t("dash.holdingIs") : t("dash.holdingAre"),
                    })}
                </Alert>
            )}
            {down.length === 0 && s.queue.pending > 0 && (
                <Alert tone="warn">
                    <strong>{t("dash.stuckTitle", { n: s.queue.pending })}</strong>{" "}
                    {t("dash.stuckBody")}
                </Alert>
            )}

            <div className="grid" style={{ marginBottom: "1.5rem" }}>
                <Stat
                    label={t("dash.waiting")}
                    value={s.queue.pending}
                    note={t("dash.onSpool", { size: bytes(s.queue.pending_bytes) })}
                />
                <Stat
                    label={t("dash.primariesUp")}
                    value={`${s.domains.filter((d) => d.is_up).length} / ${s.domains.length}`}
                    note={s.domains.length ? undefined : t("dash.addDomainToBegin")}
                />
                <Stat
                    label={t("dash.retention")}
                    value={s.queue.retention}
                    note={t("dash.beforeExpires")}
                />
                <Stat
                    label={t("dash.version")}
                    value={s.version}
                    note={s.commit !== "unknown" ? s.commit : undefined}
                />
            </div>

            <div className="stack">
                <Card>
                    <h2 style={{ marginBottom: ".9rem" }}>{t("dash.domains")}</h2>
                    {s.domains.length === 0 ? (
                        <Empty
                            title={t("dash.noDomainsYet")}
                            hint={t("dash.noDomainsHint")}
                        />
                    ) : (
                        <div className="table-wrap">
                            <table>
                                <thead>
                                    <tr>
                                        <th>{t("dash.thDomain")}</th>
                                        <th>{t("dash.thPrimary")}</th>
                                        <th>{t("dash.thSince")}</th>
                                        <th>{t("dash.thWaiting")}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {s.domains.map((d) => (
                                        <tr key={d.id}>
                                            <td>
                                                <strong>{d.name}</strong>
                                                {!d.enabled && (
                                                    <>
                                                        {" "}
                                                        <Pill tone="mute">{t("dash.paused")}</Pill>
                                                    </>
                                                )}
                                            </td>
                                            <td>
                                                <Pill tone={d.is_up ? "ok" : "bad"}>
                                                    {d.is_up ? t("dash.up") : t("dash.down")}
                                                </Pill>
                                                {d.last_error && !d.is_up && (
                                                    <div
                                                        className="stat-note truncate"
                                                        title={d.last_error}
                                                    >
                                                        {d.last_error}
                                                    </div>
                                                )}
                                            </td>
                                            <td>{relative(d.since)}</td>
                                            <td>{d.pending}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </Card>

                <Card>
                    <h2 style={{ marginBottom: ".9rem" }}>{t("dash.recentActivity")}</h2>
                    {!events.data?.events?.length ? (
                        <Empty title={t("dash.nothingYet")} />
                    ) : (
                        <ul className="timeline">
                            {events.data.events.map((e) => (
                                <li key={e.id}>
                                    <time>{relative(e.created_at)}</time>
                                    <Pill tone={eventTone(e.type)}>{eventLabel(e.type)}</Pill>
                                </li>
                            ))}
                        </ul>
                    )}
                </Card>
            </div>
        </>
    );
}
