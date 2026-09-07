import { useState } from "react";
import { api, type ClusterState } from "../api";
import { bytes, relative } from "../format";
import { Alert, Card, Empty, PageHead, Pill } from "../components/ui";
import { useAsync } from "../useAsync";
import { useT } from "../i18n";

export function Cluster({
    refreshKey,
    canEdit,
    onChanged,
}: {
    refreshKey: number;
    canEdit: boolean;
    onChanged: () => void;
}) {
    const t = useT();
    const [error, setError] = useState("");
    const state = useAsync<ClusterState>(api.cluster, [refreshKey]);

    async function forget(nodeID: string) {
        if (!confirm(t("cluster.forgetConfirm", { node: nodeID }))) return;
        setError("");
        try {
            await api.forgetNode(nodeID);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("cluster.couldNotForget"));
        }
    }

    if (state.error) {
        return (
            <>
                <PageHead title={t("cluster.title")} />
                <Alert>{state.error}</Alert>
            </>
        );
    }

    if (state.data && !state.data.enabled) {
        return (
            <>
                <PageHead title={t("cluster.title")} subtitle={t("cluster.subtitle")} />
                <Card>
                    <Empty title={t("cluster.offTitle")} hint={t("cluster.offHint")} />
                </Card>
            </>
        );
    }

    const nodes = state.data?.nodes ?? [];
    const drifted = state.data?.drifted ?? 0;
    const down = nodes.filter((n) => !n.healthy).length;

    return (
        <>
            <PageHead
                title={t("cluster.title")}
                subtitle={t("cluster.subtitleOn", {
                    node: state.data?.node_id ?? "",
                    role:
                        state.data?.role === "primary"
                            ? t("cluster.rolePrimary")
                            : t("cluster.roleFollower"),
                })}
            />

            {error && <Alert>{error}</Alert>}

            {/*
                Said first and said plainly. Somebody looking at a fleet view
                will otherwise assume the queue is shared, and act on that
                assumption during exactly the incident where it is not true.
            */}
            <Alert tone="ok">{t("cluster.notSharedNotice")}</Alert>

            {drifted > 0 && (
                <Alert tone="bad">
                    <div style={{ fontWeight: 550 }}>{t("cluster.driftTitle", { n: drifted })}</div>
                    {t("cluster.driftBody")}
                </Alert>
            )}

            {down > 0 && <Alert tone="warn">{t("cluster.downNotice", { n: down })}</Alert>}

            <Card>
                {nodes.length === 0 ? (
                    <Empty title={t("cluster.noNodesTitle")} hint={t("cluster.noNodesHint")} />
                ) : (
                    <div className="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("cluster.thNode")}</th>
                                    <th>{t("cluster.thState")}</th>
                                    <th>{t("cluster.thQueue")}</th>
                                    <th>{t("cluster.thDomains")}</th>
                                    <th>{t("cluster.thConfig")}</th>
                                    <th>{t("cluster.thVersion")}</th>
                                    {canEdit && <th />}
                                </tr>
                            </thead>
                            <tbody>
                                {nodes.map((n) => (
                                    <tr key={n.node_id}>
                                        <td>
                                            <strong>{n.node_id}</strong>
                                            {n.self && (
                                                <>
                                                    {" "}
                                                    <Pill tone="ok">{t("cluster.thisNode")}</Pill>
                                                </>
                                            )}
                                            <div className="mono-sm break">
                                                {n.advertise_url || t("cluster.noAddress")}
                                            </div>
                                        </td>
                                        <td>
                                            {n.healthy ? (
                                                <Pill tone="ok">{t("cluster.up")}</Pill>
                                            ) : (
                                                <Pill tone="bad">{t("cluster.down")}</Pill>
                                            )}
                                            <div className="stat-note">
                                                {t("cluster.lastSeen", { when: relative(n.last_seen) })}
                                            </div>
                                            <Pill tone={n.role === "primary" ? "warn" : "mute"}>
                                                {n.role === "primary"
                                                    ? t("cluster.rolePrimary")
                                                    : t("cluster.roleFollower")}
                                            </Pill>
                                        </td>
                                        <td>
                                            {n.queue_pending}
                                            <div className="stat-note">{bytes(n.queue_bytes)}</div>
                                        </td>
                                        <td>{n.domains}</td>
                                        <td>
                                            {!n.config_hash ? (
                                                <Pill tone="mute">{t("common.unknown")}</Pill>
                                            ) : n.config_drift ? (
                                                <>
                                                    <Pill tone="bad">{t("cluster.drift")}</Pill>
                                                    <div className="mono-sm">{n.config_hash}</div>
                                                </>
                                            ) : (
                                                <>
                                                    <Pill tone="ok">{t("cluster.inSync")}</Pill>
                                                    <div className="mono-sm">{n.config_hash}</div>
                                                </>
                                            )}
                                        </td>
                                        <td className="mono-sm">{n.version || "—"}</td>
                                        {canEdit && (
                                            <td className="right">
                                                {!n.self && (
                                                    <button
                                                        className="btn-sm"
                                                        onClick={() => forget(n.node_id)}
                                                    >
                                                        {t("cluster.forget")}
                                                    </button>
                                                )}
                                            </td>
                                        )}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </Card>
        </>
    );
}
