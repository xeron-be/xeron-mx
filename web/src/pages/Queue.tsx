import { useState } from "react";
import { api, type Message } from "../api";
import { absolute, bytes, relative, statusLabel, statusTone } from "../format";
import { Alert, Card, Empty, PageHead, Pill } from "../components/ui";
import { useAsync } from "../useAsync";
import { useT } from "../i18n";
import type { TranslationKey } from "../locales/en";

const DIRECTIONS: { key: string; label: TranslationKey }[] = [
    { key: "", label: "queue.both" },
    { key: "inbound", label: "queue.inbound" },
    { key: "outbound", label: "queue.outbound" },
];

const HOLD: { key: string; label: TranslationKey }[] = [
    { key: "", label: "queue.all" },
    { key: "held", label: "queue.quarantined" },
];

const FILTERS: { key: string; label: TranslationKey }[] = [
    { key: "", label: "queue.all" },
    { key: "queued", label: "queue.waiting" },
    { key: "delivered", label: "queue.delivered" },
    { key: "failed", label: "queue.failed" },
    { key: "expired", label: "queue.expired" },
];

function FilterGroup({
    options,
    active,
    onSelect,
}: {
    options: { key: string; label: TranslationKey }[];
    active: string;
    onSelect: (key: string) => void;
}) {
    const t = useT();
    return (
        <>
            {options.map((o) => (
                <button
                    key={o.key || "all"}
                    className="btn-sm"
                    onClick={() => onSelect(o.key)}
                    aria-pressed={active === o.key}
                    style={
                        active === o.key
                            ? {
                                  background: "var(--accent)",
                                  color: "#fff",
                                  borderColor: "var(--accent)",
                              }
                            : undefined
                    }
                >
                    {t(o.label)}
                </button>
            ))}
        </>
    );
}

export function Queue({
    refreshKey,
    canEdit,
    onChanged,
}: {
    refreshKey: number;
    canEdit: boolean;
    onChanged: () => void;
}) {
    const t = useT();
    const [filter, setFilter] = useState("");
    const [direction, setDirection] = useState("");
    const [held, setHeld] = useState("");
    const [open, setOpen] = useState<string | null>(null);
    const [error, setError] = useState("");

    const list = useAsync<{ messages: Message[]; count: number }>(
        () =>
            api.listQueue({
                quarantined: held === "held" ? true : undefined,
                status: filter || undefined,
                direction: direction || undefined,
                limit: 200,
            }),
        [refreshKey, filter, direction, held],
    );

    async function retry(id: string) {
        setError("");
        try {
            await api.retryMessage(id);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("queue.couldNotRetry"));
        }
    }

    async function remove(id: string) {
        if (!confirm(t("queue.deleteConfirm"))) {
            return;
        }
        setError("");
        try {
            await api.deleteMessage(id);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("queue.couldNotDelete"));
        }
    }

    return (
        <>
            <PageHead
                title={t("queue.title")}
                subtitle={t("queue.subtitle")}
                actions={
                    <>
                        <FilterGroup
                            options={DIRECTIONS}
                            active={direction}
                            onSelect={setDirection}
                        />
                        <span style={{ color: "var(--border)" }}>|</span>
                        <FilterGroup options={FILTERS} active={filter} onSelect={setFilter} />
                        <span style={{ color: "var(--border)" }}>|</span>
                        <FilterGroup options={HOLD} active={held} onSelect={setHeld} />
                    </>
                }
            />

            {error && <Alert>{error}</Alert>}
            {list.error && <Alert>{list.error}</Alert>}

            <Card>
                {!list.data?.messages?.length ? (
                    <Empty
                        title={
                            held
                                ? t("queue.heldTitle")
                                : filter || direction
                                  ? t("queue.noMatch")
                                  : t("queue.emptyTitle")
                        }
                        hint={
                            held
                                ? t("queue.heldHint")
                                : filter || direction
                                  ? t("queue.noMatchHint")
                                  : t("queue.emptyHint")
                        }
                    />
                ) : (
                    <div className="table-wrap">
                        <table className="queue-table">
                            <thead>
                                <tr>
                                    <th>{t("queue.thReceived")}</th>
                                    <th className="col-address">{t("queue.thFrom")}</th>
                                    <th className="col-address">{t("queue.thTo")}</th>
                                    <th className="col-subject">{t("queue.thSubject")}</th>
                                    <th>{t("queue.thStatus")}</th>
                                    <th>{t("queue.thSize")}</th>
                                    {canEdit && <th />}
                                </tr>
                            </thead>
                            <tbody>
                                {list.data.messages.map((m) => (
                                    <>
                                        <tr
                                            key={m.id}
                                            onClick={() => setOpen(open === m.id ? null : m.id)}
                                            style={{ cursor: "pointer" }}
                                        >
                                            <td className="nowrap" title={absolute(m.received_at)}>
                                                {relative(m.received_at)}
                                            </td>
                                            <td className="cell-text mono" title={m.from}>
                                                <div className="clip">{m.from || "<>"}</div>
                                            </td>
                                            <td className="cell-text mono" title={m.to.join(", ")}>
                                                <div className="clip">
                                                    {m.to[0]}
                                                    {m.to.length > 1 && ` +${m.to.length - 1}`}
                                                </div>
                                            </td>
                                            <td className="cell-text cell-wide" title={m.subject}>
                                                <div className="clip">
                                                    {m.subject || <span style={{ opacity: 0.5 }}>—</span>}
                                                </div>
                                            </td>
                                            <td className="nowrap">
                                                <Pill tone={statusTone(m.status)}>{statusLabel(m.status)}</Pill>
                                                {m.quarantined_at && (
                                                    <span
                                                        className="badge"
                                                        style={{ marginLeft: ".3rem" }}
                                                        title={m.quarantine_reason}
                                                    >
                                                        {t("queue.quarantined")}
                                                    </span>
                                                )}
                                                {m.direction === "outbound" && (
                                                    <span className="badge" style={{ marginLeft: ".3rem" }}>
                                                        {t("queue.outBadge")}
                                                    </span>
                                                )}
                                                {m.spam_action && m.spam_action !== "no action" && (
                                                    <span
                                                        className="badge"
                                                        style={{ marginLeft: ".3rem" }}
                                                        title={t("queue.spamScore", { score: m.spam_score ?? "?" })}
                                                    >
                                                        {t("queue.spamBadge")}
                                                    </span>
                                                )}
                                                {m.attempts > 0 && (
                                                    <span className="badge" style={{ marginLeft: ".3rem" }}>
                                                        {t("queue.attempts", { n: m.attempts })}
                                                    </span>
                                                )}
                                            </td>
                                            <td className="nowrap">{bytes(m.size_bytes)}</td>
                                            {canEdit && (
                                                <td className="nowrap" onClick={(e) => e.stopPropagation()}>
                                                    <div className="row" style={{ flexWrap: "nowrap" }}>
                                                        {m.status !== "delivered" && (
                                                            <button
                                                                className="btn-sm"
                                                                onClick={() => retry(m.id)}
                                                            >
                                                                {t("queue.retry")}
                                                            </button>
                                                        )}
                                                        <button
                                                            className="btn-sm btn-danger"
                                                            onClick={() => remove(m.id)}
                                                        >
                                                            {t("queue.delete")}
                                                        </button>
                                                    </div>
                                                </td>
                                            )}
                                        </tr>
                                        {open === m.id && (
                                            <tr key={`${m.id}-detail`}>
                                                <td colSpan={canEdit ? 7 : 6} style={{ background: "var(--bg)" }}>
                                                    <Detail message={m} canEdit={canEdit} />
                                                </td>
                                            </tr>
                                        )}
                                    </>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </Card>
        </>
    );
}

function Detail({ message, canEdit }: { message: Message; canEdit: boolean }) {
    const t = useT();
    const [releasing, setReleasing] = useState(false);
    const [releaseError, setReleaseError] = useState("");

    async function release() {
        if (!confirm(t("queue.releaseConfirm"))) return;
        setReleaseError("");
        setReleasing(true);
        try {
            await api.releaseMessage(message.id);
            window.location.reload();
        } catch (err) {
            setReleaseError(err instanceof Error ? err.message : t("queue.couldNotRelease"));
            setReleasing(false);
        }
    }

    return (
        <div style={{ fontSize: ".88rem", display: "grid", gap: ".4rem" }}>
            <div>
                <strong>{t("queue.recipients")}</strong>{" "}
                <span className="mono">{message.to.join(", ")}</span>
            </div>
            <div>
                <strong>{t("queue.receivedFrom")}</strong>{" "}
                <span className="mono">{message.received_from || "unknown"}</span>
            </div>
            <div>
                <strong>{t("queue.direction")}</strong>{" "}
                {message.direction === "outbound"
                    ? "outbound — submitted here, on its way out"
                    : "inbound — held for your primary"}
            </div>
            {message.spam_action && message.spam_action !== "no action" && (
                <div>
                    <strong>{t("queue.spamVerdict")}</strong> {message.spam_action}
                    {message.spam_score != null && ` (score ${message.spam_score})`}
                </div>
            )}
            {message.auth_results && (
                <div>
                    <strong>{t("queue.authentication")}</strong>{" "}
                    <span className="mono">{message.auth_results}</span>{" "}
                    ({message.sender_authenticated ? t("queue.authenticated") : t("queue.notAuthenticated")})
                </div>
            )}
            {message.malware_scan && (
                <div>
                    <strong>{t("queue.malwareScan")}</strong>{" "}
                    <span
                        className="mono"
                        style={message.malware_scan === "clean" ? undefined : { color: "var(--bad)" }}
                    >
                        {message.malware_scan}
                    </span>
                </div>
            )}
            <div>
                <strong>{t("queue.expires")}</strong> {absolute(message.expires_at)} ({relative(message.expires_at)})
            </div>
            {message.status === "queued" && (
                <div>
                    <strong>{t("queue.nextAttempt")}</strong> {relative(message.next_retry_at)}
                </div>
            )}
            {message.delivered_at && (
                <div>
                    <strong>{t("queue.deliveredAt")}</strong> {absolute(message.delivered_at)}
                </div>
            )}
            {message.quarantined_at && (
                <div>
                    <strong>{t("queue.quarantineReason")}</strong>{" "}
                    <span className="mono">{message.quarantine_reason}</span>
                    {canEdit && (
                        <div style={{ marginTop: ".4rem" }}>
                            <button className="btn-sm" onClick={release} disabled={releasing}>
                                {releasing ? t("common.working") : t("queue.release")}
                            </button>
                        </div>
                    )}
                    {releaseError && (
                        <div className="hint" style={{ color: "var(--bad)" }}>{releaseError}</div>
                    )}
                </div>
            )}
            {message.last_error && (
                <div>
                    <strong>{t("queue.lastError")}</strong>{" "}
                    <span className="mono" style={{ color: "var(--bad)" }}>
                        {message.last_error}
                    </span>
                </div>
            )}
            {canEdit && (
                <div style={{ marginTop: ".3rem" }}>
                    <a href={api.rawMessageUrl(message.id)} download={`${message.id}.eml`}>
                        {t("queue.downloadRaw")}
                    </a>
                    <div className="hint">
                        {t("queue.downloadNote")}
                    </div>
                </div>
            )}
        </div>
    );
}
