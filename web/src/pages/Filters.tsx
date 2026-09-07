import { useState, type FormEvent } from "react";
import { api, type Filter, type SecurityStatus, type DNSBLTestResult } from "../api";
import { relative } from "../format";
import { Alert, Card, Empty, PageHead, Pill } from "../components/ui";
import { useAsync } from "../useAsync";
import { useT } from "../i18n";
import type { TranslationKey } from "../locales/en";

const FIELD_LABEL: Record<string, TranslationKey> = {
    from: "filters.fieldFrom",
    to: "filters.fieldTo",
    subject: "filters.fieldSubject",
};

const ACTION_LABEL: Record<string, TranslationKey> = {
    reject: "filters.actionReject",
    quarantine: "filters.actionQuarantine",
    allow: "filters.actionAllow",
};

function actionTone(action: string): "ok" | "warn" | "bad" | "mute" {
    if (action === "reject") return "bad";
    if (action === "quarantine") return "warn";
    if (action === "allow") return "ok";
    return "mute";
}

export function Filters({
    refreshKey,
    canEdit,
    onChanged,
}: {
    refreshKey: number;
    canEdit: boolean;
    onChanged: () => void;
}) {
    const t = useT();
    const [adding, setAdding] = useState(false);
    const [error, setError] = useState("");
    const list = useAsync<{ filters: Filter[] }>(api.listFilters, [refreshKey]);

    async function toggle(f: Filter) {
        setError("");
        try {
            await api.updateFilter(f.id, { enabled: !f.enabled });
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("filters.couldNotUpdate"));
        }
    }

    async function remove(f: Filter) {
        if (!confirm(t("filters.deleteConfirm", { name: f.name }))) return;
        setError("");
        try {
            await api.deleteFilter(f.id);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("filters.couldNotDelete"));
        }
    }

    return (
        <>
            <PageHead
                title={t("filters.title")}
                subtitle={t("filters.subtitle")}
            />

            {error && <Alert>{error}</Alert>}
            {list.error && <Alert>{list.error}</Alert>}

            <div className="stack">
                <PerimeterSecurity refreshKey={refreshKey} />

                {adding && (
                    <AddFilter
                        onDone={() => {
                            setAdding(false);
                            onChanged();
                        }}
                        onCancel={() => setAdding(false)}
                    />
                )}

                <Card>
                    <div className="section-head">
                        <div>
                            <h2>{t("filters.rulesTitle")}</h2>
                            <p className="hint">{t("filters.rulesSubtitle")}</p>
                        </div>
                        {canEdit && !adding && (
                            <button className="btn-primary" onClick={() => setAdding(true)}>
                                {t("filters.add")}
                            </button>
                        )}
                    </div>

                    {!list.data?.filters?.length ? (
                        <Empty title={t("filters.noneTitle")} hint={t("filters.noneHint")} />
                    ) : (
                        <div className="table-wrap">
                            <table>
                                <thead>
                                    <tr>
                                        <th>{t("filters.thName")}</th>
                                        <th>{t("filters.thMatch")}</th>
                                        <th>{t("filters.thAction")}</th>
                                        <th>{t("filters.thPriority")}</th>
                                        <th>{t("filters.thMatches")}</th>
                                        {canEdit && <th />}
                                    </tr>
                                </thead>
                                <tbody>
                                    {list.data.filters.map((f) => (
                                        <tr key={f.id}>
                                            <td>
                                                <strong>{f.name}</strong>
                                                {!f.enabled && (
                                                    <>
                                                        {" "}
                                                        <Pill tone="mute">
                                                            {t("filters.disabledBadge")}
                                                        </Pill>
                                                    </>
                                                )}
                                            </td>
                                            <td>
                                                {t(FIELD_LABEL[f.field] ?? "filters.fieldSubject")}{" "}
                                                <span className="mono">{f.pattern}</span>
                                            </td>
                                            <td>
                                                <Pill tone={actionTone(f.action)}>
                                                    {t(ACTION_LABEL[f.action] ?? "filters.actionAllow")}
                                                </Pill>
                                            </td>
                                            <td>{f.priority}</td>
                                            <td>
                                                {t("filters.matches", { n: f.match_count })}
                                                {f.last_match_at && (
                                                    <div className="stat-note">
                                                        {t("filters.lastMatch", {
                                                            when: relative(f.last_match_at),
                                                        })}
                                                    </div>
                                                )}
                                            </td>
                                            {canEdit && (
                                                <td>
                                                    <div className="row">
                                                        <button
                                                            className="btn-sm"
                                                            onClick={() => toggle(f)}
                                                        >
                                                            {f.enabled
                                                                ? t("filters.disable")
                                                                : t("filters.enable")}
                                                        </button>
                                                        <button
                                                            className="btn-sm btn-danger"
                                                            onClick={() => remove(f)}
                                                        >
                                                            {t("filters.delete")}
                                                        </button>
                                                    </div>
                                                </td>
                                            )}
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </Card>
            </div>
        </>
    );
}

function AddFilter({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
    const t = useT();
    const [name, setName] = useState("");
    const [field, setField] = useState("subject");
    const [pattern, setPattern] = useState("");
    const [action, setAction] = useState("quarantine");
    const [priority, setPriority] = useState(100);
    const [sample, setSample] = useState("");
    const [tried, setTried] = useState<string | null>(null);
    const [testing, setTesting] = useState(false);
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);

    async function tryPattern() {
        setError("");
        setTried(null);
        setTesting(true);
        try {
            const body: { pattern: string; field: string; from?: string; to?: string[]; subject?: string } =
                { pattern, field };
            if (field === "from") body.from = sample;
            else if (field === "to") body.to = [sample];
            else body.subject = sample;

            const res = await api.testFilters(body);
            setTried(
                res.matched ? t("filters.tryMatched", { value: res.value ?? sample }) : t("filters.tryNoMatch"),
            );
        } catch (err) {
            setError(err instanceof Error ? err.message : t("filters.couldNotTest"));
        } finally {
            setTesting(false);
        }
    }

    async function submit(e: FormEvent) {
        e.preventDefault();
        setError("");
        setBusy(true);
        try {
            await api.createFilter({ name, field, pattern, action, priority });
            onDone();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("filters.couldNotCreate"));
            setBusy(false);
        }
    }

    return (
        <Card>
            <h2 style={{ marginBottom: "1rem" }}>{t("filters.addTitle")}</h2>
            {error && <Alert>{error}</Alert>}
            <form onSubmit={submit}>
                <div className="field">
                    <label htmlFor="filter-name">{t("filters.fldName")}</label>
                    <input
                        id="filter-name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        required
                        autoFocus
                    />
                </div>

                <div className="row">
                    <div className="field" style={{ flex: 1 }}>
                        <label htmlFor="filter-field">{t("filters.fldField")}</label>
                        <select
                            id="filter-field"
                            value={field}
                            onChange={(e) => setField(e.target.value)}
                        >
                            <option value="from">{t("filters.fieldFrom")}</option>
                            <option value="to">{t("filters.fieldTo")}</option>
                            <option value="subject">{t("filters.fieldSubject")}</option>
                        </select>
                    </div>
                    <div className="field" style={{ flex: 1 }}>
                        <label htmlFor="filter-action">{t("filters.fldAction")}</label>
                        <select
                            id="filter-action"
                            value={action}
                            onChange={(e) => setAction(e.target.value)}
                        >
                            <option value="quarantine">{t("filters.actionQuarantine")}</option>
                            <option value="reject">{t("filters.actionReject")}</option>
                            <option value="allow">{t("filters.actionAllow")}</option>
                        </select>
                    </div>
                    <div className="field" style={{ width: "8rem" }}>
                        <label htmlFor="filter-priority">{t("filters.fldPriority")}</label>
                        <input
                            id="filter-priority"
                            type="number"
                            min={0}
                            max={10000}
                            value={priority}
                            onChange={(e) => setPriority(Number(e.target.value))}
                        />
                    </div>
                </div>
                <div className="hint" style={{ marginTop: "-.5rem", marginBottom: ".8rem" }}>
                    {t("filters.actionHint")}
                </div>

                <div className="field">
                    <label htmlFor="filter-pattern">{t("filters.fldPattern")}</label>
                    <input
                        id="filter-pattern"
                        className="mono"
                        value={pattern}
                        onChange={(e) => setPattern(e.target.value)}
                        placeholder="invoice|facture"
                        required
                    />
                    <div className="hint">{t("filters.patternHint")}</div>
                </div>

                <div className="field">
                    <div className="row">
                        <input
                            aria-label={t("filters.tryIt")}
                            value={sample}
                            onChange={(e) => setSample(e.target.value)}
                            placeholder="example@sender.test"
                            style={{ flex: 1 }}
                        />
                        <button
                            type="button"
                            className="btn-sm"
                            onClick={tryPattern}
                            disabled={testing || !pattern}
                        >
                            {testing ? t("filters.trying") : t("filters.tryIt")}
                        </button>
                    </div>
                    {tried && <div className="hint">{tried}</div>}
                </div>

                <div className="row">
                    <button type="submit" className="btn-primary" disabled={busy}>
                        {busy ? t("filters.adding") : t("filters.add")}
                    </button>
                    <button type="button" onClick={onCancel} disabled={busy}>
                        {t("sending.cancel")}
                    </button>
                </div>
            </form>
        </Card>
    );
}

function PerimeterSecurity({ refreshKey }: { refreshKey: number }) {
    const t = useT();
    const sec = useAsync<SecurityStatus>(api.getSecurityStatus, [refreshKey]);
    const [testIP, setTestIP] = useState("");
    const [testing, setTesting] = useState(false);
    const [testResult, setTestResult] = useState<DNSBLTestResult | null>(null);
    const [testError, setTestError] = useState("");

    async function handleTest(e: FormEvent) {
        e.preventDefault();
        const ip = testIP.trim();
        if (!ip) return;
        setTesting(true);
        setTestError("");
        setTestResult(null);
        try {
            const res = await api.testDNSBL(ip);
            setTestResult(res);
        } catch (err) {
            setTestError(err instanceof Error ? err.message : t("filters.dnsblTestFailed"));
        } finally {
            setTesting(false);
        }
    }

    const dnsblEnabled = Boolean(sec.data?.dnsbl?.enabled);
    const clamavStatus = sec.data?.clamav?.status || "disabled";
    const rspamdEnabled = Boolean(sec.data?.rspamd?.enabled);

    return (
        <Card>
            <div className="section-head">
                <div>
                    <h2>{t("filters.perimeterTitle")}</h2>
                    <p className="hint">{t("filters.perimeterSubtitle")}</p>
                </div>
            </div>

            {sec.error && <Alert>{sec.error}</Alert>}

            <div
                style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                    gap: "1rem",
                    marginBottom: "1.25rem",
                }}
            >
                <div
                    style={{
                        padding: "0.85rem 1rem",
                        border: "1px solid var(--border)",
                        borderRadius: "var(--radius)",
                    }}
                >
                    <div
                        style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            marginBottom: "0.4rem",
                        }}
                    >
                        <strong>{t("filters.dnsblLabel")}</strong>
                        <Pill tone={dnsblEnabled ? "ok" : "mute"}>
                            {dnsblEnabled ? t("filters.statusActive") : t("filters.statusDisabled")}
                        </Pill>
                    </div>
                    <div className="stat-note" style={{ fontSize: "0.85rem" }}>
                        {dnsblEnabled && sec.data?.dnsbl?.zones?.length
                            ? sec.data.dnsbl.zones.join(", ")
                            : t("filters.dnsblNoZones")}
                    </div>
                </div>

                <div
                    style={{
                        padding: "0.85rem 1rem",
                        border: "1px solid var(--border)",
                        borderRadius: "var(--radius)",
                    }}
                >
                    <div
                        style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            marginBottom: "0.4rem",
                        }}
                    >
                        <strong>{t("filters.clamavLabel")}</strong>
                        <Pill
                            tone={
                                clamavStatus === "online"
                                    ? "ok"
                                    : clamavStatus === "offline"
                                      ? "bad"
                                      : "mute"
                            }
                        >
                            {clamavStatus === "online"
                                ? t("filters.clamavOnline")
                                : clamavStatus === "offline"
                                  ? t("filters.clamavOffline")
                                  : t("filters.statusDisabled")}
                        </Pill>
                    </div>
                    <div className="stat-note" style={{ fontSize: "0.85rem" }}>
                        {sec.data?.clamav?.enabled
                            ? t("filters.clamavActionNote", {
                                  action: sec.data.clamav.action || "quarantine",
                              })
                            : t("filters.clamavDisabledNote")}
                    </div>
                </div>

                <div
                    style={{
                        padding: "0.85rem 1rem",
                        border: "1px solid var(--border)",
                        borderRadius: "var(--radius)",
                    }}
                >
                    <div
                        style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            marginBottom: "0.4rem",
                        }}
                    >
                        <strong>{t("filters.rspamdLabel")}</strong>
                        <Pill tone={rspamdEnabled ? "ok" : "mute"}>
                            {rspamdEnabled ? t("filters.statusActive") : t("filters.statusDisabled")}
                        </Pill>
                    </div>
                    <div className="stat-note" style={{ fontSize: "0.85rem" }}>
                        {rspamdEnabled
                            ? t("filters.rspamdActiveNote")
                            : t("filters.rspamdDisabledNote")}
                    </div>
                </div>
            </div>

            <div style={{ borderTop: "1px solid var(--border)", paddingTop: "1rem" }}>
                <h3 style={{ fontSize: "0.95rem", margin: "0 0 0.25rem 0" }}>
                    {t("filters.dnsblTesterTitle")}
                </h3>
                <div className="hint" style={{ marginBottom: "0.75rem" }}>
                    {t("filters.dnsblTesterHint")}
                </div>

                {testError && <Alert>{testError}</Alert>}

                <form
                    onSubmit={handleTest}
                    className="row"
                    style={{ alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}
                >
                    <input
                        type="text"
                        className="mono"
                        placeholder="198.51.100.1"
                        value={testIP}
                        onChange={(e) => setTestIP(e.target.value)}
                        style={{ flex: 1, maxWidth: "320px" }}
                        disabled={testing}
                        required
                    />
                    <button
                        type="submit"
                        className="btn-sm btn-primary"
                        disabled={testing || !testIP.trim()}
                    >
                        {testing ? t("filters.dnsblTesting") : t("filters.dnsblTestBtn")}
                    </button>
                </form>

                {testResult && (
                    <div
                        style={{
                            padding: "0.75rem 1rem",
                            border: "1px solid var(--border)",
                            borderRadius: "var(--radius)",
                            background: "rgba(255, 255, 255, 0.02)",
                        }}
                    >
                        <div
                            style={{
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "space-between",
                                marginBottom: "0.5rem",
                            }}
                        >
                            <span>
                                <strong>{testResult.ip}</strong>:{" "}
                                {testResult.listed ? (
                                    <span style={{ color: "var(--bad)" }}>
                                        {t("filters.dnsblListedOverall", {
                                            zone: testResult.zone || "",
                                        })}
                                    </span>
                                ) : (
                                    <span style={{ color: "var(--ok)" }}>
                                        {t("filters.dnsblCleanOverall")}
                                    </span>
                                )}
                            </span>
                            <Pill tone={testResult.listed ? "bad" : "ok"}>
                                {testResult.listed
                                    ? t("filters.dnsblPillListed")
                                    : t("filters.dnsblPillClean")}
                            </Pill>
                        </div>

                        {testResult.details && testResult.details.length > 0 && (
                            <div className="table-wrap" style={{ marginTop: "0.5rem" }}>
                                <table>
                                    <thead>
                                        <tr>
                                            <th>{t("filters.thZone")}</th>
                                            <th>{t("filters.thStatus")}</th>
                                            <th>{t("filters.thRecord")}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {testResult.details.map((d) => (
                                            <tr key={d.zone}>
                                                <td className="mono">{d.zone}</td>
                                                <td>
                                                    {d.error ? (
                                                        <Pill tone="warn">
                                                            {t("filters.dnsblZoneError")}
                                                        </Pill>
                                                    ) : d.listed ? (
                                                        <Pill tone="bad">
                                                            {t("filters.dnsblPillListed")}
                                                        </Pill>
                                                    ) : (
                                                        <Pill tone="ok">
                                                            {t("filters.dnsblPillClean")}
                                                        </Pill>
                                                    )}
                                                </td>
                                                <td className="mono">
                                                    {d.record || (d.error ? d.error : "—")}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </Card>
    );
}
