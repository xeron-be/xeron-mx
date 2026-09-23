import { useEffect, useState, type FormEvent } from "react";
import { api, type DKIMCheckResult, type DKIMInfo, type DMARCDNSCheck, type DMARCInfo, type DnsGuide, type Domain, type ProbeResult } from "../api";
import { relative } from "../format";
import { Alert, Card, Empty, PageHead, Pill } from "../components/ui";
import { useAsync } from "../useAsync";
import { useT } from "../i18n";

export function Domains({
    refreshKey,
    canEdit,
    canTest = canEdit,
    onChanged,
}: {
    refreshKey: number;
    canEdit: boolean;
    canTest?: boolean;
    onChanged: () => void;
}) {
    const t = useT();
    const [adding, setAdding] = useState(false);
    const list = useAsync<{ domains: Domain[] }>(api.listDomains, [refreshKey]);

    return (
        <>
            <PageHead
                title={t("domains.title")}
                subtitle={t("domains.subtitle")}
                actions={
                    canEdit && !adding ? (
                        <button className="btn-primary" onClick={() => setAdding(true)}>
                            {t("domains.add")}
                        </button>
                    ) : null
                }
            />

            {list.error && <Alert>{list.error}</Alert>}

            {adding && (
                <div style={{ marginBottom: "1rem" }}>
                    <AddDomain
                        onDone={() => {
                            setAdding(false);
                            onChanged();
                        }}
                        onCancel={() => setAdding(false)}
                    />
                </div>
            )}

            {list.data?.domains?.length ? (
                <div className="stack">
                    {list.data.domains.map((d) => (
                        <DomainCard key={d.id} domain={d} canEdit={canEdit} canTest={canTest} onChanged={onChanged} />
                    ))}
                </div>
            ) : (
                !adding && (
                    <Card>
                        <Empty
                            title={t("domains.noneTitle")}
                            hint={t("domains.noneHint")}
                        />
                    </Card>
                )
            )}
        </>
    );
}

function AddDomain({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
    const t = useT();
    const [name, setName] = useState("");
    const [host, setHost] = useState("");
    const [port, setPort] = useState(25);
    const [tls, setTls] = useState("opportunistic");
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);

    async function submit(e: FormEvent) {
        e.preventDefault();
        setError("");
        setBusy(true);
        try {
            await api.createDomain({
                name,
                primary_host: host,
                primary_port: port,
                primary_tls: tls,
            });
            onDone();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("domains.couldNotAdd"));
        } finally {
            setBusy(false);
        }
    }

    return (
        <Card>
            <h2 style={{ marginBottom: "1rem" }}>{t("domains.addTitle")}</h2>
            {error && <Alert>{error}</Alert>}
            <form onSubmit={submit}>
                <div className="field">
                    <label htmlFor="name">{t("domains.fldDomain")}</label>
                    <input
                        id="name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="example.com"
                        required
                        autoFocus
                    />
                    <div className="hint">
                        {t("domains.fldDomainHint")}
                    </div>
                </div>

                <div className="field">
                    <label htmlFor="host">{t("domains.fldPrimary")}</label>
                    <input
                        id="host"
                        value={host}
                        onChange={(e) => setHost(e.target.value)}
                        placeholder="mail.example.com"
                        required
                    />
                    <div className="hint">
                        {t("domains.fldPrimaryHint")}
                    </div>
                </div>

                <div className="row" style={{ alignItems: "flex-start" }}>
                    <div className="field" style={{ flex: "0 0 8rem" }}>
                        <label htmlFor="port">{t("domains.fldPort")}</label>
                        <input
                            id="port"
                            type="number"
                            value={port}
                            min={1}
                            max={65535}
                            onChange={(e) => setPort(Number(e.target.value))}
                        />
                    </div>
                    <div className="field" style={{ flex: 1, minWidth: "12rem" }}>
                        <label htmlFor="tls">TLS</label>
                        <select id="tls" value={tls} onChange={(e) => setTls(e.target.value)}>
                            <option value="opportunistic">{t("domains.tlsOpportunistic")}</option>
                            <option value="starttls">{t("domains.tlsRequired")}</option>
                            <option value="none">{t("domains.tlsNone")}</option>
                            <option value="tls">{t("domains.tlsImplicit")}</option>
                        </select>
                        <div className="hint">
                            {t("domains.tlsHint")}
                        </div>
                    </div>
                </div>

                <div className="row">
                    <button type="submit" className="btn-primary" disabled={busy}>
                        {busy ? t("domains.adding") : t("domains.add")}
                    </button>
                    <button type="button" onClick={onCancel} disabled={busy}>
                        {t("common.cancel")}
                    </button>
                </div>
            </form>
        </Card>
    );
}

function DomainCard({
    domain,
    canEdit,
    canTest = canEdit,
    onChanged,
}: {
    domain: Domain;
    canEdit: boolean;
    canTest?: boolean;
    onChanged: () => void;
}) {
    const t = useT();
    const [probe, setProbe] = useState<ProbeResult | null>(null);
    const [dns, setDns] = useState<DnsGuide | null>(null);
    const [showDkim, setShowDkim] = useState(false);
    const [dkim, setDkim] = useState<DKIMInfo | null>(null);
    const [dkimLoading, setDkimLoading] = useState(false);
    const [showDmarc, setShowDmarc] = useState(false);
    const [dmarc, setDmarc] = useState<DMARCInfo | null>(null);
    const [dmarcLoading, setDmarcLoading] = useState(false);
    const [showRecipients, setShowRecipients] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");

    const up = domain.primary?.is_up ?? false;

    async function runProbe() {
        setBusy(true);
        setError("");
        try {
            setProbe(await api.testDomain(domain.id));
        } catch (err) {
            setError(err instanceof Error ? err.message : t("domains.testCouldNotRun"));
        } finally {
            setBusy(false);
        }
    }

    async function toggleDns() {
        if (dns) {
            setDns(null);
            return;
        }
        try {
            setDns(await api.domainDns(domain.id));
        } catch (err) {
            setError(err instanceof Error ? err.message : t("domains.couldNotLoadDns"));
        }
    }

    async function toggleDkim() {
        if (showDkim) {
            setShowDkim(false);
            return;
        }
        setShowDkim(true);
        setDkimLoading(true);
        try {
            const info = await api.getDKIM(domain.id);
            setDkim(info);
        } catch (err) {
            setError(err instanceof Error ? err.message : t("domains.couldNotLoadDkim"));
        } finally {
            setDkimLoading(false);
        }
    }

    async function toggleDmarc() {
        if (showDmarc) {
            setShowDmarc(false);
            return;
        }
        setShowDmarc(true);
        setDmarcLoading(true);
        try {
            const info = await api.getDMARC(domain.id);
            setDmarc(info);
        } catch (err) {
            setError(err instanceof Error ? err.message : t("domains.couldNotLoadDmarc"));
        } finally {
            setDmarcLoading(false);
        }
    }

    async function setEnabled(enabled: boolean) {
        setBusy(true);
        try {
            await api.updateDomain(domain.id, { enabled });
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("domains.couldNotUpdate"));
        } finally {
            setBusy(false);
        }
    }

    async function remove() {
        const pending = domain.pending ?? 0;
        const warning =
            pending > 0
                ? t("domains.deleteConfirmQueued", { name: domain.name, n: pending })
                : t("domains.deleteConfirm", { name: domain.name });
        if (!confirm(warning)) return;

        setBusy(true);
        try {
            await api.deleteDomain(domain.id, pending > 0);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("domains.couldNotDelete"));
            setBusy(false);
        }
    }

    return (
        <Card>
            <div className="page-head" style={{ marginBottom: "1rem" }}>
                <div>
                    <h2>
                        {domain.name}{" "}
                        <Pill tone={up ? "ok" : "bad"}>
                            {up ? t("domains.primaryUp") : t("domains.primaryDown")}
                        </Pill>
                        {!domain.enabled && <> <Pill tone="mute">{t("dash.paused")}</Pill></>}
                    </h2>
                    <p>
                        <span className="mono">
                            {domain.primary_host}:{domain.primary_port}
                        </span>{" "}
                        · {domain.primary_tls} · {t("domains.holds", { h: domain.retention_hours })}{" "}
                        · {t("domains.waiting", { n: domain.pending ?? 0 })}
                    </p>
                </div>
                <div className="row">
                    <button className="btn-sm" onClick={toggleDns}>
                        {dns ? t("domains.hideDns") : t("domains.dnsSetup")}
                    </button>
                    <button className="btn-sm" onClick={toggleDkim}>
                        {t("domains.dkim")}
                    </button>
                    <button className="btn-sm" onClick={toggleDmarc}>
                        {t("domains.dmarc")}
                    </button>
                    <button className="btn-sm" onClick={() => setShowRecipients(!showRecipients)}>
                        {t("domains.recipients")}
                    </button>
                    {canTest && (
                        <button className="btn-sm" onClick={runProbe} disabled={busy}>
                            {busy ? t("domains.testing") : t("domains.testConnection")}
                        </button>
                    )}
                    {canEdit && (
                        <>
                            <button
                                className="btn-sm"
                                onClick={() => setEnabled(!domain.enabled)}
                                disabled={busy}
                            >
                                {domain.enabled ? t("domains.pause") : t("domains.resume")}
                            </button>
                            <button className="btn-sm btn-danger" onClick={remove} disabled={busy}>
                                {t("domains.delete")}
                            </button>
                        </>
                    )}
                </div>
            </div>

            {error && <Alert>{error}</Alert>}

            {!up && domain.primary?.last_error && (
                <Alert tone="warn">
                    {t("domains.lastProbeFailed")}{" "}
                    <span className="mono">{domain.primary.last_error}</span>
                    {domain.primary.last_down && (
                        <> · {t("domains.downSince", { when: relative(domain.primary.last_down) })}</>
                    )}
                </Alert>
            )}

            {probe && (
                <Alert tone={probe.reachable ? "ok" : "bad"}>
                    {probe.reachable ? (
                        <>
                            {t("domains.reachable", { ms: probe.took_ms })}{" "}
                            {t("domains.readyToReceive")}
                        </>
                    ) : (
                        <>
                            <strong>{t("domains.couldNotReach")}</strong>
                            <div className="mono" style={{ marginTop: ".35rem", fontSize: ".85em" }}>
                                {probe.error}
                            </div>
                            {probe.hint && <div style={{ marginTop: ".4rem" }}>{probe.hint}</div>}
                        </>
                    )}
                </Alert>
            )}

            {dns && (
                <div>
                    <h3 style={{ margin: "0 0 .6rem" }}>{t("domains.dnsRecords")}</h3>
                    {dns.records.map((r, i) => (
                        <div key={i} className="dns-record">
                            {r.name} IN {r.type} {r.priority ? `${r.priority} ` : ""}
                            {r.value}
                            {r.note && <div className="note">{r.note}</div>}
                        </div>
                    ))}
                    <h3 style={{ margin: "1rem 0 .5rem" }}>{t("domains.beforeThisWorks")}</h3>
                    <ul style={{ margin: 0, paddingLeft: "1.2rem", fontSize: ".9rem" }}>
                        {dns.checklist.map((item, i) => (
                            <li key={i} style={{ marginBottom: ".3rem" }}>
                                {item}
                            </li>
                        ))}
                    </ul>
                </div>
            )}

            {showDkim && (
                <DKIMSection
                    domain={domain}
                    dkim={dkim}
                    loading={dkimLoading}
                    canEdit={canEdit}
                    onUpdated={(info) => {
                        setDkim(info);
                        onChanged();
                    }}
                    onDeleted={() => {
                        setDkim({ domain: domain.name, configured: false });
                        onChanged();
                    }}
                />
            )}

            {showRecipients && <RecipientsSection domain={domain} canEdit={canEdit} onChanged={onChanged} />}

            {showDmarc && (
                <DMARCSection
                    domain={domain}
                    dmarc={dmarc}
                    loading={dmarcLoading}
                    onChecked={(res) => {
                        if (dmarc) setDmarc({ ...dmarc, dns: res });
                    }}
                />
            )}
        </Card>
    );
}

function RecipientsSection({
    domain,
    canEdit,
    onChanged,
}: {
    domain: Domain;
    canEdit: boolean;
    onChanged: () => void;
}) {
    const t = useT();
    const [text, setText] = useState("");
    const [loaded, setLoaded] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const [saved, setSaved] = useState<number | null>(null);

    useEffect(() => {
        let live = true;
        api.getRecipients(domain.id)
            .then((res) => {
                if (!live) return;
                setText(res.recipients.join("\n"));
                setLoaded(true);
            })
            .catch((err) => live && setError(err instanceof Error ? err.message : t("domains.couldNotLoadRecipients")));
        return () => {
            live = false;
        };
    }, [domain.id]);

    const addresses = text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);

    async function save(e: FormEvent) {
        e.preventDefault();
        setBusy(true);
        setError("");
        setSaved(null);
        try {
            const res = await api.setRecipients(domain.id, addresses);
            setText(res.recipients.join("\n"));
            setSaved(res.recipients.length);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("domains.couldNotSaveRecipients"));
        } finally {
            setBusy(false);
        }
    }

    const count = addresses.length;

    return (
        <div>
            <h3 style={{ margin: "0 0 .4rem" }}>
                {t("domains.recipients")}{" "}
                <Pill tone={count > 0 ? "ok" : "mute"}>
                    {count > 0 ? t("domains.recipientsCount", { n: count }) : t("domains.recipientsAll")}
                </Pill>
            </h3>
            <p style={{ fontSize: ".9rem", margin: "0 0 .6rem" }}>
                {t("domains.recipientsHint", { domain: domain.name })}
            </p>
            {error && <Alert>{error}</Alert>}
            {saved !== null && <Alert tone="ok">{t("domains.recipientsSaved", { n: saved })}</Alert>}
            {loaded && (
                <form onSubmit={save}>
                    <textarea
                        className="mono"
                        rows={Math.min(Math.max(count + 1, 4), 16)}
                        value={text}
                        onChange={(e) => setText(e.target.value)}
                        readOnly={!canEdit}
                        placeholder={`alice@${domain.name}\nbob@${domain.name}`}
                        spellCheck={false}
                    />
                    {canEdit && (
                        <button className="btn-sm" type="submit" disabled={busy} style={{ marginTop: ".5rem" }}>
                            {t("domains.recipientsSave")}
                        </button>
                    )}
                </form>
            )}
        </div>
    );
}

function CopyButton({ text, label }: { text: string; label?: string }) {
    const t = useT();
    const [copied, setCopied] = useState(false);

    function copy() {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    }

    return (
        <button type="button" className="btn-copy" onClick={copy}>
            {copied ? t("domains.copied") : (label ?? t("domains.copy"))}
        </button>
    );
}

function DKIMSection({
    domain,
    dkim,
    loading,
    canEdit,
    onUpdated,
    onDeleted,
}: {
    domain: Domain;
    dkim: DKIMInfo | null;
    loading: boolean;
    canEdit: boolean;
    onUpdated: (info: DKIMInfo) => void;
    onDeleted: () => void;
}) {
    const t = useT();
    const [generating, setGenerating] = useState(false);
    const [selector, setSelector] = useState("xeronmx");
    const [algo, setAlgo] = useState("rsa");
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);
    const [dnsCheck, setDnsCheck] = useState<DKIMCheckResult | null>(null);
    const [checkingDns, setCheckingDns] = useState(false);
    const [canForce, setCanForce] = useState(false);

    async function runDnsCheck() {
        setCheckingDns(true);
        setError("");
        try {
            const res = await api.checkDKIM(domain.id);
            setDnsCheck(res);
        } catch (err) {
            setError(err instanceof Error ? err.message : t("common.somethingWrong"));
        } finally {
            setCheckingDns(false);
        }
    }

    async function handleGenerate(e: FormEvent) {
        e.preventDefault();
        setError("");
        setGenerating(true);
        try {
            const res = await api.createDKIM(domain.id, {
                selector: selector.trim() || "xeronmx",
                algorithm: algo,
            });
            onUpdated(res);
        } catch (err) {
            setError(err instanceof Error ? err.message : t("domains.couldNotGenerateDkim"));
        } finally {
            setGenerating(false);
        }
    }

    async function handleToggleSigning(enable: boolean, force = false) {
        setError("");
        setBusy(true);
        setCanForce(false);
        try {
            const res = await api.updateDKIM(domain.id, enable, force);
            const merged: DKIMInfo = {
                ...(dkim ?? { domain: domain.name, configured: true }),
                ...res,
                configured: true,
            };
            onUpdated(merged);
        } catch (err) {
            setError(err instanceof Error ? err.message : t("domains.couldNotUpdateDkim"));
            if (enable && !force) {
                setCanForce(true);
            }
        } finally {
            setBusy(false);
        }
    }

    async function handleDeleteKey() {
        if (!confirm(t("domains.dkimDeleteConfirm", { name: domain.name }))) {
            return;
        }
        setError("");
        setBusy(true);
        try {
            await api.deleteDKIM(domain.id);
            onDeleted();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("domains.couldNotDeleteDkim"));
        } finally {
            setBusy(false);
        }
    }

    return (
        <div className="dkim-block">
            <div className="dkim-header">
                <div>
                    <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: "0.5rem" }}>
                        {t("domains.dkimTitle")}
                        {dkim?.configured && (
                            <Pill tone={dkim.enabled ? "ok" : "warn"}>
                                {t(dkim.enabled ? "domains.dkimActive" : "domains.dkimInactive")}
                            </Pill>
                        )}
                    </h3>
                    <p style={{ margin: "0.25rem 0 0", fontSize: "0.85rem", color: "var(--muted)" }}>
                        {t("domains.dkimSubtitle")}
                    </p>
                </div>
            </div>

            {error && <Alert>{error}</Alert>}

            {loading ? (
                <p style={{ color: "var(--muted)" }}>{t("domains.testing")}</p>
            ) : !dkim?.configured ? (
                <div>
                    <p style={{ color: "var(--muted)", margin: "0.5rem 0 1rem" }}>
                        {t("domains.dkimNone")}
                    </p>
                    {canEdit && (
                        <form onSubmit={handleGenerate} className="row" style={{ alignItems: "flex-end" }}>
                            <div className="field" style={{ margin: 0, minWidth: "140px" }}>
                                <label htmlFor={`sel-${domain.id}`}>{t("domains.dkimRecordName")}</label>
                                <input
                                    id={`sel-${domain.id}`}
                                    value={selector}
                                    onChange={(e) => setSelector(e.target.value)}
                                    placeholder="xeronmx"
                                    required
                                />
                            </div>
                            <div className="field" style={{ margin: 0, minWidth: "120px" }}>
                                <label htmlFor={`algo-${domain.id}`}>{t("domains.dkimRecordType")}</label>
                                <select
                                    id={`algo-${domain.id}`}
                                    value={algo}
                                    onChange={(e) => setAlgo(e.target.value)}
                                >
                                    <option value="rsa">RSA 2048</option>
                                    <option value="ed25519">Ed25519</option>
                                </select>
                            </div>
                            <button type="submit" className="btn-primary" disabled={generating}>
                                {generating ? t("domains.dkimGenerating") : t("domains.dkimGenerate")}
                            </button>
                        </form>
                    )}
                </div>
            ) : (
                <div>
                    {!dkim.enabled && (
                        <div style={{ marginBottom: "0.75rem" }}>
                            <Alert tone="warn">
                                {t("domains.dkimPublishWarning")}
                            </Alert>
                        </div>
                    )}

                    <div className="dkim-field">
                        <label>{t("domains.dkimRecordName")}</label>
                        <div className="dkim-copy-box">
                            <code>{dkim.record?.name ?? `${dkim.selector}._domainkey.${domain.name}`}</code>
                            <CopyButton text={dkim.record?.name ?? `${dkim.selector}._domainkey.${domain.name}`} />
                        </div>
                    </div>

                    <div className="row" style={{ margin: "0.5rem 0" }}>
                        <div style={{ fontSize: "0.85rem", color: "var(--muted)" }}>
                            {t("domains.dkimRecordType")}: <span className="mono" style={{ fontWeight: 600, color: "var(--text)" }}>TXT</span>
                        </div>
                    </div>

                    <div className="dkim-field">
                        <label>{t("domains.dkimRecordValue")}</label>
                        <div className="dkim-copy-box">
                            <code>{dkim.record?.value ?? ""}</code>
                            <CopyButton text={dkim.record?.value ?? ""} />
                        </div>
                    </div>

                    <div className="row" style={{ marginTop: "1rem", alignItems: "center" }}>
                        <button
                            type="button"
                            className="btn-sm"
                            onClick={runDnsCheck}
                            disabled={checkingDns || busy}
                        >
                            {checkingDns ? t("domains.dkimCheckingDns") : t("domains.dkimCheckDns")}
                        </button>
                    </div>

                    {dnsCheck && (
                        <div style={{ marginTop: "0.75rem" }}>
                            {dnsCheck.valid ? (
                                <Alert tone="ok">
                                    {t("domains.dkimDnsValid")}
                                </Alert>
                            ) : dnsCheck.found && !dnsCheck.matched ? (
                                <Alert tone="warn">
                                    {t("domains.dkimDnsMismatch")}
                                </Alert>
                            ) : (
                                <Alert tone="warn">
                                    {t("domains.dkimDnsNotFound", {
                                        record: dnsCheck.record_name,
                                        selector: dkim.selector ?? "xeronmx",
                                    })}
                                </Alert>
                            )}
                        </div>
                    )}

                    {canEdit && (
                        <div className="row" style={{ marginTop: "1rem" }}>
                            <button
                                type="button"
                                className={dkim.enabled ? "btn-sm" : "btn-primary"}
                                onClick={() => handleToggleSigning(!dkim.enabled)}
                                disabled={busy}
                            >
                                {t(dkim.enabled ? "domains.dkimDisable" : "domains.dkimEnable")}
                            </button>
                            {canForce && !dkim.enabled && (
                                <button
                                    type="button"
                                    className="btn-sm"
                                    onClick={() => handleToggleSigning(true, true)}
                                    disabled={busy}
                                >
                                    {t("domains.dkimForceEnable")}
                                </button>
                            )}
                            <button
                                type="button"
                                className="btn-sm btn-danger"
                                onClick={handleDeleteKey}
                                disabled={busy}
                            >
                                {t("domains.dkimDelete")}
                            </button>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

function DMARCSection({
    domain,
    dmarc,
    loading,
    onChecked,
}: {
    domain: Domain;
    dmarc: DMARCInfo | null;
    loading: boolean;
    onChecked: (res: DMARCDNSCheck) => void;
}) {
    const t = useT();
    const [policy, setPolicy] = useState("quarantine");
    const [error, setError] = useState("");
    const [checkingDns, setCheckingDns] = useState(false);
    const [dnsCheck, setDnsCheck] = useState<DMARCDNSCheck | null>(dmarc?.dns ?? null);

    const recordName = `_dmarc.${domain.name}.`;
    const recordValue = `v=DMARC1; p=${policy}; sp=${policy}; rua=mailto:dmarc@${domain.name}; pct=100`;

    async function runDnsCheck() {
        setCheckingDns(true);
        setError("");
        try {
            const res = await api.checkDMARC(domain.id);
            setDnsCheck(res);
            onChecked(res);
        } catch (err) {
            setError(err instanceof Error ? err.message : t("common.somethingWrong"));
        } finally {
            setCheckingDns(false);
        }
    }

    const isDmarcActive = dnsCheck?.valid && (dnsCheck.policy === "quarantine" || dnsCheck.policy === "reject");
    const isDmarcMonitoring = dnsCheck?.valid && dnsCheck.policy === "none";

    return (
        <div className="dkim-block">
            <div className="dkim-header">
                <div>
                    <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: "0.5rem" }}>
                        {t("domains.dmarcTitle")}
                        {dnsCheck ? (
                            <Pill tone={isDmarcActive ? "ok" : isDmarcMonitoring ? "warn" : dnsCheck.found ? "bad" : "mute"}>
                                {isDmarcActive
                                    ? t("domains.dmarcActive")
                                    : isDmarcMonitoring
                                    ? t("domains.dmarcMonitoring")
                                    : dnsCheck.found
                                    ? t("domains.dmarcSyntaxError")
                                    : t("domains.dmarcPending")}
                            </Pill>
                        ) : null}
                        <Pill tone={dmarc?.arc_enabled ? "ok" : "mute"}>
                            {t(dmarc?.arc_enabled ? "domains.arcActive" : "domains.arcInactive")}
                        </Pill>
                    </h3>
                    <p style={{ margin: "0.25rem 0 0", fontSize: "0.85rem", color: "var(--muted)" }}>
                        {t("domains.dmarcSubtitle")}
                    </p>
                </div>
            </div>

            {error && <Alert>{error}</Alert>}

            {loading ? (
                <p style={{ color: "var(--muted)" }}>{t("domains.testing")}</p>
            ) : (
                <div>
                    <div style={{ margin: "0.75rem 0" }}>
                        <div style={{ fontSize: "0.85rem", color: "var(--muted)", marginBottom: "0.4rem" }}>
                            {t("domains.dmarcExplain")}
                        </div>
                    </div>

                    <div className="field" style={{ maxWidth: "320px", marginBottom: "0.75rem" }}>
                        <label htmlFor={`dmarc-pol-${domain.id}`}>{t("domains.dmarcPolicy")}</label>
                        <select
                            id={`dmarc-pol-${domain.id}`}
                            value={policy}
                            onChange={(e) => setPolicy(e.target.value)}
                        >
                            <option value="quarantine">{t("domains.dmarcPolicyQuarantine")}</option>
                            <option value="reject">{t("domains.dmarcPolicyReject")}</option>
                            <option value="none">{t("domains.dmarcPolicyNone")}</option>
                        </select>
                    </div>

                    <div className="dkim-field">
                        <label>{t("domains.dkimRecordName")}</label>
                        <div className="dkim-copy-box">
                            <code>{recordName}</code>
                            <CopyButton text={recordName} />
                        </div>
                    </div>

                    <div className="row" style={{ margin: "0.5rem 0" }}>
                        <div style={{ fontSize: "0.85rem", color: "var(--muted)" }}>
                            {t("domains.dkimRecordType")}: <span className="mono" style={{ fontWeight: 600, color: "var(--text)" }}>TXT</span>
                        </div>
                    </div>

                    <div className="dkim-field">
                        <label>{t("domains.dkimRecordValue")}</label>
                        <div className="dkim-copy-box">
                            <code>{recordValue}</code>
                            <CopyButton text={recordValue} />
                        </div>
                    </div>

                    <div className="row" style={{ marginTop: "1rem", alignItems: "center" }}>
                        <button
                            type="button"
                            className="btn-sm"
                            onClick={runDnsCheck}
                            disabled={checkingDns}
                        >
                            {checkingDns ? t("domains.dmarcCheckingDns") : t("domains.dmarcCheckDns")}
                        </button>
                    </div>

                    {dnsCheck && (
                        <div style={{ marginTop: "0.75rem" }}>
                            {dnsCheck.valid ? (
                                <Alert tone="ok">
                                    {t("domains.dmarcDnsValid", { policy: dnsCheck.policy || policy })}
                                </Alert>
                            ) : (
                                <Alert tone="warn">
                                    {t("domains.dmarcDnsNotFound", { record: recordName })}
                                </Alert>
                            )}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

