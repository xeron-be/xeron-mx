import { useState, type FormEvent } from "react";
import { api, type Domain, type SMTPUser } from "../api";
import { relative } from "../format";
import { Alert, Card, Empty, PageHead, Pill } from "../components/ui";
import { useAsync } from "../useAsync";
import { useT } from "../i18n";

export function Sending({
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
    const accounts = useAsync<{ accounts: SMTPUser[] }>(api.listSMTPUsers, [refreshKey]);
    const domains = useAsync<{ domains: Domain[] }>(api.listDomains, [refreshKey]);

    async function toggle(u: SMTPUser) {
        setError("");
        try {
            await api.updateSMTPUser(u.id, !u.enabled);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("sending.couldNotUpdate"));
        }
    }

    async function remove(u: SMTPUser) {
        if (!confirm(t("sending.deleteConfirm", { name: u.username }))) {
            return;
        }
        setError("");
        try {
            await api.deleteSMTPUser(u.id);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("sending.couldNotDelete"));
        }
    }

    return (
        <>
            <PageHead
                title={t("sending.title")}
                subtitle={t("sending.subtitle")}
                actions={
                    canEdit && !adding ? (
                        <button className="btn-primary" onClick={() => setAdding(true)}>
                            {t("sending.addButton")}
                        </button>
                    ) : null
                }
            />

            {error && <Alert>{error}</Alert>}
            {accounts.error && <Alert>{accounts.error}</Alert>}

            {adding && (
                <div style={{ marginBottom: "1rem" }}>
                    <AddAccount
                        domains={domains.data?.domains ?? []}
                        onDone={() => {
                            setAdding(false);
                            onChanged();
                        }}
                        onCancel={() => setAdding(false)}
                    />
                </div>
            )}

            <Card>
                {!accounts.data?.accounts?.length ? (
                    <Empty
                        title={t("sending.noneTitle")}
                        hint={t("sending.noneHint")}
                    />
                ) : (
                    <div className="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th>{t("sending.thUsername")}</th>
                                    <th>{t("sending.thMaySend")}</th>
                                    <th>{t("sending.thLastUsed")}</th>
                                    <th>{t("sending.thStatus")}</th>
                                    {canEdit && <th />}
                                </tr>
                            </thead>
                            <tbody>
                                {accounts.data.accounts.map((u) => (
                                    <tr key={u.id}>
                                        <td className="mono">{u.username}</td>
                                        <td>
                                            {u.allowed_domains?.length ? (
                                                u.allowed_domains.join(", ")
                                            ) : (
                                                <span style={{ color: "var(--muted)" }}>{t("sending.anyDomain")}</span>
                                            )}
                                        </td>
                                        <td>{relative(u.last_used_at)}</td>
                                        <td>
                                            <Pill tone={u.enabled ? "ok" : "mute"}>
                                                {u.enabled ? t("sending.active") : t("sending.disabled")}
                                            </Pill>
                                        </td>
                                        {canEdit && (
                                            <td>
                                                <div className="row">
                                                    <button className="btn-sm" onClick={() => toggle(u)}>
                                                        {u.enabled ? t("sending.disable") : t("sending.enable")}
                                                    </button>
                                                    <button
                                                        className="btn-sm btn-danger"
                                                        onClick={() => remove(u)}
                                                    >
                                                        {t("sending.delete")}
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
        </>
    );
}

function AddAccount({
    domains,
    onDone,
    onCancel,
}: {
    domains: Domain[];
    onDone: () => void;
    onCancel: () => void;
}) {
    const t = useT();
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [allowed, setAllowed] = useState<string[]>([]);
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);
    const [created, setCreated] = useState<string | null>(null);

    async function submit(e: FormEvent) {
        e.preventDefault();
        setError("");
        setBusy(true);
        try {
            await api.createSMTPUser(username, password, allowed);
            setCreated(password);
        } catch (err) {
            setError(err instanceof Error ? err.message : t("sending.couldNotCreate"));
        } finally {
            setBusy(false);
        }
    }

    if (created) {
        return (
            <Card>
                <h2 style={{ marginBottom: ".6rem" }}>{t("sending.createdTitle")}</h2>
                <Alert tone="warn">
                    <strong>{t("sending.copyNow")}</strong> {t("sending.copyNowBody")}{" "}
                    {t("sending.losingIt")}
                </Alert>
                <div className="dns-record">
                    username: {username}
                    <br />
                    password: {created}
                </div>
                <p style={{ fontSize: ".9rem", color: "var(--muted)" }}>
                    {t("sending.smarthostHint")}
                </p>
                <button className="btn-primary" onClick={onDone}>
                    {t("sending.done")}
                </button>
            </Card>
        );
    }

    return (
        <Card>
            <h2 style={{ marginBottom: "1rem" }}>{t("sending.newTitle")}</h2>
            {error && <Alert>{error}</Alert>}
            <form onSubmit={submit}>
                <div className="field">
                    <label htmlFor="username">{t("sending.fldUsername")}</label>
                    <input
                        id="username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="mailserver"
                        required
                        autoFocus
                    />
                </div>

                <div className="field">
                    <label htmlFor="smtp-password">{t("sending.fldPassword")}</label>
                    <input
                        id="smtp-password"
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        autoComplete="new-password"
                        required
                    />
                    <div className="hint">
                        {t("sending.passwordHint")}
                    </div>
                </div>

                <div className="field">
                    <label htmlFor="allowed">{t("sending.fldMaySend")}</label>
                    <select
                        id="allowed"
                        multiple
                        size={Math.min(4, Math.max(2, domains.length))}
                        value={allowed}
                        onChange={(e) =>
                            setAllowed(Array.from(e.target.selectedOptions, (o) => o.value))
                        }
                    >
                        {domains.map((d) => (
                            <option key={d.id} value={d.name}>
                                {d.name}
                            </option>
                        ))}
                    </select>
                    <div className="hint">
                        {t("sending.maySendHint")}
                    </div>
                </div>

                <div className="row">
                    <button type="submit" className="btn-primary" disabled={busy}>
                        {busy ? t("sending.creating") : t("sending.create")}
                    </button>
                    <button type="button" onClick={onCancel} disabled={busy}>
                        {t("sending.cancel")}
                    </button>
                </div>
            </form>
        </Card>
    );
}
