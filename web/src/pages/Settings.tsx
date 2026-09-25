import { useState, type FormEvent } from "react";
import {
    api,
    type ApiToken,
    type Delivery,
    type Domain,
    type EventCategory,
    type UserAccount,
    type Webhook,
} from "../api";
import { relative } from "../format";
import { Alert, Card, Empty, PageHead, Pill } from "../components/ui";
import { useAsync } from "../useAsync";
import { useT, type TFunction } from "../i18n";
import { Account } from "./Account";
import type { TranslationKey } from "../locales/en";

export function Settings({
    refreshKey,
    canEdit,
    currentUserEmail,
    onChanged,
}: {
    refreshKey: number;
    canEdit: boolean;
    currentUserEmail?: string;
    onChanged: () => void;
}) {
    const t = useT();
    return (
        <>
            <PageHead title={t("settings.title")} subtitle={t("settings.subtitle")} />
            <div className="stack">
                <Account refreshKey={refreshKey} />
                {canEdit && (
                    <>
                        <Operators
                            refreshKey={refreshKey}
                            canEdit={canEdit}
                            currentUserEmail={currentUserEmail}
                            onChanged={onChanged}
                        />
                        <Webhooks refreshKey={refreshKey} canEdit={canEdit} onChanged={onChanged} />
                        <Tokens refreshKey={refreshKey} canEdit={canEdit} onChanged={onChanged} />
                    </>
                )}
            </div>
        </>
    );
}

function Operators({
    refreshKey,
    canEdit,
    currentUserEmail,
    onChanged,
}: {
    refreshKey: number;
    canEdit: boolean;
    currentUserEmail?: string;
    onChanged: () => void;
}) {
    const t = useT();
    const [error, setError] = useState("");
    const [adding, setAdding] = useState(false);
    const [editingId, setEditingId] = useState<number | null>(null);
    const [editDomains, setEditDomains] = useState<string[]>([]);
    const list = useAsync<{ users: UserAccount[] }>(api.listUsers, [refreshKey]);
    const domains = useAsync<{ domains: Domain[] }>(api.listDomains, [refreshKey]);

    async function remove(op: UserAccount) {
        if (!confirm(t("operators.deleteConfirm", { email: op.email }))) return;
        setError("");
        try {
            await api.deleteUser(op.id);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("operators.couldNotDelete"));
        }
    }

    async function updateRole(op: UserAccount, newRole: string) {
        setError("");
        try {
            await api.updateUserRole(op.id, newRole);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("operators.couldNotUpdate"));
        }
    }

    async function resetTOTP(op: UserAccount) {
        if (!confirm(t("operators.resetTotpConfirm", { email: op.email }))) return;
        setError("");
        try {
            await api.updateUser(op.id, { reset_totp: true });
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("operators.couldNotUpdate"));
        }
    }

    async function saveDomains(op: UserAccount) {
        setError("");
        try {
            await api.updateUser(op.id, { allowed_domains: editDomains });
            setEditingId(null);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("operators.couldNotUpdate"));
        }
    }

    function sourceLabel(op: UserAccount) {
        if (op.is_sso && op.has_password) return t("operators.sourceBoth");
        if (op.is_sso) return t("operators.sourceOIDC");
        if (op.has_password) return t("operators.sourcePassword");
        return t("operators.sourceOIDC");
    }

    return (
        <Card>
            <div className="section-head">
                <div>
                    <h2>{t("operators.title")}</h2>
                    <p className="hint">{t("operators.subtitle")}</p>
                </div>
                {canEdit && !adding && (
                    <button className="btn-primary" onClick={() => setAdding(true)}>
                        {t("operators.add")}
                    </button>
                )}
            </div>

            {error && <Alert>{error}</Alert>}
            {list.error && <Alert>{list.error}</Alert>}

            {adding && (
                <AddOperator
                    domains={domains.data?.domains ?? []}
                    onDone={() => {
                        setAdding(false);
                        onChanged();
                    }}
                    onCancel={() => setAdding(false)}
                />
            )}

            {!list.data?.users?.length ? (
                <Empty title={t("operators.noneTitle")} hint={t("operators.noneHint")} />
            ) : (
                <div className="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>{t("operators.thEmail")}</th>
                                <th>{t("operators.thRole")}</th>
                                <th>{t("operators.thDomains")}</th>
                                <th>{t("operators.thSource")}</th>
                                <th>{t("operators.th2fa")}</th>
                                <th>{t("operators.thSince")}</th>
                                {canEdit && <th />}
                            </tr>
                        </thead>
                        <tbody>
                            {list.data.users.map((op) => {
                                const isSelf = currentUserEmail === op.email;
                                return (
                                    <tr key={op.id}>
                                        <td>
                                            <strong>{op.email}</strong>
                                            {isSelf && (
                                                <span style={{ marginLeft: ".5rem", opacity: 0.65, fontSize: "0.85em" }}>
                                                    ({t("operators.you")})
                                                </span>
                                            )}
                                        </td>
                                        <td>
                                            {canEdit && !isSelf ? (
                                                <select
                                                    value={op.role}
                                                    onChange={(e) => updateRole(op, e.target.value)}
                                                    className="select-sm"
                                                >
                                                    <option value="admin">{t("operators.roleAdmin")}</option>
                                                    <option value="operator">{t("operators.roleOperator")}</option>
                                                    <option value="viewer">{t("operators.roleViewer")}</option>
                                                </select>
                                            ) : (
                                                <Pill tone={op.role === "admin" ? "warn" : op.role === "operator" ? "ok" : "mute"}>
                                                    {op.role === "admin"
                                                        ? t("operators.roleAdmin")
                                                        : op.role === "operator"
                                                        ? t("operators.roleOperator")
                                                        : t("operators.roleViewer")}
                                                </Pill>
                                            )}
                                        </td>
                                        <td>
                                            {op.role === "admin" ? (
                                                <span className="hint">{t("operators.allDomains")}</span>
                                            ) : editingId === op.id ? (
                                                <div style={{ display: "flex", flexDirection: "column", gap: ".3rem" }}>
                                                    <select
                                                        multiple
                                                        size={Math.min(4, Math.max(2, domains.data?.domains?.length ?? 2))}
                                                        value={editDomains}
                                                        onChange={(e) =>
                                                            setEditDomains(Array.from(e.target.selectedOptions, (o) => o.value))
                                                        }
                                                        className="select-sm"
                                                    >
                                                        {domains.data?.domains?.map((d) => (
                                                            <option key={d.id} value={d.name}>
                                                                {d.name}
                                                            </option>
                                                        ))}
                                                    </select>
                                                    <div className="row" style={{ gap: ".3rem" }}>
                                                        <button
                                                            className="btn-sm btn-primary"
                                                            onClick={() => saveDomains(op)}
                                                        >
                                                            {t("common.save")}
                                                        </button>
                                                        <button
                                                            className="btn-sm"
                                                            onClick={() => setEditingId(null)}
                                                        >
                                                            {t("common.cancel")}
                                                        </button>
                                                    </div>
                                                </div>
                                            ) : (
                                                <div className="row" style={{ gap: ".3rem", flexWrap: "wrap", alignItems: "center" }}>
                                                    {op.allowed_domains && op.allowed_domains.length > 0 ? (
                                                        op.allowed_domains.map((d) => (
                                                            <Pill key={d} tone="mute">
                                                                {d}
                                                            </Pill>
                                                        ))
                                                    ) : (
                                                        <span className="hint">{t("operators.allDomains")}</span>
                                                    )}
                                                    {canEdit && !isSelf && (
                                                        <button
                                                            className="btn-sm"
                                                            style={{ padding: "0 .4rem", fontSize: ".75rem" }}
                                                            onClick={() => {
                                                                setEditingId(op.id);
                                                                setEditDomains(op.allowed_domains || []);
                                                            }}
                                                        >
                                                            {t("common.edit")}
                                                        </button>
                                                    )}
                                                </div>
                                            )}
                                        </td>
                                        <td>
                                            <Pill tone="mute">{sourceLabel(op)}</Pill>
                                        </td>
                                        <td>
                                            {op.has_password ? (
                                                <div className="row" style={{ gap: ".3rem", alignItems: "center" }}>
                                                    <Pill tone={op.totp_enabled ? "ok" : "mute"}>
                                                        {op.totp_enabled ? t("operators.totpOn") : t("operators.totpOff")}
                                                    </Pill>
                                                    {canEdit && !isSelf && op.totp_enabled && (
                                                        <button
                                                            className="btn-sm"
                                                            style={{ padding: "0 .4rem", fontSize: ".75rem" }}
                                                            onClick={() => resetTOTP(op)}
                                                        >
                                                            {t("operators.resetTotp")}
                                                        </button>
                                                    )}
                                                </div>
                                            ) : (
                                                <span className="hint">—</span>
                                            )}
                                        </td>
                                        <td>{relative(op.created_at)}</td>
                                        {canEdit && (
                                            <td className="right">
                                                {!isSelf && (
                                                    <button className="btn-sm" onClick={() => remove(op)}>
                                                        {t("domains.delete")}
                                                    </button>
                                                )}
                                            </td>
                                        )}
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            )}
        </Card>
    );
}

function AddOperator({
    domains,
    onDone,
    onCancel,
}: {
    domains: Domain[];
    onDone: () => void;
    onCancel: () => void;
}) {
    const t = useT();
    const [email, setEmail] = useState("");
    const [role, setRole] = useState("viewer");
    const [password, setPassword] = useState("");
    const [allowedDomains, setAllowedDomains] = useState<string[]>([]);
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);

    async function submit(e: FormEvent) {
        e.preventDefault();
        setBusy(true);
        setError("");
        try {
            await api.createUser({
                email,
                role,
                password: password.trim() ? password : undefined,
                allowed_domains: role !== "admin" && allowedDomains.length > 0 ? allowedDomains : undefined,
            });
            onDone();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("operators.couldNotCreate"));
        } finally {
            setBusy(false);
        }
    }

    return (
        <form className="inline-form" onSubmit={submit}>
            {error && <Alert>{error}</Alert>}
            <div className="grid-2">
                <div className="field">
                    <label htmlFor="op-email">{t("operators.fldEmail")}</label>
                    <input
                        id="op-email"
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder={t("operators.emailPlaceholder")}
                        required
                        autoFocus
                    />
                </div>
                <div className="field">
                    <label htmlFor="op-role">{t("operators.fldRole")}</label>
                    <select id="op-role" value={role} onChange={(e) => setRole(e.target.value)}>
                        <option value="viewer">{t("operators.roleViewerDesc")}</option>
                        <option value="operator">{t("operators.roleOperatorDesc")}</option>
                        <option value="admin">{t("operators.roleAdminDesc")}</option>
                    </select>
                </div>
            </div>
            {role !== "admin" && domains.length > 0 && (
                <div className="field">
                    <label htmlFor="op-domains">{t("operators.fldDomains")}</label>
                    <select
                        id="op-domains"
                        multiple
                        size={Math.min(4, Math.max(2, domains.length))}
                        value={allowedDomains}
                        onChange={(e) =>
                            setAllowedDomains(Array.from(e.target.selectedOptions, (o) => o.value))
                        }
                    >
                        {domains.map((d) => (
                            <option key={d.id} value={d.name}>
                                {d.name}
                            </option>
                        ))}
                    </select>
                    <div className="hint">{t("operators.fldDomainsHint")}</div>
                </div>
            )}
            <div className="field">
                <label htmlFor="op-pass">{t("operators.fldPassword")}</label>
                <input
                    id="op-pass"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    minLength={password ? 12 : undefined}
                />
                <div className="hint">{t("operators.fldPasswordHint")}</div>
            </div>
            <div className="row">
                <button type="submit" className="btn-primary" disabled={busy}>
                    {busy ? t("common.working") : t("operators.create")}
                </button>
                <button type="button" className="btn-sm" onClick={onCancel}>
                    {t("sending.cancel")}
                </button>
            </div>
        </form>
    );
}

function Tokens({
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
    const [adding, setAdding] = useState(false);
    const [minted, setMinted] = useState<{ name: string; secret: string } | null>(null);
    const list = useAsync<{ tokens: ApiToken[] }>(api.listTokens, [refreshKey]);

    async function revoke(tok: ApiToken) {
        if (!confirm(t("tokens.revokeConfirm", { name: tok.name }))) return;
        setError("");
        try {
            await api.deleteToken(tok.id);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("tokens.couldNotRevoke"));
        }
    }

    return (
        <Card>
            <div className="section-head">
                <div>
                    <h2>{t("tokens.title")}</h2>
                    <p className="hint">{t("tokens.subtitle")}</p>
                </div>
                {canEdit && !adding && (
                    <button className="btn-primary" onClick={() => setAdding(true)}>
                        {t("tokens.add")}
                    </button>
                )}
            </div>

            {error && <Alert>{error}</Alert>}
            {list.error && <Alert>{list.error}</Alert>}

            {minted && (
                <Alert tone="warn">
                    <div style={{ fontWeight: 550 }}>{t("tokens.copyNow", { name: minted.name })}</div>
                    <code className="secret">{minted.secret}</code>
                    <div style={{ marginTop: ".5rem" }}>
                        <button className="btn-sm" onClick={() => setMinted(null)}>
                            {t("tokens.hide")}
                        </button>
                    </div>
                </Alert>
            )}

            {adding && (
                <AddToken
                    onDone={(name, secret) => {
                        setAdding(false);
                        setMinted({ name, secret });
                        onChanged();
                    }}
                    onCancel={() => setAdding(false)}
                />
            )}

            {!list.data?.tokens?.length ? (
                <Empty title={t("tokens.noneTitle")} hint={t("tokens.noneHint")} />
            ) : (
                <div className="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>{t("tokens.thName")}</th>
                                <th>{t("tokens.thRole")}</th>
                                <th>{t("tokens.thExpires")}</th>
                                <th>{t("tokens.thLastUsed")}</th>
                                {canEdit && <th />}
                            </tr>
                        </thead>
                        <tbody>
                            {list.data.tokens.map((tok) => (
                                <tr key={tok.id}>
                                    <td>
                                        <strong>{tok.name}</strong>
                                        <div className="mono-sm">{tok.prefix}…</div>
                                    </td>
                                    <td>
                                        <Pill tone={tok.role === "admin" ? "warn" : "mute"}>
                                            {tok.role === "admin"
                                                ? t("tokens.roleAdmin")
                                                : t("tokens.roleViewer")}
                                        </Pill>
                                    </td>
                                    <td>
                                        {tok.expired ? (
                                            <Pill tone="bad">{t("tokens.expired")}</Pill>
                                        ) : (
                                            relative(tok.expires_at)
                                        )}
                                    </td>
                                    <td>{tok.last_used_at ? relative(tok.last_used_at) : t("common.never")}</td>
                                    {canEdit && (
                                        <td className="right">
                                            <button className="btn-sm" onClick={() => revoke(tok)}>
                                                {t("tokens.revoke")}
                                            </button>
                                        </td>
                                    )}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </Card>
    );
}

function AddToken({
    onDone,
    onCancel,
}: {
    onDone: (name: string, secret: string) => void;
    onCancel: () => void;
}) {
    const t = useT();
    const [name, setName] = useState("");
    const [role, setRole] = useState("viewer");
    const [expiresIn, setExpiresIn] = useState("2160h");
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);

    async function submit(e: FormEvent) {
        e.preventDefault();
        setBusy(true);
        setError("");
        try {
            const res = await api.createToken({ name, role, expires_in: expiresIn });
            onDone(res.token.name, res.secret);
        } catch (err) {
            setError(err instanceof Error ? err.message : t("tokens.couldNotCreate"));
        } finally {
            setBusy(false);
        }
    }

    return (
        <form className="inline-form" onSubmit={submit}>
            {error && <Alert>{error}</Alert>}
            <div className="grid-2">
                <div className="field">
                    <label htmlFor="tok-name">{t("tokens.fldName")}</label>
                    <input
                        id="tok-name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder={t("tokens.namePlaceholder")}
                        required
                        autoFocus
                    />
                </div>
                <div className="field">
                    <label htmlFor="tok-role">{t("tokens.fldRole")}</label>
                    <select id="tok-role" value={role} onChange={(e) => setRole(e.target.value)}>
                        <option value="viewer">{t("tokens.roleViewer")}</option>
                        <option value="admin">{t("tokens.roleAdmin")}</option>
                    </select>
                    <div className="hint">{t("tokens.roleHint")}</div>
                </div>
            </div>
            <div className="field">
                <label htmlFor="tok-exp">{t("tokens.fldExpires")}</label>
                <select id="tok-exp" value={expiresIn} onChange={(e) => setExpiresIn(e.target.value)}>
                    <option value="720h">{t("tokens.exp30")}</option>
                    <option value="2160h">{t("tokens.exp90")}</option>
                    <option value="8760h">{t("tokens.exp365")}</option>
                </select>
                <div className="hint">{t("tokens.expiresHint")}</div>
            </div>
            <div className="row">
                <button type="submit" className="btn-primary" disabled={busy}>
                    {busy ? t("common.working") : t("tokens.create")}
                </button>
                <button type="button" className="btn-sm" onClick={onCancel}>
                    {t("sending.cancel")}
                </button>
            </div>
        </form>
    );
}

const CATEGORY_KEYS: Record<string, TranslationKey> = {
    mail: "hooks.catMail",
    health: "hooks.catHealth",
    admin: "hooks.catAdmin",
};

function categoryLabel(name: string, t: TFunction): string {
    const key = CATEGORY_KEYS[name];
    return key ? t(key) : name;
}

function Webhooks({
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
    const [adding, setAdding] = useState(false);
    const [minted, setMinted] = useState<{ name: string; secret: string } | null>(null);
    const [tested, setTested] = useState<Record<number, string>>({});
    const [showLog, setShowLog] = useState(false);

    const list = useAsync<{ webhooks: Webhook[]; enabled: boolean }>(api.listWebhooks, [refreshKey]);

    async function toggle(h: Webhook) {
        setError("");
        try {
            await api.updateWebhook(h.id, { enabled: !h.enabled });
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("hooks.couldNotUpdate"));
        }
    }

    async function remove(h: Webhook) {
        if (!confirm(t("hooks.deleteConfirm", { name: h.name }))) return;
        setError("");
        try {
            await api.deleteWebhook(h.id);
            onChanged();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("hooks.couldNotDelete"));
        }
    }

    async function test(h: Webhook) {
        setTested((prev) => ({ ...prev, [h.id]: t("hooks.testing") }));
        try {
            const res = await api.testWebhook(h.id);
            setTested((prev) => ({
                ...prev,
                [h.id]: res.ok
                    ? t("hooks.testOK", { status: res.status })
                    : t("hooks.testFailed", { error: res.error ?? "" }),
            }));
        } catch (err) {
            setTested((prev) => ({
                ...prev,
                [h.id]: err instanceof Error ? err.message : t("hooks.couldNotTest"),
            }));
        }
    }

    return (
        <Card>
            <div className="section-head">
                <div>
                    <h2>{t("hooks.title")}</h2>
                    <p className="hint">{t("hooks.subtitle")}</p>
                </div>
                {canEdit && !adding && (
                    <button className="btn-primary" onClick={() => setAdding(true)}>
                        {t("hooks.add")}
                    </button>
                )}
            </div>

            {list.data && !list.data.enabled && (
                <Alert tone="warn">{t("hooks.disabledGlobally")}</Alert>
            )}
            {error && <Alert>{error}</Alert>}
            {list.error && <Alert>{list.error}</Alert>}

            {minted && (
                <Alert tone="warn">
                    <div style={{ fontWeight: 550 }}>{t("hooks.copySecret", { name: minted.name })}</div>
                    <code className="secret">{minted.secret}</code>
                    <div className="hint" style={{ marginTop: ".4rem" }}>
                        {t("hooks.secretHint")}
                    </div>
                    <div style={{ marginTop: ".5rem" }}>
                        <button className="btn-sm" onClick={() => setMinted(null)}>
                            {t("tokens.hide")}
                        </button>
                    </div>
                </Alert>
            )}

            {adding && (
                <AddWebhook
                    onDone={(name, secret) => {
                        setAdding(false);
                        if (secret) setMinted({ name, secret });
                        onChanged();
                    }}
                    onCancel={() => setAdding(false)}
                />
            )}

            {!list.data?.webhooks?.length ? (
                <Empty title={t("hooks.noneTitle")} hint={t("hooks.noneHint")} />
            ) : (
                <div className="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>{t("hooks.thName")}</th>
                                <th>{t("hooks.thEvents")}</th>
                                <th>{t("hooks.thHealth")}</th>
                                {canEdit && <th />}
                            </tr>
                        </thead>
                        <tbody>
                            {list.data.webhooks.map((h) => (
                                <tr key={h.id}>
                                    <td>
                                        <strong>{h.name}</strong>
                                        {!h.enabled && (
                                            <>
                                                {" "}
                                                <Pill tone="mute">{t("filters.disabledBadge")}</Pill>
                                            </>
                                        )}
                                        <div className="mono-sm break">{h.url}</div>
                                        {!h.signed && (
                                            <Pill tone="warn">{t("hooks.unsigned")}</Pill>
                                        )}
                                    </td>
                                    <td>
                                        {h.events.length === 0
                                            ? t("hooks.allEvents")
                                            : t("hooks.nEvents", { n: h.events.length })}
                                    </td>
                                    <td>
                                        {h.last_error ? (
                                            <>
                                                <Pill tone="bad">{t("hooks.failing")}</Pill>
                                                <div className="mono-sm break">{h.last_error}</div>
                                            </>
                                        ) : h.last_success_at ? (
                                            <Pill tone="ok">{relative(h.last_success_at)}</Pill>
                                        ) : (
                                            <Pill tone="mute">{t("hooks.neverFired")}</Pill>
                                        )}
                                        {tested[h.id] && (
                                            <div className="hint">{tested[h.id]}</div>
                                        )}
                                    </td>
                                    {canEdit && (
                                        <td className="right">
                                            <button className="btn-sm" onClick={() => test(h)}>
                                                {t("hooks.test")}
                                            </button>{" "}
                                            <button className="btn-sm" onClick={() => toggle(h)}>
                                                {h.enabled ? t("filters.disable") : t("filters.enable")}
                                            </button>{" "}
                                            <button className="btn-sm" onClick={() => remove(h)}>
                                                {t("filters.delete")}
                                            </button>
                                        </td>
                                    )}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}

            {list.data?.webhooks?.length ? (
                <div style={{ marginTop: "1rem" }}>
                    <button className="btn-sm" onClick={() => setShowLog((v) => !v)}>
                        {showLog ? t("hooks.hideLog") : t("hooks.showLog")}
                    </button>
                    {showLog && <DeliveryLog refreshKey={refreshKey} />}
                </div>
            ) : null}
        </Card>
    );
}

function DeliveryLog({ refreshKey }: { refreshKey: number }) {
    const t = useT();
    const log = useAsync<{ deliveries: Delivery[] }>(() => api.listDeliveries(), [refreshKey]);

    if (log.error) return <Alert>{log.error}</Alert>;
    if (!log.data?.deliveries?.length) {
        return <Empty title={t("hooks.logEmpty")} hint={t("hooks.logEmptyHint")} />;
    }

    return (
        <div className="table-wrap" style={{ marginTop: ".75rem" }}>
            <table>
                <thead>
                    <tr>
                        <th>{t("hooks.thWhen")}</th>
                        <th>{t("hooks.thSubscription")}</th>
                        <th>{t("hooks.thEvent")}</th>
                        <th>{t("hooks.thResult")}</th>
                    </tr>
                </thead>
                <tbody>
                    {log.data.deliveries.map((d) => (
                        <tr key={d.id}>
                            <td>{relative(d.created_at)}</td>
                            <td>{d.webhook_name}</td>
                            <td className="mono-sm">{d.event}</td>
                            <td>
                                {d.status === "delivered" && (
                                    <Pill tone="ok">{t("hooks.delivered", { status: d.status_code ?? 0 })}</Pill>
                                )}
                                {d.status === "pending" && (
                                    <Pill tone="warn">
                                        {t("hooks.retrying", { n: d.attempts })}
                                    </Pill>
                                )}
                                {d.status === "failed" && <Pill tone="bad">{t("hooks.gaveUp")}</Pill>}
                                {d.last_error && <div className="mono-sm break">{d.last_error}</div>}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function AddWebhook({
    onDone,
    onCancel,
}: {
    onDone: (name: string, secret?: string) => void;
    onCancel: () => void;
}) {
    const t = useT();
    const [name, setName] = useState("");
    const [url, setUrl] = useState("");
    const [selected, setSelected] = useState<string[]>([]);
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);
    const cats = useAsync<{ categories: EventCategory[] }>(api.webhookEventTypes, []);

    function toggleEvent(type: string) {
        setSelected((prev) =>
            prev.includes(type) ? prev.filter((e) => e !== type) : [...prev, type],
        );
    }

    async function submit(e: FormEvent) {
        e.preventDefault();
        setBusy(true);
        setError("");
        try {
            const res = await api.createWebhook({ name, url, events: selected });
            onDone(res.webhook.name, res.secret);
        } catch (err) {
            setError(err instanceof Error ? err.message : t("hooks.couldNotCreate"));
        } finally {
            setBusy(false);
        }
    }

    return (
        <form className="inline-form" onSubmit={submit}>
            {error && <Alert>{error}</Alert>}
            <div className="grid-2">
                <div className="field">
                    <label htmlFor="hook-name">{t("hooks.fldName")}</label>
                    <input
                        id="hook-name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        required
                        autoFocus
                    />
                </div>
                <div className="field">
                    <label htmlFor="hook-url">{t("hooks.fldURL")}</label>
                    <input
                        id="hook-url"
                        type="url"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        placeholder="https://hooks.example.com/xeronmx"
                        required
                    />
                </div>
            </div>

            <div className="field">
                <label>{t("hooks.fldEvents")}</label>
                <div className="hint">
                    {selected.length === 0 ? t("hooks.allEventsHint") : t("hooks.nEvents", { n: selected.length })}
                </div>
                {cats.data?.categories.map((cat) => (
                    <div key={cat.name}>
                        <div className="checkbox-group-name">{categoryLabel(cat.name, t)}</div>
                        <div className="checkbox-grid">
                            {cat.types.map((type) => (
                                <label key={type} className="checkbox">
                                    <input
                                        type="checkbox"
                                        checked={selected.includes(type)}
                                        onChange={() => toggleEvent(type)}
                                    />
                                    <span>{type}</span>
                                </label>
                            ))}
                        </div>
                    </div>
                ))}
            </div>

            <div className="row">
                <button type="submit" className="btn-primary" disabled={busy}>
                    {busy ? t("common.working") : t("hooks.create")}
                </button>
                <button type="button" className="btn-sm" onClick={onCancel}>
                    {t("sending.cancel")}
                </button>
            </div>
        </form>
    );
}
