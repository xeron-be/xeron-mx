import { useState, type FormEvent } from "react";
import { api, type TOTPSetup, type User } from "../api";
import { Alert, Card, Pill } from "../components/ui";
import { useAsync } from "../useAsync";
import { useT } from "../i18n";

export function Account({ refreshKey }: { refreshKey: number }) {
    const t = useT();
    const [version, setVersion] = useState(0);
    const me = useAsync<User>(api.me, [refreshKey, version]);
    const reload = () => setVersion((v) => v + 1);

    if (!me.data) {
        return me.error ? (
            <Card>
                <Alert>{me.error}</Alert>
            </Card>
        ) : null;
    }

    return (
        <Card>
            <div className="section-head">
                <div>
                    <h2>{t("account.title")}</h2>
                    <p className="hint">{t("account.subtitle")}</p>
                </div>
            </div>
            {me.data.has_password === false ? (
                <p className="hint">{t("account.ssoOnly")}</p>
            ) : (
                <div className="stack">
                    <ChangePassword />
                    <SecondFactor user={me.data} onChanged={reload} />
                </div>
            )}
        </Card>
    );
}

function ChangePassword() {
    const t = useT();
    const [current, setCurrent] = useState("");
    const [next, setNext] = useState("");
    const [confirm, setConfirm] = useState("");
    const [error, setError] = useState("");
    const [done, setDone] = useState(false);
    const [busy, setBusy] = useState(false);
    const [open, setOpen] = useState(false);

    function close() {
        setOpen(false);
        setCurrent("");
        setNext("");
        setConfirm("");
        setError("");
    }

    async function submit(e: FormEvent) {
        e.preventDefault();
        setError("");
        setDone(false);
        if (next !== confirm) {
            setError(t("account.passwordsDiffer"));
            return;
        }
        setBusy(true);
        try {
            await api.changePassword(current, next);
            close();
            setDone(true);
        } catch (err) {
            setError(err instanceof Error ? err.message : t("common.somethingWrong"));
        } finally {
            setBusy(false);
        }
    }

    if (!open) {
        return (
            <div className="account-part">
                <h3>{t("account.passwordTitle")}</h3>
                {done && <Alert tone="ok">{t("account.passwordChanged")}</Alert>}
                <button
                    className="btn-sm"
                    onClick={() => {
                        setDone(false);
                        setOpen(true);
                    }}
                >
                    {t("account.changePassword")}
                </button>
            </div>
        );
    }

    return (
        <form onSubmit={submit} className="account-part">
            <h3>{t("account.passwordTitle")}</h3>
            {error && <Alert>{error}</Alert>}
            <div className="field">
                <label htmlFor="acct-current">{t("account.currentPassword")}</label>
                <input
                    id="acct-current"
                    type="password"
                    autoComplete="current-password"
                    value={current}
                    onChange={(e) => setCurrent(e.target.value)}
                    required
                    autoFocus
                />
            </div>
            <div className="field">
                <label htmlFor="acct-new">{t("account.newPassword")}</label>
                <input
                    id="acct-new"
                    type="password"
                    autoComplete="new-password"
                    minLength={12}
                    value={next}
                    onChange={(e) => setNext(e.target.value)}
                    required
                />
                <div className="hint">{t("account.passwordHint")}</div>
            </div>
            <div className="field">
                <label htmlFor="acct-confirm">{t("account.confirmNewPassword")}</label>
                <input
                    id="acct-confirm"
                    type="password"
                    autoComplete="new-password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    required
                />
            </div>
            <FormButtons busy={busy} label={t("account.changePassword")} onCancel={close} />
        </form>
    );
}

type Mode = "idle" | "password" | "scan" | "codes" | "disable" | "renew";

function SecondFactor({ user, onChanged }: { user: User; onChanged: () => void }) {
    const t = useT();
    const [mode, setMode] = useState<Mode>("idle");
    const [password, setPassword] = useState("");
    const [code, setCode] = useState("");
    const [setup, setSetup] = useState<TOTPSetup | null>(null);
    const [codes, setCodes] = useState<string[]>([]);
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);

    function reset(to: Mode = "idle") {
        setMode(to);
        setPassword("");
        setCode("");
        setError("");
        if (to === "idle") setSetup(null);
    }

    async function run(action: () => Promise<void>) {
        setError("");
        setBusy(true);
        try {
            await action();
        } catch (err) {
            setError(err instanceof Error ? err.message : t("common.somethingWrong"));
        } finally {
            setBusy(false);
        }
    }

    const startSetup = (e: FormEvent) => {
        e.preventDefault();
        run(async () => {
            setSetup(await api.totpSetup(password));
            setPassword("");
            setMode("scan");
        });
    };

    const confirmSetup = (e: FormEvent) => {
        e.preventDefault();
        run(async () => {
            const res = await api.totpEnable(code);
            setCodes(res.recovery_codes);
            setCode("");
            setSetup(null);
            setMode("codes");
            onChanged();
        });
    };

    const confirmIdentity = (e: FormEvent) => {
        e.preventDefault();
        run(async () => {
            if (mode === "disable") {
                await api.totpDisable(password, code);
                reset();
            } else {
                const res = await api.totpRecoveryCodes(password, code);
                setCodes(res.recovery_codes);
                setPassword("");
                setCode("");
                setMode("codes");
            }
            onChanged();
        });
    };

    return (
        <div className="account-part">
            <h3>
                {t("account.totpTitle")}{" "}
                <Pill tone={user.totp_enabled ? "ok" : "warn"}>
                    {user.totp_enabled ? t("operators.totpOn") : t("operators.totpOff")}
                </Pill>
            </h3>
            <p className="hint">
                {user.totp_enabled ? t("account.totpOn") : t("account.totpOff")}
                {user.totp_enabled && user.recovery_codes_left !== undefined && (
                    <> {t("account.recoveryLeft", { n: user.recovery_codes_left })}</>
                )}
            </p>
            {error && <Alert>{error}</Alert>}

            {mode === "idle" && (
                <div className="row" style={{ gap: ".5rem" }}>
                    {user.totp_enabled ? (
                        <>
                            <button className="btn-sm" onClick={() => reset("renew")}>
                                {t("account.renewCodes")}
                            </button>
                            <button className="btn-sm" onClick={() => reset("disable")}>
                                {t("account.disable")}
                            </button>
                        </>
                    ) : (
                        <button className="btn-primary" onClick={() => reset("password")}>
                            {t("account.enable")}
                        </button>
                    )}
                </div>
            )}

            {mode === "password" && (
                <form onSubmit={startSetup}>
                    <div className="field">
                        <label htmlFor="totp-password">{t("account.confirmPasswordToStart")}</label>
                        <input
                            id="totp-password"
                            type="password"
                            autoComplete="current-password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            autoFocus
                        />
                    </div>
                    <FormButtons busy={busy} label={t("account.continue")} onCancel={() => reset()} />
                </form>
            )}

            {mode === "scan" && setup && (
                <form onSubmit={confirmSetup}>
                    <p>{t("account.scanQr")}</p>
                    <img
                        src={setup.qr_code}
                        alt="QR code"
                        width={220}
                        height={220}
                        style={{ imageRendering: "pixelated", background: "#fff", padding: ".5rem", borderRadius: ".5rem" }}
                    />
                    <p className="hint">
                        {t("account.manualKey")} <code style={{ userSelect: "all" }}>{setup.secret}</code>
                    </p>
                    <div className="field">
                        <label htmlFor="totp-code">{t("auth.code")}</label>
                        <input
                            id="totp-code"
                            type="text"
                            inputMode="numeric"
                            autoComplete="one-time-code"
                            maxLength={7}
                            value={code}
                            onChange={(e) => setCode(e.target.value)}
                            required
                            autoFocus
                        />
                    </div>
                    <FormButtons busy={busy} label={t("account.enable")} onCancel={() => reset()} />
                </form>
            )}

            {mode === "codes" && <RecoveryCodes codes={codes} onDone={() => reset()} />}

            {(mode === "disable" || mode === "renew") && (
                <form onSubmit={confirmIdentity}>
                    <p className="hint">{t("account.confirmHint")}</p>
                    <div className="field">
                        <label htmlFor="totp-confirm-password">{t("account.currentPassword")}</label>
                        <input
                            id="totp-confirm-password"
                            type="password"
                            autoComplete="current-password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            autoFocus
                        />
                    </div>
                    <div className="field">
                        <label htmlFor="totp-confirm-code">{t("account.codeOrRecovery")}</label>
                        <input
                            id="totp-confirm-code"
                            type="text"
                            autoComplete="one-time-code"
                            spellCheck={false}
                            value={code}
                            onChange={(e) => setCode(e.target.value)}
                            required
                        />
                    </div>
                    <FormButtons
                        busy={busy}
                        label={mode === "disable" ? t("account.disable") : t("account.renewCodes")}
                        onCancel={() => reset()}
                    />
                </form>
            )}
        </div>
    );
}

function FormButtons({ busy, label, onCancel }: { busy: boolean; label: string; onCancel: () => void }) {
    const t = useT();
    return (
        <div className="row" style={{ gap: ".5rem" }}>
            <button type="submit" className="btn-primary" disabled={busy}>
                {busy ? t("common.working") : label}
            </button>
            <button type="button" className="btn-sm" onClick={onCancel}>
                {t("common.cancel")}
            </button>
        </div>
    );
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
    const t = useT();
    const [copied, setCopied] = useState(false);
    const text = codes.join("\n") + "\n";

    function download() {
        const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
        const a = document.createElement("a");
        a.href = url;
        a.download = "xeronmx-recovery-codes.txt";
        a.click();
        URL.revokeObjectURL(url);
    }

    return (
        <div>
            <Alert tone="warn">
                <strong>{t("account.recoveryTitle")}</strong>
                <div>{t("account.recoveryHint")}</div>
            </Alert>
            <pre style={{ columns: 2, fontSize: "1rem", userSelect: "all" }}>{text}</pre>
            <div className="row" style={{ gap: ".5rem" }}>
                <button
                    className="btn-sm"
                    onClick={() => navigator.clipboard?.writeText(text).then(() => setCopied(true))}
                >
                    {copied ? t("account.copied") : t("account.copy")}
                </button>
                <button className="btn-sm" onClick={download}>
                    {t("account.download")}
                </button>
                <button className="btn-primary" onClick={onDone}>
                    {t("account.saved")}
                </button>
            </div>
        </div>
    );
}
