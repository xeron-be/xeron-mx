import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError, ssoLoginURL, type SetupStatus, type User } from "../api";
import { Alert, Card } from "../components/ui";
import { useT } from "../i18n";
import type { TranslationKey } from "../locales/en";

const SSO_ERRORS: Record<string, TranslationKey> = {
    not_configured: "sso.errNotConfigured",
    not_ready: "sso.errNotReady",
    state: "sso.errState",
    exchange: "sso.errExchange",
    unverified: "sso.errUnverified",
    no_account: "sso.errNoAccount",
    conflict: "sso.errConflict",
    server: "sso.errServer",
};

function readSSOError(): string {
    const code = new URLSearchParams(window.location.search).get("sso_error");
    if (!code) return "";
    window.history.replaceState({}, "", window.location.pathname);
    return code;
}

export function Auth({
    needsSetup,
    onAuthenticated,
}: {
    needsSetup: boolean;
    onAuthenticated: (user: User) => void;
}) {
    const t = useT();
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [confirm, setConfirm] = useState("");
    const [code, setCode] = useState("");
    const [needsCode, setNeedsCode] = useState(false);
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(false);
    const [methods, setMethods] = useState<SetupStatus | null>(null);
    const [ssoError] = useState(readSSOError);

    useEffect(() => {
        api.setupStatus().then(setMethods).catch(() => {});
    }, []);

    async function submit(e: FormEvent) {
        e.preventDefault();
        setError("");

        if (needsSetup && password !== confirm) {
            setError(t("auth.passwordsDoNotMatch"));
            return;
        }
        setBusy(true);
        try {
            const user = needsSetup
                ? await api.setup(email, password)
                : await api.login(email, password, needsCode ? code : undefined);
            onAuthenticated(user);
        } catch (err) {
            if (err instanceof ApiError && err.code === "totp_required") {
                setNeedsCode(true);
                setCode("");
            } else if (needsCode && err instanceof ApiError && err.code === "invalid_credentials") {
                setError(t("auth.codeInvalid"));
                setCode("");
            } else {
                setError(err instanceof Error ? err.message : t("common.somethingWrong"));
            }
        } finally {
            setBusy(false);
        }
    }

    const sso = methods?.oidc?.enabled === true;
    const passwords = needsSetup || methods === null || methods.password_login !== false;

    if (needsCode) {
        return (
            <div className="auth">
                <Card className="auth-card">
                    <h1>{t("auth.codeTitle")}</h1>
                    <p>{t("auth.codeSubtitle")}</p>
                    {error && <Alert>{error}</Alert>}
                    <form onSubmit={submit}>
                        <div className="field">
                            <label htmlFor="code">{t("auth.code")}</label>
                            <input
                                id="code"
                                type="text"
                                inputMode="text"
                                autoComplete="one-time-code"
                                spellCheck={false}
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                required
                                autoFocus
                            />
                        </div>
                        <button
                            type="submit"
                            className="btn-primary"
                            disabled={busy}
                            style={{ width: "100%" }}
                        >
                            {busy ? t("common.working") : t("auth.verify")}
                        </button>
                        <button
                            type="button"
                            className="btn-sm"
                            style={{ width: "100%", marginTop: ".5rem" }}
                            onClick={() => {
                                setNeedsCode(false);
                                setCode("");
                                setError("");
                            }}
                        >
                            {t("auth.back")}
                        </button>
                    </form>
                </Card>
            </div>
        );
    }

    return (
        <div className="auth">
            <Card className="auth-card">
                <h1>{needsSetup ? t("auth.setupTitle") : t("auth.signInTitle")}</h1>
                <p>{needsSetup ? t("auth.setupSubtitle") : t("auth.signInSubtitle")}</p>

                {ssoError && (
                    <Alert>{t(SSO_ERRORS[ssoError] ?? "sso.errServer")}</Alert>
                )}
                {error && <Alert>{error}</Alert>}

                {sso && !needsSetup && (
                    <>
                        <a className="btn-sso" href={ssoLoginURL}>
                            <svg
                                className="btn-sso-icon"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                strokeWidth="2"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                            >
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                <path d="m9 12 2 2 4-4" />
                            </svg>
                            <span>{t("sso.signIn")}</span>
                        </a>
                        {methods?.oidc.ready === false && (
                            <div className="hint" style={{ marginTop: ".5rem" }}>
                                {t("sso.notReadyHint")}
                            </div>
                        )}
                        {passwords && <div className="auth-divider">{t("sso.or")}</div>}
                    </>
                )}

                {!passwords && !needsSetup ? (
                    <p className="hint" style={{ marginTop: "1rem" }}>
                        {t("sso.onlyProvider")}
                    </p>
                ) : (
                    <form onSubmit={submit}>
                        <div className="field">
                            <label htmlFor="email">{t("auth.email")}</label>
                            <input
                                id="email"
                                type="email"
                                autoComplete="username"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                required
                                autoFocus
                            />
                        </div>

                        <div className="field">
                            <label htmlFor="password">{t("auth.password")}</label>
                            <input
                                id="password"
                                type="password"
                                autoComplete={needsSetup ? "new-password" : "current-password"}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                            />
                            {needsSetup && <div className="hint">{t("auth.passwordHint")}</div>}
                        </div>

                        {needsSetup && (
                            <div className="field">
                                <label htmlFor="confirm">{t("auth.confirmPassword")}</label>
                                <input
                                    id="confirm"
                                    type="password"
                                    autoComplete="new-password"
                                    value={confirm}
                                    onChange={(e) => setConfirm(e.target.value)}
                                    required
                                />
                            </div>
                        )}

                        <button
                            type="submit"
                            className="btn-primary"
                            disabled={busy}
                            style={{ width: "100%" }}
                        >
                            {busy
                                ? t("common.working")
                                : needsSetup
                                  ? t("auth.createAccount")
                                  : t("auth.signInTitle")}
                        </button>
                    </form>
                )}
            </Card>
        </div>
    );
}
