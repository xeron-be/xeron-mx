import { useCallback, useEffect, useState } from "react";
import { ApiError, api, subscribeLive, type Status, type User } from "./api";
import { LANGUAGES, setLang, useLang, useT, type Lang } from "./i18n";
import type { TranslationKey } from "./locales/en";
import { Auth } from "./pages/Auth";
import { Cluster } from "./pages/Cluster";
import { Dashboard } from "./pages/Dashboard";
import { Domains } from "./pages/Domains";
import { Events } from "./pages/Events";
import { Filters } from "./pages/Filters";
import { Queue } from "./pages/Queue";
import { Sending } from "./pages/Sending";
import { Settings } from "./pages/Settings";

type Tab =
    | "overview"
    | "domains"
    | "queue"
    | "filters"
    | "sending"
    | "cluster"
    | "settings"
    | "events";

const TABS: { key: Tab; label: TranslationKey }[] = [
    { key: "overview", label: "nav.overview" },
    { key: "domains", label: "nav.domains" },
    { key: "queue", label: "nav.queue" },
    { key: "filters", label: "nav.filters" },
    { key: "sending", label: "nav.sending" },
    { key: "cluster", label: "nav.cluster" },
    { key: "settings", label: "nav.settings" },
    { key: "events", label: "nav.timeline" },
];

export function App() {
    const t = useT();
    const [user, setUser] = useState<User | null>(null);
    const [needsSetup, setNeedsSetup] = useState(false);
    const [booting, setBooting] = useState(true);
    const [tab, setTab] = useState<Tab>("overview");
    const [refreshKey, setRefreshKey] = useState(0);
    const [pending, setPending] = useState(0);
    // The fleet view is only meaningful when peers exist, so the tab appears
    // only once clustering is switched on. A tab that always says "off" is a
    // tab that gets ignored, including on the day it stops saying that.
    const [clustered, setClustered] = useState(false);

    const refresh = useCallback(() => setRefreshKey((n) => n + 1), []);

    useEffect(() => {
        (async () => {
            try {
                const me = await api.me();
                setUser(me);
            } catch {
                try {
                    const status = await api.setupStatus();
                    setNeedsSetup(status.needs_setup);
                } catch {
                }
            } finally {
                setBooting(false);
            }
        })();
    }, []);

    useEffect(() => {
        if (!user) return;
        return subscribeLive(() => refresh());
    }, [user, refresh]);

    useEffect(() => {
        if (!user) return;
        api.cluster()
            .then((c) => setClustered(c.enabled))
            .catch(() => setClustered(false));
    }, [user]);

    useEffect(() => {
        if (!user) return;
        let alive = true;
        const load = () =>
            api
                .status()
                .then((s: Status) => {
                    if (alive) setPending(s.queue.pending);
                })
                .catch(() => {});
        load();
        const timer = setInterval(load, 30_000);
        return () => {
            alive = false;
            clearInterval(timer);
        };
    }, [user, refreshKey]);

    async function signOut() {
        try {
            await api.logout();
        } catch {
        }
        setUser(null);
        setNeedsSetup(false);
    }

    if (booting) {
        return <div className="empty" style={{ paddingTop: "20vh" }}>{t("common.loading")}</div>;
    }

    if (!user) {
        return (
            <Auth
                needsSetup={needsSetup}
                onAuthenticated={(u) => {
                    setUser(u);
                    setNeedsSetup(false);
                    refresh();
                }}
            />
        );
    }

    const isAdmin = user.role === "admin";
    const isOperator = user.role === "admin" || user.role === "operator";

    return (
        <div className="shell">
            <nav className="sidebar">
                <div className="brand">XeronMX</div>
                {TABS.filter((tabDef) => {
                    if (tabDef.key === "cluster" && !clustered) return false;
                    if (tabDef.key === "settings" && !isAdmin) return false;
                    return true;
                }).map((tabDef) => (
                    <button
                        key={tabDef.key}
                        className="nav-item"
                        aria-current={tab === tabDef.key ? "page" : undefined}
                        onClick={() => setTab(tabDef.key)}
                    >
                        {t(tabDef.label)}
                        {tabDef.key === "queue" && pending > 0 && (
                            <span className="badge">{pending}</span>
                        )}
                    </button>
                ))}
                <div className="sidebar-footer">
                    <div style={{ marginBottom: ".4rem", wordBreak: "break-all" }}>{user.email}</div>
                    {user.allowed_domains && user.allowed_domains.length > 0 && (
                        <div style={{ marginBottom: ".4rem", fontSize: "0.8em", opacity: 0.85 }}>
                            {user.allowed_domains.join(", ")}
                        </div>
                    )}
                    <LanguagePicker />
                    <button className="btn-sm" onClick={signOut}>
                        {t("nav.signOut")}
                    </button>
                </div>
            </nav>

            <main className="main">
                <ErrorBoundaryless>
                    {tab === "overview" && <Dashboard refreshKey={refreshKey} />}
                    {tab === "domains" && (
                        <Domains refreshKey={refreshKey} canEdit={isAdmin} canTest={isOperator} onChanged={refresh} />
                    )}
                    {tab === "queue" && (
                        <Queue refreshKey={refreshKey} canEdit={isOperator} onChanged={refresh} />
                    )}
                    {tab === "filters" && (
                        <Filters refreshKey={refreshKey} canEdit={isAdmin} onChanged={refresh} />
                    )}
                    {tab === "sending" && (
                        <Sending refreshKey={refreshKey} canEdit={isAdmin} onChanged={refresh} />
                    )}
                    {tab === "cluster" && (
                        <Cluster refreshKey={refreshKey} canEdit={isAdmin} onChanged={refresh} />
                    )}
                    {tab === "settings" && (
                        <Settings
                            refreshKey={refreshKey}
                            canEdit={isAdmin}
                            currentUserEmail={user.email}
                            onChanged={refresh}
                        />
                    )}
                    {tab === "events" && <Events refreshKey={refreshKey} />}
                </ErrorBoundaryless>
            </main>
        </div>
    );
}

function LanguagePicker() {
    const t = useT();
    const lang = useLang();
    return (
        <label className="lang-picker">
            <span className="visually-hidden">{t("nav.language")}</span>
            <select
                value={lang}
                aria-label={t("nav.language")}
                onChange={(e) => setLang(e.target.value as Lang)}
            >
                {LANGUAGES.map((l) => (
                    <option key={l.code} value={l.code}>
                        {l.label}
                    </option>
                ))}
            </select>
        </label>
    );
}

function ErrorBoundaryless({ children }: { children: React.ReactNode }) {
    useEffect(() => {
        const onRejection = (e: PromiseRejectionEvent) => {
            if (e.reason instanceof ApiError && e.reason.status === 401) {
                window.location.reload();
            }
        };
        window.addEventListener("unhandledrejection", onRejection);
        return () => window.removeEventListener("unhandledrejection", onRejection);
    }, []);
    return <>{children}</>;
}
