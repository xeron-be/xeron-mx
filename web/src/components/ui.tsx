import type { ReactNode } from "react";

export function Pill({
    tone,
    children,
}: {
    tone: "ok" | "warn" | "bad" | "mute";
    children: ReactNode;
}) {
    return <span className={`pill pill-${tone}`}>{children}</span>;
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
    return <div className={`card ${className}`}>{children}</div>;
}

export function Stat({
    label,
    value,
    note,
}: {
    label: string;
    value: ReactNode;
    note?: ReactNode;
}) {
    return (
        <Card>
            <div className="stat-label">{label}</div>
            <div className="stat-value">{value}</div>
            {note && <div className="stat-note">{note}</div>}
        </Card>
    );
}

export function Alert({
    tone = "bad",
    children,
}: {
    tone?: "ok" | "warn" | "bad";
    children: ReactNode;
}) {
    return <div className={`alert alert-${tone}`}>{children}</div>;
}

export function Empty({ title, hint }: { title: string; hint?: ReactNode }) {
    return (
        <div className="empty">
            <div style={{ fontWeight: 550, marginBottom: ".35rem" }}>{title}</div>
            {hint && <div style={{ fontSize: ".88rem" }}>{hint}</div>}
        </div>
    );
}

export function PageHead({
    title,
    subtitle,
    actions,
}: {
    title: string;
    subtitle?: ReactNode;
    actions?: ReactNode;
}) {
    return (
        <div className="page-head">
            <div>
                <h1>{title}</h1>
                {subtitle && <p>{subtitle}</p>}
            </div>
            {actions && <div className="row">{actions}</div>}
        </div>
    );
}
