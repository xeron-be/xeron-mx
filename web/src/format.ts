import { locale, t } from "./i18n";
import type { TranslationKey } from "./locales/en";

export function bytes(n: number): string {
    if (n < 1024) return `${n} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let value = n / 1024;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) {
        value /= 1024;
        i++;
    }
    return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
}

export function relative(iso?: string | null): string {
    if (!iso) return t("common.never");
    const then = new Date(iso).getTime();
    if (Number.isNaN(then)) return t("common.unknown");

    const seconds = Math.round((Date.now() - then) / 1000);
    const future = seconds < 0;
    const s = Math.abs(seconds);

    if (s < 45) return future ? t("time.now") : t("time.justNow");

    let value: string;
    if (s < 90) value = t("time.minutes", { n: 1 });
    else if (s < 3600) value = t("time.minutes", { n: Math.round(s / 60) });
    else if (s < 86400) value = t("time.hours", { n: Math.round(s / 3600) });
    else value = t("time.days", { n: Math.round(s / 86400) });

    return future ? t("time.in", { value }) : t("time.ago", { value });
}

export function absolute(iso?: string | null): string {
    if (!iso) return "—";
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString(locale());
}

export function duration(seconds: number): string {
    if (seconds < 60) return t("time.seconds", { n: Math.round(seconds) });
    if (seconds < 3600) return t("time.minutes", { n: Math.round(seconds / 60) });
    if (seconds < 86400) return t("time.hours", { n: (seconds / 3600).toFixed(1) });
    return t("time.days", { n: (seconds / 86400).toFixed(1) });
}

const EVENT_KEYS: Record<string, TranslationKey> = {
    mail_received: "ev.mail_received",
    mail_delivered: "ev.mail_delivered",
    mail_deferred: "ev.mail_deferred",
    mail_failed: "ev.mail_failed",
    mail_expired: "ev.mail_expired",
    mail_rejected: "ev.mail_rejected",
    mail_quarantined: "ev.mail_quarantined",
    mail_released: "ev.mail_released",
    filter_created: "ev.filter_created",
    filter_deleted: "ev.filter_deleted",
    primary_up: "ev.primary_up",
    primary_down: "ev.primary_down",
    queue_full: "ev.queue_full",
    admin_read_message: "ev.admin_read_message",
    admin_delete_message: "ev.admin_delete_message",
    admin_retry_message: "ev.admin_retry_message",
    domain_added: "ev.domain_added",
    domain_deleted: "ev.domain_deleted",
    smtp_user_created: "ev.smtp_user_created",
    smtp_user_deleted: "ev.smtp_user_deleted",
    config_imported: "ev.config_imported",
    api_token_created: "ev.api_token_created",
    api_token_deleted: "ev.api_token_deleted",
    webhook_created: "ev.webhook_created",
    webhook_updated: "ev.webhook_updated",
    webhook_deleted: "ev.webhook_deleted",
    route_created: "ev.route_created",
    route_deleted: "ev.route_deleted",
    dkim_key_created: "ev.dkim_key_created",
    dkim_key_deleted: "ev.dkim_key_deleted",
    cluster_config_synced: "ev.cluster_config_synced",
    login: "ev.login",
    login_failed: "ev.login_failed",
    startup: "ev.startup",
};

export function eventLabel(type: string): string {
    const key = EVENT_KEYS[type];
    return key ? t(key) : type.replace(/_/g, " ");
}

export function eventTone(type: string): "ok" | "warn" | "bad" | "mute" {
    if (type === "primary_down" || type === "mail_failed" || type === "mail_expired") return "bad";
    if (type === "queue_full" || type === "mail_deferred" || type === "login_failed") return "warn";
    if (type === "mail_quarantined" || type === "mail_rejected") return "warn";
    if (type === "mail_released") return "ok";
    if (type === "primary_up" || type === "mail_delivered") return "ok";
    return "mute";
}

const STATUS_KEYS: Record<string, TranslationKey> = {
    queued: "queue.waiting",
    delivering: "queue.delivering",
    delivered: "queue.delivered",
    failed: "queue.failed",
    expired: "queue.expired",
};

export function statusLabel(status: string): string {
    const key = STATUS_KEYS[status];
    return key ? t(key) : status;
}

export function statusTone(status: string): "ok" | "warn" | "bad" | "mute" {
    switch (status) {
        case "delivered":
            return "ok";
        case "queued":
        case "delivering":
            return "warn";
        case "failed":
        case "expired":
            return "bad";
        default:
            return "mute";
    }
}
