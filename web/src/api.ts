import { translateApiError } from "./i18n";

const BASE = "/api/v1";

export class ApiError extends Error {
    constructor(
        message: string,
        readonly status: number,
    ) {
        super(message);
    }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const res = await fetch(BASE + path, {
        ...init,
        headers: {
            ...(init.body ? { "Content-Type": "application/json" } : {}),
            ...init.headers,
        },
        credentials: "same-origin",
    });

    if (res.status === 204) return undefined as T;

    let body: unknown;
    const text = await res.text();
    try {
        body = text ? JSON.parse(text) : {};
    } catch {
        body = { error: text || res.statusText };
    }

    if (!res.ok) {
        const raw =
            typeof body === "object" && body !== null && "error" in body
                ? String((body as { error: unknown }).error)
                : "";
        const message = translateApiError(raw) || raw || `Request failed (${res.status})`;
        throw new ApiError(message, res.status);
    }
    return body as T;
}

const post = <T,>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });

export interface SetupStatus {
    needs_setup: boolean;
    version: string;
    password_login: boolean;
    oidc: { enabled: boolean; ready?: boolean };
}

export interface User {
    id: number;
    email: string;
    role: "admin" | "operator" | "viewer";
    allowed_domains?: string[];
    last_login_at?: string | null;
    from_directory?: boolean;
    has_password?: boolean;
}

export interface UserAccount {
    id: number;
    email: string;
    role: "admin" | "operator" | "viewer";
    allowed_domains?: string[];
    has_password: boolean;
    is_sso: boolean;
    created_at: string;
    last_login_at?: string | null;
}

export interface ApiToken {
    id: number;
    name: string;
    prefix: string;
    role: "admin" | "viewer";
    created_at: string;
    expires_at?: string | null;
    last_used_at?: string | null;
    expired: boolean;
}

export interface Webhook {
    id: number;
    name: string;
    url: string;
    events: string[];
    enabled: boolean;
    signed: boolean;
    created_at: string;
    last_error?: string;
    last_success_at?: string | null;
}

export interface Delivery {
    id: number;
    webhook_id: number;
    webhook_name: string;
    event: string;
    status: "pending" | "delivered" | "failed";
    attempts: number;
    status_code?: number;
    last_error?: string;
    created_at: string;
    next_attempt_at?: string | null;
    delivered_at?: string | null;
}

export interface EventCategory {
    name: string;
    types: string[];
}

export interface ClusterNode {
    node_id: string;
    advertise_url?: string;
    version?: string;
    role: "primary" | "follower";
    config_hash?: string;
    queue_pending: number;
    queue_bytes: number;
    domains: number;
    first_seen: string;
    last_seen: string;
    healthy: boolean;
    self: boolean;
    config_drift: boolean;
}

export interface ClusterState {
    enabled: boolean;
    node_id?: string;
    role?: "primary" | "follower";
    healthy_after?: number;
    nodes: ClusterNode[];
    healthy?: number;
    drifted?: number;
    queue_is_shared?: boolean;
}

export interface PrimaryState {
    is_up: boolean;
    last_check?: string | null;
    last_up?: string | null;
    last_down?: string | null;
    last_error?: string;
}

export interface Domain {
    id: number;
    name: string;
    primary_host: string;
    primary_port: number;
    primary_tls: "none" | "opportunistic" | "starttls" | "tls";
    retention_hours: number;
    max_queue_messages: number | null;
    enabled: boolean;
    created_at: string;
    primary?: PrimaryState;
    pending?: number;
    recipients_count?: number;
}

export interface DKIMInfo {
    domain: string;
    configured: boolean;
    selector?: string;
    algorithm?: string;
    enabled?: boolean;
    created_at?: string;
    record?: {
        type: string;
        name: string;
        value: string;
        note?: string;
    };
}

export interface DKIMCheckResult {
    valid: boolean;
    found: boolean;
    matched: boolean;
    record_name: string;
    records?: string[];
    status?: string;
    error?: string;
}

export interface DMARCDNSCheck {
    valid: boolean;
    found: boolean;
    record_name?: string;
    records?: string[];
    policy?: string;
    subdomain_policy?: string;
    rua?: string[];
    adkim?: string;
    aspf?: string;
    status?: string;
    error?: string;
}

export interface DMARCInfo {
    domain: string;
    record: {
        type: string;
        name: string;
        value: string;
        note?: string;
    };
    dns: DMARCDNSCheck | null;
    arc_enabled: boolean;
}

export interface SecurityStatus {
    dnsbl: {
        enabled: boolean;
        zones: string[];
    };
    clamav: {
        enabled: boolean;
        addr?: string;
        status: "online" | "offline" | "disabled";
        action?: string;
    };
    rspamd: {
        enabled: boolean;
    };
}

export interface DNSBLTestResult {
    ip: string;
    listed: boolean;
    zone?: string;
    record?: string;
    duration?: number;
    details?: {
        zone: string;
        listed: boolean;
        record?: string;
        error?: string;
    }[];
}

export interface DomainStatus {
    id: number;
    name: string;
    enabled: boolean;
    is_up: boolean;
    since?: string | null;
    pending: number;
    last_error?: string;
    last_check?: string | null;
}

export interface Status {
    version: string;
    commit: string;
    draining?: boolean;
    disk?: {
        min_free_bytes: number;
        guard_enabled: boolean;
        available_bytes?: number;
        is_low?: boolean;
    };
    queue: {
        pending: number;
        pending_bytes: number;
        total: number;
        max_messages: number;
        max_bytes: number;
        retention: string;
    };
    domains: DomainStatus[];
    all_primaries_up: boolean;
    dashboards_watching: number;
    quarantined: number;
    tls?: {
        source: "acme" | "self-signed";
        domain: string;
        since: string;
        last_error?: string;
    };
}

export interface Filter {
    id: number;
    name: string;
    field: "from" | "to" | "subject";
    pattern: string;
    action: "reject" | "quarantine" | "allow";
    enabled: boolean;
    priority: number;
    match_count: number;
    last_match_at?: string | null;
    created_at: string;
}

export interface FilterTestResult {
    matched: boolean;
    filter?: string;
    id?: number;
    field?: string;
    action?: string;
    value?: string;
    reason?: string;
}

export interface SMTPUser {
    id: number;
    username: string;
    allowed_domains: string[];
    enabled: boolean;
    created_at: string;
    last_used_at?: string | null;
}

export interface Message {
    quarantined_at?: string | null;
    quarantine_reason?: string;
    id: string;
    domain_id: number;
    from: string;
    to: string[];
    subject: string;
    size_bytes: number;
    received_at: string;
    expires_at: string;
    status: "queued" | "delivering" | "delivered" | "failed" | "expired";
    attempts: number;
    next_retry_at: string;
    last_error: string;
    delivered_at?: string | null;
    received_from: string;
    direction: "inbound" | "outbound";
    spam_action?: string;
    spam_score?: number | null;
    auth_results?: string;
    sender_authenticated?: boolean;
    malware_scan?: string;
}

export interface TimelineEvent {
    id: number;
    type: string;
    domain_id?: number | null;
    queue_id?: string | null;
    data?: Record<string, unknown>;
    created_at: string;
}

export interface DnsRecord {
    type: string;
    name: string;
    value: string;
    priority?: string;
    note?: string;
}

export interface DnsGuide {
    records: DnsRecord[];
    checklist: string[];
}

export interface ProbeResult {
    reachable: boolean;
    took_ms: number;
    error?: string;
    hint?: string;
}

export interface DomainInput {
    name?: string;
    primary_host?: string;
    primary_port?: number;
    primary_tls?: string;
    retention_hours?: number;
    enabled?: boolean;
}

export const api = {
    setupStatus: () => request<SetupStatus>("/setup"),
    setup: (email: string, password: string) => post<User>("/setup", { email, password }),

    login: (email: string, password: string) => post<User>("/auth/login", { email, password }),
    logout: () => post<{ status: string }>("/auth/logout"),
    me: () => request<User>("/auth/me"),

    status: () => request<Status>("/status"),

    listDomains: () => request<{ domains: Domain[] }>("/domains"),
    createDomain: (input: DomainInput) => post<Domain>("/domains", input),
    updateDomain: (id: number, input: DomainInput) =>
        request<Domain>(`/domains/${id}`, { method: "PATCH", body: JSON.stringify(input) }),
    deleteDomain: (id: number, force = false) =>
        request<{ deleted: string }>(`/domains/${id}${force ? "?force=true" : ""}`, {
            method: "DELETE",
        }),
    testDomain: (id: number) => post<ProbeResult>(`/domains/${id}/test`),
    domainDns: (id: number) => request<DnsGuide>(`/domains/${id}/dns`),
    getDKIM: (id: number) => request<DKIMInfo>(`/domains/${id}/dkim`),
    checkDKIM: (id: number) =>
        request<DKIMCheckResult>(`/domains/${id}/dkim/check`, { method: "POST" }),
    createDKIM: (id: number, body?: { selector?: string; algorithm?: string }) =>
        post<DKIMInfo>(`/domains/${id}/dkim`, body ?? {}),
    updateDKIM: (id: number, enabled: boolean, force = false) =>
        request<DKIMInfo>(`/domains/${id}/dkim`, {
            method: "PATCH",
            body: JSON.stringify({ enabled, force }),
        }),
    deleteDKIM: (id: number) =>
        request<{ status: string }>(`/domains/${id}/dkim`, { method: "DELETE" }),
    getRecipients: (id: number) => request<{ recipients: string[] }>(`/domains/${id}/recipients`),
    setRecipients: (id: number, recipients: string[]) =>
        request<{ recipients: string[] }>(`/domains/${id}/recipients`, {
            method: "PUT",
            body: JSON.stringify({ recipients }),
        }),
    getDMARC: (id: number) => request<DMARCInfo>(`/domains/${id}/dmarc`),
    checkDMARC: (id: number) =>
        request<DMARCDNSCheck>(`/domains/${id}/dmarc/check`, { method: "POST" }),

    listQueue: (
        params: {
            status?: string;
            domain_id?: number;
            direction?: string;
            limit?: number;
            quarantined?: boolean;
        } = {},
    ) => {
        const q = new URLSearchParams();
        if (params.status) q.set("status", params.status);
        if (params.domain_id) q.set("domain_id", String(params.domain_id));
        if (params.direction) q.set("direction", params.direction);
        if (params.limit) q.set("limit", String(params.limit));
        if (params.quarantined !== undefined) q.set("quarantined", String(params.quarantined));
        const suffix = q.toString() ? `?${q}` : "";
        return request<{ messages: Message[]; count: number }>(`/queue${suffix}`);
    },
    retryMessage: (id: string) => post<{ status: string }>(`/queue/${id}/retry`),
    deleteMessage: (id: string) =>
        request<{ deleted: string }>(`/queue/${id}`, { method: "DELETE" }),
    rawMessageUrl: (id: string) => `${BASE}/queue/${id}/raw`,
    releaseMessage: (id: string) => post<{ released: string }>(`/queue/${id}/release`),

    listFilters: () => request<{ filters: Filter[] }>("/filters"),
    createFilter: (f: {
        name: string;
        field: string;
        pattern: string;
        action: string;
        priority?: number;
    }) => post<Filter>("/filters", f),
    updateFilter: (id: number, changes: Partial<Filter>) =>
        request<Filter>(`/filters/${id}`, {
            method: "PATCH",
            body: JSON.stringify(changes),
        }),
    deleteFilter: (id: number) =>
        request<{ deleted: number }>(`/filters/${id}`, { method: "DELETE" }),
    testFilters: (body: {
        from?: string;
        to?: string[];
        subject?: string;
        pattern?: string;
        field?: string;
    }) => post<FilterTestResult>("/filters/test", body),

    listEvents: (limit = 100) => request<{ events: TimelineEvent[] }>(`/events?limit=${limit}`),

    listSMTPUsers: () => request<{ accounts: SMTPUser[] }>("/smtp-users"),
    createSMTPUser: (username: string, password: string, allowedDomains: string[]) =>
        post<SMTPUser>("/smtp-users", {
            username,
            password,
            allowed_domains: allowedDomains,
        }),
    updateSMTPUser: (id: number, enabled: boolean) =>
        request<{ id: number }>(`/smtp-users/${id}`, {
            method: "PATCH",
            body: JSON.stringify({ enabled }),
        }),
    deleteSMTPUser: (id: number) =>
        request<{ deleted: number }>(`/smtp-users/${id}`, { method: "DELETE" }),

    listTokens: () => request<{ tokens: ApiToken[] }>("/tokens"),
    createToken: (body: { name: string; role: string; expires_in?: string }) =>
        post<{ token: ApiToken; secret: string; notice: string }>("/tokens", body),
    deleteToken: (id: number) =>
        request<{ deleted: number }>(`/tokens/${id}`, { method: "DELETE" }),

    listUsers: () => request<{ users: UserAccount[] }>("/users"),
    createUser: (body: { email: string; role: string; password?: string; allowed_domains?: string[] }) =>
        post<UserAccount>("/users", body),
    updateUser: (id: number, body: { role?: string; allowed_domains?: string[] }) =>
        request<UserAccount>(`/users/${id}`, {
            method: "PATCH",
            body: JSON.stringify(body),
        }),
    updateUserRole: (id: number, role: string) =>
        request<UserAccount>(`/users/${id}`, {
            method: "PATCH",
            body: JSON.stringify({ role }),
        }),
    deleteUser: (id: number) =>
        request<{ ok: boolean }>(`/users/${id}`, { method: "DELETE" }),

    listWebhooks: () => request<{ webhooks: Webhook[]; enabled: boolean }>("/webhooks"),
    webhookEventTypes: () =>
        request<{ categories: EventCategory[] }>("/webhooks/events"),
    createWebhook: (body: {
        name: string;
        url: string;
        events: string[];
        secret?: string | null;
    }) => post<{ webhook: Webhook; secret?: string; notice?: string }>("/webhooks", body),
    updateWebhook: (id: number, changes: Record<string, unknown>) =>
        request<{ webhook: Webhook; secret?: string }>(`/webhooks/${id}`, {
            method: "PATCH",
            body: JSON.stringify(changes),
        }),
    deleteWebhook: (id: number) =>
        request<{ deleted: number }>(`/webhooks/${id}`, { method: "DELETE" }),
    testWebhook: (id: number) =>
        post<{ ok: boolean; status: number; error?: string }>(`/webhooks/${id}/test`),
    listDeliveries: (webhookId?: number, limit = 30) => {
        const q = new URLSearchParams({ limit: String(limit) });
        if (webhookId) q.set("webhook_id", String(webhookId));
        return request<{ deliveries: Delivery[] }>(`/webhooks/deliveries?${q}`);
    },

    cluster: () => request<ClusterState>("/cluster"),
    forgetNode: (id: string) =>
        request<{ forgotten: string }>(`/cluster/nodes/${encodeURIComponent(id)}`, {
            method: "DELETE",
        }),

    getSecurityStatus: () => request<SecurityStatus>("/security/status"),
    testDNSBL: (ip: string) => post<DNSBLTestResult>("/security/dnsbl/test", { ip }),

    getDrain: () =>
        request<{ draining: boolean; pending: number; pending_bytes: number }>("/maintenance/drain"),
    setDrain: (enabled: boolean) =>
        post<{ draining: boolean; pending: number; pending_bytes: number }>("/maintenance/drain", { enabled }),
};

export const ssoLoginURL = `${BASE}/auth/oidc/login`;

export function subscribeLive(onEvent: (type: string) => void): () => void {
    const source = new EventSource(`${BASE}/live`);
    source.onmessage = (e) => {
        try {
            const parsed = JSON.parse(e.data) as { type?: string };
            if (parsed.type) onEvent(parsed.type);
        } catch {
        }
    };
    return () => source.close();
}
