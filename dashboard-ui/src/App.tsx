import { useCallback, useEffect, useMemo, useState } from "react";
import type { ChangeEvent, KeyboardEvent } from "react";
import {
  AlertEvidence,
  AlertSummary,
  asRecord,
  asText,
  DetectionMatch,
  getSeverity,
  readableTime,
  relativeTime,
  TriageRecord,
  TriageState,
} from "./types";

const TRIAGE_STORAGE_KEY = "sentinelforge.triage.v1";
const PAGE_SIZE = 12;

type TriageMap = Record<string, TriageRecord>;
type LoadState = "loading" | "ready" | "error";

function readTriage(): TriageMap {
  try {
    const stored = window.localStorage.getItem(TRIAGE_STORAGE_KEY);
    if (!stored) return {};
    const parsed: unknown = JSON.parse(stored);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const records: TriageMap = {};
    for (const [eventId, value] of Object.entries(parsed)) {
      if (value === null || typeof value !== "object" || Array.isArray(value)) continue;
      const record = value as Record<string, unknown>;
      if (!["open", "investigating", "resolved"].includes(String(record.state))) continue;
      records[eventId] = {
        state: record.state as TriageState,
        note: typeof record.note === "string" ? record.note : "",
        updated_at: typeof record.updated_at === "string" ? record.updated_at : "",
      };
    }
    return records;
  } catch (error) {
    console.warn("Could not read local investigation notes.", error);
    return {};
  }
}

function persistTriage(records: TriageMap): void {
  try {
    window.localStorage.setItem(TRIAGE_STORAGE_KEY, JSON.stringify(records));
  } catch (error) {
    console.warn("Could not save local investigation notes.", error);
  }
}

function Metric({
  label,
  value,
  detail,
  tone = "",
}: {
  label: string;
  value: number;
  detail: string;
  tone?: string;
}) {
  return (
    <article className={`metric-card ${tone}`}>
      <div className="metric-top">
        <span>{label}</span>
        <span className="metric-dot" aria-hidden="true" />
      </div>
      <strong>{value.toLocaleString()}</strong>
      <small>{detail}</small>
    </article>
  );
}

function SeverityPill({ severity }: { severity: string }) {
  const known = ["critical", "high", "medium", "low", "informational"].includes(severity);
  const normalized = known ? severity : "unknown";
  return <span className={`severity-pill ${normalized}`}>{severity}</span>;
}

function StatePill({ state }: { state: TriageState }) {
  return <span className={`state-pill ${state}`}>{state}</span>;
}

function Distribution({ alerts }: { alerts: AlertSummary[] }) {
  const values = ["critical", "high", "medium", "low", "informational"].map((severity) => ({
    severity,
    count: alerts.filter((alert) => getSeverity(alert) === severity).length,
  }));
  const max = Math.max(1, ...values.map(({ count }) => count));
  return (
    <div className="distribution">
      {values.map(({ severity, count }) => (
        <div className="distribution-row" key={severity}>
          <span className={`legend-dot ${severity}`} />
          <span className="distribution-name">{severity}</span>
          <div className="distribution-track">
            <span className={severity} style={{ width: `${(count / max) * 100}%` }} />
          </div>
          <span className="distribution-count">{count}</span>
        </div>
      ))}
    </div>
  );
}

function Trend({ alerts }: { alerts: AlertSummary[] }) {
  const days = useMemo(() => {
    const result = Array.from({ length: 7 }, (_, index) => {
      const date = new Date();
      date.setHours(0, 0, 0, 0);
      date.setDate(date.getDate() - (6 - index));
      return { key: date.toISOString().slice(0, 10), label: date.toLocaleDateString(undefined, { weekday: "short" }), count: 0 };
    });
    for (const alert of alerts) {
      const timestamp = new Date(alert.timestamp);
      if (Number.isNaN(timestamp.getTime())) continue;
      const key = timestamp.toISOString().slice(0, 10);
      const target = result.find((item) => item.key === key);
      if (target) target.count += 1;
    }
    return result;
  }, [alerts]);
  const max = Math.max(1, ...days.map(({ count }) => count));
  return (
    <div className="trend-chart" aria-label="Alert count for the last seven days">
      {days.map((day) => (
        <div className="trend-column" key={day.key} title={`${day.count} alerts`}>
          <span className="trend-count">{day.count || ""}</span>
          <div className="trend-track">
            <span style={{ height: `${Math.max(4, (day.count / max) * 100)}%` }} />
          </div>
          <span className="trend-label">{day.label}</span>
        </div>
      ))}
    </div>
  );
}

function AlertInvestigation({
  alert,
  triage,
  onStateChange,
  onNoteChange,
  onClose,
}: {
  alert: AlertSummary;
  triage: TriageRecord;
  onStateChange: (state: TriageState) => void;
  onNoteChange: (note: string) => void;
  onClose: () => void;
}) {
  const [evidence, setEvidence] = useState<AlertEvidence | null>(null);
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [loadError, setLoadError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    setEvidence(null);
    setLoadState("loading");
    setLoadError("");
    fetch(`/v1/alerts/${encodeURIComponent(alert.event_id)}`, {
      cache: "no-store",
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(response.status === 404 ? "Evidence was not found in the event store." : `Evidence service returned ${response.status}.`);
        }
        return (await response.json()) as AlertEvidence;
      })
      .then((data) => {
        if (!data || !data.event || !Array.isArray(data.matches)) {
          throw new Error("Evidence service returned an invalid record.");
        }
        setEvidence(data);
        setLoadState("ready");
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setLoadError(error instanceof Error ? error.message : "Could not load evidence.");
        setLoadState("error");
      });
    return () => controller.abort();
  }, [alert.event_id]);

  useEffect(() => {
    function closeOnEscape(event: Event) {
      if (event instanceof window.KeyboardEvent && event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  const event = evidence?.event ?? {};
  const host = asRecord(event.host);
  const process = asRecord(event.process);
  const user = asRecord(event.user);
  const network = asRecord(event.network);
  const file = asRecord(event.file);
  const authentication = asRecord(event.authentication);
  const matches = evidence?.matches ?? [];

  async function copyEventId() {
    try {
      await navigator.clipboard.writeText(alert.event_id);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch (error) {
      console.warn("Could not copy event ID.", error);
      setCopied(false);
    }
  }

  function downloadEvidence() {
    if (!evidence) return;
    const blob = new Blob([JSON.stringify(evidence, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sentinelforge-${alert.event_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="drawer-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside className="investigation-drawer" role="dialog" aria-modal="true" aria-labelledby="investigation-title">
        <div className="drawer-header">
          <div>
            <div className="eyebrow">Alert investigation</div>
            <h2 id="investigation-title">Evidence &amp; triage</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close investigation">×</button>
        </div>
        <div className="drawer-scroll">
          <section className="drawer-alert">
            <div className="drawer-alert-top">
              <SeverityPill severity={getSeverity(alert)} />
              <StatePill state={triage.state} />
              <span className="quiet">{relativeTime(alert.timestamp)}</span>
            </div>
            <h3>{alert.rule_titles?.filter(Boolean).join(", ") || "Detection matched"}</h3>
            <div className="event-id-line">
              <code>{alert.event_id}</code>
              <button className="text-button" onClick={copyEventId}>{copied ? "Copied" : "Copy ID"}</button>
            </div>
            <div className="drawer-meta">
              <span><small>Host</small><strong>{alert.host_id || "Unknown host"}</strong></span>
              <span><small>Observed</small><strong>{readableTime(alert.timestamp)}</strong></span>
              <span><small>Rule matches</small><strong>{alert.match_count}</strong></span>
            </div>
          </section>

          <section className="drawer-section">
            <div className="section-heading">
              <div><h3>Investigation state</h3><p>Changes and notes are stored in this browser only.</p></div>
            </div>
            <label className="field-label" htmlFor="triage-state">Workflow</label>
            <select id="triage-state" className="state-select" value={triage.state} onChange={(event) => onStateChange(event.target.value as TriageState)}>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
            </select>
            <label className="field-label" htmlFor="analyst-note">Analyst notes</label>
            <textarea id="analyst-note" rows={4} value={triage.note} onChange={(event) => onNoteChange(event.target.value)} placeholder="Record context, pivots, and next steps…" />
            <div className="note-updated">{triage.updated_at ? `Saved locally · ${readableTime(triage.updated_at)}` : "Notes remain on this device."}</div>
          </section>

          <section className="drawer-section">
            <div className="section-heading">
              <div><h3>Detection matches</h3><p>Rule metadata from the stored alert.</p></div>
            </div>
            {matches.length ? matches.map((match: DetectionMatch, index) => (
              <article className="match-card" key={`${match.rule_id || match.title}-${index}`}>
                <div className="match-heading"><strong>{match.title || "Untitled rule"}</strong><SeverityPill severity={String(match.level || "unknown").toLowerCase()} /></div>
                {match.description && <p>{match.description}</p>}
                <div className="match-foot">
                  <code>{match.rule_id || "Rule ID unavailable"}</code>
                  <span>{(match.tags || []).join(" · ")}</span>
                </div>
              </article>
            )) : <div className="quiet-block">No rule metadata is available.</div>}
          </section>

          <section className="drawer-section">
            <div className="section-heading">
              <div><h3>Event context</h3><p>Fields are shown as received; missing telemetry is not inferred.</p></div>
              {evidence && <button className="text-button" onClick={downloadEvidence}>Export JSON</button>}
            </div>
            {loadState === "loading" && <div className="quiet-block">Loading stored event evidence…</div>}
            {loadState === "error" && <div className="inline-error">{loadError}</div>}
            {loadState === "ready" && (
              <>
                <div className="context-grid">
                  <ContextField label="Category / action" value={`${asText(event.category, "Unknown")} / ${asText(event.action, "Unknown")}`} />
                  <ContextField label="Platform" value={`${asText(host.os, "Unknown OS")} ${asText(host.os_version, "")}`.trim()} />
                  <ContextField label="Process" value={asText(process.name, asText(process.path))} />
                  <ContextField label="Command line" value={asText(process.command_line)} />
                  <ContextField label="User" value={asText(user.name)} />
                  <ContextField label="Parent process" value={asText(asRecord(process.parent).name)} />
                  <ContextField label="Network" value={network.remote_address ? `${asText(network.remote_address)}:${asText(network.remote_port, "")}` : "—"} />
                  <ContextField label="File" value={asText(file.path)} />
                  <ContextField label="Authentication" value={asText(authentication.result, asText(authentication.logon_type))} />
                  <ContextField label="Sensor" value={`${asText(asRecord(event.raw).source, "Unknown")} · ${asText(asRecord(event.raw).provider, "Unknown provider")}`} />
                </div>
                <details className="raw-evidence">
                  <summary>Full event payload</summary>
                  <pre>{JSON.stringify(event, null, 2)}</pre>
                </details>
              </>
            )}
          </section>
        </div>
      </aside>
    </div>
  );
}

function ContextField({ label, value }: { label: string; value: string }) {
  return <div className="context-field"><small>{label}</small><span title={value}>{value}</span></div>;
}

export default function App() {
  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [loadError, setLoadError] = useState("");
  const [lastUpdated, setLastUpdated] = useState("");
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [stateFilter, setStateFilter] = useState("all");
  const [page, setPage] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [triage, setTriage] = useState<TriageMap>(readTriage);
  const [refreshing, setRefreshing] = useState(false);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setRefreshing(true);
    try {
      const response = await fetch("/v1/alerts?limit=100", { cache: "no-store", signal });
      if (!response.ok) throw new Error(response.status === 403 ? "Alert data is available from this machine only." : `Alert service returned ${response.status}.`);
      const data: unknown = await response.json();
      if (!Array.isArray(data) || data.some((alert) =>
        alert === null ||
        typeof alert !== "object" ||
        typeof alert.event_id !== "string" ||
        typeof alert.timestamp !== "string" ||
        typeof alert.host_id !== "string" ||
        typeof alert.match_count !== "number" ||
        !Array.isArray(alert.levels) ||
        !Array.isArray(alert.rule_ids) ||
        !Array.isArray(alert.rule_titles)
      )) {
        throw new Error("Alert service returned an invalid response.");
      }
      setAlerts(data as AlertSummary[]);
      setLoadState("ready");
      setLoadError("");
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
      setLoadState("error");
      setLoadError(error instanceof Error ? error.message : "Could not load alert records.");
    } finally {
      if (!signal?.aborted) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    const timer = window.setInterval(() => void refresh(), 30_000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [refresh]);

  const selectedAlert = alerts.find((alert) => alert.event_id === selectedId) ?? null;
  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return alerts.filter((alert) => {
      const status = triage[alert.event_id]?.state ?? "open";
      const matchesSeverity = severityFilter === "all" || getSeverity(alert) === severityFilter;
      const matchesState = stateFilter === "all" || status === stateFilter;
      const text = [
        alert.host_id,
        alert.event_id,
        ...(alert.rule_titles || []),
        ...(alert.rule_ids || []),
      ].join(" ").toLowerCase();
      return matchesSeverity && matchesState && (!normalizedQuery || text.includes(normalizedQuery));
    });
  }, [alerts, query, severityFilter, stateFilter, triage]);

  useEffect(() => setPage(0), [query, severityFilter, stateFilter]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageAlerts = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const criticalCount = alerts.filter((alert) => ["critical", "high"].includes(getSeverity(alert))).length;
  const affectedHosts = new Set(alerts.map((alert) => alert.host_id).filter(Boolean)).size;
  const investigatingCount = alerts.filter((alert) => triage[alert.event_id]?.state === "investigating").length;
  const openCount = alerts.filter((alert) => (triage[alert.event_id]?.state ?? "open") === "open").length;

  function updateTriage(eventId: string, patch: Partial<TriageRecord>) {
    setTriage((current) => {
      const existing = current[eventId];
      const next = {
        ...current,
        [eventId]: {
          state: patch.state ?? existing?.state ?? "open",
          note: patch.note ?? existing?.note ?? "",
          updated_at: new Date().toISOString(),
        },
      };
      persistTriage(next);
      return next;
    });
  }

  function setFilter(event: ChangeEvent<HTMLSelectElement>, kind: "severity" | "state") {
    if (kind === "severity") setSeverityFilter(event.target.value);
    else setStateFilter(event.target.value);
  }

  function openWithKeyboard(event: KeyboardEvent<HTMLButtonElement>, alert: AlertSummary) {
    if (event.key === "Enter" || event.key === " ") setSelectedId(alert.event_id);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="/" aria-label="SentinelForge home">
          <span className="brand-mark"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.8 20 6v5.6c0 5-3.4 8.3-8 9.7-4.6-1.4-8-4.7-8-9.7V6l8-3.2Z" /><path d="m8.8 12.2 2.1 2.1 4.5-4.7" /></svg></span>
          <span>SentinelForge<small>Security operations</small></span>
        </a>
        <div className="nav-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Main navigation">
          <a className="nav-item active" href="#overview"><span className="nav-icon">◫</span>Overview</a>
          <a className="nav-item" href="#alert-queue"><span className="nav-icon">◉</span>Alert queue<span className="nav-count">{alerts.length}</span></a>
          <span className="nav-item disabled" aria-disabled="true"><span className="nav-icon">⌖</span>Incidents<span className="nav-soon">Planned</span></span>
          <span className="nav-item disabled" aria-disabled="true"><span className="nav-icon">⌘</span>Hunting<span className="nav-soon">Planned</span></span>
        </nav>
        <div className="sidebar-spacer" />
        <div className="access-card">
          <span className="access-dot" />
          <div><strong>Local analyst view</strong><small>Read-only · loopback only</small></div>
        </div>
        <div className="sidebar-foot">SENTINELFORGE <span>v0.1 · early access</span></div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div className="breadcrumb">Security operations <span>/</span> Overview</div>
          <div className="topbar-right">
            <span className="connection"><i /> Local data</span>
            <button className="refresh-button" onClick={() => void refresh()} disabled={refreshing}>
              <span className={refreshing ? "refresh-glyph spinning" : "refresh-glyph"}>↻</span>
              {refreshing ? "Refreshing" : "Refresh"}
            </button>
          </div>
        </header>

        <section className="page-heading">
          <div>
            <div className="eyebrow">Detection &amp; response</div>
            <h1>Overview</h1>
            <p>Review recent detections, validate evidence, and track local triage.</p>
          </div>
          <div className="updated-caption">Auto-refreshes every 30 seconds{lastUpdated && <span>Last updated {lastUpdated}</span>}</div>
        </section>

        {loadState === "error" && <div className="page-error" role="alert">{loadError}</div>}

        <section className="metric-grid" aria-label="Recent alert metrics">
          <Metric label="Alerts in view" value={alerts.length} detail="Latest 100 stored detections" />
          <Metric label="High priority" value={criticalCount} detail="Critical and high severity" tone="orange" />
          <Metric label="Open triage" value={openCount} detail="Not yet under investigation" tone="blue" />
          <Metric label="Hosts affected" value={affectedHosts} detail={`${investigatingCount} currently investigating`} tone="green" />
        </section>

        <section className="insight-grid" aria-label="Alert analytics">
          <article className="surface insight-card">
            <div className="card-heading"><div><h2>Severity breakdown</h2><p>Among the latest {alerts.length} detections</p></div><span className="card-mark">01</span></div>
            <Distribution alerts={alerts} />
          </article>
          <article className="surface insight-card trend-card">
            <div className="card-heading"><div><h2>Recent activity</h2><p>Alerts by day · latest records</p></div><span className="trend-total">{alerts.length}<small>events</small></span></div>
            <Trend alerts={alerts} />
          </article>
        </section>

        <section className="surface queue-panel" id="alert-queue">
          <div className="queue-heading">
            <div><div className="queue-title-line"><h2>Alert queue</h2><span className="queue-total">{filtered.length}</span></div><p>Open a detection to inspect event evidence and record triage notes.</p></div>
            <div className="filter-toolbar">
              <label className="search-box"><span aria-hidden="true">⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search alerts, hosts, rules…" aria-label="Search alerts" /></label>
              <select value={severityFilter} onChange={(event) => setFilter(event, "severity")} aria-label="Filter by severity">
                <option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Informational</option>
              </select>
              <select value={stateFilter} onChange={(event) => setFilter(event, "state")} aria-label="Filter by triage state">
                <option value="all">All states</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option>
              </select>
            </div>
          </div>
          <div className="table-scroll">
            <table className="alert-table">
              <thead><tr><th>Detection</th><th>Severity</th><th>Host</th><th>Observed</th><th>Triage</th><th aria-label="Open investigation" /></tr></thead>
              <tbody>
                {loadState === "loading" && <tr><td className="table-message" colSpan={6}>Loading recent alert records…</td></tr>}
                {loadState !== "loading" && pageAlerts.map((alert) => {
                  const state = triage[alert.event_id]?.state ?? "open";
                  return (
                    <tr key={alert.event_id}>
                      <td><button className="alert-link" onClick={() => setSelectedId(alert.event_id)} onKeyDown={(event) => openWithKeyboard(event, alert)}>
                        <strong>{alert.rule_titles?.filter(Boolean).join(", ") || "Detection matched"}</strong>
                        <small>{alert.rule_ids?.filter(Boolean).join(", ") || alert.event_id}</small>
                      </button></td>
                      <td><SeverityPill severity={getSeverity(alert)} /></td>
                      <td><span className="host-cell">{alert.host_id || "Unknown host"}</span></td>
                      <td><span className="time-cell">{relativeTime(alert.timestamp)}</span><small className="time-exact">{readableTime(alert.timestamp)}</small></td>
                      <td><StatePill state={state} /></td>
                      <td><button className="row-open" onClick={() => setSelectedId(alert.event_id)} aria-label={`Investigate ${alert.event_id}`}>→</button></td>
                    </tr>
                  );
                })}
                {loadState === "ready" && !pageAlerts.length && <tr><td className="table-message" colSpan={6}>{alerts.length ? "No detections match these filters." : "No alerts yet. Matching detections will appear here."}</td></tr>}
              </tbody>
            </table>
          </div>
          <footer className="queue-footer">
            <span>{filtered.length ? `Showing ${page * PAGE_SIZE + 1}–${Math.min((page + 1) * PAGE_SIZE, filtered.length)} of ${filtered.length}` : "No results"} · local triage notes stay in this browser</span>
            <div className="pagination">
              <button onClick={() => setPage((current) => Math.max(0, current - 1))} disabled={page === 0}>Previous</button>
              <span>{page + 1} / {pageCount}</span>
              <button onClick={() => setPage((current) => Math.min(pageCount - 1, current + 1))} disabled={page >= pageCount - 1}>Next</button>
            </div>
          </footer>
        </section>
        <footer className="page-foot">Investigation is a local analyst aid; incident correlation, shared case management, and response actions are not enabled.</footer>
      </main>

      {selectedAlert && (
        <AlertInvestigation
          alert={selectedAlert}
          triage={triage[selectedAlert.event_id] ?? { state: "open", note: "", updated_at: "" }}
          onStateChange={(state) => updateTriage(selectedAlert.event_id, { state })}
          onNoteChange={(note) => updateTriage(selectedAlert.event_id, { note })}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}
