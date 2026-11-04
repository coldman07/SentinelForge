import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Bell, Bot, ChevronDown,
  ChevronRight, Clock3, Command, Cpu, FileSearch, Filter, Globe2, LoaderCircle,
  LockKeyhole, Network, RefreshCw, Search, Shield, ShieldAlert, ShieldCheck,
  Sparkles, Terminal, X,
} from 'lucide-react';
import './style.css';

const CATEGORIES = ['process', 'file', 'network', 'authentication', 'service', 'persistence'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const WINDOWS = [
  { label: 'Last hour', ms: 3_600_000 },
  { label: 'Last 24 hours', ms: 86_400_000 },
  { label: 'Last 7 days', ms: 604_800_000 },
  { label: 'All loaded', ms: 0 },
];

function time(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function ago(value) {
  const diff = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(diff) || diff < 0) return 'just now';
  if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}
function severity(alert) {
  const levels = (alert.levels || []).map((x) => String(x).toLowerCase());
  return SEVERITIES.find((level) => levels.includes(level)) || levels[0] || 'unknown';
}
function eventDetail(record) {
  const detail = record?.event?.[record.category] || {};
  if (record.category === 'process') return detail.command_line || detail.path || detail.name || 'Process activity';
  if (record.category === 'file') return detail.path || 'File activity';
  if (record.category === 'network') return [detail.remote_address, detail.remote_port].filter(Boolean).join(':') || 'Network activity';
  if (record.category === 'authentication') return detail.target || detail.method || 'Authentication activity';
  return detail.display_name || detail.target || detail.name || `${record.category} activity`;
}
async function getJSON(url, signal) {
  const response = await fetch(url, { cache: 'no-store', signal });
  if (!response.ok) throw new Error(response.status === 503 ? 'The event store is not ready.' : `Request failed (${response.status}).`);
  return response.json();
}

function Badge({ children, className = '' }) {
  return <span className={`badge ${className}`}>{children}</span>;
}

function MiniBars({ events, windowMs }) {
  const series = useMemo(() => {
    const points = Array.from({ length: 12 }, () => 0);
    const now = Date.now();
    const duration = windowMs || 86_400_000;
    events.forEach((event) => {
      const age = now - new Date(event.timestamp).getTime();
      if (age >= 0 && age <= duration) {
        const slot = Math.min(11, Math.floor((duration - age) / (duration / 12)));
        points[slot] += 1;
      }
    });
    return points;
  }, [events, windowMs]);
  const max = Math.max(1, ...series);
  return <div className="mini-bars" aria-label="Event activity over the last 24 hours">{series.map((value, i) => <i key={i} style={{ height: `${Math.max(5, value / max * 100)}%` }} title={`${value} events`} />)}</div>;
}

function App() {
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loadState, setLoadState] = useState('loading');
  const [loadError, setLoadError] = useState('');
  const [updated, setUpdated] = useState(null);
  const [windowMs, setWindowMs] = useState(WINDOWS[1].ms);
  const [query, setQuery] = useState('');
  const [eventQuery, setEventQuery] = useState('');
  const [levelFilter, setLevelFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [selectedEventId, setSelectedEventId] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [section, setSection] = useState('overview');
  const [assistant, setAssistant] = useState({ prompt: '', busy: false, error: '', answer: null });
  const [chatOpen, setChatOpen] = useState(false);
  const requestRef = useRef(null);

  const refresh = useCallback(async () => {
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    setLoadState((state) => state === 'ready' ? 'refreshing' : 'loading');
    setLoadError('');
    try {
      const [eventRows, alertRows, incidentRows] = await Promise.all([
        getJSON('/v1/events?limit=100', controller.signal),
        getJSON('/v1/alerts?limit=100', controller.signal),
        getJSON('/v1/incidents?limit=50', controller.signal),
      ]);
      setEvents(eventRows);
      setAlerts(alertRows);
      setIncidents(incidentRows);
      setUpdated(new Date());
      setLoadState('ready');
    } catch (error) {
      if (error.name === 'AbortError') return;
      setLoadError(error.message || 'Could not load telemetry.');
      setLoadState((state) => state === 'refreshing' ? 'ready' : 'error');
    }
  }, []);

  useEffect(() => { refresh(); const id = window.setInterval(refresh, 15_000); return () => { window.clearInterval(id); requestRef.current?.abort(); }; }, [refresh]);

  const withinWindow = useCallback((record) => !windowMs || Date.now() - new Date(record.timestamp || record.updated_at).getTime() <= windowMs, [windowMs]);
  const visibleEvents = useMemo(() => events.filter((record) => {
    if (!withinWindow(record) || (categoryFilter && record.category !== categoryFilter)) return false;
    return !eventQuery || [record.host_id, record.category, record.action, eventDetail(record)].join(' ').toLowerCase().includes(eventQuery.toLowerCase());
  }), [events, withinWindow, categoryFilter, eventQuery]);
  const visibleAlerts = useMemo(() => alerts.filter((alert) => {
    if (!withinWindow(alert) || (levelFilter && severity(alert) !== levelFilter)) return false;
    return !query || [alert.host_id, ...(alert.rule_titles || []), ...(alert.rule_ids || [])].join(' ').toLowerCase().includes(query.toLowerCase());
  }), [alerts, withinWindow, levelFilter, query]);
  const categoryCounts = useMemo(() => Object.fromEntries(CATEGORIES.map((category) => [category, visibleEvents.filter((event) => event.category === category).length])), [visibleEvents]);
  const activeHosts = new Set(visibleEvents.map((event) => event.host_id).filter(Boolean)).size;
  const highAlerts = visibleAlerts.filter((alert) => ['critical', 'high'].includes(severity(alert))).length;

  const investigate = async (kind, identifier) => {
    const path = kind === 'alert' ? '/v1/assistant/explain-alert' : '/v1/assistant/investigate-incident';
    const payload = kind === 'alert' ? { alert_id: identifier } : { incident_id: identifier };
    setAssistant({ prompt: '', busy: true, error: '', answer: null });
    setChatOpen(true);
    try {
      const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), cache: 'no-store' });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Investigation failed (${response.status}).`);
      setAssistant((state) => ({ ...state, busy: false, answer: result }));
    } catch (error) {
      setAssistant((state) => ({ ...state, busy: false, error: error.message || 'Assistant unavailable.' }));
    }
  };

  const ask = async (event) => {
    event.preventDefault();
    const question = assistant.prompt.trim();
    if (!question || assistant.busy) return;
    setAssistant((state) => ({ ...state, busy: true, error: '', answer: null }));
    try {
      const response = await fetch('/v1/assistant/investigate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question }), cache: 'no-store' });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Investigation failed (${response.status}).`);
      setAssistant((state) => ({ ...state, busy: false, prompt: '', answer: result }));
    } catch (error) {
      setAssistant((state) => ({ ...state, busy: false, error: error.message || 'Assistant unavailable.' }));
    }
  };

  const focusSection = (name) => {
    setSection(name);
    document.getElementById(name)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return <div className="shell">
    <aside className="sidebar">
      <a className="brand" href="#overview" onClick={() => focusSection('overview')}><span className="brand-mark"><Shield size={19} /></span><span>SentinelForge<small>THREAT OPERATIONS</small></span></a>
      <div className="side-caption">WORKSPACE</div>
      <nav aria-label="Workspace navigation">
        <button className={section === 'overview' ? 'nav-button active' : 'nav-button'} onClick={() => focusSection('overview')}><Activity size={17} /> Overview <span className="nav-key">01</span></button>
        <button className={section === 'event-stream' ? 'nav-button active' : 'nav-button'} onClick={() => focusSection('event-stream')}><Terminal size={17} /> Event stream</button>
        <button className={section === 'detections' ? 'nav-button active' : 'nav-button'} onClick={() => focusSection('detections')}><ShieldAlert size={17} /> Detections <span className="nav-count">{alerts.length}</span></button>
        <button className={section === 'investigations' ? 'nav-button active' : 'nav-button'} onClick={() => focusSection('investigations')}><FileSearch size={17} /> Investigations</button>
      </nav>
      <div className="side-bottom"><div className="environment"><span className="status-light" /> LOCAL ENVIRONMENT</div><div className="privacy-note"><LockKeyhole size={14} /><span>Local, read-only telemetry<br />No response actions enabled</span></div><div className="user-chip"><div className="avatar">SF</div><div>Security analyst<small>Local workspace</small></div><ChevronDown size={14} /></div></div>
    </aside>

    <main className="main" id="overview">
      <header className="topbar"><div className="breadcrumbs">Workspace <ChevronRight size={13} /> <strong>{section === 'overview' ? 'Overview' : section === 'detections' ? 'Detections' : 'Investigations'}</strong></div><div className="top-actions"><span className="live-state"><i /> {loadState === 'refreshing' ? 'Syncing' : 'Live'}</span><button className="icon-button" aria-label="Refresh data" onClick={refresh}><RefreshCw size={16} className={loadState === 'refreshing' ? 'spin' : ''} /></button><button className="icon-button" aria-label="Open investigation assistant" onClick={() => setChatOpen(true)}><Bot size={17} /></button><div className="top-avatar">A</div></div></header>

      {loadError && <div className="error-banner"><AlertTriangle size={16} /><span>{loadError}</span><button onClick={refresh}>Retry</button></div>}

      <section className="page-intro"><div><div className="eyebrow"><span className="eyebrow-dot" /> SECURITY OPERATIONS CENTER</div><h1>Good {new Date().getHours() < 12 ? 'morning' : new Date().getHours() < 18 ? 'afternoon' : 'evening'}.</h1><p>Here’s what’s happening across your monitored endpoints.</p></div><div className="intro-controls"><label className="select-wrap"><Clock3 size={15} /><select aria-label="Time window" value={windowMs} onChange={(e) => setWindowMs(Number(e.target.value))}>{WINDOWS.map((item) => <option key={item.label} value={item.ms}>{item.label}</option>)}</select><ChevronDown size={14} /></label><button className="primary-button" onClick={refresh}><RefreshCw size={15} /> Refresh</button></div></section>

      <section className="metric-grid" aria-label="Security overview metrics">
        <Metric label="Events observed" value={visibleEvents.length} note="Latest stored events" icon={<Activity size={17} />} accent="blue" trend={<><ArrowUpRight size={13} /> Live</>} />
        <Metric label="Active endpoints" value={activeHosts} note="Unique hosts in view" icon={<Cpu size={17} />} accent="mint" trend={<><Globe2 size={13} /> Monitored</>} />
        <Metric label="Detections" value={visibleAlerts.length} note="Sigma rule matches" icon={<ShieldAlert size={17} />} accent="purple" trend={<><Bell size={13} /> {highAlerts} high priority</>} />
        <Metric label="Open incidents" value={incidents.length} note="Correlated snapshots" icon={<Network size={17} />} accent="amber" trend={<><ArrowDownRight size={13} /> Updated</>} />
      </section>

      <section className="overview-grid">
        <article className="panel activity-panel"><PanelHeading title="Event activity" subtitle="Events received by the gateway" action={updated ? `Updated ${time(updated)}` : 'Waiting for data'} /><div className="activity-summary"><div><strong>{visibleEvents.length}</strong><span>events in view</span></div><MiniBars events={visibleEvents} windowMs={windowMs} /><div className="activity-legend"><i /> {WINDOWS.find((item) => item.ms === windowMs)?.label || 'Selected window'}</div></div><div className="category-list">{CATEGORIES.map((category) => <div className="category-row" key={category}><span className={`category-dot ${category}`} /><span className="category-label">{category}</span><div className="category-track"><i style={{ width: `${visibleEvents.length ? categoryCounts[category] / visibleEvents.length * 100 : 0}%` }} /></div><b>{categoryCounts[category]}</b></div>)}</div></article>
        <article className="panel posture-panel"><PanelHeading title="Detection posture" subtitle="Current alert severity" /><div className="posture-score"><div className="score-ring"><span>{visibleAlerts.length ? Math.round((visibleAlerts.length - highAlerts) / visibleAlerts.length * 100) : '—'}<small>%</small></span></div><div><strong>{highAlerts ? 'Needs attention' : 'Clear so far'}</strong><span>{highAlerts ? `${highAlerts} critical or high alerts need review` : 'No high priority detections in view'}</span></div></div><div className="severity-list">{SEVERITIES.slice(0, 4).map((level) => <div key={level}><span className={`severity-dot ${level}`} /><span>{level}</span><b>{visibleAlerts.filter((alert) => severity(alert) === level).length}</b></div>)}</div><button className="text-link" onClick={() => focusSection('detections')}>Review detections <ChevronRight size={14} /></button></article>
      </section>

      <section className="panel table-panel" id="event-stream">
        <PanelHeading title="Recent activity" subtitle="Searchable endpoint telemetry with expandable event evidence" action={<Badge className="quiet-badge">{visibleEvents.length} EVENTS</Badge>} />
        <div className="table-tools"><label className="search-box"><Search size={15} /><input value={eventQuery} onChange={(e) => setEventQuery(e.target.value)} placeholder="Search host, action or detail" aria-label="Search events" /></label><label className="select-wrap compact"><Filter size={14} /><select value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)} aria-label="Filter by event category"><option value="">All categories</option>{CATEGORIES.map((category) => <option key={category}>{category}</option>)}</select><ChevronDown size={13} /></label></div>
        <div className="table-scroll"><table><thead><tr><th>OBSERVED</th><th>CATEGORY</th><th>ACTION</th><th>HOST</th><th>ACTIVITY DETAIL</th><th /></tr></thead><tbody>
          {loadState === 'loading' && <EmptyRow columns={6} icon={<LoaderCircle className="spin" size={17} />} label="Loading endpoint activity…" />}
          {loadState !== 'loading' && !visibleEvents.length && <EmptyRow columns={6} icon={<Activity size={18} />} label={events.length ? 'No events match these filters.' : 'No endpoint events have been stored yet.'} />}
          {visibleEvents.map((record) => <React.Fragment key={record.event_id}><tr className="alert-row" onClick={() => setSelectedEventId((id) => id === record.event_id ? '' : record.event_id)}><td><span className="time-cell">{ago(record.timestamp)}</span><small className="exact-time">{time(record.timestamp)}</small></td><td><Badge className={`category-badge ${record.category}`}>{record.category}</Badge></td><td>{record.action}</td><td><span className="host-cell"><span className="host-dot" />{record.host_id || 'Unknown host'}</span></td><td className="event-detail-cell">{eventDetail(record)}</td><td><button className="row-open" aria-label={`Toggle evidence for ${record.event_id}`} onClick={(event) => { event.stopPropagation(); setSelectedEventId((id) => id === record.event_id ? '' : record.event_id); }}><ChevronDown size={15} /></button></td></tr>{selectedEventId === record.event_id && <tr><td colSpan={6}><pre className="event-evidence">{JSON.stringify(record.event, null, 2)}</pre></td></tr>}</React.Fragment>)}
        </tbody></table></div><div className="panel-foot"><span>Showing {visibleEvents.length} of {events.length} stored events</span><span>Click an event to inspect its full record</span></div>
      </section>

      <section className="panel table-panel" id="detections">
        <PanelHeading title="Recent detections" subtitle="Review rule matches and inspect the evidence behind them" action={<Badge className="count-badge">{visibleAlerts.length} ALERTS</Badge>} />
        <div className="table-tools"><label className="search-box"><Search size={15} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search rule or host" aria-label="Search detections" /></label><label className="select-wrap compact"><Filter size={14} /><select value={levelFilter} onChange={(e) => setLevelFilter(e.target.value)} aria-label="Filter by severity"><option value="">All severities</option>{SEVERITIES.map((level) => <option key={level}>{level}</option>)}</select><ChevronDown size={13} /></label></div>
        <div className="table-scroll"><table><thead><tr><th>DETECTION</th><th>SEVERITY</th><th>HOST</th><th>OBSERVED</th><th>RULES</th><th /></tr></thead><tbody>
          {loadState === 'loading' && <EmptyRow columns={6} icon={<LoaderCircle className="spin" size={17} />} label="Loading detections…" />}
          {loadState !== 'loading' && !visibleAlerts.length && <EmptyRow columns={6} icon={<ShieldCheck size={18} />} label={alerts.length ? 'No detections match these filters.' : 'No detections have been stored yet.'} />}
          {visibleAlerts.map((alert) => <tr className={`alert-row ${selectedAlert?.event_id === alert.event_id ? 'selected' : ''}`} key={alert.event_id} onClick={() => setSelectedAlert(alert)}><td><div className="detection-title">{alert.rule_titles?.[0] || 'Sigma rule match'}</div><code>{alert.rule_ids?.[0] || alert.event_id}</code></td><td><Severity level={severity(alert)} /></td><td><span className="host-cell"><span className="host-dot" />{alert.host_id || 'Unknown host'}</span></td><td><span className="time-cell">{ago(alert.timestamp)}</span><small className="exact-time">{time(alert.timestamp)}</small></td><td><span className="rule-count">{alert.match_count} {alert.match_count === 1 ? 'match' : 'matches'}</span></td><td><button className="row-open" aria-label={`Inspect ${alert.event_id}`} onClick={(event) => { event.stopPropagation(); setSelectedAlert(alert); }}><ChevronRight size={16} /></button></td></tr>)}
        </tbody></table></div><div className="panel-foot"><span>Showing {visibleAlerts.length} of {alerts.length} stored detections</span><span>Data refreshes every 15 seconds</span></div>
      </section>

      <section className="investigation-layout" id="investigations">
        <article className="panel incidents-panel"><PanelHeading title="Incident timeline" subtitle="Related detections grouped into a single investigation" action={<Badge className="quiet-badge">{incidents.length} INCIDENTS</Badge>} />
          {!incidents.length ? <div className="empty-state"><Network size={20} /><strong>No correlated incidents yet</strong><span>When related alerts are grouped, they’ll appear here with a timeline and entity context.</span></div> : <div className="incident-list">{incidents.map((record) => <IncidentCard key={record.incident_id} record={record} onInvestigate={() => investigate('incident', record.incident_id)} />)}</div>}
        </article>
        <article className="panel investigation-panel"><PanelHeading title="Investigation workspace" subtitle="Evidence stays linked to its source event" action={<Sparkles size={16} className="sparkle" />} />
          {selectedAlert ? <AlertEvidence alert={selectedAlert} onExplain={() => investigate('alert', selectedAlert.event_id)} onClose={() => setSelectedAlert(null)} /> : <div className="empty-state choose-alert"><FileSearch size={21} /><strong>Select a detection to investigate</strong><span>Choose a row above to see its matched event evidence and ask for a read-only explanation.</span><button className="text-link" onClick={() => focusSection('detections')}>Browse detections <ChevronRight size={14} /></button></div>}
        </article>
      </section>

      <footer className="footer"><span><Command size={13} /> SENTINELFORGE · LOCAL ANALYST CONSOLE</span><span><LockKeyhole size={12} /> Read-only mode</span></footer>
    </main>

    {chatOpen && <div className="drawer-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) setChatOpen(false); }}><aside className="chat-drawer" aria-label="Investigation assistant"><div className="drawer-header"><div className="assistant-avatar"><Bot size={19} /></div><div><strong>Investigation assistant</strong><small>Read-only · evidence cited</small></div><button className="icon-button" aria-label="Close assistant" onClick={() => setChatOpen(false)}><X size={17} /></button></div><div className="drawer-body"><div className="assistant-intro"><Sparkles size={16} /><span>Ask about endpoint activity or start from a selected alert. Answers use stored evidence and include event citations.</span></div>{assistant.busy && <div className="assistant-result pending"><LoaderCircle className="spin" size={16} /> Reviewing stored evidence…</div>}{assistant.error && <div className="assistant-result error-result"><AlertTriangle size={16} />{assistant.error}</div>}{assistant.answer && <div className="assistant-result"><div className="answer-label">ANALYSIS</div><p>{assistant.answer.answer}</p>{assistant.answer.unsupported_citations?.length > 0 && <div className="citation-warning">Unverified references: {assistant.answer.unsupported_citations.join(', ')}</div>}{assistant.answer.citations?.length > 0 && <div className="citations"><span>Evidence sources</span>{assistant.answer.citations.map((citation, index) => <code key={`${citation.event_id}-${index}`}>{citation.event_id}</code>)}</div>}<small>{assistant.answer.evidence_count || 0} evidence records reviewed</small></div>}</div><form className="chat-form" onSubmit={ask}><textarea rows="3" maxLength="4000" placeholder="Ask about an event, alert, or host…" value={assistant.prompt} onChange={(e) => setAssistant((state) => ({ ...state, prompt: e.target.value }))} /><div><span>Answers may be incomplete. Verify against the evidence.</span><button className="primary-button" disabled={assistant.busy || !assistant.prompt.trim()}><Sparkles size={14} /> Ask</button></div></form></aside></div>}
  </div>;
}

function Metric({ label, value, note, icon, accent, trend }) {
  return <article className={`metric-card ${accent}`}><div className="metric-top"><span>{label}</span><i>{icon}</i></div><div className="metric-value">{value}</div><div className="metric-bottom"><span>{note}</span><span>{trend}</span></div></article>;
}
function PanelHeading({ title, subtitle, action }) {
  return <div className="panel-heading"><div><h2>{title}</h2><p>{subtitle}</p></div>{action && <div className="panel-action">{action}</div>}</div>;
}
function Severity({ level }) { return <span className={`severity-pill ${level}`}><i />{level}</span>; }
function EmptyRow({ columns, icon, label }) { return <tr><td colSpan={columns}><div className="table-empty">{icon}<span>{label}</span></div></td></tr>; }
function AlertEvidence({ alert, onExplain, onClose }) {
  const envelope = alert.alert || {};
  const event = envelope.event || {};
  const matches = envelope.matches || [];
  return <div className="evidence-view"><div className="evidence-header"><div><Severity level={severity(alert)} /><h3>{alert.rule_titles?.[0] || 'Sigma rule match'}</h3><code>{alert.event_id}</code></div><button className="icon-button small" onClick={onClose} aria-label="Clear selected alert"><X size={15} /></button></div><div className="evidence-meta"><div><small>HOST</small><strong>{alert.host_id || 'Unknown'}</strong></div><div><small>OBSERVED</small><strong>{time(alert.timestamp)}</strong></div><div><small>RULES</small><strong>{alert.match_count}</strong></div></div>{matches.length > 0 && <div className="matched-rules"><small>MATCHED RULES</small>{matches.map((match, index) => <div key={`${match.rule_id}-${index}`}><ShieldCheck size={14} /><span>{match.title || match.rule_id}</span><code>{match.rule_id}</code></div>)}</div>}<div className="evidence-block"><div><Terminal size={14} /><span>Matched event evidence</span></div><pre>{JSON.stringify(event, null, 2)}</pre></div><button className="explain-button" onClick={onExplain}><Sparkles size={15} /> Explain this detection <ChevronRight size={14} /></button></div>;
}
function IncidentCard({ record, onInvestigate }) {
  const wrapper = record.incident || {};
  const incident = wrapper.incident || wrapper;
  const severityValue = incident.severity || 'low';
  const alerts = incident.alerts || [];
  const entities = incident.entities || [];
  return <div className="incident-item"><div className="incident-rail"><i /></div><div className="incident-content"><div className="incident-top"><Severity level={severityValue} /><span>{ago(record.updated_at)}</span></div><h3>{incident.title || 'Correlated activity'}</h3><p>{incident.alert_count || alerts.length || 0} linked alerts <span>·</span> {entities.length} entities</p>{(incident.techniques || []).length > 0 && <div className="techniques">{incident.techniques.slice(0, 4).map((technique) => <code key={technique}>{technique}</code>)}</div>}<button className="text-link" onClick={onInvestigate}>Investigate incident <ChevronRight size={14} /></button></div></div>;
}

createRoot(document.getElementById('root')).render(<React.StrictMode><App /></React.StrictMode>);
