import { FormEvent, useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api } from "./api";
import type { AgentChatResponse, ApiHealth, ChatMessage, ChatThread, FunctionContext, HarnessRun, HarnessRunDetail, ReportDetail, ReportSummary } from "./types";

type View = "dashboard" | "chat" | "reports" | "functions" | "runs";

const STARTER_PROMPTS = [
  "Summarize discovered Web routes, source candidates, and dangerous sinks.",
  "Scan likely user-input sources and separate confirmed sources from candidates.",
  "Trace the argument source for the most suspicious system call.",
  "Give me the next focused validation plan from the current baseline results."
];

const NAV_ITEMS: Array<{ view: View; label: string; icon: string }> = [
  { view: "dashboard", label: "Overview", icon: "D" },
  { view: "chat", label: "Agent Chat", icon: "A" },
  { view: "reports", label: "Findings", icon: "F" },
  { view: "functions", label: "Sources", icon: "S" },
  { view: "runs", label: "Traces", icon: "T" }
];

function short(value: unknown, limit = 88) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (!text) return "";
  return text.length <= limit ? text : `${text.slice(0, limit - 3)}...`;
}

function stateTone(status = "") {
  const normalized = status.toLowerCase();
  if (["completed", "connected", "verified", "configured", "online"].includes(normalized)) return "ok";
  if (["failed", "disconnected", "error", "offline"].includes(normalized)) return "bad";
  return "warn";
}

function parseJson(value: string) {
  try { return JSON.parse(value); } catch { return value; }
}

function nowTime() {
  return new Date().toLocaleTimeString();
}

export function App() {
  const [view, setView] = useState<View>("dashboard");
  const [health, setHealth] = useState<ApiHealth | null>(null);
  const [runs, setRuns] = useState<HarnessRun[]>([]);
  const [activeRun, setActiveRun] = useState<HarnessRunDetail | null>(null);
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [chatThreads, setChatThreads] = useState<ChatThread[]>([]);
  const [activeReport, setActiveReport] = useState<ReportDetail | null>(null);
  const [threadId, setThreadId] = useState("");
  const [prompt, setPrompt] = useState(STARTER_PROMPTS[0]);
  const [chatLog, setChatLog] = useState<ChatMessage[]>([]);
  const [showChatDemo, setShowChatDemo] = useState(true);
  const [showToolCalls, setShowToolCalls] = useState(true);
  const [address, setAddress] = useState("0x4055b8");
  const [functionContext, setFunctionContext] = useState<FunctionContext | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  async function refresh() {
    const [healthData, runData, reportData, chatData] = await Promise.all([api.health(), api.runs(), api.reports(), api.chats()]);
    setHealth(healthData);
    setRuns(runData);
    setReports(reportData);
    setChatThreads(chatData);
    if (runData[0] && !activeRun) setActiveRun(await api.run(runData[0].id));
    if (reportData[0] && !activeReport) {
      try {
        setActiveReport(await api.report(reportData[0].id));
      } catch {
        setActiveReport(null);
      }
    }
    if (!threadId && chatLog.length === 0 && chatData[0]) {
      await loadChatThread(chatData[0].id);
    }
  }

  useEffect(() => { refresh().catch((exc) => setError(String(exc))); }, []);

  async function openRun(id: string) { setActiveRun(await api.run(id)); setView("runs"); }
  async function openReport(id: string) { setActiveReport(await api.report(id)); setView("reports"); }
  async function loadChatThread(id: string) {
    const result = await api.chatMessages(id);
    setThreadId(id);
    setChatLog(result.messages);
    setShowChatDemo(false);
    setView("chat");
  }

  async function submitChat(event: FormEvent) {
    event.preventDefault();
    if (!prompt.trim()) return;
    const submitted = prompt.trim();
    const pendingMessage: ChatMessage = { id: `pending-${Date.now()}`, role: "user", content: submitted };
    setBusy("agent");
    setError("");
    setShowChatDemo(false);
    setChatLog((items) => [...items, pendingMessage]);
    try {
      const result: AgentChatResponse = await api.chat(submitted, threadId);
      setThreadId(result.thread_id);
      setChatLog(result.messages?.length ? result.messages : [pendingMessage, { id: result.run_id, role: "assistant", content: result.status === "completed" ? result.answer : result.error }]);
      await refresh();
      setActiveRun(await api.run(result.run_id));
    } catch (exc) {
      setError(String(exc));
    } finally {
      setBusy("");
    }
  }

  async function runScan() {
    setBusy("scan");
    setError("");
    try {
      const result = await api.scan(threadId);
      setThreadId(result.thread_id);
      await refresh();
      setActiveRun(await api.run(result.run_id));
      if (result.report_id) setActiveReport(await api.report(result.report_id));
      setView("reports");
    } catch (exc) {
      setError(String(exc));
    } finally {
      setBusy("");
    }
  }

  async function inspectFunction() {
    setBusy("function");
    setError("");
    try {
      setFunctionContext(await api.functionContext(address));
      setView("functions");
    } catch (exc) {
      setError(String(exc));
    } finally {
      setBusy("");
    }
  }

  const verified = useMemo(() => activeReport?.findings.filter((finding) => finding.verification_status === "verified").length ?? 0, [activeReport]);
  const highRisk = useMemo(() => activeReport?.findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length ?? 0, [activeReport]);

  const clearChat = () => { setThreadId(""); setChatLog([]); setShowChatDemo(false); };

  return (
    <div className="agent-shell">
      <Sidebar view={view} setView={setView} health={health} reports={reports} chatThreads={chatThreads} activeThreadId={threadId} runScan={runScan} busy={busy} openReport={openReport} loadChatThread={loadChatThread} clearChat={clearChat} />
      <main className={`workspace view-${view}`}>
        <Topbar health={health} activeReport={activeReport} refresh={refresh} runScan={runScan} busy={busy} />
        {error && <div className="error-banner">{error}</div>}
        <section className="kpi-row">
          <Metric label="Findings" value={activeReport?.findings.length ?? 0} hint="Open issues" />
          <Metric label="Warnings" value={highRisk} tone={highRisk > 0 ? "bad" : "neutral"} hint="High risk" />
          <Metric label="Informational Sources" value={activeReport?.source_candidates.length ?? 0} hint="Collected" />
          <Metric label="Verified" value={verified} tone="ok" hint="Confirmed" />
          <Metric label="Backend" value={health?.ida.connected ? "Online" : "Offline"} tone={health?.ida.connected ? "ok" : "bad"} hint="IDA service" />
          <Metric label="LLM Agent" value={health?.llm.configured ? "Configured" : "Missing Key"} tone={health?.llm.configured ? "ok" : "warn"} hint={health?.llm.provider ?? "DeepSeek"} />
        </section>
        {view !== "functions" && (
          <section className={`dashboard-grid focus-${view}`}>
            {(view === "dashboard" || view === "chat") && <ChatPanel prompt={prompt} setPrompt={setPrompt} setStarter={setPrompt} chatLog={chatLog} showDemo={showChatDemo} showToolCalls={showToolCalls} setShowToolCalls={setShowToolCalls} busy={busy === "agent"} submitChat={submitChat} clearChat={clearChat} />}
            {view === "reports" && <FindingsPage reports={reports} activeReport={activeReport} openReport={openReport} />}
            {view === "runs" && <TracesPage runs={runs} activeRun={activeRun} openRun={openRun} openReport={openReport} />}
            <InvestigationPanel runs={runs} activeRun={activeRun} openRun={openRun} openReport={openReport} health={health} setView={setView} />
          </section>
        )}
        {view === "functions" && <SourcesPanel activeReport={activeReport} address={address} setAddress={setAddress} inspectFunction={inspectFunction} context={functionContext} busy={busy === "function"} />}
      </main>
    </div>
  );
}

function Sidebar(props: { view: View; setView: (view: View) => void; health: ApiHealth | null; reports: ReportSummary[]; chatThreads: ChatThread[]; activeThreadId: string; runScan: () => void; busy: string; openReport: (id: string) => void; loadChatThread: (id: string) => void; clearChat: () => void; }) {
  return (
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">VA</div><div><strong>VulnAgent</strong><span>Binary Agent Console</span></div><button className="collapse-button">{"<"}</button></div>
      <p className="sidebar-label">Workspace</p>
      <nav className="nav">{NAV_ITEMS.map((item) => <button key={item.view} className={props.view === item.view ? "active" : ""} onClick={() => props.setView(item.view)}><span>{item.icon}</span>{item.label}</button>)}</nav>
      <p className="sidebar-label">Active Sample</p>
      <SidebarFact label="Status" value={props.health?.ida.connected ? "Connected" : "Disconnected"} tone={props.health?.ida.connected ? "ok" : "bad"} />
      <SidebarFact label="Backend" value={props.health?.ida.connected ? "Online" : "Offline"} />
      <SidebarFact label="Arch / Bits" value={`${props.health?.ida.architecture ?? "-"} / ${props.health?.ida.bits ?? "-"}-bit`} />
      <SidebarFact label="Protocol" value={props.health?.ida.protocol_version ?? "-"} />
      <p className="sidebar-label">LLM Agent</p>
      <SidebarFact label="Provider" value={props.health?.llm.provider ?? "DeepSeek"} />
      <SidebarFact label="Model" value={props.health?.llm.model ?? "deepseek-chat"} />
      <SidebarFact label="Status" value={props.health?.llm.configured ? "Configured" : "Missing Key"} tone={props.health?.llm.configured ? "ok" : "warn"} />
      <p className="sidebar-label">Quick Actions</p>
      <button className="danger-action" disabled={props.busy === "scan"} onClick={props.runScan}>{props.busy === "scan" ? "Scanning" : "Start Baseline Scan"}</button>
      <button className="ghost-action">Scan Limits</button>
      <button className="ghost-action" onClick={props.clearChat}>Clear Agent Chat</button>
      <p className="sidebar-label">Saved Chats</p>
      <select className="report-select" onChange={(event) => event.target.value && props.loadChatThread(event.target.value)} value={props.activeThreadId}>
        <option value="">Select chat...</option>
        {props.chatThreads.map((thread) => <option key={thread.id} value={thread.id}>{short(thread.title || thread.id, 26)}</option>)}
      </select>
      <p className="sidebar-label">Saved Reports</p>
      <select className="report-select" onChange={(event) => event.target.value && props.openReport(event.target.value)} value=""><option value="">Select report...</option>{props.reports.map((report) => <option key={report.id} value={report.id}>{short(report.id, 22)}</option>)}</select>
    </aside>
  );
}

function SidebarFact(props: { label: string; value: string; tone?: string }) { return <div className="sidebar-fact"><span>{props.label}</span><strong className={props.tone ? `tone-${props.tone}` : ""}>{props.value}</strong></div>; }

function Topbar(props: { health: ApiHealth | null; activeReport: ReportDetail | null; refresh: () => void; runScan: () => void; busy: string; }) {
  return <header className="topbar"><TopFact label="Active Sample" value={short(props.health?.ida.database ?? "No IDB connected", 34)} action="Change" /><TopFact label="Architecture" value={`${props.health?.ida.architecture ?? "-"} (${props.health?.ida.bits ?? "-"}-bit)`} /><TopFact label="Backend" value={props.health?.ida.connected ? "Online" : "Offline"} tone={props.health?.ida.connected ? "ok" : "bad"} /><TopFact label="LLM Agent" value={props.health?.llm.configured ? "Configured" : "Not configured"} tone={props.health?.llm.configured ? "ok" : "warn"} /><TopFact label="Report ID" value={short(props.activeReport?.report_id ?? "-", 20)} /><div className="top-actions"><button onClick={props.refresh}>Refresh</button><button onClick={props.runScan} disabled={props.busy === "scan"}>Open Report</button></div></header>;
}

function TopFact(props: { label: string; value: string; action?: string; tone?: string }) { return <div className="top-fact"><span>{props.label}</span><strong className={props.tone ? `tone-${props.tone}` : ""}>{props.value}</strong>{props.action && <em>{props.action} &gt;</em>}</div>; }
function Metric({ label, value, hint, tone = "neutral" }: { label: string; value: unknown; hint: string; tone?: string }) { return <div className={`metric ${tone}`}><span>{label}</span><strong>{String(value)}</strong><em>{hint}</em></div>; }

function ChatPanel(props: { prompt: string; setPrompt: (value: string) => void; setStarter: (value: string) => void; chatLog: ChatMessage[]; showDemo: boolean; showToolCalls: boolean; setShowToolCalls: (value: boolean) => void; busy: boolean; submitChat: (event: FormEvent) => void; clearChat: () => void; }) {
  return (
    <section className="panel chat-panel">
      <PanelHead title="Agent Chat" action="Clear Chat" onAction={props.clearChat} />
      <div className="chat-contextbar"><span className="context-pill live">DeepSeek</span><span>Read-only IDA tools</span><span>Harness trace enabled</span><span>Short-term memory</span></div>
      <div className="chat-feed">
        {props.showDemo && props.chatLog.length === 0 && <><Message role="user" text="Analyze this firmware for memory corruption vulnerabilities." at="10:14:22" /><Message role="assistant" text="Understood. I will analyze the firmware with focused route, source, sink, and evidence collection." at="10:14:24" />{props.showToolCalls && <ToolCard title="Tool call: discover_entry_points" status="Completed" rows={["Discovered 23 potential entry points.", "0x00401800, 0x00401588, 0x00401A2C..."]} />}<Message role="assistant" text="Identifying sources and sinks across the binary..." at="10:14:26" />{props.showToolCalls && <ToolCard title="Tool call: analyze_data_flows" status="Completed" rows={["Sources 18   Sinks 27   Flows 64   High Risk 3"]} />}</>}
        {props.chatLog.map((item, index) => <ChatMessageItem key={item.id || index} message={item} showToolCalls={props.showToolCalls} />)}
        {!props.showDemo && props.chatLog.length === 0 && <div className="chat-empty"><strong>No active conversation</strong><span>Use a quick prompt or ask VulnAgent to inspect routes, sources, sinks, or a function address.</span></div>}
      </div>
      <div className="starter-row">{STARTER_PROMPTS.map((starter) => <button key={starter} onClick={() => props.setStarter(starter)}>{short(starter, 42)}</button>)}</div>
      <form className="composer" onSubmit={props.submitChat}><div className="composer-box"><textarea value={props.prompt} onChange={(event) => props.setPrompt(event.target.value)} placeholder="Ask VulnAgent to inspect routes, sources, sinks, or a specific function..." rows={2} /><div className="composer-meta"><span>/route /source /sink /trace</span><span>Enter to send</span></div></div><button disabled={props.busy}>{props.busy ? "Running" : "Send"}</button></form>
      <div className="chat-footer"><span>Help for commands</span><button type="button" className="switch-line" onClick={() => props.setShowToolCalls(!props.showToolCalls)}>Tool Calls <b className={props.showToolCalls ? "on" : ""} /></button></div>
    </section>
  );
}

function Message({ role, text, at }: { role: string; text: string; at: string }) { return <article className={`message ${role}`}><div className="avatar">{role === "assistant" ? "VA" : "You"}</div><div><header><strong>{role === "assistant" ? "VulnAgent" : "You"}</strong><time>{at}</time></header><MarkdownBody content={text} /></div></article>; }

function ChatMessageItem({ message, showToolCalls }: { message: ChatMessage; showToolCalls: boolean }) {
  if (message.role === "tool") {
    if (!showToolCalls) return null;
    return <ToolCard title={`Tool result: ${message.name || "IDA tool"}`} status="Completed" rows={[shortToolContent(message.content, 180)]} raw={message.content} />;
  }
  const role = message.role === "user" ? "user" : "assistant";
  return <>{message.content && <article className={`message ${role}`}><div className="avatar">{role === "assistant" ? "VA" : "You"}</div><div><header><strong>{role === "assistant" ? "VulnAgent" : "You"}</strong><time>{nowTime()}</time></header><MarkdownBody content={message.content} /></div></article>}{showToolCalls && message.tool_calls?.map((toolCall) => <ToolCard key={toolCall.id || toolCall.name} title={`Tool call: ${toolCall.name}`} status="Queued" rows={[toolInputSummary(toolCall.args)]} raw={JSON.stringify(toolCall.args, null, 2)} />)}</>;
}

function MarkdownBody({ content }: { content: string }) { return <div className="markdown-body"><ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown></div>; }
function ToolCard(props: { title: string; status: string; rows: string[]; raw?: string }) { return <details className="tool-card" open><summary><strong>{props.title}</strong><span>{props.status}</span></summary>{props.rows.map((row) => <p key={row}>{row}</p>)}{props.raw && props.raw.length > 180 && <pre>{props.raw}</pre>}</details>; }
function toolInputSummary(args: Record<string, unknown> = {}) { const entries = Object.entries(args); if (!entries.length) return "no arguments"; const visible = entries.slice(0, 4).map(([key, value]) => `${key}=${short(value, 44)}`); if (entries.length > 4) visible.push(`+${entries.length - 4} more`); return visible.join(", "); }
function shortToolContent(content: string, limit: number) { const parsed = parseJson(content); if (typeof parsed === "string") return short(parsed, limit); if (parsed && typeof parsed === "object") { const record = parsed as Record<string, unknown>; if (typeof record.summary === "string") return short(record.summary, limit); if (typeof record.error === "string") return short(record.error, limit); if (Array.isArray(record.confirmed_sources)) { const pendingSinks = Array.isArray(record.pending_sinks) ? record.pending_sinks.length : 0; return `confirmed_sources=${record.confirmed_sources.length}, pending_sinks=${pendingSinks}`; } } return short(parsed, limit); }

function InvestigationPanel(props: { runs: HarnessRun[]; activeRun: HarnessRunDetail | null; openRun: (id: string) => void; openReport: (id: string) => void; health: ApiHealth | null; setView: (view: View) => void; }) {
  return <aside className="panel investigation-panel"><PanelHead title="Investigation State" action="Refresh" /><div className="run-card"><h3>Harness Runs</h3><div className="run-table"><div className="run-table-head"><span>Run ID</span><span>Status</span><span>Findings</span></div>{props.runs.slice(0, 4).map((run) => <button key={run.id} onClick={() => props.openRun(run.id)}><span>{short(run.id, 12)}</span><em className={`state ${stateTone(run.status)}`}>{run.status}</em><strong>{run.report_id ? "1" : "0"}</strong></button>)}{props.runs.length === 0 && <p>No harness run has been recorded.</p>}</div><button className="panel-link" onClick={() => props.setView("runs")}>View all runs &gt;</button></div><TraceTimeline run={props.activeRun} /><div className="focus-card"><h3>Current Focus</h3><dl><dt>Finding</dt><dd>{props.activeRun?.mode ?? "Agent analysis"}</dd><dt>Status</dt><dd><span className={`state ${stateTone(props.activeRun?.status)}`}>{props.activeRun?.status ?? "idle"}</span></dd><dt>Backend</dt><dd>{props.health?.ida.connected ? "Connected" : "Disconnected"}</dd><dt>Last Updated</dt><dd>{props.activeRun?.finished_at || props.activeRun?.started_at || "-"}</dd></dl>{props.activeRun?.report_id && <button onClick={() => props.openReport(props.activeRun!.report_id)}>Open linked report</button>}</div></aside>;
}

function TraceTimeline({ run }: { run: HarnessRunDetail | null }) { return <div className="trace-card"><div className="trace-head"><h3>Trace Timeline</h3><select defaultValue="all"><option value="all">All Events</option></select></div><div className="timeline">{!run && <p>Select a run to inspect trace events.</p>}{run?.trace_events.slice(0, 7).map((event) => <article key={event.id} className={event.event_type.includes("fail") ? "failed" : ""}><time>{event.created_at?.slice(11, 19) || "--:--:--"}</time><div><strong>{event.event_type}</strong><p>{event.message}</p><small>{short(parseJson(event.data_json), 90)}</small></div></article>)}</div>{run && <button className="panel-link">View full trace &gt;</button>}</div>; }

function FindingsPage(props: { reports: ReportSummary[]; activeReport: ReportDetail | null; openReport: (id: string) => void; }) {
  const findings = props.activeReport?.findings ?? [];
  const verified = findings.filter((finding) => finding.verification_status === "verified").length;
  const high = findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length;
  return <section className="panel data-page findings-page"><PanelHead title="Findings" action="Export JSON" /><div className="page-summary"><MiniMetric label="Total Findings" value={findings.length} hint="Open issues" /><MiniMetric label="High Risk" value={high} hint="Critical / high" tone={high > 0 ? "bad" : "neutral"} /><MiniMetric label="Verified" value={verified} hint="Confirmed" tone="ok" /><MiniMetric label="Reports" value={props.reports.length} hint="Saved runs" /></div><div className="table-card"><div className="table-head"><strong>Finding Evidence</strong><span>{props.activeReport?.report_id ? short(props.activeReport.report_id, 28) : "No active report"}</span></div><table><thead><tr><th>ID</th><th>Category</th><th>Severity</th><th>Source</th><th>Sink</th><th>Status</th></tr></thead><tbody>{findings.map((finding) => <tr key={finding.finding_id}><td>{finding.finding_id}</td><td>{finding.category}</td><td><span className={`risk ${finding.severity}`}>{finding.severity}</span></td><td>{finding.source || "-"}</td><td>{finding.sink.caller_name} / {finding.sink.sink_name}</td><td>{finding.verification_status}</td></tr>)}{findings.length === 0 && <tr><td colSpan={6}>No findings yet. Run Baseline Scan or open a saved report.</td></tr>}</tbody></table></div><div className="evidence-grid">{findings.slice(0, 6).map((finding) => <article className="evidence-item" key={finding.finding_id}><header><strong>{finding.finding_id}</strong><span className={`risk ${finding.severity}`}>{finding.severity}</span></header><p>{finding.category}</p><small>{finding.evidence?.[0] || `${finding.source || "source"} -> ${finding.sink.sink_name}`}</small></article>)}</div><div className="report-strip">{props.reports.slice(0, 6).map((report) => <button key={report.id} onClick={() => props.openReport(report.id)}>{short(report.id, 22)}</button>)}</div></section>;
}

function SourcesPanel(props: { activeReport: ReportDetail | null; address: string; setAddress: (value: string) => void; inspectFunction: () => void; context: FunctionContext | null; busy: boolean; }) {
  const sources = props.activeReport?.source_candidates ?? [];
  return <section className="panel function-panel sources-page"><PanelHead title="Sources" action="IDA Context" /><div className="source-list"><div className="table-head"><strong>Source Candidates</strong><span>{sources.length} collected</span></div><div className="source-grid">{sources.slice(0, 12).map((source, index) => <article className="source-card" key={index}><strong>{recordTitle(source, `source-${index + 1}`)}</strong><p>{short(source, 140)}</p></article>)}{sources.length === 0 && <div className="empty-state">No source candidates yet. Run Baseline Scan to collect likely user-input sources.</div>}</div></div><div className="function-bar"><input value={props.address} onChange={(event) => props.setAddress(event.target.value)} /><button disabled={props.busy} onClick={props.inspectFunction}>{props.busy ? "Loading" : "Decompile"}</button></div>{props.context ? <div className="code-context large"><header><strong>{props.context.name}</strong><span>{props.context.start_ea} - {props.context.end_ea}</span></header><pre>{props.context.decompile_ok ? props.context.pseudocode : props.context.decompile_error}</pre></div> : <div className="empty-state">Enter a function address to inspect pseudocode and references.</div>}</section>;
}

function TracesPage(props: { runs: HarnessRun[]; activeRun: HarnessRunDetail | null; openRun: (id: string) => void; openReport: (id: string) => void; }) {
  return <section className="panel data-page traces-page"><PanelHead title="Harness Runs & Trace" action="Refresh" /><div className="trace-layout"><div className="table-card"><div className="table-head"><strong>Recent Runs</strong><span>{props.runs.length} runs</span></div><div className="run-list">{props.runs.map((run) => <button key={run.id} className={props.activeRun?.id === run.id ? "active" : ""} onClick={() => props.openRun(run.id)}><span>{short(run.id, 18)}</span><em className={`state ${stateTone(run.status)}`}>{run.status}</em><small>{run.mode}</small></button>)}{props.runs.length === 0 && <p>No harness run has been recorded.</p>}</div></div><div className="trace-detail"><TraceTimeline run={props.activeRun} /><div className="table-card"><div className="table-head"><strong>Trace Events</strong><span>{props.activeRun?.trace_events.length ?? 0} events</span></div><table><thead><tr><th>#</th><th>Event</th><th>Message</th><th>Time</th></tr></thead><tbody>{props.activeRun?.trace_events.map((event) => <tr key={event.id}><td>{event.sequence}</td><td>{event.event_type}</td><td>{event.message}</td><td>{event.created_at?.slice(11, 19)}</td></tr>)}{!props.activeRun && <tr><td colSpan={4}>Select a run to inspect trace events.</td></tr>}</tbody></table></div>{props.activeRun?.report_id && <button className="primary-inline" onClick={() => props.openReport(props.activeRun!.report_id)}>Open linked report</button>}</div></div></section>;
}

function recordTitle(value: unknown, fallback: string) { if (!value || typeof value !== "object") return fallback; const record = value as Record<string, unknown>; return String(record.name ?? record.function ?? record.function_name ?? record.address ?? record.ea ?? fallback); }
function PanelHead({ title, action, onAction }: { title: string; action: string; onAction?: () => void }) { return <header className="panel-head"><h2>{title}</h2><button onClick={onAction}>{action}</button></header>; }
function MiniMetric({ label, value, hint, tone = "neutral" }: { label: string; value: unknown; hint: string; tone?: string }) { return <div className={`mini-metric ${tone}`}><span>{label}</span><strong>{String(value)}</strong><em>{hint}</em></div>; }
