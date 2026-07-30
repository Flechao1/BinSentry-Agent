import { FormEvent, useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import { memo, useRef } from "react";
import type { KeyboardEvent } from "react";
import remarkGfm from "remark-gfm";
import { api } from "./api";
import type { AgentChatResponse, ApiHealth, CandidateFinding, ChatMessage, ChatThread, FirmwareCandidate, FirmwareTriageReport, FunctionContext, HarnessRun, HarnessRunDetail, IntelSearchResult, ReportDetail, ReportSummary } from "./types";

type View = "dashboard" | "firmware" | "sessions" | "chat" | "reports" | "candidates" | "functions" | "intel" | "runs" | "settings";

const STARTER_PROMPTS = [
  "梳理当前样本的 Web 路由、输入源和危险函数调用。",
  "扫描疑似用户输入点，区分已确认来源和候选来源。",
  "追踪最可疑 system 调用的参数来源。",
  "基于当前基线结果，给出下一步验证计划。"
];

const NAV_ITEMS: Array<{ view: View; label: string; icon: string }> = [
  { view: "dashboard", label: "态势总览", icon: "OV" },
  { view: "firmware", label: "固件分诊", icon: "FW" },
  { view: "sessions", label: "调查会话", icon: "SS" },
  { view: "chat", label: "Agent 对话", icon: "AI" },
  { view: "reports", label: "漏洞发现", icon: "VF" },
  { view: "candidates", label: "候选验证", icon: "CV" },
  { view: "functions", label: "输入来源", icon: "SRC" },
  { view: "intel", label: "CVE 情报", icon: "CVE" },
  { view: "runs", label: "执行轨迹", icon: "TR" },
  { view: "settings", label: "模型配置", icon: "CFG" }
];
const ACTIVE_THREAD_STORAGE_KEY = "vulnagent.active_thread_id";

type ChatDraftSeed = {
  id: number;
  text: string;
};

function short(value: unknown, limit = 88) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (!text) return "";
  return text.length <= limit ? text : `${text.slice(0, limit - 3)}...`;
}

function splitPath(value?: string | null) {
  const text = value?.trim() || "";
  if (!text) return { full: "", name: "", parent: "" };
  const normalized = text.replace(/[\\/]+$/, "");
  const parts = normalized.split(/[\\/]/).filter(Boolean);
  const name = parts[parts.length - 1] || normalized;
  const parent = normalized.slice(0, Math.max(0, normalized.length - name.length)).replace(/[\\/]$/, "");
  return { full: text, name, parent };
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
  const [threadId, setThreadId] = useState(() => window.localStorage.getItem(ACTIVE_THREAD_STORAGE_KEY) ?? "");
  const [chatDraftSeed, setChatDraftSeed] = useState<ChatDraftSeed>({ id: 0, text: "" });
  const [chatLog, setChatLog] = useState<ChatMessage[]>([]);
  const [showChatDemo, setShowChatDemo] = useState(true);
  const [showToolCalls, setShowToolCalls] = useState(true);
  const [address, setAddress] = useState("0x4055b8");
  const [functionContext, setFunctionContext] = useState<FunctionContext | null>(null);
  const [firmwareRoot, setFirmwareRoot] = useState("");
  const [firmwareLimit, setFirmwareLimit] = useState(20);
  const [firmwareReport, setFirmwareReport] = useState<FirmwareTriageReport | null>(null);
  const [selectedFirmwarePath, setSelectedFirmwarePath] = useState("");
  const [intelForm, setIntelForm] = useState({
    vendor: "",
    product: "",
    firmwareVersion: "",
    component: "",
    vulnerabilityType: "command injection",
    route: "",
    sink: "",
    symbols: "",
    keywords: "",
    sources: "cveorg,nvd,github",
    maxResults: 10
  });
  const [intelResult, setIntelResult] = useState<IntelSearchResult | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const chatAbortRef = useRef<AbortController | null>(null);
  const cancelingChatRef = useRef(false);
  const activeChatThreadRef = useRef("");

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
    const selectedThreadExists = chatData.some((thread) => thread.id === threadId);
    if (threadId && !selectedThreadExists) {
      setThreadId("");
      setChatLog([]);
      setShowChatDemo(false);
    } else if (threadId && chatLog.length === 0) {
      await loadChatThread(threadId);
    } else if (!threadId && chatLog.length === 0 && chatData[0]) {
      await loadChatThread(chatData[0].id);
    }
  }

  useEffect(() => { refresh().catch((exc) => setError(String(exc))); }, []);
  useEffect(() => {
    if (threadId) window.localStorage.setItem(ACTIVE_THREAD_STORAGE_KEY, threadId);
    else window.localStorage.removeItem(ACTIVE_THREAD_STORAGE_KEY);
  }, [threadId]);

  async function openRun(id: string) { setActiveRun(await api.run(id)); setView("runs"); }
  async function openReport(id: string) { setActiveReport(await api.report(id)); setView("reports"); }
  async function loadChatThread(id: string) {
    const result = await api.chatMessages(id);
    setThreadId(id);
    setChatLog(result.messages);
    setShowChatDemo(false);
    setView("chat");
  }

  function seedChatDraft(text: string) {
    setChatDraftSeed((seed) => ({ id: seed.id + 1, text }));
  }

  async function submitChat(submitted: string) {
    if (busy) return;
    submitted = submitted.trim();
    if (!submitted) return;
    const pendingMessage: ChatMessage = { id: `pending-${Date.now()}`, role: "user", content: submitted };
    setBusy("agent");
    setError("");
    setShowChatDemo(false);
    setChatLog((items) => [...items, pendingMessage]);
    const controller = new AbortController();
    chatAbortRef.current = controller;
    cancelingChatRef.current = false;
    try {
      let activeThreadId = threadId;
      if (!activeThreadId) {
        const thread = await api.createChat();
        activeThreadId = thread.id;
        setThreadId(thread.id);
      }
      activeChatThreadRef.current = activeThreadId;
      const result: AgentChatResponse = await api.chat(submitted, activeThreadId, controller.signal);
      setThreadId(result.thread_id);
      setChatLog(result.messages?.length ? result.messages : [pendingMessage, { id: result.run_id, role: "assistant", content: result.status === "completed" ? result.answer : result.error }]);
      await refresh();
      setActiveRun(await api.run(result.run_id));
    } catch (exc) {
      if (!cancelingChatRef.current) {
        setError(String(exc));
        seedChatDraft(submitted);
      }
    } finally {
      if (chatAbortRef.current === controller) chatAbortRef.current = null;
      activeChatThreadRef.current = "";
      cancelingChatRef.current = false;
      setBusy("");
    }
  }

  async function cancelChat() {
    if (busy !== "agent") return;
    cancelingChatRef.current = true;
    setError("");
    const activeThreadId = activeChatThreadRef.current || threadId;
    chatAbortRef.current?.abort();
    try {
      if (activeThreadId) await api.cancelChat(activeThreadId);
      if (activeThreadId) {
        const result = await api.chatMessages(activeThreadId);
        setChatLog(result.messages);
      }
      await refresh();
    } catch (exc) {
      setError(String(exc));
    } finally {
      setBusy("");
      chatAbortRef.current = null;
      activeChatThreadRef.current = "";
      cancelingChatRef.current = false;
    }
  }

  async function closeIdaFromTopbar() {
    setBusy("ida");
    setError("");
    try {
      await api.shutdownIdaBackend(false);
      await refresh();
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

  async function runFirmwareTriage() {
    if (!firmwareRoot.trim()) return;
    setBusy("firmware");
    setError("");
    try {
      const result = await api.firmwareTriage(firmwareRoot.trim(), firmwareLimit);
      setFirmwareReport(result);
      setSelectedFirmwarePath(result.candidates[0]?.relative_path ?? "");
      setView("firmware");
    } catch (exc) {
      setError(String(exc));
    } finally {
      setBusy("");
    }
  }

  function sendFirmwareTargetToChat(candidate: FirmwareCandidate) {
    seedChatDraft(
      [
        "I selected this firmware binary after filesystem triage:",
        candidate.path,
        "",
        "Explain why it is a good IDA target, summarize the first evidence to collect,",
        "and remind me to start the IDA backend with:",
        candidate.ida_backend_command
      ].join("\n")
    );
    setView("chat");
  }

  async function searchIntel() {
    setBusy("intel");
    setError("");
    try {
      const result = await api.vulnerabilityIntel({
        vendor: intelForm.vendor.trim(),
        product: intelForm.product.trim(),
        firmware_version: intelForm.firmwareVersion.trim(),
        component: intelForm.component.trim(),
        vulnerability_type: intelForm.vulnerabilityType.trim(),
        route: intelForm.route.trim(),
        sink: intelForm.sink.trim(),
        symbols: splitCsv(intelForm.symbols),
        keywords: splitCsv(intelForm.keywords),
        sources: splitSources(intelForm.sources),
        max_results: intelForm.maxResults
      });
      setIntelResult(result);
      setView("intel");
    } catch (exc) {
      setError(String(exc));
    } finally {
      setBusy("");
    }
  }

  function sendIntelToChat() {
    const matches = intelResult?.matches.slice(0, 5).map((match) => {
      const ref = match.reference;
      return `- ${ref.identifier} (${ref.source}) score=${match.score}: ${ref.url}`;
    }).join("\n") || "- No matches yet";
    seedChatDraft([
      "Please review this known-vulnerability intelligence result and compare it with the current binary evidence.",
      "",
      `Query: ${[
        intelForm.vendor,
        intelForm.product,
        intelForm.firmwareVersion,
        intelForm.component,
        intelForm.vulnerabilityType,
        intelForm.route,
        intelForm.sink
      ].filter(Boolean).join(" ")}`,
      "",
      `Assessment: ${intelResult?.assessment ?? "not searched"}`,
      "Matches:",
      matches,
      "",
      "Explain which matches are plausible, which are weak keyword overlap, and what binary evidence is still required."
    ].join("\n"));
    setView("chat");
  }

  async function createChat() {
    setBusy("session");
    setError("");
    try {
      const thread = await api.createChat();
      setThreadId(thread.id);
      setChatLog([]);
      setShowChatDemo(false);
      setView("chat");
      await refresh();
    } catch (exc) {
      setError(String(exc));
    } finally {
      setBusy("");
    }
  }

  async function renameChat(targetThreadId = threadId) {
    if (!targetThreadId) return;
    const current = chatThreads.find((thread) => thread.id === targetThreadId);
    const title = window.prompt("Rename investigation", current?.title || "New investigation");
    if (!title?.trim()) return;
    setBusy("session");
    setError("");
    try {
      await api.renameChat(targetThreadId, title.trim());
      await refresh();
    } catch (exc) {
      setError(String(exc));
    } finally {
      setBusy("");
    }
  }

  async function clearChat(targetThreadId = threadId) {
    if (!targetThreadId) {
      setChatLog([]);
      setShowChatDemo(false);
      return;
    }
    setBusy("session");
    setError("");
    try {
      await api.clearChat(targetThreadId);
      if (targetThreadId === threadId) {
        setChatLog([]);
        setShowChatDemo(false);
      }
      await refresh();
    } catch (exc) {
      setError(String(exc));
    } finally {
      setBusy("");
    }
  }

  async function deleteChat(targetThreadId = threadId) {
    if (!targetThreadId || !window.confirm("Delete this investigation and its conversation history?")) return;
    setBusy("session");
    setError("");
    try {
      await api.deleteChat(targetThreadId);
      if (targetThreadId === threadId) {
        setThreadId("");
        setChatLog([]);
        setShowChatDemo(false);
      }
      await refresh();
    } catch (exc) {
      setError(String(exc));
    } finally {
      setBusy("");
    }
  }

  const verified = useMemo(() => activeReport?.findings.filter((finding) => finding.verification_status === "verified").length ?? 0, [activeReport]);
  const highRisk = useMemo(() => activeReport?.findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length ?? 0, [activeReport]);

  return (
    <div className="agent-shell">
      <Sidebar view={view} setView={setView} health={health} reports={reports} chatThreads={chatThreads} activeThreadId={threadId} runScan={runScan} busy={busy} openReport={openReport} loadChatThread={loadChatThread} createChat={createChat} renameChat={renameChat} clearChat={clearChat} deleteChat={deleteChat} />
      <main className={`workspace view-${view}`}>
        <Topbar health={health} activeReport={activeReport} refresh={refresh} openReport={openReport} closeIda={closeIdaFromTopbar} busy={busy} />
        {error && <div className="error-banner">{error}</div>}
        {view === "dashboard" && <section className="kpi-row overview-kpis">
          <Metric label="漏洞发现" value={activeReport?.findings.length ?? 0} hint="当前报告" />
          <Metric label="高危告警" value={highRisk} tone={highRisk > 0 ? "bad" : "neutral"} hint="Critical / High" />
          <Metric label="输入来源" value={activeReport?.source_candidates.length ?? 0} hint="已收集" />
          <Metric label="已验证" value={verified} tone="ok" hint="证据闭环" />
          <Metric label="IDA 后端" value={health?.ida.connected ? "在线" : "离线"} tone={health?.ida.connected ? "ok" : "bad"} hint="分析服务" />
          <Metric label="LLM Agent" value={health?.llm.configured ? "已配置" : "缺少 Key"} tone={health?.llm.configured ? "ok" : "warn"} hint={health?.llm.provider ?? "DeepSeek"} />
        </section>}
        {view !== "functions" && (
          <section className={`dashboard-grid focus-${view}`}>
            {view === "dashboard" && <OverviewPage activeReport={activeReport} reports={reports} runs={runs} openReport={openReport} openRun={openRun} />}
            {view === "chat" && <ChatPanel draftSeed={chatDraftSeed} chatLog={chatLog} showDemo={showChatDemo} showToolCalls={showToolCalls} setShowToolCalls={setShowToolCalls} busy={busy === "agent"} submitChat={submitChat} cancelChat={cancelChat} clearChat={clearChat} createChat={createChat} threadTitle={chatThreads.find((thread) => thread.id === threadId)?.title ?? "New investigation"} />}
            {view === "sessions" && <SessionsPage threads={chatThreads} activeThreadId={threadId} busy={busy === "session"} createChat={createChat} loadChatThread={loadChatThread} renameChat={renameChat} clearChat={clearChat} deleteChat={deleteChat} />}
            {view === "firmware" && <FirmwareTriagePage root={firmwareRoot} setRoot={setFirmwareRoot} limit={firmwareLimit} setLimit={setFirmwareLimit} report={firmwareReport} selectedPath={selectedFirmwarePath} setSelectedPath={setSelectedFirmwarePath} busy={busy === "firmware"} runTriage={runFirmwareTriage} sendToChat={sendFirmwareTargetToChat} />}
            {view === "reports" && <FindingsPage reports={reports} activeReport={activeReport} openReport={openReport} />}
            {view === "candidates" && <CandidateFindingsPage activeReport={activeReport} runScan={runScan} busy={busy === "scan"} />}
            {view === "intel" && <IntelPage form={intelForm} setForm={setIntelForm} result={intelResult} busy={busy === "intel"} searchIntel={searchIntel} sendToChat={sendIntelToChat} activeReport={activeReport} />}
            {view === "runs" && <TracesPage runs={runs} activeRun={activeRun} openRun={openRun} openReport={openReport} />}
            {view === "settings" && <SettingsPage health={health} refresh={refresh} />}
            {(view === "dashboard" || view === "chat") && <InvestigationPanel runs={runs} activeRun={activeRun} activeReport={activeReport} openRun={openRun} openReport={openReport} health={health} setView={setView} />}
          </section>
        )}
        {view === "functions" && <SourcesPanel activeReport={activeReport} address={address} setAddress={setAddress} inspectFunction={inspectFunction} context={functionContext} busy={busy === "function"} />}
      </main>
    </div>
  );
}

function Sidebar(props: { view: View; setView: (view: View) => void; health: ApiHealth | null; reports: ReportSummary[]; chatThreads: ChatThread[]; activeThreadId: string; runScan: () => void; busy: string; openReport: (id: string) => void; loadChatThread: (id: string) => void; createChat: () => void; renameChat: () => void; clearChat: () => void; deleteChat: () => void; }) {
  const activeThread = props.chatThreads.find((thread) => thread.id === props.activeThreadId);
  return (
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">VA</div><div><strong>VulnAgent</strong><span>Binary Evidence Console</span></div></div>
      <p className="sidebar-label">工作区</p>
      <nav className="nav">{NAV_ITEMS.map((item) => <button key={item.view} className={props.view === item.view ? "active" : ""} onClick={() => props.setView(item.view)}><span>{item.icon}</span>{item.label}</button>)}</nav>
      <p className="sidebar-label">当前样本</p>
      <SidebarFact label="状态" value={props.health?.ida.connected ? "已连接" : "未连接"} tone={props.health?.ida.connected ? "ok" : "bad"} />
      <SidebarFact label="后端" value={props.health?.ida.connected ? "在线" : "离线"} />
      <SidebarFact label="架构 / 位数" value={`${props.health?.ida.architecture ?? "-"} / ${props.health?.ida.bits ?? "-"}-bit`} />
      <SidebarFact label="协议" value={props.health?.ida.protocol_version ?? "-"} />
      <p className="sidebar-label">LLM Agent</p>
      <SidebarFact label="供应商" value={props.health?.llm.provider ?? "DeepSeek"} />
      <SidebarFact label="模型" value={props.health?.llm.model ?? "deepseek-v4-flash"} />
      <SidebarFact label="状态" value={props.health?.llm.configured ? "已配置" : "缺少 Key"} tone={props.health?.llm.configured ? "ok" : "warn"} />
      <p className="sidebar-label">快速操作</p>
      <button className="danger-action" disabled={props.busy === "scan"} onClick={props.runScan}>{props.busy === "scan" ? "扫描中" : "启动基线扫描"}</button>
      <p className="sidebar-label">调查会话</p>
      <div className="session-current"><span>{short(activeThread?.title || "未选择会话", 26)}</span><small>{activeThread ? `更新 ${activeThread.updated_at.slice(0, 10)}` : "创建或选择一个调查会话"}</small></div>
      <div className="session-actions"><button title="新建调查" aria-label="新建调查" disabled={props.busy === "session"} onClick={props.createChat}>+</button><button title="重命名当前调查" aria-label="重命名当前调查" disabled={!activeThread || props.busy === "session"} onClick={props.renameChat}>R</button><button title="清空当前对话" aria-label="清空当前对话" disabled={!activeThread || props.busy === "session"} onClick={props.clearChat}>C</button><button title="删除当前调查" aria-label="删除当前调查" className="delete-session" disabled={!activeThread || props.busy === "session"} onClick={props.deleteChat}>X</button></div>
      <p className="sidebar-label">已保存调查</p>
      <select className="report-select" onChange={(event) => event.target.value && props.loadChatThread(event.target.value)} value={props.activeThreadId}>
        <option value="">选择调查...</option>
        {props.chatThreads.map((thread) => <option key={thread.id} value={thread.id}>{short(thread.title || thread.id, 26)}</option>)}
      </select>
      <p className="sidebar-label">已保存报告</p>
      <select className="report-select" onChange={(event) => event.target.value && props.openReport(event.target.value)} value=""><option value="">选择报告...</option>{props.reports.map((report) => <option key={report.id} value={report.id}>{short(report.id, 22)}</option>)}</select>
      <div className="sidebar-account"><div className="account-avatar">VA</div><div><strong>漏洞分析</strong><span>Security Workspace</span></div><b>⌄</b></div>
    </aside>
  );
}

function SidebarFact(props: { label: string; value: string; tone?: string }) { return <div className="sidebar-fact"><span>{props.label}</span><strong className={props.tone ? `tone-${props.tone}` : ""}>{props.value}</strong></div>; }

function Topbar(props: { health: ApiHealth | null; activeReport: ReportDetail | null; refresh: () => void; openReport: (id: string) => void; closeIda: () => void; busy: string; }) {
  const reportId = props.activeReport?.report_id ?? "";
  return <header className="topbar"><TopPathFact label="当前样本" value={props.health?.ida.database ?? ""} empty="未连接 IDB" action="切换" /><div className="top-statuses"><TopStatus label="IDA" value={props.health?.ida.connected ? "已连接" : "离线"} tone={props.health?.ida.connected ? "ok" : "bad"} /><TopStatus label="架构" value={`${props.health?.ida.architecture ?? "-"} / ${props.health?.ida.bits ?? "-"}-bit`} /><TopStatus label="模型" value={props.health?.llm.configured ? `${props.health?.llm.provider ?? "已配置"}` : "未配置"} tone={props.health?.llm.configured ? "ok" : "warn"} /></div><TopFact label="报告 ID" value={reportId ? short(reportId, 20) : "-"} title={reportId || undefined} /><div className="top-actions"><button onClick={props.refresh}>刷新</button><button onClick={() => reportId && props.openReport(reportId)} disabled={!reportId || props.busy === "report"}>打开报告</button><button className="danger-inline" onClick={props.closeIda} disabled={!props.health?.ida.connected || props.busy === "ida"}>{props.busy === "ida" ? "停止中" : "停止 IDA"}</button></div></header>;
}

function TopFact(props: { label: string; value: string; action?: string; tone?: string; title?: string }) { return <div className="top-fact" title={props.title ?? props.value}><span>{props.label}</span><strong className={props.tone ? `tone-${props.tone}` : ""}>{props.value}</strong>{props.action && <em>{props.action} &gt;</em>}</div>; }
function TopPathFact(props: { label: string; value: string; empty: string; action?: string }) {
  const path = splitPath(props.value);
  return <div className="top-fact top-path-fact" title={path.full || props.empty}><span>{props.label}</span><strong>{path.name || props.empty}</strong>{path.parent && <small>{path.parent}</small>}{props.action && <em>{props.action} &gt;</em>}</div>;
}
function TopStatus(props: { label: string; value: string; tone?: string }) { return <div className="top-status"><span>{props.label}</span><strong className={props.tone ? `tone-${props.tone}` : ""}><i />{props.value}</strong></div>; }
function Metric({ label, value, hint, tone = "neutral" }: { label: string; value: unknown; hint: string; tone?: string }) { return <div className={`metric ${tone}`}><span>{label}</span><strong>{String(value)}</strong><em>{hint}</em></div>; }

function ChatPanel(props: { draftSeed: ChatDraftSeed; chatLog: ChatMessage[]; showDemo: boolean; showToolCalls: boolean; setShowToolCalls: (value: boolean) => void; busy: boolean; submitChat: (message: string) => void; cancelChat: () => void; clearChat: () => void; createChat: () => void; threadTitle: string; }) {
  const feedRef = useRef<HTMLDivElement>(null);
  const [draft, setDraft] = useState("");

  useEffect(() => {
    const feed = feedRef.current;
    if (feed) feed.scrollTo({ top: feed.scrollHeight, behavior: "smooth" });
  }, [props.busy, props.chatLog, props.showDemo]);

  useEffect(() => {
    setDraft(props.draftSeed.text);
  }, [props.draftSeed.id, props.draftSeed.text]);

  function submitOnEnter(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key !== "Enter" || event.shiftKey) return;
    event.preventDefault();
    event.currentTarget.form?.requestSubmit();
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    const submitted = draft.trim();
    if (!submitted || props.busy) return;
    setDraft("");
    props.submitChat(submitted);
  }

  return (
    <section className="panel chat-panel">
      <PanelHead title="Agent 对话" action="新建会话" onAction={props.createChat} />
      <div className="chat-session-bar"><span>调查会话</span><strong>{props.threadTitle}</strong><button onClick={props.clearChat}>清空对话</button></div>
      <div className="chat-contextbar"><span className="context-pill live">DeepSeek</span><span>只读 IDA 工具</span><span>执行轨迹已记录</span><span>上下文已保存</span></div>
      <div className="chat-feed" ref={feedRef}>
        {props.showDemo && props.chatLog.length === 0 && <><Message role="user" text="Analyze this firmware for memory corruption vulnerabilities." at="10:14:22" /><Message role="assistant" text="Understood. I will analyze the firmware with focused route, source, sink, and evidence collection." at="10:14:24" />{props.showToolCalls && <ToolCard title="Tool call: discover_entry_points" status="Completed" rows={["Discovered 23 potential entry points.", "0x00401800, 0x00401588, 0x00401A2C..."]} />}<Message role="assistant" text="Identifying sources and sinks across the binary..." at="10:14:26" />{props.showToolCalls && <ToolCard title="Tool call: analyze_data_flows" status="Completed" rows={["Sources 18   Sinks 27   Flows 64   High Risk 3"]} />}</>}
        {!props.showDemo && <ChatTranscript messages={props.chatLog} showToolCalls={props.showToolCalls} />}
        {props.busy && <AgentActivity messages={props.chatLog} />}
        {!props.showDemo && props.chatLog.length === 0 && <div className="chat-empty"><strong>没有活动对话</strong><span>选择一个提示词，或让 VulnAgent 检查路由、输入源、危险调用和函数地址。</span></div>}
      </div>
      <div className="starter-row">{STARTER_PROMPTS.map((starter) => <button key={starter} disabled={props.busy} onClick={() => setDraft(starter)}>{short(starter, 42)}</button>)}</div>
      <form className="composer" onSubmit={submit}><div className="composer-box"><textarea value={draft} disabled={props.busy} onKeyDown={submitOnEnter} onChange={(event) => setDraft(event.target.value)} placeholder="输入要分析的路由、source、sink 或函数地址..." rows={2} /><div className="composer-meta"><span>/route /source /sink /trace /context press</span><span>Enter 发送 · Shift+Enter 换行</span></div></div>{props.busy ? <button type="button" className="stop-run" aria-label="停止 Agent 运行" onClick={props.cancelChat}>停止</button> : <button aria-label="发送消息" disabled={!draft.trim()}>发送</button>}</form>
      <div className="chat-footer"><span>{props.busy ? "VulnAgent 正在处理当前请求" : "本次调查会保存工具调用和证据记录"}</span><button type="button" className="switch-line" onClick={() => props.setShowToolCalls(!props.showToolCalls)}>执行细节 <b className={props.showToolCalls ? "on" : ""} /></button></div>
    </section>
  );
}

const Message = memo(function Message({ role, text, at }: { role: string; text: string; at: string }) { return <article className={`message ${role}`}><div className="avatar">{role === "assistant" ? "VA" : "You"}</div><div><header><strong>{role === "assistant" ? "VulnAgent" : "You"}</strong><time>{at}</time></header><MarkdownBody content={text} /></div></article>; });

const ChatTranscript = memo(function ChatTranscript({ messages, showToolCalls }: { messages: ChatMessage[]; showToolCalls: boolean }) {
  const toolResults = new Map(
    messages
      .filter((message) => message.role === "tool" && message.tool_call_id)
      .map((message) => [message.tool_call_id!, message])
  );
  return <>{messages.map((message, index) => message.role === "tool" ? null : <ChatMessageItem key={message.id || index} message={message} showToolCalls={showToolCalls} toolResults={toolResults} />)}</>;
});

const ChatMessageItem = memo(function ChatMessageItem({ message, showToolCalls, toolResults }: { message: ChatMessage; showToolCalls: boolean; toolResults: Map<string, ChatMessage> }) {
  const role = message.role === "user" ? "user" : "assistant";
  return <>{message.content && <article className={`message ${role}`}><div className="avatar">{role === "assistant" ? "VA" : "You"}</div><div><header><strong>{role === "assistant" ? "VulnAgent" : "You"}</strong><time>{nowTime()}</time></header><MarkdownBody content={message.content} /></div></article>}{showToolCalls && message.tool_calls?.map((toolCall) => <ToolExecutionCard key={toolCall.id || toolCall.name} toolCall={toolCall} result={toolResults.get(toolCall.id)} />)}</>;
});

const ToolExecutionCard = memo(function ToolExecutionCard({ toolCall, result }: { toolCall: { id: string; name: string; args: Record<string, unknown> }; result?: ChatMessage }) {
  const status = !result ? "Queued" : result.status === "error" ? "Failed" : "Completed";
  const rows = [toolInputSummary(toolCall.args)];
  if (result) rows.push(shortToolContent(result.content, 220));
  return <ToolCard title={`IDA tool: ${toolCall.name}`} status={status} rows={rows} raw={JSON.stringify({ input: toolCall.args, output: result ? parseJson(result.content) : undefined }, null, 2)} />;
});

const AgentActivity = memo(function AgentActivity({ messages }: { messages: ChatMessage[] }) {
  const latestTool = [...messages].reverse().find((message) => message.role === "tool");
  return <div className="agent-activity" role="status"><div className="activity-spinner" /><div><strong>VulnAgent is working</strong><span>{latestTool ? `Latest completed step: ${latestTool.name || "IDA tool"}. Preparing the next response.` : "Preparing context and requesting model analysis."}</span></div></div>;
});

function SettingsPage({ health, refresh }: { health: ApiHealth | null; refresh: () => void }) {
  const [provider, setProvider] = useState("DeepSeek");
  const [model, setModel] = useState("deepseek-v4-flash");
  const [baseUrl, setBaseUrl] = useState("https://api.deepseek.com");
  const [temperature, setTemperature] = useState(0);
  const [maxTokens, setMaxTokens] = useState(2400);
  const [apiKey, setApiKey] = useState("");
  const [idaPath, setIdaPath] = useState("");
  const [idaWritable, setIdaWritable] = useState(false);
  const [idaBusy, setIdaBusy] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const config = health?.llm;
    if (!config) return;
    setProvider(config.provider ?? "DeepSeek");
    setModel(config.model ?? "deepseek-v4-flash");
    setBaseUrl(config.base_url && config.base_url !== "default" ? config.base_url : "");
    setTemperature(config.temperature ?? 0);
    setMaxTokens(config.max_tokens ?? 2400);
  }, [health?.llm.configured, health?.llm.provider, health?.llm.model, health?.llm.base_url, health?.llm.temperature, health?.llm.max_tokens]);
  useEffect(() => {
    if (health?.ida.database) setIdaPath(health.ida.database);
  }, [health?.ida.database]);

  async function save() {
    setSaving(true);
    setMessage("");
    try {
      await api.updateLlmConfig({ provider, model: model.trim(), base_url: baseUrl.trim(), temperature, max_tokens: maxTokens, api_key: apiKey });
      setApiKey("");
      setMessage("Model configuration applied to the running API.");
      await refresh();
    } catch (exc) {
      setMessage(String(exc));
    } finally {
      setSaving(false);
    }
  }

  async function reset() {
    setSaving(true);
    setMessage("");
    try {
      await api.resetLlmConfig();
      setMessage("Runtime override cleared. The API is using .env settings.");
      await refresh();
    } catch (exc) {
      setMessage(String(exc));
    } finally {
      setSaving(false);
    }
  }

  async function openIda() {
    if (!idaPath.trim()) return;
    setIdaBusy(true);
    setMessage("");
    try {
      const result = await api.openIdaDatabase(idaPath.trim(), idaWritable);
      setMessage(`IDA database opened: ${result.database}${result.writable ? " (writable)" : " (read-only)"}`);
      await refresh();
    } catch (exc) {
      setMessage(String(exc));
    } finally {
      setIdaBusy(false);
    }
  }

  async function closeIda(save: boolean) {
    setIdaBusy(true);
    setMessage("");
    try {
      await api.closeIdaDatabase(save);
      setMessage(save ? "IDA database saved and closed." : "IDA database closed without saving.");
      await refresh();
    } catch (exc) {
      setMessage(String(exc));
    } finally {
      setIdaBusy(false);
    }
  }

  return (
    <section className="panel data-page settings-page">
      <PanelHead title="Model Settings" action={saving ? "Applying" : "Apply"} onAction={save} />
      <div className="settings-hero">
        <div>
          <strong>Agent Runtime Configuration</strong>
          <span>Change the active model without exposing API keys in the UI. Runtime changes last until the API restarts.</span>
        </div>
        <div className="settings-badges">
          <span className={health?.llm.configured ? "ok" : "bad"}>{health?.llm.configured ? "LLM ready" : "Missing key"}</span>
          <span className={health?.patching?.enabled ? "warn" : "neutral"}>{health?.patching?.enabled ? "Write tools enabled" : "Read-only tools"}</span>
        </div>
      </div>
      <div className="settings-layout">
        <div className="table-card settings-card">
          <div className="table-head"><strong>Provider</strong><span>{provider}</span></div>
          <div className="settings-form">
            <label><span>Provider</span><select value={provider} onChange={(event) => { setProvider(event.target.value); if (event.target.value === "DeepSeek") { setBaseUrl("https://api.deepseek.com"); setModel("deepseek-v4-flash"); } }}><option>DeepSeek</option><option>OpenAI-compatible</option></select></label>
            <label><span>Model</span><input value={model} onChange={(event) => setModel(event.target.value)} placeholder="deepseek-v4-flash" /></label>
            <label><span>Base URL</span><input value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://api.deepseek.com" /></label>
            <label><span>Temperature <em>{temperature.toFixed(1)}</em></span><input type="range" min="0" max="2" step="0.1" value={temperature} onChange={(event) => setTemperature(Number(event.target.value))} /></label>
            <label><span>Max output tokens</span><input type="number" min="256" max="128000" step="256" value={maxTokens} onChange={(event) => setMaxTokens(Number(event.target.value))} /></label>
            <label><span>API Key <em>{health?.llm.api_key_configured ? "Configured" : "Required"}</em></span><input type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder="Leave blank to keep current key" autoComplete="new-password" /></label>
          </div>
          <div className="settings-actions"><button className="primary-inline" disabled={saving || !model.trim()} onClick={save}>{saving ? "Applying..." : "Apply configuration"}</button><button className="secondary-inline" disabled={saving} onClick={reset}>Reset to .env</button></div>
          {message && <div className="settings-message">{message}</div>}
        </div>
        <div className="table-card settings-card ida-control-card">
          <div className="table-head"><strong>IDA Database</strong><span className={health?.ida.connected ? "state ok" : "state bad"}>{health?.ida.connected ? "Connected" : "Offline"}</span></div>
          <div className="settings-form">
            <label><span>IDB / ELF Path</span><input value={idaPath} onChange={(event) => setIdaPath(event.target.value)} placeholder="E:\\firmware\\squashfs-root\\bin\\boa or /path/to/file.i64" /></label>
            <label className="checkbox-label"><input type="checkbox" checked={idaWritable} onChange={(event) => setIdaWritable(event.target.checked)} /><span>Request writable session for patch/export operations</span></label>
          </div>
          <div className="settings-actions">
            <button className="primary-inline" disabled={idaBusy || !idaPath.trim()} onClick={openIda}>{idaBusy ? "Working..." : "Open Database"}</button>
            <button className="secondary-inline" disabled={idaBusy || !health?.ida.connected} onClick={() => closeIda(false)}>Close</button>
            <button className="secondary-inline" disabled={idaBusy || !health?.ida.connected} onClick={() => closeIda(true)}>Save & Close</button>
          </div>
        </div>
        <div className="table-card settings-card runtime-card">
          <div className="table-head"><strong>Active Runtime</strong><span>{health?.llm.provider ?? "Not configured"}</span></div>
          <dl className="settings-status">
            <dt>Provider</dt><dd>{health?.llm.provider ?? "Not configured"}</dd>
            <dt>Model</dt><dd>{health?.llm.model ?? "-"}</dd>
            <dt>Base URL</dt><dd>{health?.llm.base_url ?? "-"}</dd>
            <dt>API Key</dt><dd><span className={health?.llm.api_key_configured ? "state ok" : "state bad"}>{health?.llm.api_key_configured ? "Configured" : "Missing"}</span></dd>
            <dt>IDA Backend</dt><dd><span className={health?.ida.connected ? "state ok" : "state bad"}>{health?.ida.connected ? "Connected" : "Offline"}</span></dd>
            <dt>Write Tools</dt><dd><span className={health?.patching?.enabled ? "state warn" : "state ok"}>{health?.patching?.enabled ? "Enabled" : "Disabled"}</span></dd>
          </dl>
        </div>
      </div>
    </section>
  );
}

const MarkdownBody = memo(function MarkdownBody({ content }: { content: string }) { return <div className="markdown-body"><ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown></div>; });
const ToolCard = memo(function ToolCard(props: { title: string; status: string; rows: string[]; raw?: string }) { return <details className={`tool-card tool-${props.status.toLowerCase()}`}><summary><strong>{props.title}</strong><span>{props.status}</span></summary>{props.rows.map((row) => <p key={row}>{row}</p>)}{props.raw && props.raw.length > 180 && <pre>{props.raw}</pre>}</details>; });
function toolInputSummary(args: Record<string, unknown> = {}) { const entries = Object.entries(args); if (!entries.length) return "no arguments"; const visible = entries.slice(0, 4).map(([key, value]) => `${key}=${short(value, 44)}`); if (entries.length > 4) visible.push(`+${entries.length - 4} more`); return visible.join(", "); }
function shortToolContent(content: string, limit: number) { const parsed = parseJson(content); if (typeof parsed === "string") return short(parsed, limit); if (parsed && typeof parsed === "object") { const record = parsed as Record<string, unknown>; if (typeof record.summary === "string") return short(record.summary, limit); if (typeof record.error === "string") return short(record.error, limit); if (Array.isArray(record.confirmed_sources)) { const pendingSinks = Array.isArray(record.pending_sinks) ? record.pending_sinks.length : 0; return `confirmed_sources=${record.confirmed_sources.length}, pending_sinks=${pendingSinks}`; } } return short(parsed, limit); }

function SessionsPage(props: { threads: ChatThread[]; activeThreadId: string; busy: boolean; createChat: () => void; loadChatThread: (id: string) => void; renameChat: (id?: string) => void; clearChat: (id?: string) => void; deleteChat: (id?: string) => void; }) {
  const activeThread = props.threads.find((thread) => thread.id === props.activeThreadId);
  const [query, setQuery] = useState("");
  const filteredThreads = props.threads.filter((thread) => {
    const haystack = `${thread.title} ${thread.id} ${thread.sample_id ?? ""}`.toLowerCase();
    return haystack.includes(query.trim().toLowerCase());
  });
  return (
    <section className="panel data-page sessions-page">
      <PanelHead title="Investigation Sessions" action={props.busy ? "Working" : "New Session"} onAction={props.createChat} />
      <div className="page-summary sessions-summary">
        <MiniMetric label="Sessions" value={props.threads.length} hint="Saved investigations" />
        <MiniMetric label="Active" value={activeThread ? short(activeThread.title, 24) : "-"} hint={activeThread ? short(activeThread.id, 16) : "No active session"} tone={activeThread ? "ok" : "neutral"} />
        <MiniMetric label="Latest Update" value={props.threads[0]?.updated_at?.slice(0, 10) || "-"} hint="Most recent thread" />
        <MiniMetric label="Storage" value="SQLite" hint="Chat history persisted" tone="ok" />
      </div>
      <div className="sessions-toolbar">
        <div>
          <strong>Session Manager</strong>
          <span>Open, rename, clear, or delete persisted Agent conversations.</span>
        </div>
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search title, thread id, or sample..." />
      </div>
      <div className="table-card sessions-card">
        <div className="table-head"><strong>Saved Investigation Threads</strong><span>{filteredThreads.length} shown</span></div>
        <div className="session-list">
          {filteredThreads.map((thread) => (
            <article key={thread.id} className={thread.id === props.activeThreadId ? "active" : ""}>
              <div className="session-title">
                <strong>{thread.title || "New investigation"}</strong>
                <span>{short(thread.id, 18)}</span>
              </div>
              <dl>
                <dt>Created</dt><dd>{thread.created_at?.replace("T", " ").slice(0, 19) || "-"}</dd>
                <dt>Updated</dt><dd>{thread.updated_at?.replace("T", " ").slice(0, 19) || "-"}</dd>
                <dt>Sample</dt><dd>{thread.sample_id ? short(thread.sample_id, 24) : "Not linked"}</dd>
              </dl>
              <div className="session-row-actions">
                <button className="primary-inline" onClick={() => props.loadChatThread(thread.id)}>Open</button>
                <button className="secondary-inline" disabled={props.busy} onClick={() => props.renameChat(thread.id)}>Rename</button>
                <button className="secondary-inline" disabled={props.busy} onClick={() => props.clearChat(thread.id)}>Clear</button>
                <button className="secondary-inline danger-inline" disabled={props.busy} onClick={() => props.deleteChat(thread.id)}>Delete</button>
              </div>
            </article>
          ))}
          {props.threads.length === 0 && <div className="empty-state">No investigation session has been created. Start a new session before Agent Chat analysis.</div>}
          {props.threads.length > 0 && filteredThreads.length === 0 && <div className="empty-state">No session matches the current search.</div>}
        </div>
      </div>
    </section>
  );
}

function InvestigationPanel(props: { runs: HarnessRun[]; activeRun: HarnessRunDetail | null; activeReport: ReportDetail | null; openRun: (id: string) => void; openReport: (id: string) => void; health: ApiHealth | null; setView: (view: View) => void; }) {
  const findings = props.activeReport?.findings ?? [];
  const warnings = findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length;
  const sources = props.activeReport?.source_candidates.length ?? 0;
  const verified = findings.filter((finding) => finding.verification_status === "verified").length;
  return <aside className="panel investigation-panel"><PanelHead title="Investigation State" action="Refresh" /><div className="state-section summary-section"><div className="section-title"><h3>Findings Summary</h3><span>⌃</span></div><div className="summary-metrics"><MiniMetric label="Findings" value={findings.length} hint="" tone={findings.length ? "bad" : "neutral"} /><MiniMetric label="Warnings" value={warnings} hint="" tone={warnings ? "warn" : "neutral"} /><MiniMetric label="Sources" value={sources} hint="" /><MiniMetric label="Verified" value={verified} hint="" tone="ok" /></div><button className="panel-link" onClick={() => props.setView("reports")}>View all findings <b>→</b></button></div><div className="run-card"><div className="section-title"><h3>Harness Runs</h3><span>⌃</span></div><div className="run-table"><div className="run-table-head"><span>Run ID</span><span>Status</span><span>Findings</span></div>{props.runs.slice(0, 4).map((run) => <button key={run.id} onClick={() => props.openRun(run.id)}><span>{short(run.id, 12)}</span><em className={`state ${stateTone(run.status)}`}>{run.status}</em><strong>{run.report_id ? "1" : "0"}</strong></button>)}{props.runs.length === 0 && <p>No harness run has been recorded.</p>}</div><button className="panel-link" onClick={() => props.setView("runs")}>View all runs <b>→</b></button></div><TraceTimeline run={props.activeRun} /><div className="focus-card"><div className="section-title"><h3>Current Focus</h3><span>⌃</span></div><dl><dt>Finding</dt><dd>{props.activeRun?.mode ?? "Agent analysis"}</dd><dt>Status</dt><dd><span className={`state ${stateTone(props.activeRun?.status)}`}>{props.activeRun?.status ?? "idle"}</span></dd><dt>Backend</dt><dd>{props.health?.ida.connected ? "Connected" : "Disconnected"}</dd><dt>Last Updated</dt><dd>{props.activeRun?.finished_at || props.activeRun?.started_at || "-"}</dd></dl>{props.activeRun?.report_id && <button onClick={() => props.openReport(props.activeRun!.report_id)}>Open linked report</button>}</div></aside>;
}

function TraceTimeline({ run }: { run: HarnessRunDetail | null }) { return <div className="trace-card"><div className="trace-head"><h3>Trace Timeline</h3><select defaultValue="all"><option value="all">All Events</option></select></div><div className="timeline">{!run && <p>Select a run to inspect trace events.</p>}{run?.trace_events.slice(0, 7).map((event) => <article key={event.id} className={event.event_type.includes("fail") ? "failed" : ""}><time>{event.created_at?.slice(11, 19) || "--:--:--"}</time><div><strong>{event.event_type}</strong><p>{event.message}</p><small>{short(parseJson(event.data_json), 90)}</small></div></article>)}</div>{run && <button className="panel-link">View full trace &gt;</button>}</div>; }

function OverviewPage(props: { activeReport: ReportDetail | null; reports: ReportSummary[]; runs: HarnessRun[]; openReport: (id: string) => void; openRun: (id: string) => void; }) {
  const findings = props.activeReport?.findings ?? [];
  return <section className="panel data-page overview-page"><PanelHead title="Overview" action="Refresh" /><div className="overview-grid"><div className="overview-column"><div className="table-card"><div className="table-head"><strong>Recent Findings</strong><button onClick={() => props.openReport(props.activeReport?.report_id || "")}>View all</button></div><table><thead><tr><th>Category</th><th>Severity</th><th>Status</th><th>Evidence</th></tr></thead><tbody>{findings.slice(0, 6).map((finding) => <tr key={finding.finding_id}><td>{finding.category}</td><td><span className={`risk ${finding.severity}`}>{finding.severity}</span></td><td><span className={`state ${stateTone(finding.verification_status)}`}>{finding.verification_status}</span></td><td>{short(finding.evidence?.[0] || `${finding.source || "source"} -> ${finding.sink.sink_name}`, 70)}</td></tr>)}{findings.length === 0 && <tr><td colSpan={4}>No findings in the active report.</td></tr>}</tbody></table></div><div className="table-card"><div className="table-head"><strong>Saved Reports</strong><span>{props.reports.length} reports</span></div><div className="overview-report-list">{props.reports.slice(0, 5).map((report) => <button key={report.id} onClick={() => props.openReport(report.id)}><span>{short(report.id, 26)}</span><em>{report.created_at?.slice(0, 10) || "Saved report"}</em></button>)}{props.reports.length === 0 && <p>No saved reports yet.</p>}</div></div></div><div className="overview-column"><div className="table-card"><div className="table-head"><strong>Recent Harness Runs</strong><button onClick={() => props.openRun(props.runs[0]?.id || "")}>View traces</button></div><div className="overview-run-list">{props.runs.slice(0, 6).map((run) => <button key={run.id} onClick={() => props.openRun(run.id)}><span>{short(run.id, 18)}</span><em className={`state ${stateTone(run.status)}`}>{run.status}</em><small>{run.mode}</small></button>)}{props.runs.length === 0 && <p>No harness runs yet.</p>}</div></div><div className="overview-note"><strong>Analysis workflow</strong><p>Firmware triage → IDA evidence collection → Source-to-Sink validation → auditable report.</p><button className="panel-link" onClick={() => props.openRun(props.runs[0]?.id || "")}>Open latest trace <b>→</b></button></div></div></div></section>;
}

function FirmwareTriagePage(props: { root: string; setRoot: (value: string) => void; limit: number; setLimit: (value: number) => void; report: FirmwareTriageReport | null; selectedPath: string; setSelectedPath: (value: string) => void; busy: boolean; runTriage: () => void; sendToChat: (candidate: FirmwareCandidate) => void; }) {
  const selected = props.report?.candidates.find((candidate) => candidate.relative_path === props.selectedPath) ?? props.report?.candidates[0] ?? null;
  return (
    <section className="panel data-page firmware-page">
      <PanelHead title="Firmware Directory Mode" action={props.busy ? "Scanning" : "Scan"} onAction={props.runTriage} />
      <div className="firmware-form">
        <label>
          <span>Extracted firmware filesystem</span>
          <input value={props.root} onChange={(event) => props.setRoot(event.target.value)} placeholder="E:\\path\\to\\squashfs-root" />
        </label>
        <label>
          <span>Candidate limit</span>
          <input type="number" min={1} max={100} value={props.limit} onChange={(event) => props.setLimit(Number(event.target.value))} />
        </label>
        <button disabled={props.busy || !props.root.trim()} onClick={props.runTriage}>{props.busy ? "Scanning..." : "Scan Firmware"}</button>
      </div>
      {!props.report && <div className="empty-state">Start here when you only have a rootfs or squashfs-root directory. VulnAgent will rank Web-facing binaries before IDA analysis.</div>}
      {props.report && (
        <>
          <div className="page-summary">
            <MiniMetric label="Files" value={props.report.total_files} hint="Filesystem entries" />
            <MiniMetric label="ELF Binaries" value={props.report.elf_files} hint="IDA candidates" />
            <MiniMetric label="Web Endpoints" value={props.report.web_endpoints.length} hint="Route hints" />
            <MiniMetric label="Sensitive Files" value={props.report.sensitive_files.length} hint="Config exposure" tone={props.report.sensitive_files.length ? "warn" : "neutral"} />
          </div>
          <div className="firmware-layout">
            <div className="table-card">
              <div className="table-head"><strong>Recommended IDA Targets</strong><span className="path-tail" title={props.report.root}>{props.report.root}</span></div>
              <div className="firmware-candidates">
                {props.report.candidates.map((candidate) => (
                  <button key={candidate.relative_path} className={selected?.relative_path === candidate.relative_path ? "active" : ""} onClick={() => props.setSelectedPath(candidate.relative_path)}>
                    <span>#{candidate.rank}</span>
                    <strong>{candidate.relative_path}</strong>
                    <em>{candidate.score}</em>
                    <small>{candidate.machine}/{candidate.elf_class}/{candidate.endian}</small>
                  </button>
                ))}
              </div>
            </div>
            <div className="firmware-detail">
              {selected ? (
                <>
                  <div className="table-card">
                    <div className="table-head"><strong>{selected.relative_path}</strong><span>score {selected.score}</span></div>
                    <div className="detail-list">
                      <strong>Reasons</strong>
                      {selected.reasons.map((reason) => <p key={reason}>{reason}</p>)}
                      {selected.route_markers.length > 0 && <><strong>Route markers</strong><p>{selected.route_markers.join(", ")}</p></>}
                      {selected.source_markers.length > 0 && <><strong>Source markers</strong><p>{selected.source_markers.join(", ")}</p></>}
                      {selected.sink_markers.length > 0 && <><strong>Sink markers</strong><p>{selected.sink_markers.join(", ")}</p></>}
                      {selected.web_endpoints.length > 0 && <><strong>Mapped endpoints</strong><p>{selected.web_endpoints.slice(0, 8).join(", ")}</p></>}
                      {selected.startup_references.length > 0 && <><strong>Startup refs</strong><p>{selected.startup_references.join(", ")}</p></>}
                    </div>
                  </div>
                  <div className="table-card command-card">
                    <div className="table-head"><strong>Next Step</strong><span>Binary Mode</span></div>
                    <pre>{selected.ida_backend_command}</pre>
                    <button className="primary-inline" onClick={() => props.sendToChat(selected)}>Send target to Agent Chat</button>
                  </div>
                </>
              ) : <div className="empty-state">Select a candidate to inspect its evidence.</div>}
            </div>
          </div>
          <div className="firmware-extra">
            <div className="table-card">
              <div className="table-head"><strong>Web Endpoint Samples</strong><span>{props.report.web_endpoints.length}</span></div>
              <table><thead><tr><th>Endpoint</th><th>Source File</th><th>Candidate</th></tr></thead><tbody>{props.report.web_endpoints.slice(0, 12).map((endpoint, index) => <tr key={`${endpoint.endpoint}-${index}`}><td>{endpoint.endpoint}</td><td>{endpoint.source_file}</td><td>{endpoint.candidate || "-"}</td></tr>)}{props.report.web_endpoints.length === 0 && <tr><td colSpan={3}>No Web endpoint hints found.</td></tr>}</tbody></table>
            </div>
            <div className="table-card">
              <div className="table-head"><strong>Sensitive Files</strong><span>{props.report.sensitive_files.length}</span></div>
              <div className="sensitive-list">{props.report.sensitive_files.slice(0, 20).map((path) => <span key={path}>{path}</span>)}{props.report.sensitive_files.length === 0 && <p>No sensitive file names matched.</p>}</div>
            </div>
          </div>
        </>
      )}
    </section>
  );
}

function FindingsPage(props: { reports: ReportSummary[]; activeReport: ReportDetail | null; openReport: (id: string) => void; }) {
  const findings = props.activeReport?.findings ?? [];
  const verified = findings.filter((finding) => finding.verification_status === "verified").length;
  const high = findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length;
  return <section className="panel data-page findings-page"><PanelHead title="Findings" action="Export JSON" /><div className="page-summary"><MiniMetric label="Total Findings" value={findings.length} hint="Open issues" /><MiniMetric label="High Risk" value={high} hint="Critical / high" tone={high > 0 ? "bad" : "neutral"} /><MiniMetric label="Verified" value={verified} hint="Confirmed" tone="ok" /><MiniMetric label="Reports" value={props.reports.length} hint="Saved runs" /></div><div className="table-card"><div className="table-head"><strong>Finding Evidence</strong><span>{props.activeReport?.report_id ? short(props.activeReport.report_id, 28) : "No active report"}</span></div><table><thead><tr><th>ID</th><th>Category</th><th>Severity</th><th>Source</th><th>Sink</th><th>Status</th></tr></thead><tbody>{findings.map((finding) => <tr key={finding.finding_id}><td>{finding.finding_id}</td><td>{finding.category}</td><td><span className={`risk ${finding.severity}`}>{finding.severity}</span></td><td>{finding.source || "-"}</td><td>{finding.sink.caller_name} / {finding.sink.sink_name}</td><td>{finding.verification_status}</td></tr>)}{findings.length === 0 && <tr><td colSpan={6}>No findings yet. Run Baseline Scan or open a saved report.</td></tr>}</tbody></table></div><div className="evidence-grid">{findings.slice(0, 6).map((finding) => <article className="evidence-item" key={finding.finding_id}><header><strong>{finding.finding_id}</strong><span className={`risk ${finding.severity}`}>{finding.severity}</span></header><p>{finding.category}</p><small>{finding.evidence?.[0] || `${finding.source || "source"} -> ${finding.sink.sink_name}`}</small></article>)}</div><div className="report-strip">{props.reports.slice(0, 6).map((report) => <button key={report.id} onClick={() => props.openReport(report.id)}>{short(report.id, 22)}</button>)}</div></section>;
}

function CandidateFindingsPage(props: { activeReport: ReportDetail | null; runScan: () => void; busy: boolean; }) {
  const candidates = props.activeReport?.candidate_findings ?? [];
  const counts = {
    verified: candidates.filter((candidate) => candidate.status === "verified").length,
    unverified: candidates.filter((candidate) => candidate.status === "unverified").length,
    rejected: candidates.filter((candidate) => candidate.status === "rejected").length
  };
  return <section className="panel data-page candidate-page"><PanelHead title="Candidate Findings" action={props.busy ? "Scanning" : "Baseline Scan"} onAction={props.runScan} /><div className="page-summary"><MiniMetric label="Validated" value={candidates.length} hint="Top sink candidates" /><MiniMetric label="Verified" value={counts.verified} hint="Evidence-backed" tone="ok" /><MiniMetric label="Unverified" value={counts.unverified} hint="Needs evidence" tone="warn" /><MiniMetric label="Rejected" value={counts.rejected} hint="Clean / constant" /></div><div className="candidate-list">{candidates.map((candidate) => <CandidateCard key={candidate.candidate_id} candidate={candidate} />)}{candidates.length === 0 && <div className="empty-state">No validated candidates in this report. Run Baseline Scan to validate high-priority sinks automatically.</div>}</div></section>;
}

function CandidateCard({ candidate }: { candidate: CandidateFinding }) {
  return <article className="candidate-card"><header><div><span className={`state ${stateTone(candidate.status)}`}>{candidate.status}</span><strong>{candidate.category}</strong></div><span className={`risk ${candidate.severity}`}>{candidate.severity}</span></header><div className="candidate-location"><code>{candidate.caller_name} @ {candidate.caller_ea}</code><span>calls</span><code>{candidate.sink_name} @ {candidate.sink_ea}</code></div><p>{candidate.conclusion}</p><div className="candidate-arguments">{candidate.arguments.map((argument) => <div key={argument.index}><strong>arg {argument.index}</strong><code>{argument.expression || "?"}</code><span className={`state ${stateTone(argument.taint_status)}`}>{argument.taint_status || "unknown"}</span><small>{argument.source_func || argument.reason || "origin unresolved"}</small></div>)}</div>{candidate.missing_evidence.length > 0 && <details><summary>Missing evidence ({candidate.missing_evidence.length})</summary><ul>{candidate.missing_evidence.map((item) => <li key={item}>{item}</li>)}</ul></details>}<footer>Confidence {Math.round(candidate.confidence * 100)}%</footer></article>;
}

type IntelFormState = {
  vendor: string;
  product: string;
  firmwareVersion: string;
  component: string;
  vulnerabilityType: string;
  route: string;
  sink: string;
  symbols: string;
  keywords: string;
  sources: string;
  maxResults: number;
};

function IntelPage(props: { form: IntelFormState; setForm: (value: IntelFormState) => void; result: IntelSearchResult | null; busy: boolean; searchIntel: () => void; sendToChat: () => void; activeReport: ReportDetail | null; }) {
  const best = props.result?.matches[0];
  const strong = props.result?.matches.filter((match) => match.score >= 70).length ?? 0;
  const possible = props.result?.matches.filter((match) => match.score >= 40 && match.score < 70).length ?? 0;
  const errors = props.result?.errors.length ?? 0;
  const queryPreview = buildIntelQueryPreview(props.form);
  const evidencePreview = hiddenIntelEvidence(props.form);

  function update<K extends keyof IntelFormState>(key: K, value: IntelFormState[K]) {
    props.setForm({ ...props.form, [key]: value });
  }

  function fillFromReport() {
    const finding = props.activeReport?.findings[0];
    const sample = props.activeReport?.sample;
    const symbols = [
      finding?.sink?.caller_name,
      finding?.sink?.sink_name,
      ...((finding?.evidence ?? []).slice(0, 2)),
    ].filter(Boolean).join(", ");
    props.setForm({
      ...props.form,
      component: props.form.component || sample?.database?.split(/[\\/]/).pop() || "",
      vulnerabilityType: props.form.vulnerabilityType || finding?.category || "command injection",
      sink: props.form.sink || finding?.sink?.sink_name || "",
      symbols: props.form.symbols || symbols,
    });
  }

  function clearEvidence() {
    props.setForm({
      ...props.form,
      component: "",
      route: "",
      sink: "",
      symbols: "",
      keywords: "",
    });
  }

  return (
    <section className="panel data-page intel-page">
      <PanelHead title="CVE Intelligence" action={props.busy ? "Searching" : "Search"} onAction={props.searchIntel} />
      <div className="intel-command-strip">
        <div>
          <strong>Public query</strong>
          <code>{queryPreview || "Vendor Product Firmware"}</code>
        </div>
        <div>
          <strong>Assessment</strong>
          <span className={`state ${props.result?.assessment === "lookup_failed" ? "bad" : props.result?.assessment === "likely_known_vulnerability" ? "ok" : "neutral"}`}>{formatAssessment(props.result?.assessment)}</span>
        </div>
      </div>
      <div className="intel-layout">
        <div className="intel-query table-card">
          <div className="table-head"><strong>Known Vulnerability Lookup</strong><span>Broad search, local rerank</span></div>
          <div className="intel-query-note">
            <strong>Only fill public CVE search terms.</strong>
            <span>CVE.org will search short queries like <code>{queryPreview || "D-Link DIR-882"}</code>. Binary-only details are used only for local scoring.</span>
          </div>
          <div className="intel-form intel-form-compact">
            <label><span>Vendor</span><input value={props.form.vendor} onChange={(event) => update("vendor", event.target.value)} placeholder="D-Link" /></label>
            <label><span>Product / Model</span><input value={props.form.product} onChange={(event) => update("product", event.target.value)} placeholder="DIR-882" /></label>
            <label><span>Firmware Version</span><input value={props.form.firmwareVersion} onChange={(event) => update("firmwareVersion", event.target.value)} placeholder="1.30B06" /></label>
            <label><span>Vulnerability Type</span><input value={props.form.vulnerabilityType} onChange={(event) => update("vulnerabilityType", event.target.value)} placeholder="command injection" /></label>
            <label><span>Sources</span><select value={props.form.sources} onChange={(event) => update("sources", event.target.value)}><option value="cveorg,nvd,github">CVE.org + NVD + GitHub</option><option value="cveorg">CVE.org only</option><option value="nvd">NVD only</option><option value="github">GitHub only</option></select></label>
            <label><span>Max Results</span><input type="number" min={1} max={50} value={props.form.maxResults} onChange={(event) => update("maxResults", Number(event.target.value))} /></label>
          </div>
          {evidencePreview && <div className="intel-evidence-note"><div><strong>Local rerank evidence</strong><span>{evidencePreview}</span></div><button onClick={clearEvidence}>Clear</button></div>}
          <div className="settings-actions intel-actions">
            <button className="primary-inline" disabled={props.busy} onClick={props.searchIntel}>{props.busy ? "Searching..." : "Search intelligence"}</button>
            <button className="secondary-inline" disabled={!props.activeReport} onClick={fillFromReport}>Use active report evidence</button>
            <button className="secondary-inline" disabled={!props.result} onClick={props.sendToChat}>Send to Agent Chat</button>
          </div>
        </div>
        <div className="intel-side">
          <div className="page-summary intel-summary">
            <MiniMetric label="Assessment" value={formatAssessment(props.result?.assessment)} hint={props.result ? "Current query" : "Not searched"} tone={props.result?.assessment === "likely_known_vulnerability" ? "ok" : props.result?.assessment === "lookup_failed" ? "bad" : "neutral"} />
            <MiniMetric label="Strong" value={strong} hint="Score >= 70" tone={strong ? "ok" : "neutral"} />
            <MiniMetric label="Possible" value={possible} hint="Score 40-69" tone={possible ? "warn" : "neutral"} />
            <MiniMetric label="Errors" value={errors} hint="Source failures" tone={errors ? "bad" : "neutral"} />
          </div>
          <div className="table-card intel-best">
            <div className="table-head"><strong>Best Match</strong><span>{best ? `${best.score}/100` : "No match"}</span></div>
            {best ? <IntelMatchCard match={best} compact /> : <div className="empty-state">Run a lookup to compare the current evidence with known CVE records.</div>}
          </div>
        </div>
      </div>
      <div className="table-card intel-results">
        <div className="table-head"><strong>Matched References</strong><span>{props.result?.searched_sources.join(", ") || "No sources searched"}</span></div>
        {props.result?.errors.length ? <div className="intel-errors">{props.result.errors.map((error) => <span key={error}>{error}</span>)}</div> : null}
        <div className="intel-match-list">
          {props.result?.matches.map((match) => <IntelMatchCard key={`${match.reference.source}-${match.reference.identifier}-${match.reference.url}`} match={match} />)}
          {props.result && props.result.matches.length === 0 && <div className="empty-state">No strong public intelligence match found.</div>}
          {!props.result && <div className="empty-state">Search by vendor, model, firmware version, and vulnerability type. Keep internal function names and sinks out of the public search query.</div>}
        </div>
      </div>
    </section>
  );
}

function IntelMatchCard({ match, compact = false }: { match: IntelSearchResult["matches"][number]; compact?: boolean }) {
  const ref = match.reference;
  return <article className={`intel-match ${compact ? "compact" : ""}`}><header><div><span className={`source-badge source-${ref.source}`}>{ref.source}</span><strong>{ref.identifier || ref.title || "Reference"}</strong></div><em className={`state ${match.confidence === "high" ? "ok" : match.confidence === "medium" ? "warn" : "neutral"}`}>{match.score}/100 {match.confidence}</em></header>{ref.description && <p>{compact ? short(ref.description, 240) : ref.description}</p>}<div className="intel-reasons">{match.reasons.map((reason) => <span key={reason}>{reason}</span>)}</div>{match.matched_terms.length > 0 && <small>Matched: {match.matched_terms.join(", ")}</small>}<footer><span>{ref.severity || "severity unknown"}</span>{ref.url && <a href={ref.url} target="_blank" rel="noreferrer">Open reference</a>}</footer></article>;
}

function SourcesPanel(props: { activeReport: ReportDetail | null; address: string; setAddress: (value: string) => void; inspectFunction: () => void; context: FunctionContext | null; busy: boolean; }) {
  const sources = props.activeReport?.source_candidates ?? [];
  return <section className="panel function-panel sources-page"><PanelHead title="Sources" action="IDA Context" /><div className="source-list"><div className="table-head"><strong>Source Candidates</strong><span>{sources.length} collected</span></div><div className="source-grid">{sources.slice(0, 12).map((source, index) => <article className="source-card" key={index}><strong>{recordTitle(source, `source-${index + 1}`)}</strong><p>{short(source, 140)}</p></article>)}{sources.length === 0 && <div className="empty-state">No source candidates yet. Run Baseline Scan to collect likely user-input sources.</div>}</div></div><div className="function-bar"><input value={props.address} onChange={(event) => props.setAddress(event.target.value)} /><button disabled={props.busy} onClick={props.inspectFunction}>{props.busy ? "Loading" : "Decompile"}</button></div>{props.context ? <div className="code-context large"><header><strong>{props.context.name}</strong><span>{props.context.start_ea} - {props.context.end_ea}</span></header><pre>{props.context.decompile_ok ? props.context.pseudocode : props.context.decompile_error}</pre></div> : <div className="empty-state">Enter a function address to inspect pseudocode and references.</div>}</section>;
}

function TracesPage(props: { runs: HarnessRun[]; activeRun: HarnessRunDetail | null; openRun: (id: string) => void; openReport: (id: string) => void; }) {
  return <section className="panel data-page traces-page"><PanelHead title="Harness Runs & Trace" action="Refresh" /><div className="trace-layout"><div className="table-card"><div className="table-head"><strong>Recent Runs</strong><span>{props.runs.length} runs</span></div><div className="run-list">{props.runs.map((run) => <button key={run.id} className={props.activeRun?.id === run.id ? "active" : ""} onClick={() => props.openRun(run.id)}><span>{short(run.id, 18)}</span><em className={`state ${stateTone(run.status)}`}>{run.status}</em><small>{run.mode}</small></button>)}{props.runs.length === 0 && <p>No harness run has been recorded.</p>}</div></div><div className="trace-detail"><TraceTimeline run={props.activeRun} /><div className="table-card"><div className="table-head"><strong>Trace Events</strong><span>{props.activeRun?.trace_events.length ?? 0} events</span></div><table><thead><tr><th>#</th><th>Event</th><th>Message</th><th>Time</th></tr></thead><tbody>{props.activeRun?.trace_events.map((event) => <tr key={event.id}><td>{event.sequence}</td><td>{event.event_type}</td><td>{event.message}</td><td>{event.created_at?.slice(11, 19)}</td></tr>)}{!props.activeRun && <tr><td colSpan={4}>Select a run to inspect trace events.</td></tr>}</tbody></table></div>{props.activeRun?.report_id && <button className="primary-inline" onClick={() => props.openReport(props.activeRun!.report_id)}>Open linked report</button>}</div></div></section>;
}

function recordTitle(value: unknown, fallback: string) { if (!value || typeof value !== "object") return fallback; const record = value as Record<string, unknown>; return String(record.name ?? record.function ?? record.function_name ?? record.address ?? record.ea ?? fallback); }
function splitCsv(value: string) { return value.split(",").map((item) => item.trim()).filter(Boolean); }
function splitSources(value: string): Array<"cveorg" | "nvd" | "github"> {
  const allowed = new Set(["cveorg", "nvd", "github"]);
  return splitCsv(value).filter((item) => allowed.has(item)) as Array<"cveorg" | "nvd" | "github">;
}
function formatAssessment(value = "") {
  return value ? value.replace(/_/g, " ") : "-";
}
function buildIntelQueryPreview(form: IntelFormState) {
  return [form.vendor, form.product, form.firmwareVersion].filter(Boolean).join(" ");
}
function hiddenIntelEvidence(form: IntelFormState) {
  return [
    form.component && `component: ${form.component}`,
    form.route && `route: ${form.route}`,
    form.sink && `sink: ${form.sink}`,
    form.symbols && `symbols: ${form.symbols}`,
    form.keywords && `keywords: ${form.keywords}`,
  ].filter(Boolean).join(" | ");
}
function PanelHead({ title, action, onAction }: { title: string; action: string; onAction?: () => void }) { return <header className="panel-head"><h2>{title}</h2><button onClick={onAction}>{action}</button></header>; }
function MiniMetric({ label, value, hint, tone = "neutral" }: { label: string; value: unknown; hint: string; tone?: string }) { return <div className={`mini-metric ${tone}`}><span>{label}</span><strong>{String(value)}</strong><em>{hint}</em></div>; }
