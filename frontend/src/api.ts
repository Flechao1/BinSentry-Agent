import type {
  AgentChatResponse,
  ApiHealth,
  ChatThread,
  ChatThreadMessages,
  FunctionContext,
  FirmwareTriageReport,
  HarnessRun,
  HarnessRunDetail,
  IdaOpenResponse,
  IntelSearchResult,
  ReportDetail,
  ReportSummary
} from "./types";

const API_BASE = import.meta.env.VITE_VULNAGENT_API_BASE ?? "http://127.0.0.1:8787";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${detail}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<ApiHealth>("/api/health"),
  llmConfig: () => request<ApiHealth["llm"]>("/api/settings/llm"),
  updateLlmConfig: (config: { provider: string; model: string; base_url: string; temperature: number; max_tokens: number; api_key: string }) =>
    request<ApiHealth["llm"]>("/api/settings/llm", {
      method: "POST",
      body: JSON.stringify(config)
    }),
  resetLlmConfig: () => request<ApiHealth["llm"]>("/api/settings/llm/reset", { method: "POST" }),
  openIdaDatabase: (idbPath: string, writable = false) =>
    request<IdaOpenResponse>("/api/ida/open", {
      method: "POST",
      body: JSON.stringify({ idb_path: idbPath, writable })
    }),
  closeIdaDatabase: (save = false) =>
    request<{ ok: boolean }>("/api/ida/close", {
      method: "POST",
      body: JSON.stringify({ save })
    }),
  shutdownIdaBackend: (save = false) =>
    request<{ ok: boolean }>("/api/ida/shutdown", {
      method: "POST",
      body: JSON.stringify({ save })
    }),
  runs: () => request<HarnessRun[]>("/api/harness/runs?limit=12"),
  run: (id: string) => request<HarnessRunDetail>(`/api/harness/runs/${id}`),
  reports: () => request<ReportSummary[]>("/api/reports?limit=20"),
  report: (id: string) => request<ReportDetail>(`/api/reports/${id}`),
  chats: () => request<ChatThread[]>("/api/chats?limit=20"),
  chatMessages: (threadId: string) => request<ChatThreadMessages>(`/api/chats/${threadId}/messages`),
  createChat: (title = "New investigation") =>
    request<ChatThread>("/api/chats", {
      method: "POST",
      body: JSON.stringify({ title })
    }),
  renameChat: (threadId: string, title: string) =>
    request<ChatThread>(`/api/chats/${threadId}`, {
      method: "PATCH",
      body: JSON.stringify({ title })
    }),
  clearChat: (threadId: string) =>
    request<ChatThread>(`/api/chats/${threadId}/clear`, { method: "POST" }),
  deleteChat: (threadId: string) =>
    request<{ deleted: boolean }>(`/api/chats/${threadId}`, { method: "DELETE" }),
  functionContext: (ea: string) => request<FunctionContext>(`/api/functions/${ea}/context`),
  firmwareTriage: (root: string, limit = 20, idaHost = "127.0.0.1", idaPort = 8765) =>
    request<FirmwareTriageReport>(
      "/api/firmware/triage",
      {
        method: "POST",
        body: JSON.stringify({ root, limit, ida_host: idaHost, ida_port: idaPort })
      }
    ),
  vulnerabilityIntel: (query: {
    vendor?: string;
    product?: string;
    firmware_version?: string;
    component?: string;
    vulnerability_type?: string;
    route?: string;
    sink?: string;
    symbols?: string[];
    keywords?: string[];
    max_results?: number;
    sources?: Array<"cveorg" | "nvd" | "github">;
  }) =>
    request<IntelSearchResult>("/api/intel/search", {
      method: "POST",
      body: JSON.stringify(query)
    }),
  cancelChat: (threadId: string) =>
    request<{ canceled: boolean; detail?: string; run_id?: string; status?: string; thread_id?: string }>("/api/agent/chat/cancel", {
      method: "POST",
      body: JSON.stringify({ thread_id: threadId })
    }),
  chat: (prompt: string, threadId = "", signal?: AbortSignal) =>
    request<AgentChatResponse>(
      "/api/agent/chat",
      {
        method: "POST",
        signal,
        body: JSON.stringify({ prompt, thread_id: threadId, new_thread: !threadId })
      }
    ),
  /** SSE streaming chat. Returns an EventSource-like async generator over parsed event objects. */
  chatStream: async function* (
    prompt: string,
    threadId = "",
    signal?: AbortSignal
  ): AsyncGenerator<{ type: string; name?: string; input?: string; summary?: string; content?: string }> {
    const response = await fetch(`${API_BASE}/api/agent/chat/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt, thread_id: threadId, new_thread: !threadId }),
      signal,
    });
    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`${response.status} ${response.statusText}: ${detail}`);
    }
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() ?? "";
      for (const part of parts) {
        const line = part.trim();
        if (!line.startsWith("data:")) continue;
        try {
          yield JSON.parse(line.slice(5).trim());
        } catch { /* skip malformed line */ }
      }
    }
  },
  scan: (threadId = "") =>
    request<{ run_id: string; status: string; thread_id: string; report_id: string; answer: string; error: string }>(
      "/api/baseline/scan",
      {
        method: "POST",
        body: JSON.stringify({ thread_id: threadId, new_thread: !threadId })
      }
    )
};
