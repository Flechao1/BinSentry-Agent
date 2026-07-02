export type ApiHealth = {
  ida: {
    connected: boolean;
    database?: string;
    writable?: boolean;
    protocol_version?: string;
    architecture?: string;
    bits?: number;
    endian?: string;
    error?: string;
  };
  llm: {
    configured: boolean;
    provider?: string;
    model?: string;
  };
  storage: {
    db_path: string;
    summary: Record<string, number>;
  };
};

export type HarnessRun = {
  id: string;
  mode: string;
  status: string;
  thread_id: string | null;
  report_id: string;
  answer: string;
  error: string;
  metadata_json: string;
  started_at: string;
  finished_at: string;
};

export type TraceEvent = {
  id: string;
  run_id: string;
  sequence: number;
  event_type: string;
  message: string;
  data_json: string;
  created_at: string;
};

export type HarnessRunDetail = HarnessRun & {
  trace_events: TraceEvent[];
};

export type ChatToolCall = {
  id: string;
  name: string;
  args: Record<string, unknown>;
};

export type ChatMessage = {
  id: string;
  role: "user" | "assistant" | "tool" | string;
  content: string;
  name?: string;
  tool_call_id?: string;
  tool_calls?: ChatToolCall[];
};

export type ChatThread = {
  id: string;
  sample_id: string | null;
  title: string;
  created_at: string;
  updated_at: string;
};

export type ChatThreadMessages = {
  thread: ChatThread;
  messages: ChatMessage[];
};

export type AgentChatResponse = {
  run_id: string;
  status: string;
  thread_id: string;
  answer: string;
  error: string;
  messages: ChatMessage[];
};

export type ReportSummary = {
  id: string;
  status: string;
  scope: string;
  summary: string;
  report_path: string;
  started_at: string;
  finished_at: string;
};

export type ReportDetail = {
  report_id: string;
  summary: string;
  scope: string;
  sample: {
    database: string;
    architecture: string;
    bits: number;
    endian: string;
  };
  routes: unknown[];
  source_candidates: unknown[];
  findings: Array<{
    finding_id: string;
    category: string;
    severity: string;
    confidence: number;
    verification_status: string;
    source: string;
    evidence: string[];
    sink: {
      loc: string;
      caller_name: string;
      sink_name: string;
      category?: string;
    };
  }>;
};

export type FunctionContext = {
  name: string;
  start_ea: string;
  end_ea: string;
  size: number;
  prototype: string;
  decompile_ok: boolean;
  pseudocode: string;
  decompile_error: string;
  callers: unknown[];
  callees: unknown[];
  imports_used: string[];
  string_records: unknown[];
};
