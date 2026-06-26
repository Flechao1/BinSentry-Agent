# VulnAgent 简历项目说明

## 简历可直接使用版本

### VulnAgent：面向 Web/CGI 固件的二进制漏洞分析 Agent

**技术栈：** Python、LangGraph、LangChain、DeepSeek API、FastAPI、Uvicorn、IDA Pro / IDALib、Hex-Rays、SQLite、Streamlit、Pydantic、HTTPX

**项目描述：**  
面向固件 Web/CGI 场景设计并实现二进制漏洞分析 Agent。系统将 IDA 逆向分析能力封装为独立 HTTP 服务，通过 LangGraph 编排 LLM 工具调用，并结合确定性 Baseline Scan 完成路由发现、输入源识别、危险函数扫描和 source-to-sink 调用链验证。项目默认只读分析，保留完整审计记录，重点解决 Agent 长对话上下文膨胀、工具循环失控和分析结果持久化问题。

**核心工作：**

- 基于 LangGraph 构建二进制漏洞分析 Agent，将 IDA 反编译、函数调用关系、交叉引用、Web 路由发现、source 候选扫描、sink 扫描和污点链追踪封装为可组合工具。
- 设计“确定性扫描流水线 + LLM 定向调查”的混合架构：Baseline Scan 负责有边界的批量初筛，LLM Agent 负责根据工具证据解释结果并推进后续验证。
- 实现 SQLite 持久化层，保存样本元数据、扫描任务、漏洞线索、完整聊天记录、工具调用事件、会话摘要和结构化调查状态，支持历史会话恢复与分析审计。
- 实现短期记忆治理：采用滑动窗口、远期规则摘要、显式调查状态和 Token 预算控制，避免将全部历史消息和超长反编译结果重复发送给 LLM。
- 实现 Agent 执行规模限制：限制单轮工具调用次数、循环轮数、反编译次数、扫描次数和执行时长；拦截重复工具调用，并为模型调用和工具执行增加超时保护。
- 将 IDALib 封装为 FastAPI 服务，修复 IDA API 只能在主线程调用的问题；HTTP 路由在 Uvicorn 事件循环线程串行执行，避免线程池调用导致运行时异常。
- 提供 Streamlit 可视化工作台，支持样本状态、Baseline Scan、finding 报告、路由、source、函数伪代码、Agent Chat、历史会话和执行预算展示。
- 为关键流程编写回归测试，覆盖协议校验、错误透传、SQLite 持久化、短期记忆、工具重复调用拦截、工具超时和 IDA 主线程执行约束。

## 一句话介绍

VulnAgent 是一个面向 Web/CGI 固件的二进制漏洞分析 Agent：使用 IDA 提供确定性逆向证据，使用 LangGraph 和 LLM 编排调查流程，并通过短期记忆、工具预算和 SQLite 审计机制保证分析过程可控、可追踪。

## 技术路线拆解

### 1. Domain Agent：为特定安全场景设计 Agent

项目不是通用聊天机器人，而是面向固件 Web/CGI 二进制审计场景的领域 Agent。

审计目标集中在：

- 命令注入风险；
- 不安全内存操作；
- Web / CGI 路由入口；
- 用户可控输入 source；
- `system`、`popen`、`sprintf`、`strcpy` 等危险 sink；
- source-to-sink 调用链证据。

领域规则写入：

```text
vulnagent/skills/firmware_web_audit/SKILL.md
```

Skill 明确约束：

- IDA 工具输出是事实来源；
- 仅发现危险函数导入不能判定漏洞成立；
- 只有存在 source-to-sink 工具证据时，finding 才能标记为 `verified`；
- 默认只读，写入 IDB 必须获得用户确认。

### 2. LangGraph：编排 LLM、工具和终止条件

核心 Agent 图位于：

```text
vulnagent/agent/langgraph_agent.py
```

主要执行链：

```text
用户输入
  -> 初始化单轮执行预算
  -> LLM 判断是否调用工具
  -> 审核工具预算和重复调用
  -> 串行执行 IDA 工具
  -> 工具结果返回 LLM
  -> 继续调查或结束
```

项目使用 LangGraph `StateGraph` 管理：

- 消息历史；
- 上下文提示；
- 工具调用次数；
- 工具循环次数；
- 反编译次数；
- 扫描次数；
- 已执行工具签名；
- 达到预算后的终止原因。

### 3. Tool Calling：将逆向能力封装为 Agent 工具

工具适配层位于：

```text
vulnagent/tools/langchain_tools.py
vulnagent/tools/recon_tools.py
```

当前只读工具包括：

```text
check_ida_backend
detect_binary_architecture
list_binary_imports
list_binary_functions
get_function_context
decompile_function
get_function_xrefs
get_function_signals
find_web_route_handlers
scan_indirect_calls
scan_taint_source_candidates
analyze_function_as_source
propagate_taint_sources
find_function_sink_calls
scan_dangerous_sink_calls
trace_taint_call_chain
trace_argument_origin
```

这条路线体现了 Agent 应用开发中的核心思想：LLM 不直接“猜测”二进制行为，而是按需调用确定性工具获取证据，再完成优先级判断和解释。

### 4. Hybrid Workflow：确定性流水线与 Agent 推理结合

Baseline Scan 位于：

```text
vulnagent/agent/baseline_scan.py
```

执行步骤：

```text
检查 IDA 后端
  -> 获取架构和导入函数
  -> 发现 Web / CGI 路由
  -> 扫描输入源候选
  -> 传播 source 包装函数
  -> 有界扫描危险 sink
  -> 追踪非固定参数的调用链
  -> 生成 finding 和 JSON 报告
  -> 写入 SQLite
```

采用混合架构的原因：

- 全部交给 LLM 自主探索，成本高且容易重复调用；
- 全部做成静态流水线，无法灵活处理复杂样本；
- 流水线适合稳定初筛，Agent 适合围绕可疑 finding 做定向验证和解释。

### 5. Context Engineering：短期记忆管理

上下文构建器位于：

```text
vulnagent/agent/context_builder.py
vulnagent/agent/investigation_state.py
```

实现策略：

```text
System Prompt + Skill
  + 结构化调查状态
  + 远期会话摘要
  + 最近若干轮完整消息
  + 当前用户输入
```

具体机制：

- 完整聊天记录始终保存到 SQLite；
- 发送给 LLM 的只是受控上下文副本；
- 默认保留最近 `8` 轮完整对话；
- 窗口外历史使用确定性规则压缩；
- 超长工具结果仅在 LLM 上下文副本中裁剪；
- 为摘要、调查状态、近期消息和模型回答分别分配 Token 预算。

结构化调查状态记录：

```text
objective
phase
confirmed_routes
source_candidates
confirmed_sources
pending_sinks
missing_evidence
verified_findings
active_function
active_sink
investigated_functions
open_questions
```

工具执行完成后，系统按工具类型解析 `ToolMessage`，将路由、source、sink、
验证结论和缺失证据合并到状态中。Baseline Scan 报告也会写入同一状态。
完整工具输出保留在 SQLite 中，System Prompt 仅注入经过数量限制、去重和裁剪的
紧凑证据索引。

### 6. Guardrails：控制 Agent 执行规模

执行限制位于：

```text
vulnagent/agent/execution_limits.py
```

默认单轮限制：

```text
最大工具调用次数：48
最大工具循环轮数：24
最大反编译次数：20
最大扫描和污点分析次数：8
单轮最长执行时间：300 秒
单工具最长执行时间：60 秒
单次模型调用最长时间：90 秒
```

额外保护：

- 对工具名称和参数生成稳定签名；
- 相同工具和参数重复调用时直接拒绝；
- 工具按顺序执行，避免并发请求冲击 IDA；
- 达到预算后返回可读终止消息，引导用户发起更聚焦的下一轮分析。

### 7. Human-in-the-loop：敏感写操作确认

写操作适配层位于：

```text
vulnagent/tools/langgraph_write_tools.py
vulnagent/tools/controlled_writes.py
```

当前设计默认关闭写入能力。启用后，以下操作需要显式确认：

- 重命名 IDA 函数；
- 保存 IDB 数据库。

这体现了安全 Agent 的重要设计原则：分析可以自动化，具有副作用的操作必须经过人工授权。

### 8. Service Boundary：隔离 IDA 运行环境

IDA HTTP 服务位于：

```text
vulnagent/ida/backend.py
vulnagent/ida/idalib_backend.py
```

架构：

```text
Streamlit UI / LangGraph Agent
  -> HTTP Client
  -> FastAPI IDA Backend
  -> IDALib + Hex-Rays
```

拆分服务的原因：

- IDA Python 环境与普通 Agent 环境依赖不同；
- IDA API 存在主线程调用约束；
- Agent 可以通过 HTTP 访问工具，无需直接导入 IDA 模块；
- 后续可以替换 UI 或部署方式，而不重写逆向分析逻辑。

### 9. Persistence and Auditability：SQLite 持久化与审计

数据库实现位于：

```text
vulnagent/storage/sqlite.py
```

主要数据表：

| 表 | 用途 |
|---|---|
| `projects` | 项目容器 |
| `samples` | 二进制样本元数据 |
| `scan_runs` | Baseline Scan 运行记录 |
| `findings` | 漏洞线索和验证状态 |
| `chat_threads` | Agent 对话线程 |
| `chat_messages` | 完整 LangChain 消息 |
| `tool_events` | 工具调用输入、输出和状态 |
| `chat_summaries` | 窗口外历史摘要 |
| `investigation_states` | 结构化调查状态 |
| `analyst_notes` | 人工审计笔记预留 |

SQLite 使用：

- WAL 模式；
- 外键约束；
- 显式事务；
- 连接及时关闭；
- schema 版本记录。

### 10. Visualization：Agent 工作台

当前前端位于：

```text
vulnagent/ui/app.py
```

使用 Streamlit 实现：

- IDA 后端状态；
- 当前样本架构；
- 扫描参数配置；
- Baseline Scan 进度；
- finding 报告；
- 路由和 source 展示；
- Function Explorer；
- Agent Chat；
- 历史会话；
- SQLite 数据统计；
- 短期记忆策略与执行预算状态。

### 11. Engineering Quality：测试与兼容性

测试位于：

```text
vulnagent/tests/test_vulnerability_workflow.py
```

当前覆盖：

- IDA HTTP 协议校验；
- 后端错误详情透传；
- SQLite 报告持久化；
- LangChain 消息恢复；
- 工具事件记录；
- 会话摘要与调查状态；
- 滑动窗口上下文；
- 重复工具调用拦截；
- 工具执行超时；
- IDA API 主线程执行约束；
- Baseline Scan finding 生成；
- 写操作人工确认。

已在 Python `3.10` 和 `3.11` 环境运行回归测试。

## 项目架构图

```text
┌──────────────────────────────────────────────────────────────┐
│ Streamlit Analysis Workspace                                 │
│ Sample | Scan | Report | Function Explorer | Agent Chat      │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ LangGraph Binary Vulnerability Agent                         │
│ Skill Prompt | ContextBuilder | InvestigationState           │
│ ExecutionLimits | Controlled Tool Loop | Human Confirmation  │
└───────────────┬───────────────────────────────┬──────────────┘
                │                               │
                ▼                               ▼
┌──────────────────────────────┐  ┌────────────────────────────┐
│ SQLite                       │  │ FastAPI IDA Backend        │
│ Samples | Findings | Chats   │  │ IDALib | Hex-Rays         │
│ Summaries | Tool Events      │  │ Taint | Routes | Xrefs    │
└──────────────────────────────┘  └────────────────────────────┘
```

## 面试时的 60 秒表达

我实现了一个面向 Web/CGI 固件的二进制漏洞分析 Agent。系统没有让大模型直接猜测漏洞，而是把 IDA 的反编译、交叉引用、路由发现、危险函数扫描和污点链追踪封装成工具，通过 LangGraph 编排调用。为了兼顾稳定性和灵活性，我使用确定性 Baseline Scan 做批量初筛，再由 Agent 围绕可疑 finding 做定向验证。工程上重点处理了两类问题：一类是上下文治理，使用滑动窗口、远期摘要、结构化调查状态和 Token 预算；另一类是执行治理，限制工具次数、循环轮数、反编译次数和超时，并拦截重复调用。分析记录、工具事件和会话历史都会写入 SQLite，便于恢复和审计。

## 能力边界

当前项目可以准确表述为：

- 二进制漏洞分析 Agent 原型；
- 支持 Web/CGI 固件场景的辅助发现和证据验证；
- 支持有边界的自动扫描与对话式定向调查；
- 支持本地单用户分析、持久化和审计。

当前不应表述为：

- 全自动漏洞利用生成平台；
- 无人值守批量漏洞挖掘平台；
- 已完成生产级多用户部署；
- 已实现 RAG、向量数据库或语义检索；
- 已实现 React / Next.js 前端。

## 后续可扩展方向

- 继续细化证据解析规则，从伪代码中提取过滤器、校验函数和更具体的缺失证据；
- 增加 IDA 请求任务队列、任务取消和更完整的运行日志；
- 使用 PostgreSQL 支持多人协作；
- 将 Streamlit 逐步替换为 Next.js + React 工作台；
- 在样本和函数数量扩大后，再评估是否引入 RAG 或向量检索。



## 开发中遇到的问题与解决方案

### IDA 后端接口异常不透明与主线程调用限制

**问题表现：**

在运行 Baseline Scan 时，前端曾出现 `/sources/scan` 接口返回 400 的问题：

```text
HTTPError: 400 Client Error: Bad Request for url:
http://127.0.0.1:8765/sources/scan?limit=100&min_score=25.0
```

进一步排查后发现，这类问题并不是 HTTP 参数错误，而是后端 IDA 分析函数内部抛出异常后被 FastAPI 统一转换成 400，前端最初只能看到 `Bad Request`，无法判断真实原因。后续又遇到 IDA / Hex-Rays API 的线程限制：

```text
RuntimeError: Function can be called from the main thread only
```

原因是部分 IDA API 必须在 IDA 主线程中执行，如果被放到普通线程池或其他 worker 线程中调用，就会触发运行时异常。

**定位过程：**

- 通过保留后端异常 detail，确认 400 背后实际来自 IDA 分析函数内部异常；
- 排查 source scan 相关返回结构，补齐 `SourceCandidate` 等 Pydantic schema 和 import；
- 通过记录线程 ID 验证 FastAPI handler 调用 IDA backend 时是否发生线程切换；
- 确认部分 Hex-Rays / IDA API 不能在线程池中执行。

**解决方案：**

- 改造 HTTP client 错误处理，保留后端返回的异常类型和 detail，避免前端只显示泛化的 400；
- 补齐后端 schema、client 解析和接口测试，保证 `/sources/scan` 等接口返回结构稳定；
- 将 IDA 相关 FastAPI handler 改为 `async` 直接调用后端方法，避免把 IDA API 包装到线程池执行；
- 增加回归测试，覆盖后端错误透传和 IDA API 主线程执行约束。

**面试表达：**

项目中遇到过 Baseline Scan 接口返回 400 的问题。最开始前端只能看到 `Bad Request`，无法定位真实原因。后来我发现一部分是 schema / import 不完整导致后端序列化失败，另一部分是 IDA / Hex-Rays API 必须在主线程调用，不能放到线程池里执行。为了解决这个问题，我改造了错误透传逻辑，让前端能够看到后端异常 detail；同时补齐 Pydantic schema 和 client 解析，并将 FastAPI handler 改为 async 直接调用 IDA backend，避免线程切换导致 IDA API 报错。最后补了接口错误透传和线程一致性的回归测试。
