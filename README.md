# BinSentry Agent

面向 IoT 固件 Web/CGI 场景的智能二进制漏洞分析平台。项目结合 IDA Pro / Hex-Rays 静态分析、大模型 Agent 多轮推理、Source-to-Sink 验证、CVE 情报检索和可视化工作台，辅助分析人员从固件目录中定位重点二进制、发现可疑漏洞链路并整理证据。

> 原项目名为 `VulnAgent-V2`，当前推荐项目展示名为 **BinSentry Agent**。

## 项目定位

传统固件二进制漏洞分析依赖人工逆向经验，流程重复、证据整理成本高，通用 LLM 直接分析大段伪代码又容易出现上下文遗忘和误报。BinSentry Agent 的目标不是替代人工验证，而是把固件初筛、IDA 信息检索、函数分析、证据收集、漏洞链路验证和情报关联组织成一个可审计的 Agent 工作流。

核心思路：

- 确定性扫描负责批量发现路由、Source、Sink 和高风险候选。
- LLM Agent 负责围绕具体问题调用只读 IDA 工具并补齐证据。
- Harness 负责统一运行边界、Trace、错误处理和持久化。
- SQLite 保存会话、工具事件、调查状态、扫描报告和运行轨迹。
- React 前端提供固件初筛、Agent Chat、会话管理、漏洞报告、CVE Intelligence 和 Trace 回放。

## 整体架构

```mermaid
flowchart LR
    User[分析人员] --> UI[React + Vite 工作台]
    UI --> API[FastAPI 应用 API]
    API --> Harness[BinaryVulnAgentHarness]
    Harness --> Agent[LangGraph Agent]
    Harness --> Baseline[Baseline Scanner]
    Agent --> Tools[LangChain / LangGraph Tools]
    Baseline --> IdaClient[IDA HTTP Client]
    Tools --> IdaClient
    IdaClient --> IDA[IDA Pro / IDALib / Hex-Rays 后端]
    Harness --> DB[(SQLite)]
    API --> Intel[CVE.org / NVD / GitHub Intelligence]
    API --> Firmware[Firmware Filesystem Triage]
    UI --> DB
```

## 分析工作流

```mermaid
flowchart TD
    A[固件目录或二进制样本] --> B{输入模式}
    B -->|Firmware Directory Mode| C[扫描 squashfs-root / rootfs]
    C --> D[推荐 Web/CGI 重点二进制]
    B -->|Binary Mode| E[启动 IDA 后端]
    D --> E
    E --> F[Baseline Scan]
    F --> G[路由发现 / Source 识别 / Sink 扫描]
    G --> H[Sink 参数追踪与候选验证]
    H --> I{结论}
    I -->|Verified| J[生成漏洞 Finding]
    I -->|Unverified| K[记录缺失证据]
    I -->|Rejected| L[排除误报]
    J --> M[CVE Intelligence 关联]
    K --> N[Agent Chat 定向补证]
    M --> O[报告与 Trace 持久化]
    N --> O
```

## Agent 推理闭环

```mermaid
sequenceDiagram
    participant U as User
    participant UI as React UI
    participant H as Harness
    participant C as ContextBuilder
    participant A as LangGraph Agent
    participant T as IDA Tools
    participant D as SQLite

    U->>UI: 提出分析问题
    UI->>H: Agent Chat Request
    H->>C: 构建上下文
    C->>D: 读取历史、摘要、调查状态
    C-->>H: System Context + Recent Messages
    H->>A: 调用 LLM Agent
    A->>T: 反编译 / Xrefs / Source-Sink / Taint Trace
    T-->>A: JSON 工具结果
    A-->>H: 分析结论
    H->>D: 保存消息、工具事件、Trace、调查状态
    H-->>UI: 返回回答与运行记录
```

## 核心能力

| 模块 | 能力 |
| --- | --- |
| Firmware Triage | 扫描固件文件系统，按 Web 入口、CGI 特征、危险函数、配置引用等指标推荐 IDA 分析目标 |
| IDA Backend | 封装反编译、函数列表、交叉引用、字符串、导入函数、调用关系、参数来源追踪等能力 |
| Baseline Scan | 批量发现 Web 路由、用户输入 Source、危险 Sink 和 source-to-sink 候选链路 |
| Validation Planner | 对高风险 Sink 参数做来源追踪，将候选标记为 verified / unverified / rejected |
| LangGraph Agent | 支持多轮工具调用、上下文感知分析、定向补证和自然语言解释 |
| Context Memory | 滑动窗口、语义摘要、Token 预算、结构化调查状态和 `/context press` 手动压缩 |
| Harness Trace | 为每次 Agent Chat、Baseline Scan、上下文压缩记录 run_id、状态、耗时和事件时间线 |
| CVE Intelligence | 使用 CVE.org、NVD、GitHub 做宽搜索，再用固件型号、漏洞类型和本地证据重排匹配结果 |
| React Workbench | 提供 Agent Chat、会话管理、固件初筛、报告查看、候选漏洞、CVE 情报和 Trace 回放页面 |

## 数据持久化设计

```mermaid
erDiagram
    chat_threads ||--o{ chat_messages : contains
    chat_threads ||--o{ tool_events : records
    chat_threads ||--|| chat_summaries : compresses
    chat_threads ||--|| investigation_states : tracks
    harness_runs ||--o{ harness_trace_events : emits
    harness_runs }o--|| reports : links

    chat_threads {
        text id
        text title
        text sample_id
        datetime updated_at
    }
    chat_messages {
        text thread_id
        int sequence
        text role
        json message_json
    }
    investigation_states {
        text thread_id
        json state_json
    }
    harness_runs {
        text id
        text mode
        text status
        text report_id
    }
```

## 项目结构

```text
VulnAgent-V2/
  frontend/                 React + Vite 前端工作台
  vulnagent/
    agent/                  LangGraph Agent、上下文管理、执行治理、Baseline Scan
    firmware/               固件目录扫描与重点二进制推荐
    harness/                统一任务运行层、run_id、trace、结构化结果
    ida/                    IDA FastAPI 后端、IDALib / Hex-Rays 适配
    clients/                IDA HTTP 客户端
    tools/                  Agent 可调用工具封装
    intel/                  CVE.org / NVD / GitHub 情报检索与本地重排
    storage/                SQLite 持久化
    skills/                 固件 Web/CGI 分析提示词与领域规则
    tests/                  单元测试
  data/                     本地 SQLite 数据库，默认不提交
  reports/                  本地分析报告，默认不提交
```

## 技术栈

- Python、FastAPI、SQLite
- IDA Pro / IDALib / Hex-Rays
- LangGraph、LangChain
- DeepSeek API / OpenAI-compatible API
- React、Vite、TypeScript
- CVE.org、NVD、GitHub Intelligence

## 快速启动

### 1. 安装 Python 依赖

```powershell
conda create -n BinSentry python=3.10 -y
conda activate BinSentry
pip install -r vulnagent/requirements.txt
```

### 2. 配置环境变量

```powershell
copy .env.example .env
```

至少配置一个 LLM API Key：

```env
DEEPSEEK_API_KEY=your-api-key
DEEPSEEK_API_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat

IDA_BACKEND_URL=http://127.0.0.1:8765
VULN_DB_PATH=./data/vulnagent.db
```

不要提交 `.env`、IDA 数据库、SQLite 数据库、固件样本或本地报告。

### 3. 启动 IDA 后端

```powershell
python -m vulnagent --idb "E:\path\to\sample.i64" --host 127.0.0.1 --port 8765 --read-only
```

如果是固件目录模式，可以先启动前端扫描 rootfs，选择推荐二进制后再启动 IDA 后端。

### 4. 启动应用 API

```powershell
python -m vulnagent api --host 127.0.0.1 --port 8787
```

### 5. 启动 React 前端

```powershell
cd frontend
npm install
npm run dev
```

访问：

```text
http://127.0.0.1:5173
```

## 常用命令

固件目录扫描：

```powershell
python -m vulnagent firmware-triage "E:\path\to\squashfs-root" --limit 20
```

CVE 情报检索：

```powershell
python -m vulnagent intel --vendor "D-Link" --product "DIR-882" --vuln-type "command injection" --sources cveorg,nvd,github
```

手动压缩 Agent Chat 上下文：

```text
/context press
```

## 典型测试提示词

```text
请扫描这个固件目录，推荐最值得用 IDA 分析的 Web/CGI 二进制文件。
```

```text
请开始分析这个二进制文件中可能存在的命令注入漏洞，先找 Web 路由、用户输入 Source 和危险 Sink。
```

```text
请围绕 system 调用追踪参数来源，说明是否能从 Web/CGI 用户输入到达该 Sink。
```

```text
请根据当前 finding 检索是否已有公开 CVE，并说明哪些匹配可信、哪些只是关键词重合。
```

## 测试

```powershell
python -m compileall -q vulnagent
python -m unittest vulnagent.tests.test_vulnerability_workflow
python -m unittest vulnagent.tests.test_firmware_scanner
python -m unittest vulnagent.tests.test_validation_planner
python -m unittest vulnagent.tests.test_vulnerability_intel
```

前端检查：

```powershell
cd frontend
npx tsc --noEmit
npm run build
```

## 安全与仓库注意事项

`.gitignore` 默认忽略：

- `.env`
- `data/`
- `reports/`
- `dataset/`
- `frontend/dist/`
- `node_modules/`
- IDA 数据库文件：`.i64`、`.idb`、`.id0`、`.id1`
- SQLite 数据库文件：`.db`、`.sqlite`

提交前建议检查：

```powershell
git status
```

确认没有 API Key、固件样本、IDA 数据库、SQLite 数据库或本地报告进入暂存区。

## 项目说明

BinSentry Agent 更适合作为研究型和实验型二进制漏洞分析平台使用。它不能替代人工逆向验证，也不是通用自动漏洞挖掘器。它的价值在于把重复的信息检索、函数分析、证据整理和多轮推理过程自动化，让分析人员更快聚焦到可疑链路和关键证据。
