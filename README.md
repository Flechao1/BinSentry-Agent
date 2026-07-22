# VulnAgent-V2

面向 IoT 固件 Web/CGI 场景的智能二进制漏洞分析 Agent 平台。

本项目将 IDA Pro / Hex-Rays 静态分析能力封装为 Agent 可调用工具，结合 LangGraph、DeepSeek API、SQLite 和 Streamlit，实现从二进制样本加载、Baseline Scan、Source/Sink 发现、函数反编译、工具调用推理、调查状态管理到可视化分析的完整流程。

## 项目定位

传统二进制漏洞分析高度依赖人工逆向经验，规则维护成本高，跨函数语义理解弱。VulnAgent-V2 的目标是构建一个面向固件程序的漏洞挖掘 Agent，让大模型在受控工具环境中完成多轮分析，而不是直接把大量伪代码一次性丢给模型。

系统采用 Hybrid Workflow：

- 确定性 Baseline Scan 负责批量发现路由、Source、Sink 和可疑调用链。
- LLM Agent 负责围绕具体问题进行多轮工具调用、证据补全和漏洞链路解释。
- SQLite 负责持久化样本、扫描报告、对话历史、工具事件和调查状态。
- Streamlit UI 负责提供可交互的漏洞分析工作台。

## 核心功能

- IDA 后端服务：通过 FastAPI 暴露反编译、函数列表、调用关系、交叉引用、字符串、导入函数和架构信息等能力。
- Baseline Scan：自动扫描 Web/CGI 路由、用户输入 Source、危险 Sink、参数来源和潜在漏洞链路。
- LangGraph Agent：支持多轮对话式漏洞分析，能够根据上下文选择工具、读取工具结果并继续推理。
- 短期记忆管理：支持滑动窗口、语义摘要、Token 预算和结构化调查状态。
- 结构化工具结果：工具返回 JSON，包含 confirmed sources、pending sinks、missing evidence、function notes 等字段。
- 执行治理：限制单轮工具调用、重复调用、扫描次数和运行时间，避免 Agent 无效循环。
- SQLite 持久化：保存扫描报告、Agent 对话、工具调用事件和调查状态。
- Agent Harness：统一封装 Agent Chat、Baseline Scan、上下文准备、SQLite 持久化、执行轨迹和结构化结果输出。
- Streamlit 工作台：支持 Baseline Scan、报告查看、路由分析、Source 展示、函数反编译和 Agent Chat。
- 受控写操作：支持在非只读模式下进行函数重命名、注释、字节 Patch、NOP 和保存数据库等操作，并通过确认机制降低误修改风险。

## 技术栈

- Python
- IDA Pro / IDALib / Hex-Rays
- FastAPI
- LangGraph / LangChain
- DeepSeek API
- SQLite
- Streamlit

## 项目结构

```text
VulnAgent-V2/
  vulnagent/
    agent/          Agent 工作流、上下文管理、执行限制、Baseline Scan
    clients/        IDA HTTP 客户端
    harness/        Agent Harness 运行层，统一任务入口、结果和 trace
    ida/            IDA FastAPI 后端、IDALib 实现、协议 Schema
    tools/          LangChain / LangGraph 工具封装
    storage/        SQLite 存储
    reports/        扫描报告模型
    skills/         漏洞分析技能提示词
    ui/             Streamlit 可视化界面
    docs/           项目文档和简历描述
    tests/          测试用例
  data/             本地 SQLite 数据库，默认不提交
  reports/          本地扫描报告，默认不提交
```

## 环境准备

建议使用 Conda 或 venv 创建独立 Python 环境。

```powershell
conda create -n VulnAgent python=3.10 -y
conda activate VulnAgent
pip install -r vulnagent/requirements.txt
```

或者使用 venv：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r vulnagent\requirements.txt
```

## 配置环境变量

复制示例配置：

```powershell
copy .env.example .env
```

然后在 `.env` 中配置自己的 LLM API Key：

```env
DEEPSEEK_API_KEY=your-api-key
DEEPSEEK_API_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
LLM_TEMPERATURE=0.0

IDA_BACKEND_URL=http://127.0.0.1:8765
VULN_DB_PATH=./data/vulnagent.db
```

注意：不要把 `.env`、IDA 数据库文件、SQLite 数据库和本地报告提交到代码仓库。

## 启动方式

需要先启动 IDA 后端，再启动前端 UI。

### 1. 启动 IDA 后端

只读模式：

```powershell
python -m vulnagent --idb "E:\path\to\sample.i64" --host 127.0.0.1 --port 8765 --read-only
```

可写模式：

```powershell
python -m vulnagent --idb "E:\path\to\sample.i64" --host 127.0.0.1 --port 8765
```

如果 `8765` 端口被占用，可以换一个端口，并同步修改 `.env` 中的 `IDA_BACKEND_URL`。

### 2. 启动 Streamlit UI

打开第二个终端，在项目根目录执行：

```powershell
python -m streamlit run vulnagent/ui/app.py
```

浏览器访问：

```text
http://127.0.0.1:8501
```

## 使用流程

1. 在 UI 侧边栏确认 IDA Backend 状态为 Connected。
2. 点击 `Start Baseline Scan` 运行确定性扫描。
3. 查看 Report、Routes、Sources、Function Explorer 等页面。
4. 进入 Agent Chat，针对可疑函数、Source/Sink 或调用链继续提问。
5. 查看 SQLite 中保存的历史对话、工具事件和调查状态。

## Harness 架构

VulnAgent-V2 在 LangGraph Agent 外增加了一层轻量 Harness。它不替代 LangGraph，而是作为统一运行边界管理一次分析任务：

```text
Streamlit UI / CLI / Tests
  -> BinaryVulnAgentHarness
      -> ContextBuilder / SQLite
      -> LangGraph Agent 或 BaselineScanner
      -> IDA Tools / IDA Backend
      -> HarnessRunResult
```

Harness 当前负责：

- 将 Agent Chat 和 Baseline Scan 包装成统一请求与结果。
- 生成 `run_id` 和 trace event，记录任务开始、进度、完成或失败。
- 统一调用 SQLite 保存对话历史、工具事件、扫描报告和调查状态。
- 把异常转换为结构化失败结果，方便 UI、CLI 或后续评测脚本调用。

核心接口位于：

```text
vulnagent/harness/
  schemas.py      # HarnessTurnRequest / HarnessBaselineScanRequest / HarnessRunResult
  runtime.py      # BinaryVulnAgentHarness
```

示例提问：

```text
请总结当前样本中已经发现的 Web 路由、Source 候选和危险 Sink。
请扫描可能的用户输入 Source，并说明哪些是确认的 source，哪些只是候选。
请分析 0x4055b8 的调用者、被调用函数、字符串和可疑参数来源。
请围绕 system 调用追踪参数来源，并说明还缺少哪些证据。
请根据当前 Baseline Scan 结果给出下一步漏洞验证计划。
```

## 测试

```powershell
python -m compileall -q vulnagent
python -m unittest vulnagent.tests.test_vulnerability_workflow
```

## Agent Chat 上下文压缩

在 Agent Chat 输入框中手动输入：

```text
/context press
```

系统会把当前会话中较早的消息压缩为短期记忆摘要，并只保留最近几轮完整对话继续分析。压缩结果会写入 SQLite，并生成一条 Harness Run / Trace 记录，方便后续查看。

可通过 `.env` 调整手动压缩时保留的最近轮数：

```env
VULN_CONTEXT_PRESS_KEEP_RECENT_TURNS=2
```

## 代码仓库注意事项

本项目已通过 `.gitignore` 忽略以下本地文件：

- `.env`
- `data/`
- `reports/`
- `.vscode/`
- Python 缓存文件
- SQLite 数据库文件
- IDA 数据库文件，如 `.i64`、`.idb`、`.id0`、`.id1`

提交代码前建议检查：

```powershell
git status
```

确认没有 API Key、数据库文件、样本文件或分析报告被加入暂存区。

## 项目说明

VulnAgent-V2 当前更适合作为研究型和实验型二进制漏洞分析平台使用。它不是通用自动化漏洞挖掘器，也不能替代人工逆向验证。Agent 的作用是把重复的信息检索、函数分析、证据整理和多轮推理流程自动化，让分析人员更快聚焦到可疑链路和关键证据上。
