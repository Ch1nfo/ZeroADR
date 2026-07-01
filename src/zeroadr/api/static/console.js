const translations = {
  zh: {
    eyebrow: "本地只读控制台",
    subtitle: "Agent Runtime Security Console",
    metricSessions: "会话",
    metricFindings: "发现",
    metricDecisions: "决策",
    metricPendingApprovals: "待审批",
    inventoryEyebrow: "会话总览",
    inventoryTitle: "Session Inventory",
    emptySelect: "选择一个会话以查看风险、时间线和资产清单。",
    selectedSession: "当前会话",
    timelineTitle: "执行时间线",
    timelineHint: "最近 12 条工具调用",
    evidenceTitle: "风险证据",
    evidenceHint: "敏感目标与外联目标",
    inventoryDetailTitle: "资产清单",
    inventoryDetailHint: "能力、工具、服务与进程",
    checkingApi: "检查 API...",
    apiUnavailable: "API 不可用",
    loadingSessions: "正在加载会话...",
    loadingDetail: "正在加载会话详情...",
    noSessions: "当前 SQLite 数据库中没有会话。",
    seedDemoHint: "可先生成演示数据库再刷新 Console。",
    seedDemoCommand: "conda run -n agent zeroadr api seed-demo --db .zeroadr/console-demo.sqlite",
    sessionMissing: "当前会话不存在，可能是数据库已切换或页面状态过期。",
    noMatchingSessions: "没有匹配当前筛选条件的会话。",
    noTimeline: "没有可展示的时间线事件。",
    noEventDetail: "选择时间线事件以查看完整 RuntimeEvent。",
    noEvidence: "当前 summary 中没有高亮信号。",
    noEvidenceDetail: "没有匹配的 finding 证据。",
    findingLoadError: "证据加载失败",
    noInventory: "没有可展示的资产项。",
    noPolicies: "没有策略决策记录。",
    filterAny: "全部",
    capabilityFilter: "能力筛选",
    ruleFilter: "规则筛选",
    decisionFilter: "动作筛选",
    searchPlaceholder: "搜索会话",
    filterAll: "全部",
    filterFindings: "有发现",
    filterHigh: "High+",
    filterCritical: "Critical",
    tabTimeline: "时间线",
    tabEvidence: "证据",
    tabPolicy: "策略",
    tabBom: "BOM",
    policyTitle: "策略决策",
    policyHint: "Policy decision history",
    bomTitle: "Agent-BOM",
    bomHint: "只读 JSON",
    risk: "风险",
    riskCritical: "critical",
    riskHigh: "high",
    riskMedium: "medium",
    riskLow: "low",
    riskClean: "无高风险",
    highDetail: "存在需要优先审查的高风险发现。",
    mediumDetail: "存在中等风险发现。",
    lowDetail: "未发现 high / critical 风险。",
    events: "事件",
    findings: "发现",
    decisions: "决策",
    capability: "能力",
    tool: "工具",
    server: "服务",
    processes: "进程",
    endpointEvents: "端点事件",
    sensitive: "敏感目标",
    external: "外联目标",
    action: "动作",
    policy: "策略",
    reason: "原因",
    event: "事件",
    relatedEvents: "相关事件",
    relatedDecisions: "相关决策",
    agentEyebrow: "Endpoint Agent",
    agentTitle: "Agent 健康状态",
    agentRefresh: "刷新",
    agentLoading: "正在加载 Agent 状态...",
    agentState: "状态",
    agentCollector: "Collector",
    agentRecords: "Records",
    agentEvents: "Events",
    agentUpdated: "更新时间",
    agentHintUnknown: "未找到 agent status file。请先启动 endpoint agent，并让 api serve 指向同一 status file。",
    agentHintUnhealthy: "Agent 不健康。请检查 status file 并重启 endpoint agent。",
    agentBccProbes: "BCC Probes",
    agentBccDropped: "Dropped",
    agentBccLastEvent: "Last event",
    approvalsEyebrow: "人工审批",
    approvalsTitle: "待审批队列",
    approvalsRefresh: "刷新",
    approvalsLoading: "正在加载审批队列...",
    approvalsEmpty: "当前没有待审批请求。",
    approvalsSession: "会话",
    approvalsTool: "工具",
    approvalsCapability: "能力",
    approvalsReason: "原因",
    approvalsCreated: "创建时间",
    approvalsApprove: "批准",
    approvalsDeny: "拒绝",
    approvalsPendingBadge: "待审批",
    approvalsResolvedApproved: "已批准",
    approvalsResolvedDenied: "已拒绝",
    approvalsResolvedExpired: "已过期",
    approvalsViewInbox: "查看审批",
    approvalsResolveError: "审批操作失败",
    approvalsHint: "这是本地 localhost 审批 baseline。请在 hook client 中使用 approval_id 调用 wait-approval。",
    approvalsStage: "阶段",
    toolResultWarning: "警告：批准后会将原始、不受信任的工具结果返回给 Agent。",
    llmSettingsButton: "大模型设置",
    llmSettingsEyebrow: "模型服务",
    llmSettingsTitle: "大模型设置",
    llmSettingsDescription: "配置 OpenAI-compatible Chat Completions 服务。密钥仅以明文保存在本机私有文件中。",
    llmBaseUrl: "Base URL",
    llmModel: "模型",
    llmApiKey: "API Key",
    llmLanguage: "默认语言",
    llmTimeout: "超时（秒）",
    llmMaxTokens: "最大输出 Tokens",
    llmClearKey: "清除密钥",
    llmTestTriage: "测试完整研判",
    llmTestGate: "测试 Gate",
    llmSaveTest: "保存并测试完整研判",
    llmSave: "保存",
    llmLoading: "正在读取配置...",
    llmSaved: "配置已保存。",
    llmTestingTriage: "正在测试完整研判模型...",
    llmTestingGate: "正在测试 Gate 模型...",
    llmConnected: "{target} 模型 {model} 连接成功，延迟 {latency} ms。",
    llmTargetTriage: "完整研判",
    llmTargetGate: "Gate",
    llmKeyConfigured: "已保存密钥：{masked}。留空将保留现有密钥。",
    llmKeyMissing: "尚未保存 API Key。",
    llmKeyCleared: "API Key 已清除。",
    llmEnvironmentOverride: "环境变量正在覆盖部分本地配置；运行时将优先使用环境变量。",
    llmSources: "有效配置来源：模型 {model}，地址 {baseUrl}，密钥 {apiKey}",
    llmLoadError: "配置读取失败",
    llmSaveError: "配置保存失败",
    llmTestError: "连接测试失败",
    llmGateTitle: "在线 Adjudication Gate",
    llmGateHint: "留空模型时复用完整研判模型",
    llmGateModel: "Gate 模型",
    llmGateTimeout: "Gate 超时（秒）",
    llmGateMaxTokens: "Gate 最大输出 Tokens",
    llmGateMetricsTitle: "Gate 运行指标",
    llmGateMetricsHint: "全库 Shadow / Enforce 汇总",
    llmGateMetricsLoading: "正在读取 Gate 指标...",
    llmGateMetricsEmpty: "尚无在线 Gate 研判记录。",
    llmGateMetricsError: "Gate 指标读取失败",
    llmGateMetricTotal: "调用",
    llmGateMetricCompletion: "完成率",
    llmGateMetricFallback: "转人工率",
    llmGateMetricLatency: "P95 延迟",
    llmGateMetricVerdicts: "研判分布",
    llmAdjudicationTitle: "LLM 在线研判",
    llmAdjudicationHint: "Shadow / Enforce 历史",
    noAdjudications: "当前会话没有 LLM 在线研判记录。",
  },
  en: {
    eyebrow: "Local Read-Only Console",
    subtitle: "Agent Runtime Security Console",
    metricSessions: "Sessions",
    metricFindings: "Findings",
    metricDecisions: "Decisions",
    metricPendingApprovals: "Pending",
    inventoryEyebrow: "Session Overview",
    inventoryTitle: "Session Inventory",
    emptySelect: "Select a session to inspect risk, timeline, and inventory.",
    selectedSession: "Selected Session",
    timelineTitle: "Execution Timeline",
    timelineHint: "Latest 12 tool calls",
    evidenceTitle: "Risk Evidence",
    evidenceHint: "Sensitive and external targets",
    inventoryDetailTitle: "Inventory",
    inventoryDetailHint: "Capabilities, tools, servers, and processes",
    checkingApi: "Checking API...",
    apiUnavailable: "API unavailable",
    loadingSessions: "Loading sessions...",
    loadingDetail: "Loading session detail...",
    noSessions: "No sessions found in the configured SQLite database.",
    seedDemoHint: "Generate a demo database and refresh the Console.",
    seedDemoCommand: "conda run -n agent zeroadr api seed-demo --db .zeroadr/console-demo.sqlite",
    sessionMissing: "The selected session was not found. The database may have changed or the page state is stale.",
    noMatchingSessions: "No sessions match the current filters.",
    noTimeline: "No timeline events available.",
    noEventDetail: "Select a timeline event to inspect the full RuntimeEvent.",
    noEvidence: "No evidence highlights in compact summary.",
    noEvidenceDetail: "No matching finding evidence.",
    findingLoadError: "Failed to load evidence",
    noInventory: "No inventory entries available.",
    noPolicies: "No policy decisions recorded.",
    filterAny: "All",
    capabilityFilter: "Capability filter",
    ruleFilter: "Rule filter",
    decisionFilter: "Action filter",
    searchPlaceholder: "Search sessions",
    filterAll: "All",
    filterFindings: "With findings",
    filterHigh: "High+",
    filterCritical: "Critical",
    tabTimeline: "Timeline",
    tabEvidence: "Evidence",
    tabPolicy: "Policy",
    tabBom: "BOM",
    policyTitle: "Policy Decisions",
    policyHint: "Policy decision history",
    bomTitle: "Agent-BOM",
    bomHint: "Read-only JSON",
    risk: "Risk",
    riskCritical: "critical",
    riskHigh: "high",
    riskMedium: "medium",
    riskLow: "low",
    riskClean: "No elevated risk",
    highDetail: "High-risk findings need priority review.",
    mediumDetail: "Medium severity findings present.",
    lowDetail: "No high or critical findings in summary.",
    events: "events",
    findings: "findings",
    decisions: "decisions",
    capability: "Capability",
    tool: "Tool",
    server: "Server",
    processes: "Processes",
    endpointEvents: "Endpoint events",
    sensitive: "Sensitive",
    external: "External",
    action: "Action",
    policy: "Policy",
    reason: "Reason",
    event: "Event",
    relatedEvents: "Related events",
    relatedDecisions: "Related decisions",
    agentEyebrow: "Endpoint Agent",
    agentTitle: "Agent Health",
    agentRefresh: "Refresh",
    agentLoading: "Loading agent health...",
    agentState: "State",
    agentCollector: "Collector",
    agentRecords: "Records",
    agentEvents: "Events",
    agentUpdated: "Updated",
    agentHintUnknown: "No agent status file found. Start endpoint agent and point api serve to the same status file.",
    agentHintUnhealthy: "Agent is unhealthy. Check the status file and restart the endpoint agent.",
    agentBccProbes: "BCC Probes",
    agentBccDropped: "Dropped",
    agentBccLastEvent: "Last event",
    approvalsEyebrow: "Human Approval",
    approvalsTitle: "Pending Approvals",
    approvalsRefresh: "Refresh",
    approvalsLoading: "Loading approval queue...",
    approvalsEmpty: "No pending approval requests.",
    approvalsSession: "Session",
    approvalsTool: "Tool",
    approvalsCapability: "Capability",
    approvalsReason: "Reason",
    approvalsCreated: "Created",
    approvalsApprove: "Approve",
    approvalsDeny: "Deny",
    approvalsPendingBadge: "Pending",
    approvalsResolvedApproved: "Approved",
    approvalsResolvedDenied: "Denied",
    approvalsResolvedExpired: "Expired",
    approvalsViewInbox: "View approval",
    approvalsResolveError: "Approval action failed",
    approvalsHint: "This is a localhost approval baseline. Hook clients should call wait-approval with approval_id.",
    approvalsStage: "Stage",
    toolResultWarning: "Warning: approval returns the original untrusted tool result to the Agent.",
    llmSettingsButton: "LLM Settings",
    llmSettingsEyebrow: "Model Service",
    llmSettingsTitle: "LLM Settings",
    llmSettingsDescription: "Configure an OpenAI-compatible Chat Completions service. The key is stored as plaintext in a private local file only.",
    llmBaseUrl: "Base URL",
    llmModel: "Model",
    llmApiKey: "API Key",
    llmLanguage: "Default language",
    llmTimeout: "Timeout (seconds)",
    llmMaxTokens: "Max output tokens",
    llmClearKey: "Clear key",
    llmTestTriage: "Test full triage",
    llmTestGate: "Test Gate",
    llmSaveTest: "Save and test full triage",
    llmSave: "Save",
    llmLoading: "Loading configuration...",
    llmSaved: "Configuration saved.",
    llmTestingTriage: "Testing the full triage model...",
    llmTestingGate: "Testing the Gate model...",
    llmConnected: "{target} model {model} connected in {latency} ms.",
    llmTargetTriage: "Full triage",
    llmTargetGate: "Gate",
    llmKeyConfigured: "Saved key: {masked}. Leave blank to keep it.",
    llmKeyMissing: "No API Key is saved.",
    llmKeyCleared: "API Key cleared.",
    llmEnvironmentOverride: "Environment variables override part of the local configuration and take precedence at runtime.",
    llmSources: "Effective sources: model {model}, URL {baseUrl}, key {apiKey}",
    llmLoadError: "Failed to load configuration",
    llmSaveError: "Failed to save configuration",
    llmTestError: "Connection test failed",
    llmGateTitle: "Online Adjudication Gate",
    llmGateHint: "Leave the model empty to reuse the full triage model",
    llmGateModel: "Gate model",
    llmGateTimeout: "Gate timeout (seconds)",
    llmGateMaxTokens: "Gate max output tokens",
    llmGateMetricsTitle: "Gate runtime metrics",
    llmGateMetricsHint: "Global Shadow / Enforce summary",
    llmGateMetricsLoading: "Loading Gate metrics...",
    llmGateMetricsEmpty: "No online Gate adjudications yet.",
    llmGateMetricsError: "Failed to load Gate metrics",
    llmGateMetricTotal: "Calls",
    llmGateMetricCompletion: "Completion",
    llmGateMetricFallback: "Human fallback",
    llmGateMetricLatency: "P95 latency",
    llmGateMetricVerdicts: "Verdicts",
    llmAdjudicationTitle: "LLM Adjudication",
    llmAdjudicationHint: "Shadow / Enforce history",
    noAdjudications: "No online LLM adjudications for this session.",
  },
};

const state = {
  language: localStorage.getItem("zeroadr.console.language") || "zh",
  sessions: [],
  riskFilter: "all",
  searchQuery: "",
  selectedSessionId: null,
  selectedDetail: null,
  selectedFull: null,
  selectedEvidence: null,
  selectedEvents: [],
  selectedFindings: [],
  selectedDecisions: [],
  selectedAdjudications: [],
  selectedToolResultGates: [],
  selectedRuntimeGates: [],
  selectedFindingId: null,
  selectedEventId: null,
  capabilityFilter: "all",
  ruleFilter: "all",
  decisionFilter: "all",
  activeTab: "timeline",
  pendingApprovals: [],
  approvalIndex: {},
  llmConfig: null,
  llmBusy: false,
};

const elements = {
  apiStatus: document.getElementById("api-status"),
  sessionCount: document.getElementById("session-count"),
  findingCount: document.getElementById("finding-count"),
  decisionCount: document.getElementById("decision-count"),
  pendingApprovalCount: document.getElementById("pending-approval-count"),
  sessionList: document.getElementById("session-list"),
  sessionDetail: document.getElementById("session-detail"),
  detailTemplate: document.getElementById("detail-template"),
  languageToggle: document.getElementById("language-toggle"),
  sessionSearch: document.getElementById("session-search"),
  riskFilter: document.getElementById("risk-filter"),
  agentHealthContent: document.getElementById("agent-health-content"),
  agentRefresh: document.getElementById("agent-refresh"),
  approvalsContent: document.getElementById("approvals-content"),
  approvalsRefresh: document.getElementById("approvals-refresh"),
  approvalsBadge: document.getElementById("approvals-badge"),
  llmSettingsButton: document.getElementById("llm-settings-button"),
  llmSettingsDialog: document.getElementById("llm-settings-dialog"),
  llmSettingsForm: document.getElementById("llm-settings-form"),
  llmSettingsClose: document.getElementById("llm-settings-close"),
  llmBaseUrl: document.getElementById("llm-base-url"),
  llmModel: document.getElementById("llm-model"),
  llmApiKey: document.getElementById("llm-api-key"),
  llmLanguage: document.getElementById("llm-language"),
  llmTimeout: document.getElementById("llm-timeout"),
  llmMaxOutputTokens: document.getElementById("llm-max-output-tokens"),
  llmGateModel: document.getElementById("llm-gate-model"),
  llmGateTimeout: document.getElementById("llm-gate-timeout"),
  llmGateMaxOutputTokens: document.getElementById("llm-gate-max-output-tokens"),
  llmGateMetrics: document.getElementById("llm-gate-metrics"),
  llmKeyHint: document.getElementById("llm-key-hint"),
  llmEnvironmentWarning: document.getElementById("llm-environment-warning"),
  llmConfigSource: document.getElementById("llm-config-source"),
  llmSettingsStatus: document.getElementById("llm-settings-status"),
  llmClearKey: document.getElementById("llm-clear-key"),
  llmTestTriage: document.getElementById("llm-test-triage"),
  llmTestGate: document.getElementById("llm-test-gate"),
  llmSaveTest: document.getElementById("llm-save-test"),
  llmSave: document.getElementById("llm-save"),
};

function t(key) {
  return translations[state.language][key] || translations.zh[key] || key;
}

function setLanguage(language) {
  state.language = language === "en" ? "en" : "zh";
  localStorage.setItem("zeroadr.console.language", state.language);
  document.documentElement.lang = state.language === "zh" ? "zh-CN" : "en";
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.getAttribute("data-i18n"));
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.setAttribute("placeholder", t(node.getAttribute("data-i18n-placeholder")));
  });
  document.querySelectorAll("[data-lang]").forEach((button) => {
    button.classList.toggle("active", button.getAttribute("data-lang") === state.language);
  });
  if (
    elements.apiStatus.textContent === "" ||
    (!elements.apiStatus.classList.contains("status-ok") &&
      !elements.apiStatus.classList.contains("status-error"))
  ) {
    elements.apiStatus.textContent = t("checkingApi");
  }
  renderSessions();
  renderApprovals();
  if (state.selectedSessionId) {
    selectSession(state.selectedSessionId);
  }
}

async function postJson(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok || payload.ok === false) {
    const error = new Error(payload.error?.message || `Request failed: ${response.status}`);
    error.code = payload.error?.code;
    throw error;
  }
  return payload.data || payload;
}

async function putJson(path, body) {
  const response = await fetch(path, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok || payload.ok === false) {
    const error = new Error(payload.error?.message || `Request failed: ${response.status}`);
    error.code = payload.error?.code;
    throw error;
  }
  return payload.data || payload;
}

function formatMessage(template, values) {
  return Object.entries(values).reduce(
    (message, [key, value]) => message.replace(`{${key}}`, String(value)),
    template,
  );
}

function setLlmBusy(busy) {
  state.llmBusy = busy;
  [
    elements.llmClearKey,
    elements.llmTestTriage,
    elements.llmTestGate,
    elements.llmSaveTest,
    elements.llmSave,
  ].forEach(
    (button) => {
      button.disabled =
        busy || (button === elements.llmClearKey && !state.llmConfig?.api_key_saved);
    },
  );
}

function setLlmStatus(message, kind = "") {
  elements.llmSettingsStatus.textContent = message;
  elements.llmSettingsStatus.className = `settings-status visible ${kind}`.trim();
}

function renderLlmConfig(config) {
  state.llmConfig = config;
  const saved = config.saved || {};
  elements.llmBaseUrl.value = saved.base_url || "https://api.openai.com/v1";
  elements.llmModel.value = saved.model || "";
  elements.llmApiKey.value = "";
  elements.llmLanguage.value = saved.language || "zh";
  elements.llmTimeout.value = saved.timeout || 30;
  elements.llmMaxOutputTokens.value = saved.max_output_tokens || 1200;
  elements.llmGateModel.value = saved.gate_model || "";
  elements.llmGateTimeout.value = saved.gate_timeout || 8;
  elements.llmGateMaxOutputTokens.value = saved.gate_max_output_tokens || 256;
  elements.llmKeyHint.textContent = config.api_key_saved
    ? formatMessage(t("llmKeyConfigured"), { masked: config.api_key_masked || "••••" })
    : t("llmKeyMissing");
  elements.llmEnvironmentWarning.hidden = !config.environment_override;
  elements.llmEnvironmentWarning.textContent = t("llmEnvironmentOverride");
  const sources = config.sources || {};
  elements.llmConfigSource.textContent = formatMessage(t("llmSources"), {
    model: sources.model || "unset",
    baseUrl: sources.base_url || "default",
    apiKey: sources.api_key || "unset",
  });
}

async function openLlmSettings() {
  elements.llmSettingsDialog.showModal();
  setLlmStatus(t("llmLoading"));
  setLlmBusy(true);
  elements.llmGateMetrics.textContent = t("llmGateMetricsLoading");
  try {
    renderLlmConfig(await fetchJson("/api/v0/llm/config"));
    try {
      renderGateMetrics(await fetchJson("/api/v0/llm/adjudications/metrics"));
    } catch (error) {
      elements.llmGateMetrics.textContent = `${t("llmGateMetricsError")}: ${error.message}`;
    }
    elements.llmSettingsStatus.className = "settings-status";
    elements.llmBaseUrl.focus();
  } catch (error) {
    setLlmStatus(`${t("llmLoadError")}: ${error.message}`, "error");
  } finally {
    setLlmBusy(false);
  }
}

function renderGateMetrics(metrics) {
  if (!metrics || Number(metrics.total || 0) === 0) {
    elements.llmGateMetrics.innerHTML = `<span class="meta gate-metrics-empty">${escapeHtml(t("llmGateMetricsEmpty"))}</span>`;
    return;
  }
  const verdicts = Object.entries(metrics.verdict_counts || {})
    .map(([name, count]) => `${name}: ${count}`)
    .join(" · ") || "-";
  const items = [
    [t("llmGateMetricTotal"), Number(metrics.total || 0)],
    [t("llmGateMetricCompletion"), `${Math.round(Number(metrics.completion_rate || 0) * 100)}%`],
    [t("llmGateMetricFallback"), `${Math.round(Number(metrics.fallback_rate || 0) * 100)}%`],
    [t("llmGateMetricLatency"), `${Number(metrics.latency_ms?.p95 || 0)} ms`],
  ];
  elements.llmGateMetrics.innerHTML = `
    ${items
      .map(
        ([label, value]) => `
          <div class="gate-metric">
            <span>${escapeHtml(label)}</span>
            <strong>${escapeHtml(value)}</strong>
          </div>
        `,
      )
      .join("")}
    <div class="gate-metric gate-metric-wide">
      <span>${escapeHtml(t("llmGateMetricVerdicts"))}</span>
      <strong>${escapeHtml(verdicts)}</strong>
    </div>
  `;
}

function llmFormPayload() {
  const payload = {
    schema_version: "0.1",
    base_url: elements.llmBaseUrl.value.trim(),
    model: elements.llmModel.value.trim(),
    language: elements.llmLanguage.value,
    timeout: Number(elements.llmTimeout.value),
    max_output_tokens: Number(elements.llmMaxOutputTokens.value),
    gate_model: elements.llmGateModel.value.trim() || null,
    gate_timeout: Number(elements.llmGateTimeout.value),
    gate_max_output_tokens: Number(elements.llmGateMaxOutputTokens.value),
  };
  if (elements.llmApiKey.value.trim()) {
    payload.api_key = elements.llmApiKey.value.trim();
  }
  return payload;
}

async function saveLlmSettings(testAfter = false) {
  if (!elements.llmSettingsForm.reportValidity()) {
    return;
  }
  setLlmBusy(true);
  try {
    renderLlmConfig(await putJson("/api/v0/llm/config", llmFormPayload()));
    setLlmStatus(t("llmSaved"), "success");
    if (testAfter) {
      await testLlmSettings("triage", true);
    }
  } catch (error) {
    setLlmStatus(`${t("llmSaveError")}: ${error.message}`, "error");
  } finally {
    setLlmBusy(false);
  }
}

async function testLlmSettings(target, alreadyBusy = false) {
  if (!alreadyBusy) {
    setLlmBusy(true);
  }
  setLlmStatus(t(target === "gate" ? "llmTestingGate" : "llmTestingTriage"));
  try {
    const result = await postJson("/api/v0/llm/config/test", { target });
    setLlmStatus(
      formatMessage(t("llmConnected"), {
        target: t(result.target === "gate" ? "llmTargetGate" : "llmTargetTriage"),
        model: result.model || "-",
        latency: result.latency_ms ?? 0,
      }),
      "success",
    );
  } catch (error) {
    setLlmStatus(`${t("llmTestError")}: ${error.message}`, "error");
  } finally {
    if (!alreadyBusy) {
      setLlmBusy(false);
    }
  }
}

async function clearLlmKey() {
  setLlmBusy(true);
  try {
    renderLlmConfig(await putJson("/api/v0/llm/config", { clear_api_key: true }));
    setLlmStatus(t("llmKeyCleared"), "success");
  } catch (error) {
    setLlmStatus(`${t("llmSaveError")}: ${error.message}`, "error");
  } finally {
    setLlmBusy(false);
  }
}

async function fetchJson(path) {
  const response = await fetch(path);
  const payload = await response.json();
  if (!response.ok || payload.ok === false) {
    const error = new Error(payload.error?.message || `Request failed: ${response.status}`);
    error.code = payload.error?.code;
    throw error;
  }
  return payload.data || payload;
}

async function loadSessions() {
  elements.sessionList.textContent = t("loadingSessions");
  state.sessions = (await fetchJson("/api/v0/sessions?limit=50&offset=0")).sessions || [];
  renderSessions();
  if (state.sessions.length > 0) {
    await selectSession(state.sessions[0].session_id);
  } else {
    elements.sessionDetail.innerHTML = renderSessionError(t("noSessions"), true);
  }
}

async function loadSessionDetail(sessionId) {
  return fetchJson(`/api/v0/sessions/${encodeURIComponent(sessionId)}?compact=1`);
}

async function loadSessionFull(sessionId) {
  return fetchJson(`/api/v0/sessions/${encodeURIComponent(sessionId)}`);
}

async function loadSessionEvidence(sessionId) {
  return fetchJson(`/api/v0/sessions/${encodeURIComponent(sessionId)}/evidence`);
}

async function loadSessionEvents(sessionId) {
  return fetchJson(`/api/v0/sessions/${encodeURIComponent(sessionId)}/events`);
}

async function loadSessionFindings(sessionId) {
  return fetchJson(`/api/v0/sessions/${encodeURIComponent(sessionId)}/findings`);
}

async function loadSessionDecisions(sessionId) {
  return fetchJson(`/api/v0/sessions/${encodeURIComponent(sessionId)}/decisions`);
}

async function loadSessionAdjudications(sessionId) {
  return fetchJson(`/api/v0/sessions/${encodeURIComponent(sessionId)}/adjudications`);
}

async function loadSessionToolResultGates(sessionId) {
  return fetchJson(`/api/v0/sessions/${encodeURIComponent(sessionId)}/tool-result-gates`);
}

async function loadSessionRuntimeGates(sessionId) {
  return fetchJson(`/api/v0/sessions/${encodeURIComponent(sessionId)}/runtime-gates`);
}

async function loadFindingEvidence(sessionId, findingId) {
  const encodedSession = encodeURIComponent(sessionId);
  const encodedFinding = encodeURIComponent(findingId);
  return fetchJson(`/api/v0/sessions/${encodedSession}/evidence?finding_id=${encodedFinding}`);
}

async function refreshHealth() {
  const health = await fetchJson("/health");
  elements.apiStatus.textContent = `API ${health.api_version} ${health.status}`;
  elements.apiStatus.classList.add("status-ok");
}

async function loadApprovals(status = "pending") {
  const query = status ? `?status=${encodeURIComponent(status)}` : "";
  return fetchJson(`/api/v0/approvals${query}`);
}

async function loadAllApprovals() {
  return fetchJson("/api/v0/approvals");
}

async function refreshApprovals() {
  try {
    const [pendingPayload, allPayload] = await Promise.all([loadApprovals("pending"), loadAllApprovals()]);
    state.pendingApprovals = pendingPayload.approvals || [];
    state.approvalIndex = {};
    (allPayload.approvals || []).forEach((entry) => {
      const approval = entry.approval || {};
      if (approval.decision_id) {
        state.approvalIndex[approval.decision_id] = approval;
      }
      if (approval.approval_id) {
        state.approvalIndex[approval.approval_id] = approval;
      }
    });
    elements.pendingApprovalCount.textContent = String(pendingPayload.pending_count || 0);
    elements.approvalsBadge.textContent = String(pendingPayload.pending_count || 0);
    elements.approvalsBadge.classList.toggle("empty", Number(pendingPayload.pending_count || 0) === 0);
    renderApprovals();
    renderSessions();
    if (state.selectedSessionId) {
      const policyTarget = elements.sessionDetail.querySelector("#policy-history");
      if (policyTarget) {
        renderPolicyHistory(policyTarget, filterPolicyDecisions(state.selectedDecisions));
      }
    }
  } catch (error) {
    elements.approvalsContent.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
  }
}

async function resolveApproval(approvalId, status) {
  await postJson(`/api/v0/approvals/${encodeURIComponent(approvalId)}/resolve`, {
    status,
    resolved_by: "console",
  });
  await refreshApprovals();
  if (state.selectedSessionId) {
    await selectSession(state.selectedSessionId);
  }
}

async function refreshAgentHealth() {
  try {
    const payload = await fetchJson("/api/v0/endpoint-agent/health");
    renderAgentHealth(payload);
  } catch (error) {
    elements.agentHealthContent.innerHTML = `<div class="empty-state agent-unhealthy">${escapeHtml(error.message)}</div>`;
  }
}

function renderAgentHealth(payload) {
  const agent = payload.agent || {};
  const healthy = payload.healthy !== false && agent.state !== "unknown";
  const hint =
    agent.state === "unknown" ? t("agentHintUnknown") : healthy ? "" : t("agentHintUnhealthy");
  const bcc = agent.bcc || null;
  const bccHtml = bcc
    ? `
    <div class="agent-bcc-panel">
      <p class="meta"><strong>${escapeHtml(t("agentBccProbes"))}</strong></p>
      <div class="agent-health-grid">
        ${Object.entries(bcc.probes || {})
          .map(
            ([name, probe]) => `
          <article>
            <span>${escapeHtml(name)}</span>
            <strong class="${probe.attached ? "" : "agent-unhealthy"}">${escapeHtml(
              probe.attached ? `${probe.events ?? 0}` : probe.last_error || "detached"
            )}</strong>
          </article>`
          )
          .join("")}
      </div>
      <p class="meta">${escapeHtml(t("agentBccDropped"))}: ${escapeHtml(String(bcc.dropped_events ?? 0))}</p>
      ${
        bcc.last_event_at
          ? `<p class="meta">${escapeHtml(t("agentBccLastEvent"))}: ${escapeHtml(String(bcc.last_event_at))}</p>`
          : ""
      }
    </div>`
    : "";
  elements.agentHealthContent.innerHTML = `
    <div class="agent-health-grid">
      <article><span>${escapeHtml(t("agentState"))}</span><strong class="${healthy ? "" : "agent-unhealthy"}">${escapeHtml(String(agent.state || "unknown"))}</strong></article>
      <article><span>${escapeHtml(t("agentCollector"))}</span><strong>${escapeHtml(String(agent.collector || "-"))}</strong></article>
      <article><span>${escapeHtml(t("agentRecords"))}</span><strong>${escapeHtml(String(agent.records_written ?? 0))}</strong></article>
      <article><span>${escapeHtml(t("agentEvents"))}</span><strong>${escapeHtml(String(agent.events_written ?? 0))}</strong></article>
    </div>
    ${bccHtml}
    <p class="meta">${escapeHtml(t("agentUpdated"))}: ${escapeHtml(String(agent.updated_at || "-"))}</p>
    ${agent.last_error ? `<p class="meta agent-unhealthy">${escapeHtml(String(agent.last_error))}</p>` : ""}
    ${agent.stopped_reason && agent.stopped_reason !== "running" ? `<p class="meta">${escapeHtml(String(agent.stopped_reason))}</p>` : ""}
    ${hint ? `<p class="meta">${escapeHtml(hint)}</p>` : ""}
  `;
}

function renderApprovals() {
  if (!state.pendingApprovals.length) {
    elements.approvalsContent.innerHTML = `
      <div class="empty-state">
        <p>${escapeHtml(t("approvalsEmpty"))}</p>
        <p class="meta">${escapeHtml(t("approvalsHint"))}</p>
      </div>
    `;
    return;
  }
  elements.approvalsContent.innerHTML = state.pendingApprovals
    .map((entry) => {
      const approval = entry.approval || {};
      const args = approval.arguments ? JSON.stringify(approval.arguments) : "-";
      const preview = approval.result_preview ? JSON.stringify(approval.result_preview) : "-";
      const resultWarning = approval.stage === "tool_result"
        ? `<strong class="risk-high">${escapeHtml(t("toolResultWarning"))}</strong><pre class="code-panel compact-code">${escapeHtml(preview)}</pre>`
        : "";
      return `
        <article class="approval-card" data-approval-id="${escapeHtml(approval.approval_id)}">
          <strong>${escapeHtml(approval.tool_name || "-")} · ${escapeHtml(approval.capability || "-")}</strong>
          <span class="meta">${escapeHtml(t("approvalsSession"))}: ${escapeHtml(approval.session_id || "-")}</span>
          <span class="meta">${escapeHtml(t("approvalsReason"))}: ${escapeHtml(approval.reason || "-")}</span>
          <span class="meta">${escapeHtml(t("approvalsStage"))}: ${escapeHtml(approval.stage || "pre_tool")}</span>
          <span class="meta">${escapeHtml(t("approvalsCreated"))}: ${escapeHtml(String(approval.created_at || "-"))}</span>
          <pre class="code-panel compact-code">${escapeHtml(args)}</pre>
          ${resultWarning}
          <div class="approval-actions">
            <button type="button" class="approve-button" data-approval-id="${escapeHtml(approval.approval_id)}" data-resolve="approved">${escapeHtml(t("approvalsApprove"))}</button>
            <button type="button" class="deny-button" data-approval-id="${escapeHtml(approval.approval_id)}" data-resolve="denied">${escapeHtml(t("approvalsDeny"))}</button>
            <button type="button" class="inline-button" data-session-id="${escapeHtml(approval.session_id)}">${escapeHtml(t("selectedSession"))}</button>
          </div>
        </article>
      `;
    })
    .join("");
  elements.approvalsContent.querySelectorAll("[data-resolve]").forEach((button) => {
    button.addEventListener("click", async () => {
      const approvalId = button.getAttribute("data-approval-id");
      const status = button.getAttribute("data-resolve");
      button.disabled = true;
      try {
        await resolveApproval(approvalId, status);
      } catch (error) {
        window.alert(`${t("approvalsResolveError")}: ${error.message}`);
        button.disabled = false;
      }
    });
  });
  elements.approvalsContent.querySelectorAll("[data-session-id]").forEach((button) => {
    if (button.hasAttribute("data-resolve")) {
      return;
    }
    button.addEventListener("click", () => selectSession(button.getAttribute("data-session-id")));
  });
}

async function selectSession(sessionId) {
  state.selectedSessionId = sessionId;
  renderSessions();
  elements.sessionDetail.innerHTML = `<div class="empty-state">${escapeHtml(t("loadingDetail"))}</div>`;
  try {
    const [detail, full, evidence, events, findings, decisions, adjudications, toolResultGates, runtimeGates] = await Promise.all([
      loadSessionDetail(sessionId),
      loadSessionFull(sessionId),
      loadSessionEvidence(sessionId),
      loadSessionEvents(sessionId),
      loadSessionFindings(sessionId),
      loadSessionDecisions(sessionId),
      loadSessionAdjudications(sessionId),
      loadSessionToolResultGates(sessionId),
      loadSessionRuntimeGates(sessionId),
    ]);
    state.selectedDetail = detail;
    state.selectedFull = full;
    state.selectedEvidence = evidence;
    state.selectedEvents = events.events || [];
    state.selectedFindings = findings.findings || [];
    state.selectedDecisions = decisions.policy_decisions || [];
    state.selectedAdjudications = adjudications.llm_adjudications || [];
    state.selectedToolResultGates = toolResultGates.tool_result_gates || [];
    state.selectedRuntimeGates = runtimeGates.runtime_gates || [];
    state.selectedFindingId = null;
    state.selectedEventId = null;
    state.capabilityFilter = "all";
    state.ruleFilter = "all";
    state.decisionFilter = "all";
    state.activeTab = "timeline";
    renderSessionDetail(detail, full, evidence);
  } catch (error) {
    const message = error.code === "session_not_found" ? t("sessionMissing") : error.message;
    elements.sessionDetail.innerHTML = renderSessionError(message, error.code === "session_not_found");
  }
}

function filterSessions() {
  const query = state.searchQuery.trim().toLowerCase();
  return state.sessions.filter((session) => {
    const risk = session.risk_summary || {};
    const matchesSearch = !query || String(session.session_id).toLowerCase().includes(query);
    const hasFindings = Number(session.finding_count || 0) > 0;
    const highOrCritical = Number(risk.high || 0) > 0 || Number(risk.critical || 0) > 0;
    const critical = Number(risk.critical || 0) > 0;
    const matchesRisk =
      state.riskFilter === "all" ||
      (state.riskFilter === "findings" && hasFindings) ||
      (state.riskFilter === "high" && highOrCritical) ||
      (state.riskFilter === "critical" && critical);
    return matchesSearch && matchesRisk;
  });
}

function renderSessions() {
  const visibleSessions = filterSessions();
  const findingCount = state.sessions.reduce((total, session) => total + session.finding_count, 0);
  const decisionCount = state.sessions.reduce((total, session) => total + session.decision_count, 0);
  const pendingCount = state.sessions.reduce(
    (total, session) => total + Number(session.pending_approval_count || 0),
    0,
  );
  elements.sessionCount.textContent = String(state.sessions.length);
  elements.findingCount.textContent = String(findingCount);
  elements.decisionCount.textContent = String(decisionCount);
  if (elements.pendingApprovalCount.textContent === "0" || !state.pendingApprovals.length) {
    elements.pendingApprovalCount.textContent = String(pendingCount);
  }
  if (state.sessions.length === 0) {
    elements.sessionList.innerHTML = `<div class="empty-state">${escapeHtml(t("noSessions"))}</div>`;
    return;
  }
  if (visibleSessions.length === 0) {
    elements.sessionList.innerHTML = `<div class="empty-state">${escapeHtml(t("noMatchingSessions"))}</div>`;
    return;
  }
  elements.sessionList.innerHTML = visibleSessions
    .map((session) => {
      const risk = summarizeRisk(session.risk_summary);
      const active = session.session_id === state.selectedSessionId ? " active" : "";
      const pendingBadge =
        Number(session.pending_approval_count || 0) > 0
          ? `<span class="session-pending-badge">${Number(session.pending_approval_count)} ${escapeHtml(t("approvalsPendingBadge"))}</span>`
          : "";
      return `
        <button class="session-card${active}" type="button" data-session-id="${escapeHtml(session.session_id)}">
          <strong>${escapeHtml(session.session_id)}</strong>
          <span class="meta">
            <span>${session.event_count} ${t("events")}</span>
            <span>${session.finding_count} ${t("findings")}</span>
            <span>${session.decision_count} ${t("decisions")}</span>
            ${pendingBadge}
            <span class="${risk.className}">${risk.label}</span>
          </span>
        </button>
      `;
    })
    .join("");
  document.querySelectorAll("[data-session-id]").forEach((button) => {
    button.addEventListener("click", () => selectSession(button.getAttribute("data-session-id")));
  });
}

function renderSessionDetail(payload, fullPayload, evidencePayload) {
  const fragment = elements.detailTemplate.content.cloneNode(true);
  fragment.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.getAttribute("data-i18n"));
  });
  fragment.getElementById("detail-session-id").textContent = payload.session_id;
  renderRisk(fragment.getElementById("risk-summary"), payload.risk);
  renderDetailFilters(fragment, payload.timeline || [], state.selectedFindings || [], state.selectedDecisions || []);
  renderTimeline(fragment.getElementById("timeline"), filterTimelineEvents(payload.timeline || []));
  renderEventDetail(fragment.getElementById("event-detail"), null);
  renderEvidence(fragment.getElementById("evidence"), filterEvidenceSummary(payload.summary || {}));
  renderEvidenceDetail(fragment.getElementById("evidence-detail"), evidencePayload);
  renderPolicyHistory(fragment.getElementById("policy-history"), filterPolicyDecisions(state.selectedDecisions || []));
  renderLLMAdjudications(
    fragment.getElementById("llm-adjudication-history"),
    state.selectedAdjudications || [],
    state.selectedToolResultGates || [],
    state.selectedRuntimeGates || [],
  );
  renderBom(fragment.getElementById("bom-panel"), fullPayload.agent_bom || {});
  renderInventory(fragment.getElementById("inventory"), payload.inventory || {});
  elements.sessionDetail.replaceChildren(fragment);
  elements.sessionDetail.querySelectorAll("[data-tab]").forEach((button) => {
    button.addEventListener("click", () => switchTab(button.getAttribute("data-tab")));
  });
  elements.sessionDetail.querySelectorAll("[data-finding-id]").forEach((button) => {
    button.addEventListener("click", () => selectFinding(button.getAttribute("data-finding-id")));
  });
  elements.sessionDetail.querySelectorAll("[data-event-id]").forEach((button) => {
    button.addEventListener("click", () => selectEvent(button.getAttribute("data-event-id")));
  });
  elements.sessionDetail.querySelectorAll(".timeline-approval-link").forEach((button) => {
    button.addEventListener("click", () => scrollToApprovalsPanel(button.getAttribute("data-approval-id")));
  });
  const capabilityFilter = elements.sessionDetail.querySelector("#capability-filter");
  const ruleFilter = elements.sessionDetail.querySelector("#rule-filter");
  const decisionFilter = elements.sessionDetail.querySelector("#decision-filter");
  capabilityFilter?.addEventListener("change", () => {
    state.capabilityFilter = capabilityFilter.value;
    rerenderCurrentSessionDetail();
  });
  ruleFilter?.addEventListener("change", () => {
    state.ruleFilter = ruleFilter.value;
    rerenderCurrentSessionDetail();
  });
  decisionFilter?.addEventListener("change", () => {
    state.decisionFilter = decisionFilter.value;
    rerenderCurrentSessionDetail();
  });
  highlightFindingButtons();
  highlightEventRows();
  switchTab(state.activeTab);
}

function renderDetailFilters(fragment, timeline, findings, decisions) {
  renderSelectOptions(
    fragment.getElementById("capability-filter"),
    uniqueValues(timeline.map((event) => event.capability).filter(Boolean)),
    state.capabilityFilter,
  );
  renderSelectOptions(
    fragment.getElementById("rule-filter"),
    uniqueValues(findings.map((finding) => finding.rule_id).filter(Boolean)),
    state.ruleFilter,
  );
  renderSelectOptions(
    fragment.getElementById("decision-filter"),
    uniqueValues(decisions.map((decision) => decision.action).filter(Boolean)),
    state.decisionFilter,
  );
}

function renderSelectOptions(select, values, selectedValue) {
  if (!select) {
    return;
  }
  select.innerHTML = [
    `<option value="all">${escapeHtml(t("filterAny"))}</option>`,
    ...values.map((value) => `<option value="${escapeHtml(String(value))}">${escapeHtml(String(value))}</option>`),
  ].join("");
  select.value = values.includes(selectedValue) ? selectedValue : "all";
}

function filterTimelineEvents(timeline) {
  if (state.capabilityFilter === "all") {
    return timeline;
  }
  return timeline.filter((event) => event.capability === state.capabilityFilter);
}

function filterEvidenceSummary(summary) {
  if (state.ruleFilter === "all") {
    return summary;
  }
  const matchingFindings = state.selectedFindings.filter((finding) => finding.rule_id === state.ruleFilter);
  return {
    ...summary,
    sensitive_targets: uniqueValues(matchingFindings.map((finding) => finding.target).filter(Boolean)),
    external_targets: [],
  };
}

function filterPolicyDecisions(decisions) {
  if (state.decisionFilter === "all") {
    return decisions;
  }
  return decisions.filter((decision) => decision.action === state.decisionFilter);
}

function rerenderCurrentSessionDetail() {
  if (!state.selectedDetail || !state.selectedFull) {
    return;
  }
  renderSessionDetail(state.selectedDetail, state.selectedFull, state.selectedEvidence);
}

function uniqueValues(values) {
  return [...new Set(values.map((value) => String(value)))].sort();
}

function renderRisk(target, risk) {
  const summary = summarizeRisk(risk);
  target.className = `risk-card ${summary.bgClass}`;
  target.innerHTML = `
    <p class="eyebrow">${escapeHtml(t("risk"))}</p>
    <h2 class="${summary.className}">${escapeHtml(summary.label)}</h2>
    <p class="meta">${escapeHtml(summary.detail)}</p>
  `;
}

function renderTimeline(target, timeline) {
  if (timeline.length === 0) {
    target.innerHTML = `<li>${escapeHtml(t("noTimeline"))}</li>`;
    return;
  }
  target.innerHTML = timeline
    .slice(0, 12)
    .map((event) => {
      const tool = event.tool_name || event.event_type || "event";
      const targetValue = event.target || event.requested?.target || event.requested?.path || "";
      const decisionAction = event.decision?.action || "";
      const decisionId = event.decision?.decision_id || "";
      const resultGate = event.tool_result_gate || null;
      const approval = state.approvalIndex[resultGate?.approval_id || decisionId];
      const approvalLink =
        (decisionAction === "require_approval" || resultGate?.proposed_action === "require_approval") && approval?.approval_id
          ? `<button class="inline-button timeline-approval-link" type="button" data-approval-id="${escapeHtml(String(approval.approval_id))}">${escapeHtml(t("approvalsViewInbox"))}</button>`
          : "";
      const decision = decisionAction ? `${t("action")}: ${decisionAction}` : "";
      const gateSummary = resultGate
        ? `Tool Result Gate: ${resultGate.mode}/${resultGate.review} · ${resultGate.verdict || resultGate.error_code || "rules"} · ${resultGate.effective_action}`
        : "";
      const eventId = event.event_id || event.requested?.event_id || event.id || "";
      const active = eventId && eventId === state.selectedEventId ? " active" : "";
      const findings = Array.isArray(event.findings) ? event.findings : [];
      const findingCount = findings.length;
      const findingChips = findings
        .map((finding) => {
          const findingId = finding.finding_id || finding.id;
          if (!findingId) {
            return "";
          }
          const label = `${finding.rule_id || "finding"} · ${finding.severity || "-"}`;
          const active = findingId === state.selectedFindingId ? " active" : "";
          return `
            <button class="finding-chip${active}" type="button" data-finding-id="${escapeHtml(String(findingId))}">
              ${escapeHtml(label)}
            </button>
          `;
        })
        .join("");
      return `
        <li class="${active.trim()}">
          <button class="timeline-main" type="button" data-event-id="${escapeHtml(String(eventId))}">
            <strong>${escapeHtml(tool)}</strong>
            <code>${escapeHtml(String(targetValue || "-"))}</code>
          </button>
          <span class="meta">
            <span>${escapeHtml(event.capability || "-")}</span>
            <span>${escapeHtml(decision || "allow")}</span>
            ${gateSummary ? `<span>${escapeHtml(gateSummary)}</span>` : ""}
            ${approvalLink}
            <span>${findingCount} ${t("findings")}</span>
          </span>
          ${findingChips ? `<div class="timeline-findings">${findingChips}</div>` : ""}
        </li>
      `;
    })
    .join("");
}

function renderEvidence(target, summary) {
  const items = [
    ...(summary.sensitive_targets || []).map((value) => `${t("sensitive")}: ${value}`),
    ...(summary.external_targets || []).map((value) => `${t("external")}: ${value}`),
  ];
  target.innerHTML = renderTags(items, t("noEvidence"), "finding-row");
}

function renderEvidenceDetail(target, evidence) {
  if (!evidence?.finding) {
    target.innerHTML = `<span class="meta">${escapeHtml(t("noEvidenceDetail"))}</span>`;
    return;
  }
  const finding = evidence.finding;
  const events = evidence.events || [];
  const decisions = evidence.related_decisions || [];
  target.innerHTML = `
    <section class="evidence-section">
      <h4>${escapeHtml(t("findings"))}</h4>
      <div class="finding-row active">
        <strong>${escapeHtml(finding.rule_id)}</strong>
        <span>${escapeHtml(finding.severity)}</span>
        <span>${escapeHtml(finding.target || "-")}</span>
      </div>
      <pre class="code-panel">${escapeHtml(JSON.stringify(finding, null, 2))}</pre>
    </section>
    <section class="evidence-section">
      <h4>${escapeHtml(t("relatedEvents"))}</h4>
      <pre class="code-panel">${escapeHtml(JSON.stringify(events, null, 2))}</pre>
    </section>
    <section class="evidence-section">
      <h4>${escapeHtml(t("relatedDecisions"))}</h4>
      <pre class="code-panel">${escapeHtml(JSON.stringify(decisions, null, 2))}</pre>
    </section>
  `;
}

function selectEvent(eventId) {
  if (!eventId) {
    return;
  }
  state.selectedEventId = eventId;
  const detailTarget = elements.sessionDetail.querySelector("#event-detail");
  if (!detailTarget) {
    return;
  }
  const event = findEventById(eventId);
  renderEventDetail(detailTarget, event);
  highlightEventRows();
}

function findEventById(eventId) {
  const events = state.selectedEvents || [];
  return events.find((event) => event.event_id === eventId) || null;
}

function renderEventDetail(target, event) {
  if (!event) {
    target.innerHTML = `<span class="meta">${escapeHtml(t("noEventDetail"))}</span>`;
    return;
  }
  target.innerHTML = `
    <div class="section-heading compact-heading">
      <h3>${escapeHtml(t("event"))}</h3>
      <span>${escapeHtml(event.event_id || "-")}</span>
    </div>
    <pre class="code-panel">${escapeHtml(JSON.stringify(event, null, 2))}</pre>
  `;
}

async function selectFinding(findingId) {
  if (!state.selectedSessionId || !findingId) {
    return;
  }
  state.selectedFindingId = findingId;
  switchTab("evidence");
  highlightFindingButtons();
  const detailTarget = elements.sessionDetail.querySelector("#evidence-detail");
  if (!detailTarget) {
    return;
  }
  detailTarget.innerHTML = `<span class="meta">${escapeHtml(t("loadingDetail"))}</span>`;
  try {
    state.selectedEvidence = await loadFindingEvidence(state.selectedSessionId, findingId);
    renderEvidenceDetail(detailTarget, state.selectedEvidence);
  } catch (error) {
    detailTarget.innerHTML = `<span class="meta">${escapeHtml(t("findingLoadError"))}: ${escapeHtml(error.message)}</span>`;
  }
  highlightFindingButtons();
}

function highlightFindingButtons() {
  elements.sessionDetail.querySelectorAll("[data-finding-id]").forEach((button) => {
    button.classList.toggle("active", button.getAttribute("data-finding-id") === state.selectedFindingId);
  });
}

function highlightEventRows() {
  elements.sessionDetail.querySelectorAll("[data-event-id]").forEach((button) => {
    const active = button.getAttribute("data-event-id") === state.selectedEventId;
    button.classList.toggle("active", active);
    button.closest("li")?.classList.toggle("active", active);
  });
}

function approvalStatusLabel(decision) {
  const approval = state.approvalIndex[decision.decision_id];
  if (!approval || approval.status === "pending") {
    return "";
  }
  if (approval.status === "approved") {
    return `<span class="approval-status-tag">${escapeHtml(t("approvalsResolvedApproved"))}</span>`;
  }
  if (approval.status === "denied") {
    return `<span class="approval-status-tag">${escapeHtml(t("approvalsResolvedDenied"))}</span>`;
  }
  if (approval.status === "expired") {
    return `<span class="approval-status-tag">${escapeHtml(t("approvalsResolvedExpired"))}</span>`;
  }
  return "";
}

function scrollToApprovalsPanel(approvalId) {
  const panel = document.getElementById("approvals-panel");
  if (panel) {
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  if (!approvalId) {
    return;
  }
  window.setTimeout(() => {
    const card = elements.approvalsContent.querySelector(`[data-approval-id="${approvalId}"]`);
    if (card) {
      card.classList.add("active");
      card.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, 150);
}

function renderPolicyHistory(target, decisions) {
  if (!decisions.length) {
    target.innerHTML = `<span class="meta">${escapeHtml(t("noPolicies"))}</span>`;
    return;
  }
  target.innerHTML = decisions
    .map(
      (decision) => `
        <article class="decision-row">
          <strong>${escapeHtml(t("action"))}: ${escapeHtml(decision.action || "-")}${approvalStatusLabel(decision)}</strong>
          <span>${escapeHtml(t("policy"))}: ${escapeHtml(decision.policy_id || "default")}</span>
          <span>${escapeHtml(t("event"))}: ${escapeHtml(decision.event_id || "-")}</span>
          <span>${escapeHtml(t("reason"))}: ${escapeHtml(decision.reason || "-")}</span>
        </article>
      `,
    )
    .join("");
}

function renderLLMAdjudications(target, adjudications, toolResultGates = [], runtimeGates = []) {
  if (!adjudications.length && !toolResultGates.length && !runtimeGates.length) {
    target.innerHTML = `<span class="meta">${escapeHtml(t("noAdjudications"))}</span>`;
    return;
  }
  const gateRows = toolResultGates.map((item) => `
    <article class="adjudication-row">
      <strong>Tool Result Gate · ${escapeHtml(item.mode || "-")} · ${escapeHtml(item.review || "-")}</strong>
      <span>${escapeHtml(t("action"))}: ${escapeHtml(item.base_action || "-")} → ${escapeHtml(item.proposed_action || "-")} → ${escapeHtml(item.effective_action || "-")}</span>
      <span>Verdict: ${escapeHtml(item.verdict || item.error_code || "rules")}</span>
      <span>${escapeHtml(item.latency_ms || 0)} ms · ${escapeHtml(item.response_byte_count || 0)} bytes</span>
    </article>
  `).join("");
  const runtimeGateRows = runtimeGates.map((item) => `
    <article class="adjudication-row">
      <strong>Runtime Gate · ${escapeHtml(item.stage || "-")} · ${escapeHtml(item.mode || "-")} · ${escapeHtml(item.review || "-")}</strong>
      <span>${escapeHtml(t("action"))}: ${escapeHtml(item.base_action || "-")} → ${escapeHtml(item.proposed_action || "-")} → ${escapeHtml(item.effective_action || "-")}</span>
      <span>Verdict: ${escapeHtml(item.verdict || item.error_code || "rules")} · Confidence: ${item.confidence == null ? "-" : escapeHtml(item.confidence)}</span>
      <span>${escapeHtml(item.capability || "-")} · ${escapeHtml(item.latency_ms || 0)} ms · Compromised: ${escapeHtml(Boolean(item.session_compromised))}</span>
    </article>
  `).join("");
  const adjudicationRows = adjudications
    .map((item) => {
      const verdict = item.result?.verdict || item.error_code || item.status || "-";
      const confidence = item.result?.confidence;
      return `
        <article class="adjudication-row">
          <strong>${escapeHtml(item.mode || "-")} · ${escapeHtml(verdict)}</strong>
          <span>${escapeHtml(t("policy"))}: ${escapeHtml(item.policy_id || "-")}</span>
          <span>${escapeHtml(t("action"))}: ${escapeHtml(item.proposed_action || "-")} → ${escapeHtml(item.final_action || "-")}</span>
          <span>Confidence: ${confidence == null ? "-" : escapeHtml(confidence)}</span>
          <span>${escapeHtml(item.model || "-")} · ${escapeHtml(item.latency_ms || 0)} ms</span>
        </article>
      `;
    })
    .join("");
  target.innerHTML = runtimeGateRows + gateRows + adjudicationRows;
}

function renderBom(target, bom) {
  target.textContent = JSON.stringify(bom, null, 2);
}

function switchTab(tabName) {
  state.activeTab = tabName || "timeline";
  elements.sessionDetail.querySelectorAll("[data-tab]").forEach((button) => {
    button.classList.toggle("active", button.getAttribute("data-tab") === state.activeTab);
  });
  elements.sessionDetail.querySelectorAll("[data-panel]").forEach((panel) => {
    panel.classList.toggle("active", panel.getAttribute("data-panel") === state.activeTab);
  });
}

function renderInventory(target, inventory) {
  const items = [
    ...(inventory.capabilities || []).map((value) => `${t("capability")}: ${value}`),
    ...(inventory.tools || []).map((value) => `${t("tool")}: ${value}`),
    ...(inventory.servers || []).map((value) => `${t("server")}: ${value}`),
    `${t("processes")}: ${inventory.process_count || 0}`,
    `${t("endpointEvents")}: ${inventory.endpoint_event_count || 0}`,
  ];
  target.innerHTML = renderTags(items, t("noInventory"), "tag");
}

function renderTags(items, emptyMessage, className) {
  if (items.length === 0) {
    return `<span class="meta">${escapeHtml(emptyMessage)}</span>`;
  }
  return items.map((item) => `<span class="${className}">${escapeHtml(String(item))}</span>`).join("");
}

function renderSessionError(message, includeDemoHint = false) {
  const demoHint = includeDemoHint
    ? `
      <p class="meta">${escapeHtml(t("seedDemoHint"))}</p>
      <pre class="code-panel compact-code">${escapeHtml(t("seedDemoCommand"))}</pre>
    `
    : "";
  return `
    <div class="empty-state">
      <p>${escapeHtml(message)}</p>
      ${demoHint}
    </div>
  `;
}

function summarizeRisk(risk) {
  const critical = Number(risk?.critical || 0);
  const high = Number(risk?.high || 0);
  const medium = Number(risk?.medium || 0);
  const low = Number(risk?.low || 0);
  if (critical > 0) {
    return {
      bgClass: "risk-bg-critical",
      className: "risk-critical",
      label: `${critical} ${t("riskCritical")}`,
      detail: t("highDetail"),
    };
  }
  if (high > 0) {
    return {
      bgClass: "risk-bg-high",
      className: "risk-high",
      label: `${high} ${t("riskHigh")}`,
      detail: t("highDetail"),
    };
  }
  if (medium > 0) {
    return {
      bgClass: "risk-bg-medium",
      className: "risk-medium",
      label: `${medium} ${t("riskMedium")}`,
      detail: t("mediumDetail"),
    };
  }
  return {
    bgClass: "risk-bg-low",
    className: "risk-low",
    label: low > 0 ? `${low} ${t("riskLow")}` : t("riskClean"),
    detail: t("lowDetail"),
  };
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

elements.languageToggle.querySelectorAll("[data-lang]").forEach((button) => {
  button.addEventListener("click", () => setLanguage(button.getAttribute("data-lang")));
});

elements.sessionSearch.addEventListener("input", () => {
  state.searchQuery = elements.sessionSearch.value;
  renderSessions();
});

elements.riskFilter.addEventListener("change", () => {
  state.riskFilter = elements.riskFilter.value;
  renderSessions();
});

elements.agentRefresh.addEventListener("click", () => {
  refreshAgentHealth();
});

elements.approvalsRefresh.addEventListener("click", () => {
  refreshApprovals();
});

elements.llmSettingsButton.addEventListener("click", openLlmSettings);
elements.llmSettingsClose.addEventListener("click", () => elements.llmSettingsDialog.close());
elements.llmSettingsForm.addEventListener("submit", (event) => {
  event.preventDefault();
  saveLlmSettings(false);
});
elements.llmSaveTest.addEventListener("click", () => saveLlmSettings(true));
elements.llmTestTriage.addEventListener("click", () => testLlmSettings("triage", false));
elements.llmTestGate.addEventListener("click", () => testLlmSettings("gate", false));
elements.llmClearKey.addEventListener("click", clearLlmKey);

window.addEventListener("DOMContentLoaded", async () => {
  setLanguage(state.language);
  try {
    await refreshHealth();
    await refreshAgentHealth();
    await refreshApprovals();
    await loadSessions();
    window.setInterval(refreshAgentHealth, 10000);
    window.setInterval(refreshApprovals, 10000);
  } catch (error) {
    elements.apiStatus.textContent = t("apiUnavailable");
    elements.apiStatus.classList.add("status-error");
    elements.sessionList.innerHTML = renderSessionError(error.message);
  }
});
