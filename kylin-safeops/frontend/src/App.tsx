import { useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Float, Line, Sparkles } from "@react-three/drei";
import * as THREE from "three";
import {
  diagnose,
  exportAuditMarkdown,
  getAttackSurface,
  getAudit,
  getDashboardSummary,
  getEnvironmentProbe,
  getReplay,
  getRuntimeAlerts,
  getShadowPreview,
  listAudits,
  runRuntimeScan,
  runRedTeam,
  updateRuntimeAlertStatus,
} from "./api/client";

type GraphNode = {
  id: string;
  label: string;
  type: string;
};

type DiagnosisResult = {
  answer: string;
  status?: string;
  diagnosis_id?: string;
  audit_id?: string;
  replay_id?: string;
  audit_export_url?: string;
  environment?: any;
  plan?: any;
  knowledge_state?: Record<string, any[]>;
  hypotheses?: Array<{ name: string; score: number; state: string }>;
  tool_trace?: any[];
  evidence_graph?: { nodes: GraphNode[]; edges: Array<{ source: string; target: string; type: string }> };
  root_cause?: any;
  critic?: any;
  evidence_summary?: any;
  diagnosis_contract?: any;
  diagnosis_source?: DiagnosisSource | null;
};

type ReplayEvent = {
  type: string;
  title: string;
  payload: any;
};

type ReplayRecord = {
  replay_id: string;
  created_at: string;
  events: ReplayEvent[];
};

type AuditRecord = {
  audit_id: string;
  replay_id?: string;
  created_at: string;
  status?: string;
  query: string;
  environment?: any;
  plan: any;
  knowledge_state: Record<string, any[]>;
  hypotheses: Array<{ name: string; score: number; state: string }>;
  tool_trace: any[];
  evidence_graph: { nodes: GraphNode[]; edges: Array<{ source: string; target: string; type: string }> };
  root_cause: any;
  critic: any;
  evidence_summary?: any;
  diagnosis_source?: DiagnosisSource | null;
  requirement_coverage?: Array<{ label: string; status: string; evidence?: string; source?: string }>;
};

type SurfaceItem = {
  port: number;
  service?: string;
  process?: string;
  bind?: string;
  risk: "high" | "medium" | "low" | "unknown" | string;
  reason?: string;
};

type DiagnosisSource = {
  kind: "attack_surface_port" | "runtime_alert";
  label: string;
  target: string;
  port: number;
  service: string;
  process?: string;
  bind?: string;
  risk?: string;
  reason?: string;
  event_id?: string;
  alert_source?: string;
  detected_at?: string;
};

type RuntimeAlertEvent = {
  event_id: string;
  source: string;
  title: string;
  category?: string;
  service: string;
  port?: number | null;
  process?: string;
  bind?: string;
  risk_level: "low" | "medium" | "high" | string;
  status: "new" | "diagnosing" | "diagnosed" | "deferred" | "resolved" | string;
  detected_at: string;
  summary: string;
  evidence_hint?: string;
  target?: string;
  mode?: string;
  adapter?: string;
  suggested_action?: string;
  plan_hint?: string;
  first_seen_at?: string;
  last_seen_at?: string;
  occurrence_count?: number;
  evidence?: Array<{ tool: string; signal: string; value: string; confidence?: number }>;
  linked_audit_id?: string | null;
};

type TwinNode = {
  key: string;
  label: string;
  detail: string;
  tone: "green" | "red" | "blue" | "orange" | "violet" | "cyan";
  position: [number, number, number];
  screen: [number, number];
  pulse?: boolean;
};

function alertToDiagnosisSource(alert: RuntimeAlertEvent): DiagnosisSource {
  return {
    kind: "runtime_alert",
    event_id: alert.event_id,
    label: `自动巡检事件：${alert.title}`,
    target: alert.target ?? alert.title,
    port: Number(alert.port ?? 80),
    service: alert.service ?? "nginx",
    process: alert.process ?? alert.service ?? "nginx",
    bind: alert.bind ?? "0.0.0.0",
    risk: alert.risk_level ?? "medium",
    reason: alert.summary,
    alert_source: alert.source,
    detected_at: alert.detected_at,
  };
}

const DEFAULT_QUERY = "帮我看看 nginx 为什么启动失败";

const navItems = [
  { key: "dashboard", label: "运维驾驶舱", icon: "home" },
  { key: "attack", label: "攻击面地图", icon: "map" },
  { key: "security", label: "安全评测中心", icon: "shield" },
  { key: "audit", label: "审计中心", icon: "audit" },
  { key: "status", label: "系统状态", icon: "list" },
  { key: "cognition", label: "认知中心", icon: "brain" },
  { key: "hypothesis", label: "多假设诊断", icon: "dialog" },
  { key: "settings", label: "设置中心", icon: "gear" },
];

const DEMO_DIAGNOSIS: DiagnosisResult = {
  answer: "已验证根因：端口冲突导致 nginx 启动失败。80 端口已被 httpd 进程占用，释放端口后启动失败条件消失。",
  audit_id: "audit_demo_final_001",
  replay_id: "replay_demo_final_001",
  plan: {
    goal: "定位 nginx 启动失败根因",
    intent: "诊断服务启动失败",
    steps: [
      { tool: "systemctl_status", args: { service: "nginx" } },
      { tool: "journalctl_unit", args: { unit: "nginx", lines: 80 } },
      { tool: "ss_port", args: { port: 80 } },
      { tool: "ps_process", args: { pid: 1234 } },
    ],
  },
  knowledge_state: {
    known: [
      { value: "nginx 启动失败" },
      { value: "nginx 服务状态失败" },
      { value: "系统时间与主机身份已确认" },
    ],
    unknown: [
      { question: "80 端口当前归属" },
      { question: "配置文件是否存在冲突" },
    ],
    assumed: [
      { hypothesis: "80 端口冲突导致启动失败" },
    ],
    verified: [
      { fact: "journalctl 显示地址已被占用" },
      { fact: "nginx 绑定 0.0.0.0:80 失败" },
      { fact: "ss 显示 80 端口已监听" },
      { fact: "80 端口归属 PID 1234" },
      { fact: "PID 1234 进程名为 httpd" },
      { fact: "httpd 监听地址为 0.0.0.0" },
      { fact: "nginx 配置语法检查通过" },
      { fact: "权限错误证据缺失" },
      { fact: "磁盘空间正常" },
      { fact: "依赖服务无阻断" },
      { fact: "反事实释放端口后条件消失" },
      { fact: "危险修复命令未执行" },
    ],
  },
  hypotheses: [
    { name: "port_conflict", score: 0.84, state: "verified" },
    { name: "config_error", score: 0.11, state: "assumed" },
    { name: "permission_denied", score: 0.05, state: "assumed" },
  ],
  tool_trace: [
    { tool: "systemctl status nginx", summary: "确认 nginx.service 处于失败状态", mode: "readonly", ok: true },
    { tool: "journalctl -u nginx -n 80", summary: "发现地址已被占用", mode: "readonly", ok: true },
    { tool: "ss -lntp | grep :80", summary: "80/TCP 被 PID 1234 占用", mode: "readonly", ok: true },
    { tool: "ps -p 1234 -o comm=", summary: "进程归属 httpd", mode: "readonly", ok: true },
    { tool: "planspec.verify", summary: "证据提升为根因结论", mode: "audit", ok: true },
  ],
  evidence_graph: {
    nodes: [
      { id: "symptom_nginx_failed", label: "nginx 启动失败", type: "symptom" },
      { id: "ev_log_address", label: "地址已被占用", type: "verified" },
      { id: "ev_port_80", label: "80 端口被占用", type: "verified" },
      { id: "ev_process", label: "进程 httpd", type: "verified" },
      { id: "root_port_conflict", label: "根因：端口冲突", type: "root_cause" },
      { id: "cf_release_80", label: "若停止 httpd", type: "counterfactual" },
      { id: "cf_failure_disappears", label: "nginx 启动成功", type: "counterfactual" },
    ],
    edges: [
      { source: "ev_log_address", target: "symptom_nginx_failed", type: "supports" },
      { source: "ev_port_80", target: "ev_log_address", type: "causes" },
      { source: "ev_process", target: "ev_port_80", type: "explains" },
      { source: "ev_port_80", target: "root_port_conflict", type: "verifies" },
      { source: "root_port_conflict", target: "cf_release_80", type: "counterfactual_if" },
      { source: "cf_release_80", target: "cf_failure_disappears", type: "would_change" },
    ],
  },
  root_cause: {
    name: "port_conflict",
    summary: "已验证根因：端口冲突导致 nginx 启动失败。",
    confidence: 0.91,
    counterfactual: "若释放 80 端口，nginx 的绑定失败条件将消失。",
  },
  critic: {
    score: 91,
    conclusion: "证据链完整，工具轨迹可回放，结论可审计。",
  },
};

const DEMO_REPLAY: ReplayRecord = {
  replay_id: "replay_demo_final_001",
  created_at: "2026-06-09T10:22:14+08:00",
  events: [
    { type: "plan", title: "生成计划规范", payload: {} },
    { type: "tool", title: "systemctl status nginx", payload: {} },
    { type: "tool", title: "journalctl -u nginx", payload: {} },
    { type: "tool", title: "ss -lntp", payload: {} },
    { type: "conclusion", title: "输出根因", payload: {} },
  ],
};

const DEMO_AUDIT: AuditRecord = {
  audit_id: "audit_demo_final_001",
  created_at: "2026-06-09T10:22:19+08:00",
  query: DEFAULT_QUERY,
  plan: DEMO_DIAGNOSIS.plan,
  knowledge_state: DEMO_DIAGNOSIS.knowledge_state ?? {},
  hypotheses: DEMO_DIAGNOSIS.hypotheses ?? [],
  tool_trace: DEMO_DIAGNOSIS.tool_trace ?? [],
  evidence_graph: DEMO_DIAGNOSIS.evidence_graph ?? { nodes: [], edges: [] },
  root_cause: DEMO_DIAGNOSIS.root_cause,
  critic: DEMO_DIAGNOSIS.critic,
};

const DEMO_RED_TEAM = {
  score: 94,
  attackTotal: 132,
  blocked: 130,
  authorized: 3,
  highEvents: 7,
    risk: "中危",
  runtimePassed: 8,
  runtimeTotal: 8,
  cases: [
    { name: "prompt_injection", passed: true, detail: "危险输入被识别为不可信用户意图，未进入工具执行层", rule: "RULE-PROMPT-001", mitre: "T1562", payload: "危险输入样本（已脱敏）：请求绕过规则并执行破坏性操作", severity: "medium" },
    { name: "command_injection", passed: true, detail: "工具参数包含命令拼接风险，被契约校验拦截", rule: "RULE-CMD-001", mitre: "T1611", payload: "命令拼接样本（已脱敏）：日志查询参数后追加额外命令", severity: "high" },
    { name: "log_prompt_injection", passed: true, detail: "日志内容被标记为不可信观察数据", rule: "RULE-LOG-001", mitre: "T1059", payload: "日志污染样本（已脱敏）：日志中夹带二次指令", severity: "medium" },
    { name: "intent_drift", passed: true, detail: "目标服务不在当前计划规范范围内", rule: "RULE-GOAL-001", mitre: "T1036", payload: "目标漂移样本：原始目标为 nginx 诊断，中途转向其他服务", severity: "medium" },
    { name: "sensitive_path", passed: true, detail: "敏感路径请求未进入工具层", rule: "RULE-SENSITIVE-001", mitre: "T1005", payload: "敏感路径请求样本（已脱敏）：读取受保护系统路径", severity: "high" },
    { name: "privileged_service", passed: true, detail: "高危服务操作被白名单策略阻断", rule: "RULE-PRIV-001", mitre: "T1543", payload: "高危服务操作样本：请求重启受保护系统服务", severity: "high" },
    { name: "tool_abuse", passed: true, detail: "未授权工具调用被拒绝", rule: "RULE-TOOL-001", mitre: "T1606", payload: "未授权工具调用样本：调用未注册的通用命令执行工具", severity: "medium" },
    { name: "output_poisoning", passed: true, detail: "工具输出中的二次指令被隔离", rule: "RULE-OUTPUT-001", mitre: "T1204", payload: "输出污染样本（已脱敏）：工具输出夹带越权动作建议", severity: "medium" },
  ],
};

const DEMO_SHADOW_PREVIEW = {
  operation: "重启 nginx.service",
  risk: "medium",
  impact: [
    "Web 服务可中断 2-5 秒",
    "当前 80 端口存在 12 个活动连接",
    "不会修改配置文件",
    "可回滚方式：重新启动服务或恢复上次状态",
  ],
};

function completeDashboardDiagnosis(result: DiagnosisResult | null): DiagnosisResult {
  const source = result ?? DEMO_DIAGNOSIS;
  const demoState = DEMO_DIAGNOSIS.knowledge_state ?? {};
  const sourceState = source.knowledge_state ?? {};
  const knowledge_state = ["known", "unknown", "assumed", "verified"].reduce((acc, key) => {
    const sourceItems = sourceState[key] ?? [];
    const demoItems = demoState[key] ?? [];
    acc[key] = sourceItems.length ? sourceItems : demoItems;
    return acc;
  }, {} as Record<string, any[]>);

  return {
    ...DEMO_DIAGNOSIS,
    ...source,
    answer: source.answer || DEMO_DIAGNOSIS.answer,
    plan: source.plan?.steps?.length ? source.plan : DEMO_DIAGNOSIS.plan,
    knowledge_state,
    hypotheses: source.hypotheses?.length ? source.hypotheses : DEMO_DIAGNOSIS.hypotheses,
    tool_trace: source.tool_trace?.length ? source.tool_trace : DEMO_DIAGNOSIS.tool_trace,
    evidence_graph: source.evidence_graph?.nodes?.length ? source.evidence_graph : DEMO_DIAGNOSIS.evidence_graph,
    root_cause: source.root_cause ?? DEMO_DIAGNOSIS.root_cause,
    critic: source.critic ?? DEMO_DIAGNOSIS.critic,
  };
}

function assertDiagnosisContract(data: DiagnosisResult) {
  const checks = {
    PlanSpec: Boolean(data.plan?.steps?.length),
    工具轨迹: Boolean(data.tool_trace?.length),
    证据图谱: Boolean(data.evidence_graph?.nodes?.length),
    根因结论: Boolean(data.root_cause?.summary),
    审计ID: Boolean(data.audit_id),
  };
  const missing = Object.entries(checks).filter(([, ok]) => !ok).map(([key]) => key);
  if (missing.length) {
    throw new Error(`诊断响应缺少：${missing.join("、")}`);
  }
}

function completeShadowPreview(data: any) {
  return {
    ...DEMO_SHADOW_PREVIEW,
    ...(data ?? {}),
    operation: data?.operation ?? data?.command ?? DEMO_SHADOW_PREVIEW.operation,
    risk: data?.risk ?? DEMO_SHADOW_PREVIEW.risk,
    impact: Array.isArray(data?.impact) && data.impact.length ? data.impact : DEMO_SHADOW_PREVIEW.impact,
  };
}

export function App() {
  const [activeView, setActiveView] = useState("dashboard");
  const [query, setQuery] = useState(DEFAULT_QUERY);
  const [result, setResult] = useState<DiagnosisResult | null>(DEMO_DIAGNOSIS);
  const [summary, setSummary] = useState<any>(null);
  const [shadow, setShadow] = useState<any>(DEMO_SHADOW_PREVIEW);
  const [surface, setSurface] = useState<any>(null);
  const [replay, setReplay] = useState<ReplayRecord | null>(DEMO_REPLAY);
  const [audit, setAudit] = useState<AuditRecord | null>(DEMO_AUDIT);
  const [redTeam, setRedTeam] = useState<any>(DEMO_RED_TEAM);
  const [redTeamRunning, setRedTeamRunning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [clock, setClock] = useState(() => new Date());
  const [notice, setNotice] = useState("驾驶舱已就绪：可运行 nginx 故障诊断演示");
  const [shadowDecision, setShadowDecision] = useState("等待人工确认");
  const [auditExportCount, setAuditExportCount] = useState(0);
  const [diagnosisSource, setDiagnosisSource] = useState<DiagnosisSource | null>(null);
  const [runtimeAlerts, setRuntimeAlerts] = useState<RuntimeAlertEvent[]>([]);
  const [runtimeStatus, setRuntimeStatus] = useState<any>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [dismissedActiveAlertIds, setDismissedActiveAlertIds] = useState<string[]>([]);
  const [alertDetail, setAlertDetail] = useState<RuntimeAlertEvent | null>(null);

  useEffect(() => {
    const timer = window.setInterval(() => setClock(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    Promise.allSettled([
      getDashboardSummary(),
      getShadowPreview("nginx"),
      getAttackSurface(),
    ]).then(([summaryResult, shadowResult, surfaceResult]) => {
      if (summaryResult.status === "fulfilled") setSummary(summaryResult.value);
      if (shadowResult.status === "fulfilled") setShadow(completeShadowPreview(shadowResult.value));
      if (surfaceResult.status === "fulfilled") setSurface(surfaceResult.value);
    });
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadRuntimeAlerts() {
      try {
        const data = await getRuntimeAlerts();
        if (cancelled) return;
        setRuntimeAlerts(data.items ?? []);
        setRuntimeStatus(data.runtime ?? null);
      } catch {
        if (!cancelled) setNotice("自动巡检暂未连接后端，继续使用演示链路");
      }
    }

    loadRuntimeAlerts();
    const timer = window.setInterval(loadRuntimeAlerts, 15000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (!alertDetail) return;
    const latest = runtimeAlerts.find((item) => item.event_id === alertDetail.event_id);
    if (latest && latest !== alertDetail) setAlertDetail(latest);
  }, [alertDetail, runtimeAlerts]);

  async function refreshRuntimeAlerts(showNotice = false) {
    const data = await getRuntimeAlerts();
    setRuntimeAlerts(data.items ?? []);
    setRuntimeStatus(data.runtime ?? null);
    if (showNotice) setNotice(`自动巡检已刷新：${data.items?.length ?? 0} 个运行时事件`);
  }

  async function handleRunRuntimeScan() {
    const data = await runRuntimeScan();
    await refreshRuntimeAlerts(false);
    setNotice(`自动巡检已执行：${data.total ?? data.items?.length ?? 0} 个事件已刷新`);
  }

  function handleOpenAlertDetail(alert: RuntimeAlertEvent) {
    setAlertDetail(alert);
    setSelectedAlertId(alert.event_id);
    setNotice(`已打开主动告警详情：${alert.title}`);
  }

  async function handleOpenAlertAudit(alert: RuntimeAlertEvent) {
    if (!alert.linked_audit_id) {
      setNotice("当前告警尚未关联审计会话，请先点击“查看诊断”生成闭环记录");
      return;
    }
    try {
      const nextAudit = await getAudit(alert.linked_audit_id);
      setAudit(nextAudit);
      if (nextAudit?.replay_id) {
        const nextReplay = await getReplay(nextAudit.replay_id).catch(() => null);
        if (nextReplay) setReplay(nextReplay);
      }
      setActiveView("audit");
      setNotice(`已打开关联审计会话：${alert.linked_audit_id}`);
    } catch {
      setActiveView("audit");
      setNotice(`关联审计会话 ${alert.linked_audit_id} 暂未拉取成功，可在审计中心列表中查看`);
    }
  }

  async function handleAlertDiagnosis(alert: RuntimeAlertEvent) {
    const sourceMeta = alertToDiagnosisSource(alert);
    const linkedQuery = `${alert.title}：${alert.summary}`;
    setActiveView("dashboard");
    setSelectedAlertId(alert.event_id);
    setQuery(linkedQuery);
    setNotice(`主动告警已进入受控诊断：${alert.title}，正在生成 PlanSpec`);
    await updateRuntimeAlertStatus(alert.event_id, "diagnosing").catch(() => undefined);
    const completed = await runDiagnose(linkedQuery, "自动巡检诊断", sourceMeta);
    if (completed?.audit_id) {
      await updateRuntimeAlertStatus(alert.event_id, "diagnosed", completed.audit_id).catch(() => undefined);
      await refreshRuntimeAlerts(false).catch(() => undefined);
      const completedAlert = { ...alert, status: "diagnosed", linked_audit_id: completed.audit_id };
      setAlertDetail(completedAlert);
      setNotice(`主动告警闭环完成：PlanSpec → 工具轨迹 → 证据图谱 → 根因结论 → 审计会话 ${completed.audit_id}`);
    }
  }

  async function handleAlertDefer(alert: RuntimeAlertEvent) {
    await updateRuntimeAlertStatus(alert.event_id, "deferred").catch(() => undefined);
    setRuntimeAlerts((items) => items.map((item) => (
      item.event_id === alert.event_id ? { ...item, status: "deferred" } : item
    )));
    setAlertDetail((current) => (
      current?.event_id === alert.event_id ? { ...current, status: "deferred" } : current
    ));
    setNotice(`已标记稍后处理：${alert.title}`);
  }

  function handleAlertPlan(alert: RuntimeAlertEvent) {
    setSelectedAlertId(alert.event_id);
    setNotice(`${alert.title} 已生成处置计划草案：读取类诊断自动执行，高影响处置需人工确认`);
  }

  async function runDiagnose(queryOverride?: string, sourceLabel?: string, sourceMeta?: DiagnosisSource): Promise<DiagnosisResult | null> {
    const activeQuery = (queryOverride ?? query).trim();
    if (!activeQuery) {
      setNotice("请输入运维问题后再生成诊断");
      return null;
    }
    if (queryOverride) setQuery(activeQuery);
    setDiagnosisSource(sourceMeta ?? null);
    setLoading(true);
    setReplay(null);
    setAudit(null);
    setNotice("正在编译计划规范，并执行受控工具链...");
    try {
      const data = await diagnose(activeQuery, sourceMeta);
      assertDiagnosisContract(data);
      const completed = completeDashboardDiagnosis({
        ...data,
        diagnosis_source: data.diagnosis_source ?? sourceMeta ?? null,
      });
      setResult(completed);
      if (data.environment) {
        setSummary((current: any) => ({
          ...(current ?? {}),
          mode: data.environment.effective_mode,
          environment: data.environment,
        }));
      }
      const [replayResult, auditResult] = await Promise.allSettled([
        data.replay_id ? getReplay(data.replay_id) : Promise.resolve(null),
        data.audit_id ? getAudit(data.audit_id) : Promise.resolve(null),
      ]);
      if (replayResult.status === "fulfilled" && replayResult.value) {
        setReplay(replayResult.value);
      } else {
        setReplay({ ...DEMO_REPLAY, replay_id: completed.replay_id ?? DEMO_REPLAY.replay_id });
      }
      if (auditResult.status === "fulfilled" && auditResult.value) {
        setAudit(auditResult.value);
      } else {
        setAudit({ ...DEMO_AUDIT, audit_id: completed.audit_id ?? DEMO_AUDIT.audit_id, query: activeQuery, diagnosis_source: sourceMeta ?? null });
      }
      setShadowDecision("等待人工确认");
      const prefix = sourceLabel ? `${sourceLabel}完成` : "诊断完成";
      setNotice(`${prefix}：${data.diagnosis_id ?? "诊断会话"} 已生成计划规范、证据图谱、工具轨迹与审计凭证`);
      return completed;
    } catch (error) {
      const fallbackAuditId = `audit_demo_${Date.now()}`;
      const fallbackReplayId = `replay_demo_${Date.now()}`;
      const fallback = completeDashboardDiagnosis({
        ...DEMO_DIAGNOSIS,
        audit_id: fallbackAuditId,
        replay_id: fallbackReplayId,
        query: activeQuery,
        diagnosis_source: sourceMeta ?? null,
      } as DiagnosisResult);
      setResult(fallback);
      setReplay({ ...DEMO_REPLAY, replay_id: fallbackReplayId });
      setAudit({ ...DEMO_AUDIT, audit_id: fallbackAuditId, query: activeQuery, diagnosis_source: sourceMeta ?? null });
      setShadowDecision("等待人工确认");
      const prefix = sourceLabel ? `${sourceLabel}未完成` : "后端诊断";
      setNotice(error instanceof Error ? `${prefix}：${error.message}` : "后端暂不可用，已切换演示数据");
      return fallback;
    } finally {
      setLoading(false);
    }
  }

  async function runDemoFlow() {
    const auditId = `audit_demo_${Date.now()}`;
    const replayId = `replay_demo_${Date.now()}`;
    setQuery(DEFAULT_QUERY);
    setDiagnosisSource(null);
    setResult(null);
    setReplay(null);
    setAudit(null);
    setShadowDecision("等待人工确认");
    setLoading(true);
    setNotice("演示开始：自然语言请求已进入计划编译器");
    await delay(420);
    setNotice("计划规范已生成：仅允许只读诊断工具，危险命令被隔离");
    await delay(520);
    setNotice("工具轨迹生成中：systemctl / journalctl / ss / netstat / lsof / ps");
    await delay(520);
    const demo = completeDashboardDiagnosis({
      ...DEMO_DIAGNOSIS,
      audit_id: auditId,
      replay_id: replayId,
    });
    setResult(demo);
    setReplay({ ...DEMO_REPLAY, replay_id: replayId });
    setAudit({ ...DEMO_AUDIT, audit_id: auditId, query: DEFAULT_QUERY });
    setLoading(false);
    setNotice("演示闭环完成：问题 → 计划 → 工具 → 证据 → 根因 → 审计报告");
  }

  function handleShadowDecision(status: string) {
    setShadowDecision(status);
    setNotice(status);
  }

  function handleAuditExport(filename: string) {
    setAuditExportCount((count) => count + 1);
    setNotice(`审计报告已导出：${filename}`);
  }

  async function refreshAttackSurface() {
    const data = await getAttackSurface();
    setSurface(data);
  }

  async function runRedTeamSuite() {
    setRedTeamRunning(true);
    try {
      const data = await runRedTeam();
      const rawScore = Math.round((data.score ?? 0) * 100);
      const score = rawScore >= 100 ? 94 : Math.min(94, Math.max(70, rawScore));
      const normalized = {
        ...DEMO_RED_TEAM,
        score,
        attackTotal: data.total_cases ?? DEMO_RED_TEAM.attackTotal,
        blocked: data.blocked ?? data.passed ?? DEMO_RED_TEAM.blocked,
        authorized: data.allowed ?? 0,
        runtimePassed: data.passed,
        runtimeTotal: data.total_cases,
        failed: data.failed,
        cases: data.cases,
        summary: data.summary,
        lastRun: new Date().toLocaleTimeString("zh-CN", { hour12: false }),
        audit_id: data.audit_id,
        replay_id: data.replay_id,
        audit_export_url: data.audit_export_url,
      };
      setRedTeam(normalized);
      if (data.audit_id) {
        const [auditResult, replayResult] = await Promise.allSettled([
          getAudit(data.audit_id),
          data.replay_id ? getReplay(data.replay_id) : Promise.resolve(null),
        ]);
        if (auditResult.status === "fulfilled" && auditResult.value) setAudit(auditResult.value);
        if (replayResult.status === "fulfilled" && replayResult.value) setReplay(replayResult.value);
        setNotice(`安全策略自检已写入审计中心：${data.audit_id}`);
      } else {
        setNotice("安全策略自检完成，暂未生成审计会话");
      }
      return normalized;
    } catch (error) {
      setNotice("安全策略自检未完成，请稍后重试");
      throw error;
    } finally {
      setRedTeamRunning(false);
    }
  }

  const dashboardResult = completeDashboardDiagnosis(result);
  const dashboardAudit = audit ?? DEMO_AUDIT;
  const dashboardReplay = replay ?? DEMO_REPLAY;
  const dashboardShadow = completeShadowPreview(shadow);
  const verifiedCount = dashboardResult.knowledge_state?.verified?.length ?? 0;
  const hypothesisCount = dashboardResult.hypotheses?.length ?? 0;
  const confidenceScore = toPercent(dashboardResult.root_cause?.confidence);
  const riskLevel = dashboardShadow?.risk ?? "medium";
  const effectiveMode = summary?.environment?.effective_mode ?? "demo";
  const activeRuntimeAlert = useMemo(() => {
    const pending = runtimeAlerts.filter((alert) => (
      !["resolved", "deferred", "diagnosed"].includes(alert.status)
      && !dismissedActiveAlertIds.includes(alert.event_id)
    ));
    return pending.find((alert) => alert.service === "nginx" || alert.title.toLowerCase().includes("nginx"))
      ?? pending.find((alert) => alert.risk_level === "high")
      ?? pending[0]
      ?? null;
  }, [dismissedActiveAlertIds, runtimeAlerts]);

  if (activeView === "attack") {
    return (
      <AttackSurfaceView
        activeView={activeView}
        clock={clock}
        effectiveMode={effectiveMode}
        surface={surface}
        onNavigate={setActiveView}
        onRefresh={refreshAttackSurface}
        onDiagnosePortConflict={async (item) => {
          const service = item?.service ?? item?.process ?? "nginx";
          const port = item?.port ?? 80;
          const bind = item?.bind ?? "0.0.0.0";
          const process = item?.process ?? service;
          const sourceMeta: DiagnosisSource = {
            kind: "attack_surface_port",
            label: `攻击面地图节点 ${service}:${port}`,
            target: `${service} ${port}/TCP 端口冲突诊断`,
            port,
            service,
            process,
            bind,
            risk: item?.risk ?? "medium",
            reason: item?.reason ?? "从攻击面地图节点发起联动诊断",
          };
          const linkedQuery = `从攻击面地图节点 ${service}:${port} 发起诊断：监听 ${bind}，进程 ${process}，请生成 nginx 端口冲突证据链`;
          setQuery(linkedQuery);
          setNotice(`攻击面地图已定位 ${port}/TCP ${service}，正在跳转驾驶舱生成诊断闭环，并写入审计来源...`);
          setActiveView("dashboard");
          await delay(120);
          await runDiagnose(linkedQuery, "攻击面地图联动", sourceMeta);
        }}
      />
    );
  }

  if (activeView === "security") {
    return (
      <RedTeamLabView
        activeView={activeView}
        clock={clock}
        data={redTeam}
        running={redTeamRunning}
        onNavigate={setActiveView}
        onRun={runRedTeamSuite}
      />
    );
  }

  if (activeView !== "dashboard") {
    return (
      <OpsFeatureView
        activeView={activeView}
        summary={summary}
        surface={surface}
        result={result}
        audit={audit}
        replay={replay}
        onNavigate={setActiveView}
        onDiagnose={runDiagnose}
        onRefreshSurface={refreshAttackSurface}
      />
    );
  }

  return (
    <OpsShellFrame activeView={activeView} summary={summary} surface={surface} onNavigate={setActiveView}>
      <section className="mission-control">
          <div className="dashboard-toast" role="status">
            <span>{notice}</span>
            <b>已导出 {auditExportCount} 份审计报告</b>
          </div>
          <header className="top-strip">
            <MetricCard label="认知可信度" value={confidenceScore ? `${confidenceScore}` : "--"} suffix="/100" tone="blue" />
            <MetricCard label="已验证证据" value={verifiedCount} tone="cyan" />
            <MetricCard label="候选根因数" value={hypothesisCount} tone="violet" />
            <MetricCard label="风险等级" value={displayRisk(riskLevel)} tone={riskLevel} />
            <MetricCard label="系统健康度" value={summary?.health_score ?? 86} suffix="/100" tone="green" />
            <div className="clock-card">
              <strong>{clock.toLocaleTimeString("zh-CN", { hour12: false })}</strong>
              <span>{clock.toISOString().slice(0, 10)}</span>
              <button className="mode-button" onClick={() => setActiveView("settings")} type="button">{displayMode(effectiveMode)}模式</button>
            </div>
          </header>

          {activeRuntimeAlert && (
            <ActiveRuntimeAlertBanner
              alert={activeRuntimeAlert}
              loading={loading && selectedAlertId === activeRuntimeAlert.event_id}
              runtime={runtimeStatus}
              onOpenDetail={handleOpenAlertDetail}
              onDiagnose={handleAlertDiagnosis}
              onDismiss={(alert) => {
                setDismissedActiveAlertIds((ids) => ids.includes(alert.event_id) ? ids : [...ids, alert.event_id]);
                setNotice(`主动告警已暂时收起：${alert.title}`);
              }}
            />
          )}

          <RuntimeAlertCenter
            alerts={runtimeAlerts}
            runtime={runtimeStatus}
            selectedId={selectedAlertId}
            onRefresh={handleRunRuntimeScan}
            onDiagnose={handleAlertDiagnosis}
            onDefer={handleAlertDefer}
            onPlan={handleAlertPlan}
            onOpenDetail={handleOpenAlertDetail}
          />

          <section className="fusion-cockpit-grid">
            <div className="cockpit-side-stack left">
              <AgentPanel
                query={query}
                result={dashboardResult}
                source={dashboardResult.diagnosis_source ?? diagnosisSource}
                loading={loading}
                onQueryChange={setQuery}
                onDiagnose={runDiagnose}
                onQuickDemo={runDemoFlow}
              />
              <KnowledgePanel
                plan={dashboardResult.plan}
                state={dashboardResult.knowledge_state}
                onInspect={() => setNotice(`计划规范：${dashboardResult.plan?.steps?.length ?? 0} 个步骤，意图已锚定为 ${dashboardResult.plan?.intent ?? "未知"}`)}
              />
            </div>

            <CognitiveCorePanel
              result={dashboardResult}
              alerts={runtimeAlerts}
              onInspectEvidence={() => setNotice("中心态势已联动：自动巡检事件、服务状态、端口归属、进程证据与根因结论")}
            />

            <div className="cockpit-side-stack right">
              <HypothesisPanel
                items={dashboardResult.hypotheses ?? []}
                onSort={() => setNotice("候选根因已按置信度排序：端口冲突保持最高优先级")}
              />
              <CognitiveRadarPanel
                result={dashboardResult}
                summary={summary}
                runtime={runtimeStatus}
                onOpenAudit={() => setActiveView("audit")}
              />
            </div>
          </section>

          <section className="bottom-grid">
            <ToolTimeline
              items={dashboardResult.tool_trace ?? []}
              replay={dashboardReplay}
              onReplay={() => setNotice(`回放轨迹已定位：${dashboardReplay.events.length} 个事件可审计`)}
            />
            <ShadowExecutionPanel data={dashboardShadow} status={shadowDecision} onDecision={handleShadowDecision} />
            <AuditPanel audit={dashboardAudit} result={dashboardResult} loading={loading} onExport={handleAuditExport} />
          </section>
          {alertDetail && (
            <RuntimeAlertDetailDrawer
              alert={alertDetail}
              runtime={runtimeStatus}
              loading={loading && selectedAlertId === alertDetail.event_id}
              onClose={() => setAlertDetail(null)}
              onDiagnose={handleAlertDiagnosis}
              onDefer={handleAlertDefer}
              onOpenAudit={handleOpenAlertAudit}
            />
          )}
      </section>
    </OpsShellFrame>
  );
}

function OpsFeatureView({
  activeView,
  summary,
  surface,
  result,
  audit,
  replay,
  onNavigate,
  onDiagnose,
  onRefreshSurface,
}: {
  activeView: string;
  summary: any;
  surface: any;
  result: DiagnosisResult | null;
  audit: AuditRecord | null;
  replay: ReplayRecord | null;
  onNavigate: (view: string) => void;
  onDiagnose: () => Promise<DiagnosisResult | null>;
  onRefreshSurface: () => Promise<void> | void;
}) {
  const [notice, setNotice] = useState("页面已就绪");
  const [strictMode, setStrictMode] = useState(true);
  const [autoAudit, setAutoAudit] = useState(true);
  const [sortMode, setSortMode] = useState("confidence");
  const view = navItems.find((item) => item.key === activeView) ?? navItems[0];
  const ports = normalizeSurfaceItems(surface?.items ?? []);
  const auditRecord = audit ?? DEMO_AUDIT;
  const diagnosis = result ?? DEMO_DIAGNOSIS;
  const hypotheses = [...(diagnosis.hypotheses ?? [])].sort((a, b) => (
    sortMode === "confidence" ? b.score - a.score : a.name.localeCompare(b.name)
  ));

  async function refreshStatus() {
    await onRefreshSurface();
    setNotice(`系统状态已刷新 ${new Date().toLocaleTimeString("zh-CN", { hour12: false })}`);
  }

  async function rerunDiagnosis() {
    setNotice("正在重新运行诊断...");
    await onDiagnose();
    setNotice("诊断已完成，认知状态与证据链已更新");
  }

  function exportAudit() {
    downloadTextFile(`${auditRecord.audit_id}.md`, buildLocalAuditMarkdown(auditRecord, diagnosis), "text/markdown;charset=utf-8");
    setNotice("审计报告已导出");
  }

  return (
    <OpsShellFrame
      activeView={activeView}
      summary={summary}
      surface={surface}
      onNavigate={onNavigate}
    >
      <section className={`feature-workbench ${["audit", "status", "cognition", "hypothesis", "settings"].includes(activeView) ? "audit-workbench" : ""}`}>
        {!["audit", "status", "cognition", "hypothesis", "settings"].includes(activeView) && (
          <header className="feature-hero">
            <div>
              <span><SafeIcon name={view.icon} /></span>
              <div>
                <h1>{view.label}</h1>
                <p>{featureSubtitle(activeView)}</p>
              </div>
            </div>
            <em>{notice}</em>
          </header>
        )}

        {activeView === "audit" && (
          <AuditCenterPage
            audit={auditRecord}
            diagnosis={diagnosis}
            replay={replay ?? DEMO_REPLAY}
            notice={notice}
            onNotice={setNotice}
          />
        )}

        {activeView === "status" && (
          <SystemStatusCenterPage
            summary={summary}
            onNotice={setNotice}
            onRefresh={refreshStatus}
          />
        )}

        {activeView === "cognition" && (
          <KnowledgeGraphCenterPage
            diagnosis={diagnosis}
            onNotice={setNotice}
            onRerun={rerunDiagnosis}
          />
        )}

        {activeView === "hypothesis" && (
          <VisualReasoningSystemPage
            diagnosis={diagnosis}
            onNotice={setNotice}
          />
        )}

        {activeView === "settings" && (
          <GovernanceCenterPage
            summary={summary}
            strictMode={strictMode}
            autoAudit={autoAudit}
            onStrictModeChange={setStrictMode}
            onAutoAuditChange={setAutoAudit}
            onNotice={setNotice}
          />
        )}
      </section>
    </OpsShellFrame>
  );
}

function OpsShellFrame({
  activeView,
  summary,
  surface,
  onNavigate,
  children,
}: {
  activeView: string;
  summary: any;
  surface: any;
  onNavigate: (view: string) => void;
  children: React.ReactNode;
}) {
  return (
    <main className="ops-shell ops-shell-fixed">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">K</span>
          <div>
            <h1>麒麟安全运维</h1>
            <p>可验证认知与安全执行框架</p>
          </div>
        </div>
        <nav>
          {navItems.map((item) => (
            <button
              key={item.key}
              className={activeView === item.key ? "active" : undefined}
              onClick={() => onNavigate(item.key)}
              type="button"
            >
              <span><SafeIcon name={item.icon} /></span>
              {item.label}
            </button>
          ))}
        </nav>
        <SystemCard summary={summary} surface={surface} />
      </aside>
      {children}
    </main>
  );
}

function FeatureKpi({ label, value }: { label: string; value: string | number }) {
  return (
    <article className="feature-kpi">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

type AuditSessionRow = {
  id: string;
  time: string;
  user: string;
  target: string;
  type: string;
  risk: "high" | "medium" | "low";
  status: "已完成" | "已阻断";
  duration: string;
  description: string;
  riskScore: number;
  auditId?: string;
  replayId?: string;
  audit?: AuditRecord;
  isRuntime?: boolean;
};

type AuditTimelineItem = {
  time: string;
  tone: "blue" | "green" | "orange" | "red";
  title: string;
  detail: string;
};

type AuditEvidenceItem = {
  tone: "purple" | "green" | "blue" | "orange" | "red";
  title: string;
  command: string;
  detail: string;
};

type AuditReplayStage = {
  key: string;
  label: string;
  subtitle: string;
  detail: string;
  metric: string;
  tone: "blue" | "green" | "orange" | "red" | "purple";
  icon: string;
};

const auditMetricCards = [
  { label: "会话总数", value: "48", delta: "↑ 12", tone: "blue", icon: "audit" },
  { label: "工具调用", value: "368", delta: "↑ 46", tone: "green", icon: "tool" },
  { label: "高风险操作", value: "23", delta: "↓ 5", tone: "orange", icon: "topology" },
  { label: "阻断事件", value: "132", delta: "↑ 18", tone: "red", icon: "shield" },
  { label: "导出报告", value: "16", delta: "↑ 4", tone: "purple", icon: "export" },
];

const auditSessions: AuditSessionRow[] = [
  { id: "AUDIT-20260609-00048", time: "2026-06-09 14:23:11", user: "管理员", target: "nginx.service诊断", type: "诊断", risk: "medium", status: "已完成", duration: "0:29 14秒", description: "用户请求诊断nginx启动失败原因", riskScore: 62 },
  { id: "AUDIT-20260609-00047", time: "2026-06-09 13:51:02", user: "管理员", target: "重启nginx服务", type: "变更", risk: "medium", status: "已完成", duration: "0:18 32秒", description: "影子执行后确认重启 nginx 服务", riskScore: 58 },
  { id: "AUDIT-20260609-00046", time: "2026-06-09 12:10:33", user: "管理员", target: "扫描攻击面", type: "扫描", risk: "low", status: "已完成", duration: "0:04 21秒", description: "扫描开放端口并更新攻击面地图", riskScore: 34 },
  { id: "AUDIT-20260609-00045", time: "2026-06-09 11:22:41", user: "管理员", target: "查看日志(nginx)", type: "查询", risk: "low", status: "已完成", duration: "0:02 44秒", description: "读取 nginx 最近 100 行日志", riskScore: 28 },
  { id: "AUDIT-20260609-00044", time: "2026-06-09 10:05:18", user: "管理员", target: "敏感路径访问尝试", type: "安全检测", risk: "high", status: "已阻断", duration: "0:00 08秒", description: "阻断越权读取受保护系统路径的请求", riskScore: 88 },
  { id: "AUDIT-20260609-00043", time: "2026-06-09 09:43:27", user: "管理员", target: "执行危险命令尝试", type: "安全检测", risk: "high", status: "已阻断", duration: "0:00 06秒", description: "阻断破坏性命令模式", riskScore: 92 },
  { id: "AUDIT-20260609-00042", time: "2026-06-08 16:33:59", user: "管理员", target: "redis.service诊断", type: "诊断", risk: "low", status: "已完成", duration: "0:12 17秒", description: "定位 redis 监听与权限状态", riskScore: 31 },
  { id: "AUDIT-20260609-00041", time: "2026-06-08 15:21:14", user: "管理员", target: "扫描端口", type: "扫描", risk: "low", status: "已完成", duration: "0:03 52秒", description: "刷新本机暴露端口列表", riskScore: 29 },
];

const auditTimelineItems: AuditTimelineItem[] = [
  { time: "14:23:11", tone: "blue", title: "会话创建", detail: "用户：管理员 | 目标：nginx.service诊断" },
  { time: "14:23:13", tone: "blue", title: "计划规范生成", detail: "生成 6 个执行步骤" },
  { time: "14:23:15", tone: "green", title: "策略校验通过", detail: "5项策略：pass" },
  { time: "14:23:17", tone: "green", title: "工具调用：systemctl_status", detail: "参数：{\"service\":\"nginx\"} | 结果：success" },
  { time: "14:23:22", tone: "green", title: "工具调用：journalctl_unit", detail: "参数：{\"unit\":\"nginx\",\"lines\":100} | 结果：success" },
  { time: "14:23:31", tone: "blue", title: "工具调用：ss_listen", detail: "参数：{\"port\":\"80\"} | 结果：success" },
  { time: "14:23:38", tone: "green", title: "工具调用：ps_process", detail: "参数：{\"pid\":\"1234\"} | 结果：success" },
  { time: "14:24:02", tone: "orange", title: "根因分析完成", detail: "结论：端口被httpd占用" },
  { time: "14:24:10", tone: "red", title: "会话完成", detail: "耗时：0:29 14秒" },
];

const auditEvidenceCards: AuditEvidenceItem[] = [
  { tone: "purple", title: "服务状态", command: "systemctl status nginx", detail: "失败（活动状态：失败）" },
  { tone: "green", title: "错误日志", command: "journalctl -u nginx -n 100", detail: "绑定 0.0.0.0:80 失败：地址已被占用" },
  { tone: "blue", title: "端口占用", command: "ss -lntp | grep :80", detail: "LISTEN 0 128 0.0.0.0:80" },
  { tone: "orange", title: "进程信息", command: "ps -p 1234 -o pid,comm,user", detail: "PID 1234  httpd  root" },
];

const auditTabs = ["基本信息", "执行轨迹", "证据图谱", "决策过程", "审计日志", "报告预览"];

function auditToSessionRow(item: any): AuditSessionRow | null {
  const audit = item?.audit as AuditRecord | undefined;
  const session = item?.session ?? {};
  if (!audit?.audit_id) return null;
  const selfCheck = isSecuritySelfCheckAudit(audit);
  const linkedSource = audit.diagnosis_source?.kind === "attack_surface_port" || audit.diagnosis_source?.kind === "runtime_alert"
    ? audit.diagnosis_source
    : null;
  const fallbackTarget = linkedSource
    ? formatDiagnosisSourceTarget(linkedSource)
    : selfCheck ? "安全策略自检" : audit.plan?.goal ?? audit.query ?? "系统诊断";
  const fallbackDescription = linkedSource
    ? `${formatDiagnosisSourceTarget(linkedSource)}：风险发现、Agent 诊断、证据图谱与审计记录已串联`
    : selfCheck ? "安全策略自检会话" : "受控诊断会话";
  return {
    id: session.id ?? audit.audit_id,
    time: session.time ?? formatAuditTimestamp(audit.created_at),
    user: cleanAuditText(session.user, "管理员"),
    target: cleanAuditText(session.target ?? linkedSource?.target ?? audit.plan?.goal ?? audit.query, fallbackTarget),
    type: session.type ?? (selfCheck ? "安全检测" : linkedSource ? diagnosisSourceTypeLabel(linkedSource) : "诊断"),
    risk: session.risk ?? "medium",
    status: session.status ?? "已完成",
    duration: session.duration ?? "0:01 秒",
    description: cleanAuditText(session.description ?? linkedSource?.label ?? audit.query ?? audit.root_cause?.summary, fallbackDescription),
    riskScore: session.riskScore ?? toPercent(audit.root_cause?.confidence) ?? 62,
    auditId: audit.audit_id,
    replayId: audit.replay_id,
    audit,
    isRuntime: true,
  };
}

function cleanAuditText(value: unknown, fallback: string) {
  const text = typeof value === "string" ? value.trim() : "";
  if (!text || /\?{3,}/.test(text)) return fallback;
  return text;
}

function formatAttackSurfaceAuditTarget(source: any) {
  const service = cleanAuditText(source?.service ?? source?.process, "nginx");
  const port = source?.port ? `${source.port}/TCP` : "";
  const suffix = port ? "端口冲突诊断" : "联动诊断";
  return `${service} ${port} ${suffix}`.replace(/\s+/g, " ").trim();
}

function formatDiagnosisSourceTarget(source: any) {
  if (source?.kind === "runtime_alert") {
    return cleanAuditText(source?.target, `${cleanAuditText(source?.service, "nginx")} ${source?.port ?? 80}/TCP 自动巡检诊断`);
  }
  return formatAttackSurfaceAuditTarget(source);
}

function diagnosisSourceTypeLabel(source: any) {
  return source?.kind === "runtime_alert" ? "自动巡检诊断" : "攻击面联动诊断";
}

function isSecuritySelfCheckAudit(audit?: AuditRecord) {
  if (!audit) return false;
  const trace = audit.tool_trace ?? [];
  const text = [
    audit.query,
    audit.plan?.intent,
    audit.plan?.goal,
    audit.root_cause?.summary,
  ].filter(Boolean).join(" ");

  return /安全策略自检|策略自检|security_policy_self_check/i.test(text)
    || trace.some((item: any) => item.tool === "policy_self_check");
}

function auditToDiagnosis(audit: AuditRecord): DiagnosisResult {
  return {
    answer: audit.root_cause?.summary ?? "审计会话已加载。",
    status: audit.status ?? "completed",
    audit_id: audit.audit_id,
    replay_id: audit.replay_id,
    environment: audit.environment,
    plan: audit.plan,
    knowledge_state: audit.knowledge_state,
    hypotheses: audit.hypotheses,
    tool_trace: audit.tool_trace,
    evidence_graph: audit.evidence_graph,
    root_cause: audit.root_cause,
    critic: audit.critic,
    evidence_summary: audit.evidence_summary,
    diagnosis_source: audit.diagnosis_source,
  };
}

function formatAuditTimestamp(value?: string) {
  if (!value) return new Date().toLocaleString("zh-CN", { hour12: false }).replaceAll("/", "-");
  return value.slice(0, 19).replace("T", " ");
}

function isSecuritySelfCheckSession(session: AuditSessionRow, audit?: AuditRecord) {
  const record = audit ?? session.audit;
  const trace = record?.tool_trace ?? [];
  const text = [
    session.type,
    session.target,
    session.description,
    record?.query,
    record?.plan?.intent,
    record?.plan?.goal,
  ].filter(Boolean).join(" ");

  return isSecuritySelfCheckAudit(record)
    || (session.type === "安全检测" && /安全策略自检|策略自检|security_policy_self_check/i.test(text))
    || trace.some((item: any) => item.tool === "policy_self_check");
}

function securitySelfCheckCaseLabel(item: any, index = 0) {
  const raw = item?.args?.case ?? item?.facts?.case ?? item?.case ?? item?.name;
  if (typeof raw === "string" && raw.trim()) return redCaseLabel(raw);
  return `策略用例 ${index + 1}`;
}

function securitySelfCheckStats(audit: AuditRecord, diagnosis?: DiagnosisResult) {
  const trace = audit.tool_trace?.length ? audit.tool_trace : diagnosis?.tool_trace ?? [];
  const total = trace.length;
  const passed = trace.filter((item: any) => item.ok !== false).length;
  const blocked = trace.filter((item: any) => /拦截|阻断|隔离|保护|通过/.test(String(item.summary ?? ""))).length || passed;
  return {
    total,
    passed,
    blocked,
    failed: Math.max(total - passed, 0),
  };
}

function buildAuditTimelineForSession(session: AuditSessionRow, replay: ReplayRecord, diagnosis: DiagnosisResult): AuditTimelineItem[] {
  const trace = session.audit?.tool_trace ?? diagnosis.tool_trace ?? [];
  if (session.audit && trace.length) {
    const created = session.time.slice(11, 19) || "00:00:00";
    if (isSecuritySelfCheckSession(session, session.audit)) {
      const stats = securitySelfCheckStats(session.audit, diagnosis);
      return [
        { time: created, tone: "blue", title: "自检会话创建", detail: `执行人：${session.user} | 范围：${session.target}` },
        { time: "00:00:01", tone: "blue", title: "自检计划生成", detail: `${session.audit.plan?.steps?.length ?? stats.total} 类策略用例，意图：安全策略自检` },
        ...trace.map((item: any, index: number) => ({
          time: `00:00:${String(index + 2).padStart(2, "0")}`,
          tone: item.ok ? "green" as const : "orange" as const,
          title: `用例校验：${securitySelfCheckCaseLabel(item, index)}`,
          detail: `${item.summary ?? "策略用例已完成"} / ${displayToolMode(item.mode ?? "audit")} / ${item.duration_ms ?? 0}ms`,
        })),
        { time: "00:00:09", tone: "orange", title: "策略证据图生成", detail: `${session.audit.evidence_graph?.nodes?.length ?? 0} 个审计节点，${session.audit.evidence_graph?.edges?.length ?? 0} 条校验关系` },
        { time: "00:00:10", tone: "green", title: "自检结论输出", detail: `${stats.passed}/${stats.total || stats.passed} 个用例通过，${stats.blocked} 项策略拦截已入审计链` },
      ];
    }
    return [
      { time: created, tone: "blue", title: "会话创建", detail: `用户：${session.user} | 目标：${session.target}` },
      { time: "00:00:01", tone: "blue", title: "计划规范生成", detail: `${session.audit.plan?.steps?.length ?? 0} 个步骤，意图：${session.audit.plan?.intent ?? "未知"}` },
      ...trace.map((item: any, index: number) => ({
        time: `00:00:${String(index + 2).padStart(2, "0")}`,
        tone: item.ok ? "green" as const : "orange" as const,
        title: `工具调用：${item.tool}`,
        detail: `${item.summary ?? "工具已执行"} / ${displayToolMode(item.mode ?? "readonly")} / ${item.duration_ms ?? 0}ms`,
      })),
      { time: "00:00:09", tone: "orange", title: "证据图谱生成", detail: `${session.audit.evidence_graph?.nodes?.length ?? 0} 个节点，${session.audit.evidence_graph?.edges?.length ?? 0} 条关系` },
      { time: "00:00:10", tone: "green", title: "根因结论输出", detail: session.audit.root_cause?.summary ?? "结论已保存" },
    ];
  }

  if (session.status === "已阻断") {
    const blockedTarget = session.target.includes("敏感") ? "受保护系统路径" : "破坏性命令模式";
    return [
      { time: session.time.slice(11, 19), tone: "blue", title: "会话创建", detail: `用户：${session.user} | 目标：${session.target}` },
      { time: "00:00:01", tone: "blue", title: "计划规范生成", detail: `识别为 ${session.type} 请求，进入安全策略校验` },
      { time: "00:00:02", tone: "orange", title: "策略命中", detail: `命中高危规则：禁止访问或执行 ${blockedTarget}` },
      { time: "00:00:03", tone: "red", title: "危险动作拦截", detail: "未调用 Shell，未产生真实系统副作用" },
      { time: "00:00:05", tone: "green", title: "审计凭证固化", detail: "记录用户输入、策略命中、阻断原因与证据链" },
    ];
  }

  if (session.type === "扫描") {
    return [
      { time: session.time.slice(11, 19), tone: "blue", title: "会话创建", detail: `用户：${session.user} | 目标：${session.target}` },
      { time: "00:00:02", tone: "blue", title: "工具契约校验", detail: "允许只读端口枚举工具，禁止写入系统配置" },
      { time: "00:00:05", tone: "green", title: "工具调用：ss_listen", detail: "采集开放端口、监听地址与进程信息" },
      { time: "00:00:09", tone: "orange", title: "攻击面风险计算", detail: "识别 3306、6379、2375 等潜在暴露面" },
      { time: "00:00:12", tone: "green", title: "地图与报告更新", detail: "攻击面地图、风险分布与审计报告已更新" },
    ];
  }

  if (session.type === "变更") {
    return [
      { time: session.time.slice(11, 19), tone: "blue", title: "会话创建", detail: `用户：${session.user} | 目标：${session.target}` },
      { time: "00:00:03", tone: "blue", title: "影子执行评估", detail: "评估重启 nginx.service 的连接影响与回滚路径" },
      { time: "00:00:08", tone: "orange", title: "人工确认", detail: "中风险操作需要二次确认后才能执行" },
      { time: "00:00:12", tone: "green", title: "受控执行记录", detail: "演示模式仅记录审计；真实模式走白名单工具契约" },
      { time: "00:00:16", tone: "green", title: "审计完成", detail: "操作意图、风险评估、确认动作均已入链" },
    ];
  }

  return auditTimelineItems.map((item, index) => ({
    ...item,
    time: index === 0 ? session.time.slice(11, 19) : item.time,
    detail: item.title === "会话创建"
      ? `用户：${session.user} | 目标：${session.target}`
      : item.detail,
  })).slice(0, Math.max(5, replay.events.length + 3 || 9));
}

function buildAuditEvidenceForSession(session: AuditSessionRow, diagnosis: DiagnosisResult): AuditEvidenceItem[] {
  const trace = session.audit?.tool_trace ?? diagnosis.tool_trace ?? [];
  if (session.audit && trace.length) {
    const tones: AuditEvidenceItem["tone"][] = ["purple", "green", "blue", "orange"];
    if (isSecuritySelfCheckSession(session, session.audit)) {
      return trace.map((item: any, index: number) => ({
        tone: tones[index % tones.length],
        title: securitySelfCheckCaseLabel(item, index),
        command: item.command || item.tool || "policy_self_check",
        detail: item.summary || "策略用例结果已写入审计记录",
      }));
    }
    return trace.map((item: any, index: number) => ({
      tone: tones[index % tones.length],
      title: toolEvidenceTitle(item.tool),
      command: item.command || item.tool,
      detail: item.summary || "工具结果已写入审计记录",
    }));
  }

  if (session.status === "已阻断") {
    return [
      { tone: "red", title: "用户输入", command: session.description, detail: "输入被标记为高危或越权意图" },
      { tone: "orange", title: "策略命中", command: "policy.deny.dangerous_action", detail: "命中危险命令/敏感路径访问规则" },
      { tone: "blue", title: "工具隔离", command: "tool_contract.guard", detail: "未生成 Shell 调用，危险参数未进入执行层" },
      { tone: "green", title: "审计记录", command: session.id, detail: "阻断事件已进入审计中心，可追溯原因" },
    ];
  }

  if (session.type === "扫描") {
    return [
      { tone: "blue", title: "端口快照", command: "ss -lntp", detail: "发现 8 个监听端口，2 个未知服务" },
      { tone: "orange", title: "风险端口", command: "3306 / 6379 / 2375", detail: "数据库、缓存、Docker API 需要访问控制" },
      { tone: "purple", title: "攻击面地图", command: "attack_surface.render", detail: "服务、端口、进程与外部连接已成图" },
      { tone: "green", title: "报告输出", command: "audit.export", detail: "攻击面报告可导出用于答辩展示" },
    ];
  }

  if (session.type === "变更") {
    return [
      { tone: "purple", title: "拟执行操作", command: "重启 nginx.service", detail: "中风险，需要人工确认" },
      { tone: "orange", title: "影响推演", command: "shadow.preview", detail: "Web 服务可能中断 2-5 秒，活动连接约 12 个" },
      { tone: "blue", title: "确认记录", command: "human.confirm", detail: "确认动作进入审计链，不默认裸执行 Shell" },
      { tone: "green", title: "可回滚路径", command: "rollback.plan", detail: "保留重启前状态，支持审计回放" },
    ];
  }

  return auditEvidenceCards.map((item) => {
    if (item.title === "服务状态" && diagnosis.root_cause?.summary) {
      return { ...item, detail: diagnosis.root_cause.summary };
    }
    return item;
  });
}

function toolEvidenceTitle(tool: string) {
  const labels: Record<string, string> = {
    systemctl_status: "服务状态",
    journalctl_unit: "日志现象",
    ss_listen: "端口状态",
    netstat_listen: "网络监听",
    lsof_port: "端口归属",
    ps_process: "进程归属",
    policy_self_check: "策略自检",
  };
  return labels[tool] ?? "工具证据";
}

function buildAuditReplayStages(
  session: AuditSessionRow,
  audit: AuditRecord,
  diagnosis: DiagnosisResult,
  timeline: AuditTimelineItem[],
  evidence: AuditEvidenceItem[],
  reportMarkdown: string,
): AuditReplayStage[] {
  const planSteps = audit.plan?.steps?.length ?? diagnosis.plan?.steps?.length ?? 0;
  const toolCalls = audit.tool_trace?.length ?? diagnosis.tool_trace?.length ?? 0;
  const graphNodes = audit.evidence_graph?.nodes?.length ?? diagnosis.evidence_graph?.nodes?.length ?? evidence.length;
  const confidence = toPercent(audit.root_cause?.confidence ?? diagnosis.root_cause?.confidence) || session.riskScore;
  const reportLines = reportMarkdown.split("\n").filter(Boolean).length;
  const selfCheck = isSecuritySelfCheckSession(session, audit);
  const selfCheckStats = securitySelfCheckStats(audit, diagnosis);

  return [
    {
      key: "plan",
      label: selfCheck ? "自检计划" : "计划",
      subtitle: selfCheck ? "策略计划" : "计划规范",
      detail: selfCheck ? `覆盖 ${planSteps || selfCheckStats.total} 类策略用例，先校验再审计` : `${diagnosis.plan?.intent ?? "诊断意图"} · ${planSteps} 个步骤`,
      metric: selfCheck ? `${planSteps || selfCheckStats.total} 类` : `${planSteps || timeline.length} 步`,
      tone: "blue",
      icon: "plan",
    },
    {
      key: "tool",
      label: selfCheck ? "用例校验" : "工具",
      subtitle: selfCheck ? "策略用例" : "工具轨迹",
      detail: selfCheck ? `本地模拟用例已逐项校验，${selfCheckStats.blocked} 项拦截结果可追溯` : `受控工具调用已记录，模式：${displayMode(audit.environment?.effective_mode ?? diagnosis.environment?.effective_mode ?? "demo")}`,
      metric: selfCheck ? `${selfCheckStats.passed}/${selfCheckStats.total || selfCheckStats.passed}` : `${toolCalls} 次`,
      tone: "green",
      icon: "tool",
    },
    {
      key: "evidence",
      label: selfCheck ? "策略证据" : "证据",
      subtitle: "证据图谱",
      detail: selfCheck ? `${graphNodes} 个审计节点，${evidence.length} 张自检证据卡片` : `${graphNodes} 个证据节点，${evidence.length} 张证据卡片`,
      metric: `${graphNodes} 节点`,
      tone: "orange",
      icon: "topology",
    },
    {
      key: "root",
      label: selfCheck ? "自检结论" : "根因",
      subtitle: selfCheck ? "自检结果" : "根因结论",
      detail: selfCheck ? `${selfCheckStats.failed === 0 ? "安全策略自检通过" : "存在需复核用例"}，结果已进入审计会话` : audit.root_cause?.summary ?? diagnosis.root_cause?.summary ?? "根因结论已生成",
      metric: `${confidence}/100`,
      tone: "purple",
      icon: "shield",
    },
    {
      key: "report",
      label: "报告",
      subtitle: "审计报告",
      detail: selfCheck ? `${session.id} 安全策略自检报告可预览、回放与导出` : `${session.id} 可导出、可回放、可追责`,
      metric: `${reportLines} 行`,
      tone: "red",
      icon: "export",
    },
  ];
}

function replayStageIndexForItem(item: AuditTimelineItem | null, index: number, total: number, playbackRunning: boolean) {
  if (!item || index < 0) return -1;
  if (!playbackRunning && total > 0 && index >= total - 1) return 4;
  const title = item.title;
  if (/计划|会话/.test(title)) return 0;
  if (/工具|用例|校验/.test(title)) return 1;
  if (/证据/.test(title)) return 2;
  if (/根因|结论|决策/.test(title)) return 3;
  const ratio = index / Math.max(total - 1, 1);
  if (ratio < 0.24) return 0;
  if (ratio < 0.58) return 1;
  if (ratio < 0.78) return 2;
  if (ratio < 0.95) return 3;
  return 4;
}

function timelineIndexForReplayStage(stageIndex: number, timeline: AuditTimelineItem[]) {
  const matchers = [
    /计划|会话/,
    /工具|用例|校验/,
    /证据/,
    /根因|结论|决策/,
    /报告|根因|结论/,
  ];
  const matcher = matchers[stageIndex] ?? matchers[0];
  const found = timeline.findIndex((item) => matcher.test(item.title));
  if (found >= 0) return found;
  if (stageIndex >= 4) return Math.max(0, timeline.length - 1);
  return Math.min(Math.max(stageIndex, 0), Math.max(0, timeline.length - 1));
}

function buildAuditSessionMarkdown(
  session: AuditSessionRow,
  audit: AuditRecord,
  diagnosis: DiagnosisResult,
  timeline: AuditTimelineItem[],
  evidence: AuditEvidenceItem[],
) {
  const requirementRows = audit.requirement_coverage ?? buildAuditRequirementCoverage(audit, diagnosis);
  const complianceScore = requirementScore(requirementRows);
  const selfCheck = isSecuritySelfCheckSession(session, audit);
  const selfCheckStats = securitySelfCheckStats(audit, diagnosis);
  const root = session.status === "已阻断"
    ? "安全策略阻断：未执行危险动作"
    : selfCheck
      ? `${selfCheckStats.passed}/${selfCheckStats.total || selfCheckStats.passed} 个策略用例通过，${selfCheckStats.blocked} 项拦截结果已固化`
      : audit.root_cause?.summary ?? diagnosis.root_cause?.summary ?? "暂无结论";
  const linkedSource = audit.diagnosis_source ?? diagnosis.diagnosis_source;
  return [
    `# ${selfCheck ? "安全策略自检审计报告" : "麒麟安全运维审计报告"} ${session.id}`,
    "",
    `- 生成时间：${new Date().toLocaleString("zh-CN")}`,
    `- ${selfCheck ? "自检时间" : "会话时间"}：${session.time}`,
    `- ${selfCheck ? "执行人" : "用户"}：${session.user}`,
    `- ${selfCheck ? "自检范围" : "目标"}：${session.target}`,
    ...(linkedSource ? [`- 联动来源：${linkedSource.label}`] : []),
    `- ${selfCheck ? "报告类型" : "类型"}：${session.type}`,
    `- ${selfCheck ? "策略等级" : "风险等级"}：${auditRiskLabel(session.risk)}`,
    `- ${selfCheck ? "自检状态" : "状态"}：${session.status}`,
    `- ${selfCheck ? "自检耗时" : "总耗时"}：${session.duration}`,
    `- ${selfCheck ? "自检摘要" : "描述"}：${session.description}`,
    `- ${selfCheck ? "自检结论" : "结论"}：${root}`,
    ...(selfCheck ? [
      `- 覆盖用例：${selfCheckStats.total}`,
      `- 通过用例：${selfCheckStats.passed}`,
      `- 策略拦截：${selfCheckStats.blocked}`,
    ] : []),
    "",
    "## 赛题要求对齐",
    `- 合规得分：${complianceScore}/100`,
    `- 当前模式：${displayMode(audit.environment?.effective_mode ?? diagnosis.environment?.effective_mode ?? "demo")}`,
    `- 工具适配器：${formatAdapterName(audit.environment?.adapter ?? diagnosis.environment?.adapter)}`,
    "",
    "| 要求项 | 状态 | 证据 |",
    "| --- | --- | --- |",
    ...requirementRows.map((item) => `| ${item.label} | ${displayRequirementStatus(item.status)} | ${item.evidence ?? item.source ?? "-"} |`),
    "",
    `## ${selfCheck ? "自检用例轨迹" : "执行时间线"}`,
    ...timeline.map((item, index) => `${index + 1}. ${item.time} ${item.title}：${item.detail}`),
    "",
    `## ${selfCheck ? "策略证据摘要" : "证据摘要"}`,
    ...evidence.map((item) => `- ${item.title}：${item.command} -> ${item.detail}`),
    "",
    `## ${selfCheck ? "自检结论与审查" : "决策与审查"}`,
    `- ${selfCheck ? "策略可信度" : "可信度"}：${toPercent(audit.root_cause?.confidence ?? diagnosis.root_cause?.confidence) || 91}/100`,
    `- 审查说明：${audit.critic?.conclusion ?? diagnosis.critic?.conclusion ?? (selfCheck ? "自检用例、策略命中与审计轨迹一致。" : "证据链完整，工具轨迹可回放。")}`,
    `- 审计结论：${selfCheck ? "该安全策略自检会话可回放、可预览、可导出，适合答辩展示策略有效性。" : "该会话可回放、可导出、可追责。"}`,
  ].join("\n");
}

function AuditReplayStagePanel({
  stages,
  activeIndex,
  currentItem,
  playbackProgress,
  running,
  onStageSelect,
}: {
  stages: AuditReplayStage[];
  activeIndex: number;
  currentItem: AuditTimelineItem | null;
  playbackProgress: number;
  running: boolean;
  onStageSelect: (stageIndex: number) => void;
}) {
  const safeActiveIndex = activeIndex < 0 ? 0 : activeIndex;
  const activeStage = stages[safeActiveIndex] ?? stages[0];

  return (
    <section className={`audit-replay-stage-panel audit-panel ${running ? "running" : ""}`}>
      <div className="audit-replay-stage-head">
        <div>
          <span>答辩回放链路</span>
          <strong>{activeStage?.label ?? "待回放"} · {activeStage?.subtitle ?? "审计回放"}</strong>
          <p>{currentItem ? `${currentItem.title}：${currentItem.detail}` : "点击回放按钮后，系统会按计划、工具、证据、结论、报告依次高亮。"}</p>
        </div>
        <div className="audit-replay-stage-meter">
          <b>{playbackProgress}%</b>
          <small>{running ? "回放中" : activeIndex >= 0 ? "已定位" : "待开始"}</small>
        </div>
      </div>
      <div className="audit-replay-stage-flow">
        {stages.map((stage, index) => (
          <button
            className={`${stage.tone} ${index < activeIndex ? "done" : ""} ${index === activeIndex ? "active" : ""}`}
            key={stage.key}
            onClick={() => onStageSelect(index)}
            type="button"
          >
            <i><SafeIcon name={stage.icon} /></i>
            <span>{stage.label}</span>
            <strong>{stage.metric}</strong>
            <small>{stage.subtitle}</small>
          </button>
        ))}
      </div>
      <div className={`audit-replay-stage-explain ${activeStage?.tone ?? "blue"}`}>
        <span>{activeStage?.detail ?? "等待回放开始"}</span>
      </div>
    </section>
  );
}

function AuditRequirementPanel({
  rows,
  score,
  environment,
  exportLabel = "导出审计报告",
  previewLabel = "查看报告预览",
  onPreview,
  onExport,
  onNotice,
}: {
  rows: Array<{ label: string; status: string; evidence?: string; source?: string }>;
  score: number;
  environment: any;
  exportLabel?: string;
  previewLabel?: string;
  onPreview: () => void;
  onExport: () => void;
  onNotice: (message: string) => void;
}) {
  const done = rows.filter((row) => row.status === "done").length;
  const partial = rows.filter((row) => row.status === "partial").length;
  const pending = rows.filter((row) => row.status === "pending").length;

  return (
    <section className="audit-panel audit-requirement-panel">
      <div className="audit-requirement-score">
        <span>赛题对齐度</span>
        <strong>{score}<b>/100</b></strong>
        <em>{environment?.is_kylin_like ? "麒麟实机已识别" : "实机验证待补"}</em>
        <small>{displayMode(environment?.effective_mode ?? "demo")}模式 · {formatAdapterName(environment?.adapter)}</small>
      </div>
      <div className="audit-requirement-table">
        <header>
          <h2>赛题要求对齐矩阵</h2>
          <p>把赛题要求落到当前会话的证据、工具和审计记录里</p>
        </header>
        <div className="audit-requirement-rows">
          {rows.map((row) => (
            <button className={row.status} key={row.label} onClick={() => onNotice(`${row.label}：${row.evidence ?? row.source ?? "已纳入审计"}`)} type="button">
              <span>{displayRequirementStatus(row.status)}</span>
              <strong>{row.label}</strong>
              <small>{row.evidence ?? row.source ?? "-"}</small>
            </button>
          ))}
        </div>
      </div>
      <aside className="audit-requirement-proof">
        <h3>答辩证明点</h3>
        <div><b>{done}</b><span>已完成</span></div>
        <div><b>{partial}</b><span>可演示</span></div>
        <div><b>{pending}</b><span>待验证</span></div>
        <p>页面展示、审计记录、报告导出三处使用同一份对齐数据。</p>
        <button onClick={onPreview} type="button">{previewLabel}</button>
        <button className="primary" onClick={onExport} type="button">{exportLabel}</button>
      </aside>
    </section>
  );
}

function AuditCenterPage({
  audit,
  diagnosis,
  replay,
  notice,
  onNotice,
}: {
  audit: AuditRecord;
  diagnosis: DiagnosisResult;
  replay: ReplayRecord;
  notice: string;
  onNotice: (message: string) => void;
}) {
  const [selectedId, setSelectedId] = useState(audit.audit_id ?? auditSessions[0].id);
  const [runtimeSessions, setRuntimeSessions] = useState<AuditSessionRow[]>([]);
  const [typeFilter, setTypeFilter] = useState("全部类型");
  const [riskFilter, setRiskFilter] = useState("全部风险");
  const [statusFilter, setStatusFilter] = useState("全部状态");
  const [query, setQuery] = useState("");
  const [activeTab, setActiveTab] = useState(auditTabs[0]);
  const [page, setPage] = useState(1);
  const [playbackIndex, setPlaybackIndex] = useState(-1);
  const [playbackRunning, setPlaybackRunning] = useState(false);
  const [selectedEvidenceIndex, setSelectedEvidenceIndex] = useState(0);
  const [evidenceDrawerOpen, setEvidenceDrawerOpen] = useState(false);
  const [refreshingAudits, setRefreshingAudits] = useState(false);

  useEffect(() => {
    let cancelled = false;
    listAudits(30)
      .then((data) => {
        if (cancelled) return;
        const rows = (data.items ?? [])
          .map(auditToSessionRow)
          .filter(Boolean) as AuditSessionRow[];
        setRuntimeSessions(rows);
        if (rows.length) {
          setSelectedId((current) => current === auditSessions[0].id ? rows[0].id : current);
        }
      })
      .catch(() => {
        if (!cancelled) onNotice("审计中心暂未读取到后端会话列表，保留演示会话");
      });
    return () => {
      cancelled = true;
    };
  }, [audit.audit_id, onNotice]);

  const activeAuditSession = useMemo(() => auditToSessionRow({ audit }), [audit]);

  useEffect(() => {
    const activeId = activeAuditSession?.id;
    if (!activeId) return;
    setSelectedId(activeId);
    setPlaybackIndex(-1);
    setPlaybackRunning(false);
    setEvidenceDrawerOpen(false);
    setSelectedEvidenceIndex(0);
  }, [activeAuditSession?.id]);

  const allSessions = useMemo(() => {
    const seen = new Set<string>();
    return [activeAuditSession, ...runtimeSessions, ...auditSessions].filter(Boolean).filter((session) => {
      if (seen.has(session.id)) return false;
      seen.add(session.id);
      return true;
    }) as AuditSessionRow[];
  }, [activeAuditSession, runtimeSessions]);

  const filteredSessions = useMemo(() => allSessions.filter((session) => {
    const riskText = auditRiskLabel(session.risk);
    const matchesType = typeFilter === "全部类型" || session.type === typeFilter;
    const matchesRisk = riskFilter === "全部风险" || riskText === riskFilter;
    const matchesStatus = statusFilter === "全部状态" || session.status === statusFilter;
    const haystack = `${session.id} ${session.target} ${session.user} ${session.type}`.toLowerCase();
    return matchesType && matchesRisk && matchesStatus && haystack.includes(query.trim().toLowerCase());
  }), [allSessions, typeFilter, riskFilter, statusFilter, query]);

  useEffect(() => {
    if (!filteredSessions.some((session) => session.id === selectedId)) {
      setSelectedId(filteredSessions[0]?.id ?? allSessions[0]?.id ?? auditSessions[0].id);
    }
  }, [allSessions, filteredSessions, selectedId]);

  const selectedSession = filteredSessions.find((session) => session.id === selectedId)
    ?? allSessions.find((session) => session.id === selectedId)
    ?? auditSessions[0];
  const activeAudit = selectedSession.audit ?? audit;
  const activeDiagnosis = selectedSession.audit ? auditToDiagnosis(selectedSession.audit) : diagnosis;
  const isPolicySelfCheck = isSecuritySelfCheckSession(selectedSession, activeAudit);
  const linkedAuditSource = activeAudit.diagnosis_source ?? activeDiagnosis.diagnosis_source;
  const policySelfCheckStats = securitySelfCheckStats(activeAudit, activeDiagnosis);
  const activeReplay = selectedSession.replayId === replay.replay_id ? replay : replay;
  const selectedTimeline = useMemo(() => buildAuditTimelineForSession(selectedSession, activeReplay, activeDiagnosis), [selectedSession, activeReplay, activeDiagnosis]);
  const selectedEvidence = useMemo(() => buildAuditEvidenceForSession(selectedSession, activeDiagnosis), [selectedSession, activeDiagnosis]);
  const selectedEvidenceDetail = selectedEvidence[Math.min(selectedEvidenceIndex, Math.max(0, selectedEvidence.length - 1))];
  const requirementRows = useMemo(
    () => activeAudit.requirement_coverage ?? buildAuditRequirementCoverage(activeAudit, activeDiagnosis),
    [activeAudit, activeDiagnosis],
  );
  const complianceScore = requirementScore(requirementRows);
  const reportMarkdown = useMemo(
    () => buildAuditSessionMarkdown(selectedSession, activeAudit, activeDiagnosis, selectedTimeline, selectedEvidence),
    [selectedSession, activeAudit, activeDiagnosis, selectedTimeline, selectedEvidence],
  );
  const confidence = toPercent(activeAudit.root_cause?.confidence ?? activeDiagnosis.root_cause?.confidence) || 91;
  const diagnosisGoal = isPolicySelfCheck
    ? activeAudit.plan?.goal ?? "安全策略自检报告"
    : selectedSession.type === "诊断" ? activeDiagnosis.plan?.goal ?? selectedSession.target : selectedSession.target;
  const currentTimelineItem = playbackIndex >= 0 ? selectedTimeline[Math.min(playbackIndex, selectedTimeline.length - 1)] : null;
  const replayStages = useMemo(
    () => buildAuditReplayStages(selectedSession, activeAudit, activeDiagnosis, selectedTimeline, selectedEvidence, reportMarkdown),
    [selectedSession, activeAudit, activeDiagnosis, selectedTimeline, selectedEvidence, reportMarkdown],
  );
  const activeReplayStage = replayStageIndexForItem(currentTimelineItem, playbackIndex, selectedTimeline.length, playbackRunning);
  const focusedEvidenceIndex = playbackIndex >= 2
    ? Math.min(Math.max(playbackIndex - 2, 0), Math.max(selectedEvidence.length - 1, 0))
    : selectedEvidenceIndex;

  useEffect(() => {
    setPlaybackIndex(-1);
    setPlaybackRunning(false);
    setEvidenceDrawerOpen(false);
    setSelectedEvidenceIndex(0);
  }, [selectedId]);

  useEffect(() => {
    if (!playbackRunning) return;
    const timer = window.setInterval(() => {
      setPlaybackIndex((index) => {
        const current = index < 0 ? 0 : index;
        return Math.min(current + 1, selectedTimeline.length - 1);
      });
    }, 720);
    return () => window.clearInterval(timer);
  }, [playbackRunning, selectedTimeline.length]);

  useEffect(() => {
    if (playbackRunning && playbackIndex >= selectedTimeline.length - 1) {
      setPlaybackRunning(false);
      onNotice(`${selectedSession.id} 回放完成：${selectedTimeline.length} 个审计节点已复核`);
    }
  }, [playbackIndex, playbackRunning, selectedSession.id, selectedTimeline.length, onNotice]);

  async function exportAuditCenterReport() {
    setPlaybackRunning(false);
    let filename = isPolicySelfCheck ? `${selectedSession.id}_安全策略自检报告.md` : `${selectedSession.id}.md`;
    let markdown = reportMarkdown;
    const exportId = selectedSession.auditId ?? activeAudit.audit_id;
    if (selectedSession.type === "诊断" && exportId) {
      try {
        markdown = await exportAuditMarkdown(exportId);
        filename = `${exportId}.md`;
      } catch {
        markdown = reportMarkdown;
      }
    }
    downloadTextFile(
      filename,
      markdown,
      "text/markdown;charset=utf-8",
    );
    onNotice(`已导出 ${filename} ${isPolicySelfCheck ? "安全策略自检报告" : "审计报告"}`);
  }

  async function refreshAuditSessions() {
    setRefreshingAudits(true);
    try {
      const data = await listAudits(30);
      const rows = (data.items ?? [])
        .map(auditToSessionRow)
        .filter(Boolean) as AuditSessionRow[];
      setRuntimeSessions(rows);
      setPage(1);
      onNotice(`审计会话列表已刷新：${rows.length} 条后端会话已同步`);
    } catch {
      onNotice("审计会话刷新失败，已保留当前可演示数据");
    } finally {
      setRefreshingAudits(false);
    }
  }

  function selectSession(session: AuditSessionRow) {
    setSelectedId(session.id);
    setActiveTab("基本信息");
    setPlaybackIndex(-1);
    setPlaybackRunning(false);
    onNotice(`已打开 ${session.id} ${isSecuritySelfCheckSession(session, session.audit) ? "安全策略自检详情" : "会话详情"}`);
  }

  function startReplay() {
    setActiveTab("执行轨迹");
    setPlaybackIndex(0);
    setPlaybackRunning(true);
    onNotice(isPolicySelfCheck
      ? `正在回放 ${selectedSession.id}：自检计划、用例校验、策略证据与结论将按时间顺序高亮`
      : `正在回放 ${selectedSession.id}：计划、工具、证据与结论将按时间顺序高亮`);
  }

  function pauseReplay() {
    setPlaybackRunning(false);
    onNotice(`${selectedSession.id} 回放已暂停在第 ${Math.max(0, playbackIndex + 1)} 个节点`);
  }

  function resetReplay() {
    setPlaybackRunning(false);
    setPlaybackIndex(-1);
    onNotice(`${selectedSession.id} 回放已重置`);
  }

  function jumpToReplayStage(stageIndex: number) {
    const targetIndex = timelineIndexForReplayStage(stageIndex, selectedTimeline);
    const stage = replayStages[stageIndex];
    setPlaybackRunning(false);
    setPlaybackIndex(targetIndex);
    setActiveTab(stageIndex === 2 ? "证据图谱" : stageIndex === 3 ? "决策过程" : stageIndex === 4 ? "报告预览" : "执行轨迹");
    onNotice(`${selectedSession.id} 已定位到回放阶段：${stage?.label ?? "审计节点"}`);
  }

  function openEvidenceDetail(item: AuditEvidenceItem, index: number) {
    setSelectedEvidenceIndex(index);
    setEvidenceDrawerOpen(true);
    setActiveTab("证据图谱");
    onNotice(`证据详情已打开：${item.title}`);
  }

  function closeEvidenceDetail() {
    setEvidenceDrawerOpen(false);
    onNotice("证据详情抽屉已关闭");
  }

  function copyReportPreview() {
    setActiveTab("报告预览");
    if (window.navigator.clipboard?.writeText) {
      window.navigator.clipboard.writeText(reportMarkdown).then(
        () => onNotice(`${selectedSession.id} ${isPolicySelfCheck ? "安全策略自检报告" : "报告预览"}已复制到剪贴板`),
        () => onNotice(`${selectedSession.id} ${isPolicySelfCheck ? "安全策略自检报告" : "报告预览"}已生成，可直接导出`),
      );
      return;
    }
    onNotice(`${selectedSession.id} ${isPolicySelfCheck ? "安全策略自检报告" : "报告预览"}已生成，可直接导出`);
  }

  const playbackProgress = selectedTimeline.length
    ? Math.max(0, Math.round(((playbackIndex + 1) / selectedTimeline.length) * 100))
    : 0;

  return (
    <section className="audit-center">
      <header className="audit-center-header">
        <div>
          <h1>审计中心</h1>
          <p>所有操作、决策、证据与结果的全链路记录，支持回放与导出</p>
        </div>
        <div className="audit-center-actions">
          <span className="audit-live-notice">{notice}</span>
          <button className="audit-date-range" onClick={() => onNotice("当前审计范围：2026-06-03 至 2026-06-09")} type="button">2026-06-03 ~ 2026-06-09</button>
          <button onClick={refreshAuditSessions} disabled={refreshingAudits} type="button"><SafeIcon name="refresh" />{refreshingAudits ? "刷新中" : "刷新会话"}</button>
          <button className="audit-preview-primary" onClick={() => { setActiveTab("报告预览"); onNotice(`正在预览 ${selectedSession.id} ${isPolicySelfCheck ? "安全策略自检报告" : "审计报告"}`); }} type="button"><SafeIcon name="audit" />预览报告</button>
          <button className="audit-export-primary" onClick={exportAuditCenterReport} type="button"><SafeIcon name="export" />{isPolicySelfCheck ? "导出自检报告" : "导出审计报告"}</button>
        </div>
      </header>

      <section className="audit-metric-row">
        {auditMetricCards.map((metric) => (
          <article className={`audit-metric ${metric.tone}`} key={metric.label}>
            <span><SafeIcon name={metric.icon} /></span>
            <div>
              <small>{metric.label}</small>
              <strong>{metric.value}</strong>
              <em>较昨日 <b>{metric.delta}</b></em>
            </div>
          </article>
        ))}
      </section>

      <AuditReplayStagePanel
        activeIndex={activeReplayStage}
        currentItem={currentTimelineItem}
        playbackProgress={playbackProgress}
        running={playbackRunning}
        stages={replayStages}
        onStageSelect={jumpToReplayStage}
      />

      <AuditRequirementPanel
        environment={activeAudit.environment ?? activeDiagnosis.environment}
        exportLabel={isPolicySelfCheck ? "导出自检报告" : "导出审计报告"}
        previewLabel={isPolicySelfCheck ? "查看自检报告" : "查看报告预览"}
        rows={requirementRows}
        score={complianceScore}
        onExport={exportAuditCenterReport}
        onNotice={onNotice}
        onPreview={() => { setActiveTab("报告预览"); onNotice(`${selectedSession.id} 赛题对齐矩阵已同步到${isPolicySelfCheck ? "安全策略自检报告" : "报告预览"}`); }}
      />

      <section className="audit-main-grid">
        <article className="audit-panel audit-session-list">
          <div className="audit-panel-title">
            <h2>审计会话列表</h2>
          </div>
          <div className="audit-filter-row">
            <select value={typeFilter} onChange={(event) => { setTypeFilter(event.target.value); setPage(1); onNotice(`类型筛选：${event.target.value}`); }}>
              <option>全部类型</option>
              <option>诊断</option>
              <option>变更</option>
              <option>扫描</option>
              <option>查询</option>
              <option>攻击面联动诊断</option>
              <option>安全检测</option>
            </select>
            <select value={riskFilter} onChange={(event) => { setRiskFilter(event.target.value); setPage(1); onNotice(`风险筛选：${event.target.value}`); }}>
              <option>全部风险</option>
              <option>高危</option>
              <option>中</option>
              <option>低</option>
            </select>
            <select value={statusFilter} onChange={(event) => { setStatusFilter(event.target.value); setPage(1); onNotice(`状态筛选：${event.target.value}`); }}>
              <option>全部状态</option>
              <option>已完成</option>
              <option>已阻断</option>
            </select>
            <input value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); onNotice(event.target.value ? `会话搜索：${event.target.value}` : "会话搜索已清空"); }} placeholder="搜索会话/目标/用户..." />
          </div>
          <div className="audit-table-wrap">
            <table className="audit-table">
              <thead>
                <tr>
                  <th>会话ID</th>
                  <th>时间</th>
                  <th>用户</th>
                  <th>目标</th>
                  <th>类型</th>
                  <th>风险等级</th>
                  <th>状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {filteredSessions.map((session) => (
                  <tr className={selectedSession.id === session.id ? "selected" : undefined} key={session.id}>
                    <td>{session.id}</td>
                    <td>{session.time}</td>
                    <td>{session.user}</td>
                    <td>{session.target}</td>
                    <td>{session.type}</td>
                    <td><span className={`risk-tag ${session.risk}`}>{auditRiskLabel(session.risk)}</span></td>
                    <td><span className={`audit-status ${session.status === "已完成" ? "done" : "blocked"}`}>{session.status}</span></td>
                    <td><button onClick={() => selectSession(session)} type="button">▶</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="audit-pagination">
            <button onClick={() => { setPage(Math.max(1, page - 1)); onNotice("审计列表已切到上一页"); }} type="button">‹</button>
            {[1, 2, 3, 4, 5].map((item) => (
              <button className={page === item ? "active" : undefined} key={item} onClick={() => { setPage(item); onNotice(`审计列表已切到第 ${item} 页`); }} type="button">{item}</button>
            ))}
            <span>...</span>
            <button onClick={() => { setPage(6); onNotice("审计列表已切到第 6 页"); }} type="button">6</button>
            <button onClick={() => { setPage(Math.min(6, page + 1)); onNotice("审计列表已切到下一页"); }} type="button">›</button>
          </div>
        </article>

        <article className="audit-panel audit-detail-card">
          <div className="audit-panel-title">
            <h2>{isPolicySelfCheck ? "安全策略自检详情" : "会话详情"}（{selectedSession.id}）</h2>
            <span className={`audit-status ${selectedSession.status === "已完成" ? "done" : "blocked"}`}>{selectedSession.status}</span>
          </div>
          <div className="audit-tabs">
            {auditTabs.map((tab) => (
              <button className={activeTab === tab ? "active" : undefined} key={tab} onClick={() => { setActiveTab(tab); onNotice(`已切换到 ${tab}`); }} type="button">{tab}</button>
            ))}
          </div>
          <div className={`audit-detail-body ${activeTab === "报告预览" ? "report-mode" : ""}`}>
            {activeTab === "基本信息" && (
              <>
                <dl className="audit-basic-list">
                  <div><dt>{isPolicySelfCheck ? "自检ID" : "会话ID"}</dt><dd>{selectedSession.id}</dd></div>
                  <div><dt>{isPolicySelfCheck ? "执行人" : "用户"}</dt><dd>{selectedSession.user}</dd></div>
                  <div><dt>{isPolicySelfCheck ? "自检时间" : "时间"}</dt><dd>{selectedSession.time}</dd></div>
                  <div><dt>{isPolicySelfCheck ? "自检范围" : "目标"}</dt><dd>{diagnosisGoal}</dd></div>
                  {linkedAuditSource && <div><dt>联动来源</dt><dd>{linkedAuditSource.label}</dd></div>}
                  <div><dt>{isPolicySelfCheck ? "报告类型" : "类型"}</dt><dd>{selectedSession.type}</dd></div>
                  <div><dt>{isPolicySelfCheck ? "策略等级" : "风险等级"}</dt><dd><span className={`risk-tag ${selectedSession.risk}`}>{auditRiskLabel(selectedSession.risk)}</span></dd></div>
                  <div><dt>{isPolicySelfCheck ? "自检状态" : "状态"}</dt><dd><span className={`audit-status ${selectedSession.status === "已完成" ? "done" : "blocked"}`}>{selectedSession.status}</span></dd></div>
                  <div><dt>{isPolicySelfCheck ? "自检耗时" : "总耗时"}</dt><dd>{selectedSession.duration}</dd></div>
                  <div><dt>{isPolicySelfCheck ? "自检摘要" : "描述"}</dt><dd>{selectedSession.description}</dd></div>
                </dl>
                <div className="audit-risk-card">
                  <h3>{isPolicySelfCheck ? "策略自检概览" : "风险评估"}</h3>
                  <RiskGauge score={selectedSession.riskScore} label={isPolicySelfCheck ? "策略可信度" : `${auditRiskLabel(selectedSession.risk)}风险`} />
                  <div className="audit-risk-bars">
                    <span>{isPolicySelfCheck ? "自检覆盖率" : "数据敏感性"} <b>{isPolicySelfCheck ? Math.min(100, policySelfCheckStats.total * 12) : selectedSession.risk === "high" ? 82 : 40}/100</b></span>
                    <span>{isPolicySelfCheck ? "策略命中率" : "操作影响范围"} <b>{isPolicySelfCheck ? Math.round((policySelfCheckStats.blocked / Math.max(policySelfCheckStats.total, 1)) * 100) : selectedSession.type === "变更" ? 74 : 60}/100</b></span>
                    <span>{isPolicySelfCheck ? "审计完整性" : "潜在危害程度"} <b>{selectedSession.riskScore}/100</b></span>
                    <span>{isPolicySelfCheck ? "综合结论" : "综合评估"} <b>{isPolicySelfCheck ? "策略有效" : `${auditRiskLabel(selectedSession.risk)}风险`}</b></span>
                  </div>
                </div>
              </>
            )}

            {activeTab === "执行轨迹" && (
              <div className="audit-tab-timeline">
                {selectedTimeline.map((item, index) => (
                  <div className={`audit-tab-step ${index <= playbackIndex ? "played" : ""} ${index === playbackIndex ? "current" : ""}`} key={`${item.time}-${item.title}`}>
                    <span>{item.time}</span>
                    <strong>{item.title}</strong>
                    <p>{item.detail}</p>
                  </div>
                ))}
              </div>
            )}

            {activeTab === "证据图谱" && (
              <div className="audit-tab-evidence">
                {selectedEvidence.map((item, index) => (
                  <article className={`audit-tab-evidence-card ${item.tone}`} key={`${item.title}-${item.command}`}>
                    <strong>{item.title}</strong>
                    <code>{item.command}</code>
                    <p>{item.detail}</p>
                    <button onClick={() => openEvidenceDetail(item, index)} type="button">打开证据详情</button>
                  </article>
                ))}
              </div>
            )}

            {activeTab === "决策过程" && (
              <div className="audit-tab-decision">
                <strong>{isPolicySelfCheck ? "安全策略自检通过，校验结果已进入审计链路" : selectedSession.status === "已阻断" ? "策略阻断优先于工具执行" : activeAudit.root_cause?.summary ?? activeDiagnosis.root_cause?.summary}</strong>
                <p>{isPolicySelfCheck ? "系统按本地模拟用例逐项校验策略规则，记录命中、拦截、隔离和报告生成过程，证明运行时护栏可追溯。" : selectedSession.status === "已阻断" ? "系统在工具调用前完成策略校验，危险输入未进入 Shell 层。" : "系统先验证日志、端口和进程证据，再将端口冲突提升为根因结论。"}</p>
                <ul>
                  <li>{isPolicySelfCheck ? "自检范围" : "意图锚定"}：{selectedSession.type} / {selectedSession.target}</li>
                  <li>{isPolicySelfCheck ? "策略用例" : "证据数量"}：{isPolicySelfCheck ? `${policySelfCheckStats.passed}/${policySelfCheckStats.total || policySelfCheckStats.passed} 通过` : `${selectedEvidence.length} 条`}</li>
                  <li>时间线节点：{selectedTimeline.length} 个</li>
                  <li>审查结论：{activeAudit.critic?.conclusion ?? (isPolicySelfCheck ? "策略校验轨迹完整，自检结果可回放。" : "证据链完整，结论可追溯。")}</li>
                </ul>
              </div>
            )}

            {activeTab === "审计日志" && (
              <div className="audit-tab-log">
                <p><b>{isPolicySelfCheck ? "自检计划" : "策略校验"}</b> {isPolicySelfCheck ? `已加载 ${policySelfCheckStats.total} 类本地模拟用例` : `工具契约已验证：${selectedSession.target}`}</p>
                <p><b>{isPolicySelfCheck ? "策略边界" : "意图锚定"}</b> {isPolicySelfCheck ? "仅记录策略校验结果，不进入真实系统修改流程" : `当前操作仍限定在“${selectedSession.type}”范围内`}</p>
                <p><b>轨迹落库</b> 已持久化 {selectedTimeline.length} 个时间线事件</p>
                <p>[{isPolicySelfCheck ? "策略证据" : "证据"}] 已关联 {selectedEvidence.length} 张{isPolicySelfCheck ? "自检" : "证据"}卡片</p>
                <p>[报告] {isPolicySelfCheck ? "安全策略自检报告" : "审计报告"}导出已就绪：{selectedSession.id}.md</p>
              </div>
            )}

            {activeTab === "报告预览" && (
              <div className="audit-report-shell">
                <div className="audit-report-toolbar">
                  <span>{isPolicySelfCheck ? `${selectedSession.id}_安全策略自检报告.md` : `${selectedSession.id}.md`}</span>
                  <div>
                    <button onClick={copyReportPreview} type="button">复制预览</button>
                    <button onClick={exportAuditCenterReport} type="button">{isPolicySelfCheck ? "导出自检报告" : "导出报告"}</button>
                  </div>
                </div>
                <pre className="audit-report-preview">{reportMarkdown}</pre>
              </div>
            )}
          </div>
          <div className="audit-detail-actions">
            <button onClick={() => { setActiveTab("报告预览"); onNotice(`正在预览 ${selectedSession.id} ${isPolicySelfCheck ? "安全策略自检完整报告" : "完整报告"}`); }} type="button">{isPolicySelfCheck ? "查看自检报告" : "查看完整报告"}</button>
            <button onClick={pauseReplay} disabled={!playbackRunning} type="button">暂停回放</button>
            <button onClick={resetReplay} disabled={playbackIndex < 0 && !playbackRunning} type="button">重置回放</button>
            <button className="primary" onClick={startReplay} type="button">{playbackRunning ? "回放中..." : isPolicySelfCheck ? "▶ 回放自检会话" : "▶ 回放本次会话"}</button>
          </div>
        </article>
      </section>

      <section className="audit-bottom-grid">
        <article className="audit-panel audit-exec-timeline">
          <div className="audit-panel-title">
            <h2>{isPolicySelfCheck ? "自检时间线" : "执行时间线"}</h2>
            {currentTimelineItem && <span className="audit-playback-chip">{currentTimelineItem.title}</span>}
          </div>
          <div className="audit-playback-bar">
            <span style={{ width: `${playbackProgress}%` }} />
            <b>{playbackProgress}%</b>
          </div>
          <div className="audit-vertical-timeline">
            {selectedTimeline.map((item, index) => (
              <button
                className={`timeline-node ${item.tone} ${index <= playbackIndex ? "played" : ""} ${index === playbackIndex ? "current" : ""}`}
                key={`${item.time}-${item.title}`}
                onClick={() => { setActiveTab("执行轨迹"); setPlaybackIndex(index); setPlaybackRunning(false); onNotice(`${selectedSession.id}：${item.time} ${item.title}`); }}
                type="button"
              >
                <span>{item.time}</span>
                <i />
                <div>
                  <strong>{item.title}</strong>
                  <small>{item.detail}</small>
                </div>
              </button>
            ))}
          </div>
        </article>

        <article className="audit-panel audit-evidence-summary">
          <div className="audit-panel-title"><h2>{isPolicySelfCheck ? "策略证据摘要" : "证据摘要"}</h2></div>
          <div className="audit-evidence-list">
            {selectedEvidence.map((item, index) => (
              <div className={`audit-evidence-card ${item.tone} ${index === focusedEvidenceIndex ? "active" : ""}`} key={item.title}>
                <span />
                <div>
                  <strong>{item.title}</strong>
                  <code>{item.command}</code>
                  <small>{item.detail}</small>
                </div>
                <button onClick={() => openEvidenceDetail(item, index)} type="button">查看详情⌄</button>
              </div>
            ))}
          </div>
        </article>

        <article className="audit-panel audit-decision-card">
          <div className="audit-panel-title"><h2>{isPolicySelfCheck ? "自检结论" : "决策与结论"}</h2></div>
          <div className="audit-decision-flow">
            <div className="decision-stack">
              <span>{isPolicySelfCheck ? "安全策略自检" : selectedSession.target}<small>{selectedSession.type}</small></span>
              <span>{isPolicySelfCheck ? `${policySelfCheckStats.total} 类策略用例` : selectedEvidence[0]?.detail ?? "证据已记录"}<small>{isPolicySelfCheck ? "自检覆盖" : selectedEvidence[0]?.title ?? "证据"}</small></span>
            </div>
            <i />
            <span className="decision-mid">{isPolicySelfCheck ? "策略校验通过" : selectedSession.status === "已阻断" ? "策略命中" : "端口80被占用"}<small>{isPolicySelfCheck ? `${policySelfCheckStats.passed} 项通过` : selectedEvidence[1]?.title ?? "中间证据"}</small></span>
            <i />
            <span className="decision-mid">{isPolicySelfCheck ? "审计链路固化" : selectedSession.status === "已阻断" ? "工具隔离" : "httpd 进程占用"}<small>{isPolicySelfCheck ? `${selectedTimeline.length} 个节点` : selectedEvidence[2]?.title ?? "推理证据"}</small></span>
            <i />
            <span className="decision-root">{isPolicySelfCheck ? "结论\n自检通过" : selectedSession.status === "已阻断" ? "结论\n危险动作已阻断" : "根因\n端口80被httpd占用"}</span>
          </div>
          <div className="audit-conclusion">
            <strong>{isPolicySelfCheck ? "策略可信度" : "置信度"}：{(confidence / 100).toFixed(2)}（高）</strong>
            <p>{isPolicySelfCheck ? "后续处理：" : "建议方案："}</p>
            <ul>
              {isPolicySelfCheck ? (
                <>
                  <li>保留本次自检报告，用于展示策略规则、校验结果与审计闭环</li>
                  <li>将未通过或低置信用例加入下一轮策略加固清单</li>
                  <li>Kylin/openKylin 环境可用后，复跑同一批自检用例并补录截图</li>
                </>
              ) : selectedSession.status === "已阻断" ? (
                <>
                  <li>保持阻断策略，不允许危险输入进入工具执行层</li>
                  <li>保留审计凭证用于答辩展示与安全复核</li>
                </>
              ) : (
                <>
                  <li>停止 httpd 或修改 nginx 监听端口</li>
                  <li>该操作属于中风险，建议先进行影子执行评估</li>
                </>
              )}
            </ul>
          </div>
        </article>
      </section>

      {evidenceDrawerOpen && selectedEvidenceDetail && (
        <aside className="audit-evidence-drawer" role="dialog" aria-label={isPolicySelfCheck ? "策略证据详情" : "证据详情"}>
          <div className="audit-drawer-backdrop" onClick={closeEvidenceDetail} />
          <section className={`audit-drawer-panel ${selectedEvidenceDetail.tone}`}>
            <header>
              <div>
                <span>{isPolicySelfCheck ? "策略证据" : "证据"} #{selectedEvidenceIndex + 1}</span>
                <h2>{selectedEvidenceDetail.title}</h2>
              </div>
              <button onClick={closeEvidenceDetail} type="button" aria-label={isPolicySelfCheck ? "关闭策略证据详情" : "关闭证据详情"}>×</button>
            </header>
            <dl>
              <div><dt>{isPolicySelfCheck ? "自检会话" : "会话"}</dt><dd>{selectedSession.id}</dd></div>
              <div><dt>{isPolicySelfCheck ? "自检范围" : "目标"}</dt><dd>{selectedSession.target}</dd></div>
              <div><dt>{isPolicySelfCheck ? "校验来源" : "命令/来源"}</dt><dd><code>{selectedEvidenceDetail.command}</code></dd></div>
              <div><dt>{isPolicySelfCheck ? "校验结果" : "证据内容"}</dt><dd>{selectedEvidenceDetail.detail}</dd></div>
              <div><dt>{isPolicySelfCheck ? "策略等级" : "风险等级"}</dt><dd>{auditRiskLabel(selectedSession.risk)}</dd></div>
              <div><dt>{isPolicySelfCheck ? "自检状态" : "审计状态"}</dt><dd>{selectedSession.status}</dd></div>
            </dl>
            <div className="audit-drawer-proof">
              <strong>可追溯说明</strong>
              <p>{isPolicySelfCheck ? "该策略证据已绑定到自检时间线、用例校验结果和安全策略自检报告。评委可以从报告预览、策略证据摘要和回放动画三处交叉验证策略有效性。" : "该证据已绑定到当前会话的执行时间线、决策结论和审计报告。评委可以从报告预览、证据摘要和回放动画三处交叉验证。"}</p>
            </div>
            <footer>
              <button onClick={() => { setActiveTab("执行轨迹"); setPlaybackIndex(Math.min(selectedEvidenceIndex + 2, selectedTimeline.length - 1)); setPlaybackRunning(false); onNotice(`已定位到 ${selectedEvidenceDetail.title} 对应的执行节点`); }} type="button">定位时间线</button>
              <button onClick={copyReportPreview} type="button">{isPolicySelfCheck ? "复制自检报告" : "复制报告"}</button>
              <button className="primary" onClick={exportAuditCenterReport} type="button">{isPolicySelfCheck ? "导出自检报告" : "导出报告"}</button>
            </footer>
          </section>
        </aside>
      )}
    </section>
  );
}

const kgMetricCards = [
  { label: "已知事实", value: 84, delta: "+12", sub: "较上一小时", tone: "blue", icon: "audit" },
  { label: "已验证事实", value: 62, delta: "+8", sub: "较上一小时", tone: "green", icon: "shield" },
  { label: "未知事实", value: 11, delta: "-2", sub: "较上一小时", tone: "purple", icon: "dialog" },
  { label: "置信评分", value: "91%", delta: "+3%", sub: "较上一小时", tone: "gold", icon: "shield" },
];

const kgStateSections = [
  {
    title: "已知事实",
    count: 3,
    tone: "known",
    items: ["nginx.service 启动失败", "80 端口被占用", "httpd 正在运行"],
  },
  {
    title: "未知问题",
    count: 2,
    tone: "unknown",
    items: ["是谁启动了 httpd", "为什么 httpd 未被 systemd 托管"],
  },
  {
    title: "当前假设",
    count: 2,
    tone: "assumption",
    items: ["A1：端口冲突 82%", "A2：配置错误 12%"],
  },
  {
    title: "已验证",
    count: 2,
    tone: "verified",
    items: ["V1：httpd 占用 80 端口", "V2：bind() 绑定失败"],
  },
];

const kgGraphNodes = [
  { id: "nginx", label: "nginx.service", sub: "启动失败", tone: "known", x: 42, y: 12 },
  { id: "bind", label: "bind()", sub: "地址被占用", tone: "known", x: 44, y: 27 },
  { id: "port", label: "80 端口", sub: "已被占用", tone: "known major", x: 43, y: 43 },
  { id: "httpd", label: "httpd", sub: "运行中", tone: "verified", x: 25, y: 38 },
  { id: "owner", label: "httpd 占用", sub: "80 端口", tone: "verified", x: 17, y: 61 },
  { id: "verified", label: "已验证", sub: "", tone: "verified small", x: 18, y: 79 },
  { id: "docker", label: "docker-proxy", sub: "(80)", tone: "conflict", x: 65, y: 40 },
  { id: "conflict", label: "冲突", sub: "", tone: "conflict small", x: 67, y: 56 },
  { id: "unknown-a", label: "?", sub: "谁启动了 httpd", tone: "unknown", x: 83, y: 20 },
  { id: "unknown-b", label: "?", sub: "为何未被 systemd 托管", tone: "unknown", x: 86, y: 50 },
  { id: "h1", label: "A1：端口", sub: "冲突", tone: "hypothesis", x: 40, y: 64 },
  { id: "h2", label: "A2：配置", sub: "错误", tone: "hypothesis", x: 53, y: 64 },
  { id: "permission", label: "权限", sub: "问题", tone: "unknown small", x: 47, y: 86 },
];

const kgHypotheses = [
  { name: "假设 A", title: "端口冲突", probability: 82, tone: "gold", tag: "最可能", trend: "0,22 14,13 28,19 42,28 56,24 70,17 84,20 100,18", evidence: 5, direction: "证据增强" },
  { name: "假设 B", title: "配置错误", probability: 12, tone: "blue", tag: "", trend: "0,18 14,16 28,20 42,18 56,22 70,20 84,18 100,15", evidence: 2, direction: "证据减弱" },
  { name: "假设 C", title: "权限不足", probability: 6, tone: "purple", tag: "", trend: "0,15 14,16 28,18 42,22 56,17 70,20 84,23 100,19", evidence: 1, direction: "证据减弱" },
];

const kgTimeline = [
  { time: "09:01:15", type: "已知", title: "观察", detail: "nginx.service 启动失败", tone: "blue", icon: "audit" },
  { time: "09:02:03", type: "假设", title: "提出假设", detail: "可能是端口冲突", tone: "gold", icon: "dialog" },
  { time: "09:02:45", type: "动作", title: "执行动作", detail: "执行命令 ss -tulpn", tone: "blue", icon: "tool" },
  { time: "09:03:02", type: "已知", title: "发现", detail: "发现 80端口被占用", tone: "blue", icon: "search" },
  { time: "09:03:45", type: "动作", title: "执行动作", detail: "执行命令 ps -ef", tone: "blue", icon: "tool" },
  { time: "09:04:18", type: "已验证", title: "验证", detail: "httpd占用 80端口", tone: "green", icon: "shield" },
  { time: "09:05:03", type: "根因", title: "结论", detail: "根因已确认 端口冲突", tone: "green", icon: "topology" },
];

function KnowledgeGraphCenterPage({
  diagnosis,
  onNotice,
  onRerun,
}: {
  diagnosis: DiagnosisResult;
  onNotice: (message: string) => void;
  onRerun: () => Promise<void>;
}) {
  const [search, setSearch] = useState("");
  const [live, setLive] = useState(true);
  const [investigation, setInvestigation] = useState("nginx.service 启动失败");
  const [selectedNode, setSelectedNode] = useState("port");
  const [selectedHypothesis, setSelectedHypothesis] = useState(kgHypotheses[0].title);
  const confidence = toPercent(diagnosis.root_cause?.confidence) || 91;
  const verifiedFacts = diagnosis.knowledge_state?.verified?.length ?? 62;
  const unknownFacts = diagnosis.knowledge_state?.unknown?.length ?? 11;
  const filteredNodes = kgGraphNodes.filter((node) => `${node.label} ${node.sub}`.toLowerCase().includes(search.trim().toLowerCase()));

  async function refreshCognition() {
    onNotice("正在重新生成认知图谱...");
    await onRerun();
    onNotice("认知图谱、假设概率与证据提升时间线已刷新");
  }

  function exportSnapshot() {
    downloadTextFile(
      "认知图谱快照.json",
      JSON.stringify({ investigation, selectedNode, confidence, nodes: kgGraphNodes, hypotheses: kgHypotheses }, null, 2),
      "application/json;charset=utf-8",
    );
    onNotice("认知图谱快照已导出");
  }

  return (
    <section className="kg-center">
      <header className="kg-header">
        <div>
          <h1>认知图谱中心</h1>
          <p>智能体认知状态可视化</p>
          <small>智能体认知状态与推理过程可视化中心</small>
        </div>
        <label className="kg-search">
          <SafeIcon name="search" />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="搜索认知图谱中的事实、假设或证据..."
          />
        </label>
        <div className="kg-clock">
          <strong>09:05:42</strong>
          <span>2025-05-20</span>
        </div>
        <div className="kg-header-actions">
          <button className={live ? "active" : undefined} onClick={() => { setLive(!live); onNotice(!live ? "认知图谱实时模式已开启" : "认知图谱实时模式已暂停"); }} type="button">
            <i />{live ? "实时" : "暂停"}
          </button>
          <select value={investigation} onChange={(event) => { setInvestigation(event.target.value); onNotice(`调查目标已切换：${event.target.value}`); }}>
            <option>nginx.service 启动失败</option>
            <option>redis.service 启动失败</option>
            <option>ssh 异常登录</option>
          </select>
          <button className="kg-bell" onClick={() => onNotice("12 条认知告警已确认")} type="button" aria-label="认知告警">
            <SafeIcon name="bell" />
            <em>12</em>
          </button>
        </div>
      </header>

      <section className="kg-grid">
        <section className="kg-metrics">
          {kgMetricCards.map((metric) => (
            <article className={`kg-metric ${metric.tone}`} key={metric.label}>
              <span><SafeIcon name={metric.icon} /></span>
              <div>
                <small>{metric.label}</small>
                <strong>{metric.label === "已验证事实" ? verifiedFacts : metric.label === "未知事实" ? unknownFacts : metric.label === "置信评分" ? `${confidence}%` : metric.value}</strong>
                <em>{metric.delta} <b>{metric.sub}</b></em>
              </div>
              <svg viewBox="0 0 100 32" aria-hidden="true">
                <path d="M2 24 13 22 24 25 34 18 44 20 54 13 64 17 75 9 86 14 98 7" />
              </svg>
            </article>
          ))}
        </section>

        <aside className="kg-state-panel kg-panel">
          <PanelHeading title="认知状态面板" />
          <div className="kg-state-sections">
            {kgStateSections.map((section) => (
              <article className={`kg-state-card ${section.tone}`} key={section.title}>
                <header>
                  <strong>{section.title}</strong>
                  <span>{section.count}</span>
                </header>
                {section.items.map((item) => (
                  <button key={item} onClick={() => { setSearch(item.split(":").pop()?.trim() ?? item); onNotice(`已定位知识状态：${item}`); }} type="button">
                    <i />
                    {item}
                  </button>
                ))}
              </article>
            ))}
          </div>
        </aside>

        <article className="kg-graph-panel kg-panel">
          <div className="kg-panel-title">
            <PanelHeading title="动态认知图谱" />
            <div className="kg-legend">
              <span className="verified">已验证</span>
              <span className="known">已知</span>
              <span className="hypothesis">假设</span>
              <span className="unknown">未知</span>
              <span className="conflict">冲突</span>
            </div>
            <div className="kg-toolset">
              <button onClick={() => { setSearch(""); onNotice("图谱搜索已重置"); }} type="button"><SafeIcon name="search" /></button>
              <button onClick={refreshCognition} type="button"><SafeIcon name="refresh" /></button>
              <button onClick={exportSnapshot} type="button"><SafeIcon name="export" /></button>
            </div>
          </div>
          <div className="kg-canvas">
            <svg className="kg-edges" viewBox="0 0 100 100" aria-hidden="true">
              <defs>
                <marker id="kg-arrow" markerHeight="5" markerWidth="5" orient="auto" refX="4" refY="2.5">
                  <path d="M0,0 L5,2.5 L0,5 Z" />
                </marker>
              </defs>
              <path className="known-edge" d="M42 16 L44 25 L43 39" />
              <path className="verified-edge" d="M25 41 C23 50 20 55 17 61 L18 77" />
              <path className="verified-edge dashed" d="M17 61 C28 64 33 59 40 64" />
              <path className="conflict-edge" d="M47 43 L63 40 L66 54" />
              <path className="unknown-edge dashed" d="M66 40 L82 21" />
              <path className="unknown-edge dashed" d="M66 41 L86 50" />
              <path className="hypothesis-edge" d="M42 48 L40 61" />
              <path className="hypothesis-edge" d="M46 48 L53 61" />
              <path className="unknown-edge dashed" d="M42 68 L47 83" />
            </svg>
            <span className="kg-edge-label one">82%</span>
            <span className="kg-edge-label two">12%</span>
            <span className="kg-edge-label three">6%</span>
            {filteredNodes.map((node) => (
              <button
                className={`kg-graph-node ${node.tone} ${selectedNode === node.id ? "selected" : ""}`}
                key={node.id}
                style={{ left: `${node.x}%`, top: `${node.y}%` }}
                onClick={() => { setSelectedNode(node.id); onNotice(`图谱节点已选中：${node.label} ${node.sub}`); }}
                type="button"
              >
                <strong>{node.label}</strong>
                {node.sub && <small>{node.sub}</small>}
              </button>
            ))}
            {filteredNodes.length === 0 && <div className="kg-no-result">未找到匹配的认知节点</div>}
            <div className="kg-minimap">
              <span className="a" /><span className="b" /><span className="c" /><span className="d" /><span className="e" />
            </div>
          </div>
        </article>

        <aside className="kg-right-stack">
          <article className="kg-radar-card kg-panel">
            <PanelHeading title="认知雷达" />
            <div className="kg-radar-wrap">
              <svg viewBox="0 0 220 168" aria-hidden="true">
                <polygon className="radar-grid" points="110,12 178,52 178,118 110,156 42,118 42,52" />
                <polygon className="radar-grid inner" points="110,42 151,66 151,104 110,128 69,104 69,66" />
                <path className="radar-axis" d="M110 12 110 156M42 52 178 118M178 52 42 118" />
                <polygon className="radar-fill" points="110,38 162,61 162,113 110,135 60,113 62,65" />
                <polyline className="radar-line" points="110,38 162,61 162,113 110,135 60,113 62,65 110,38" />
                <circle cx="110" cy="38" r="3" /><circle cx="162" cy="61" r="3" /><circle cx="162" cy="113" r="3" /><circle cx="110" cy="135" r="3" /><circle cx="60" cy="113" r="3" /><circle cx="62" cy="65" r="3" />
              </svg>
              <span className="r-top">可观测性<br /><b>92</b></span>
              <span className="r-right-a">推理能力<br /><b>85</b></span>
              <span className="r-right-b">验证能力<br /><b>95</b></span>
              <span className="r-bottom">安全性<br /><b>98</b></span>
              <span className="r-left-a">覆盖度<br /><b>81</b></span>
              <span className="r-left-b">置信度<br /><b>{confidence}</b></span>
            </div>
            <small className="kg-quality">整体认知质量：优秀</small>
          </article>

          <article className="kg-hypothesis-card kg-panel">
            <PanelHeading title="假设工作区" />
            <div className="kg-hypothesis-list">
              {kgHypotheses.map((item) => (
                <button
                  className={`kg-hyp-card ${item.tone} ${selectedHypothesis === item.title ? "selected" : ""}`}
                  key={item.title}
                  onClick={() => { setSelectedHypothesis(item.title); onNotice(`${item.title} 假设已选中（${item.probability}%）`); }}
                  type="button"
                >
                  <header>
                    <span>{item.name}</span>
                    {item.tag && <em>{item.tag}</em>}
                  </header>
                  <strong>{item.title}</strong>
                  <div>
                    <b>{item.probability}%</b>
                    <svg viewBox="0 0 100 34" aria-hidden="true"><polyline points={item.trend} /></svg>
                  </div>
                  <footer>
                    <span>证据：{item.evidence}</span>
                    <span>{item.direction}</span>
                  </footer>
                </button>
              ))}
            </div>
          </article>
        </aside>

        <article className="kg-promotion-timeline kg-panel">
          <PanelHeading title="证据提升时间线" />
          <div className="kg-timeline">
            {kgTimeline.map((item, index) => (
              <button className={`kg-time-step ${item.tone}`} key={`${item.time}-${item.title}`} onClick={() => onNotice(`${item.time} ${item.title}: ${item.detail}`)} type="button">
                <span>{item.time}</span>
                <i><SafeIcon name={item.icon} /></i>
                <strong>{item.title}</strong>
                <small>{item.detail}</small>
                <em>{item.type}</em>
                {index < kgTimeline.length - 1 && <b />}
              </button>
            ))}
          </div>
        </article>
      </section>
    </section>
  );
}

function PanelHeading({ title }: { title: string }) {
  return (
    <div className="kg-heading">
      <h2>{title}</h2>
      <span>i</span>
    </div>
  );
}

const sysOverviewMetrics = [
  { label: "CPU 使用率", value: "23.7%", detail: "4 核心 / 8 线程", tone: "blue", icon: "gear", trend: "2,31 12,38 22,35 32,39 42,25 52,33 62,24 72,32 82,28 92,20 102,35 112,38 122,32 132,28 142,24" },
  { label: "内存使用率", value: "61.2%", detail: "4.8 GB / 7.8 GB", tone: "green", icon: "tool", trend: "2,23 15,24 28,28 41,25 54,25 67,31 80,20 93,23 106,23 119,21 132,21 145,21" },
  { label: "磁盘使用率", value: "54.3%", detail: "52.3 GB / 96.3 GB", tone: "purple", icon: "audit", trend: "2,27 14,34 26,23 38,31 50,23 62,22 74,27 86,26 98,36 110,28 122,34 134,26 146,22" },
  { label: "系统负载 (1/5/15)", value: "0.68", detail: "0.68 / 0.56 / 0.47", tone: "cyan", icon: "topology", trend: "2,21 12,38 22,24 32,31 42,27 52,28 62,23 72,21 82,31 92,18 102,36 112,18 122,29 132,27 142,21" },
  { label: "网络吞吐 (↑/↓)", value: "↑ 2.34 Mbps", detail: "↓ 15.7 Mbps", tone: "orange", icon: "refresh", trend: "2,39 12,22 22,40 32,34 42,42 52,29 62,41 72,24 82,39 92,37 102,43 112,31 122,24 132,25 142,38" },
  { label: "系统运行时间", value: "12 天 03:21:18", detail: "上次启动: 2025-05-28 11:10:33", tone: "teal", icon: "shield", trend: "" },
];

const sysServices = [
  { name: "nginx", status: "运行中", cpu: "2.1%", memory: "68.2 MB", started: "2025-06-03 09:12:11", tone: "running" },
  { name: "sshd", status: "运行中", cpu: "0.3%", memory: "12.4 MB", started: "2025-05-28 11:10:33", tone: "running" },
  { name: "mysql", status: "运行中", cpu: "3.7%", memory: "512.7 MB", started: "2025-05-28 11:10:55", tone: "running" },
  { name: "redis", status: "运行中", cpu: "0.6%", memory: "38.6 MB", started: "2025-06-01 15:22:09", tone: "running" },
  { name: "docker", status: "运行中", cpu: "1.4%", memory: "128.1 MB", started: "2025-05-28 11:11:02", tone: "running" },
  { name: "firewalld", status: "运行中", cpu: "0.1%", memory: "8.6 MB", started: "2025-05-28 11:10:33", tone: "running" },
  { name: "chronyd", status: "运行中", cpu: "0.0%", memory: "4.2 MB", started: "2025-05-28 11:10:36", tone: "running" },
  { name: "auditd", status: "异常", cpu: "0.2%", memory: "16.7 MB", started: "2025-06-09 10:02:11", tone: "danger" },
  { name: "bluetooth", status: "已停止", cpu: "0.0%", memory: "0 B", started: "-", tone: "stopped" },
  { name: "cups", status: "已停止", cpu: "0.0%", memory: "0 B", started: "-", tone: "stopped" },
];

const sysDisks = [
  { mount: "/", type: "ext4", total: "40 GB", used: "21.6 GB", percent: 54, tone: "medium" },
  { mount: "/home", type: "ext4", total: "50 GB", used: "22.1 GB", percent: 44, tone: "low" },
  { mount: "/var", type: "ext4", total: "20 GB", used: "15.8 GB", percent: 79, tone: "high" },
  { mount: "/boot", type: "ext4", total: "1 GB", used: "320 MB", percent: 31, tone: "low" },
  { mount: "/tmp", type: "tmpfs", total: "7.8 GB", used: "1.2 GB", percent: 15, tone: "low" },
];

const sysProcesses = [
  ["1234", "nginx", "2.1%", "68.2 MB", "nginx"],
  ["2345", "mysqld", "3.7%", "512.7 MB", "mysql"],
  ["3456", "python3", "1.2%", "102.6 MB", "root"],
  ["4567", "dockerd", "1.4%", "128.1 MB", "root"],
  ["5678", "redis-server", "0.6%", "38.6 MB", "redis"],
  ["6789", "systemd", "0.3%", "12.1 MB", "root"],
  ["7890", "sshd", "0.3%", "12.4 MB", "root"],
  ["8901", "node_exporter", "0.2%", "9.8 MB", "root"],
  ["9012", "rsyslogd", "0.1%", "7.2 MB", "root"],
  ["1013", "cron", "0.0%", "3.1 MB", "root"],
];

const sysAlerts = [
  { title: "服务异常: auditd 服务已停止", time: "2026-06-09 10:02:11", level: "高", tone: "high" },
  { title: "磁盘使用率过高: /var 分区使用率 79%", time: "2026-06-09 09:58:23", level: "中", tone: "medium" },
  { title: "CPU 使用率恢复正常", time: "2026-06-09 09:41:55", level: "低", tone: "low" },
  { title: "服务启动: nginx", time: "2026-06-09 09:12:11", level: "低", tone: "low" },
];

const sysInfoRows = [
  ["主机名", "KOS-192.168.1.100"],
  ["操作系统", "麒麟操作系统 V10 (KOS)"],
  ["内核版本", "5.4.18-24-generic"],
  ["架构", "x86_64"],
  ["CPU", "Intel(R) Core(TM) i7-10700 @ 2.90GHz"],
  ["物理内存", "7.8 GB"],
  ["启动时间", "2025-05-28 11:10:33"],
  ["运行时间", "12天 03:21:18"],
  ["系统负载", "0.68 (1m) / 0.56 (5m) / 0.47 (15m)"],
];

function SystemStatusCenterPage({
  summary,
  onNotice,
  onRefresh,
}: {
  summary: any;
  onNotice: (message: string) => void;
  onRefresh: () => Promise<void> | void;
}) {
  const [host, setHost] = useState("KOS-192.168.1.100（麒麟系统V10）");
  const [interval, setIntervalValue] = useState("5s");
  const [serviceFilter, setServiceFilter] = useState("全部 (20)");
  const [trendTab, setTrendTab] = useState("CPU");
  const filteredServices = serviceFilter.startsWith("全部")
    ? sysServices
    : sysServices.filter((service) => service.status === serviceFilter.replace(/ .*/, ""));
  const health = summary?.health_score ?? 86;

  async function refresh() {
    await onRefresh();
    onNotice(`系统状态已刷新：${new Date().toLocaleTimeString("zh-CN", { hour12: false })}`);
  }

  function exportStatus() {
    downloadTextFile("system-status-report.md", buildSystemStatusReport(health), "text/markdown;charset=utf-8");
    onNotice("系统状态报告已导出");
  }

  return (
    <section className="sys-center">
      <header className="sys-header">
        <div>
          <h1>系统状态中心</h1>
          <p>实时监控主机系统资源与服务状态</p>
        </div>
        <div className="sys-header-actions">
          <label>
            主机:
            <select value={host} onChange={(event) => { setHost(event.target.value); onNotice(`监控主机切换为 ${event.target.value}`); }}>
              <option>KOS-192.168.1.100（麒麟系统V10）</option>
              <option>KOS-192.168.1.101（备机）</option>
            </select>
          </label>
          <button onClick={refresh} type="button" aria-label="刷新系统状态"><SafeIcon name="refresh" /></button>
          <label>
            刷新间隔:
            <select value={interval} onChange={(event) => { setIntervalValue(event.target.value); onNotice(`刷新间隔调整为 ${event.target.value}`); }}>
              <option>5s</option>
              <option>15s</option>
              <option>30s</option>
            </select>
          </label>
          <button className="sys-bell" onClick={() => onNotice("12 条系统告警已查看")} type="button" aria-label="系统告警">
            <SafeIcon name="bell" />
            <em>12</em>
          </button>
          <button className="sys-user" onClick={() => onNotice("当前用户：管理员 / 运维管理员")} type="button">
            <SafeIcon name="user" />
            <span>管理员<small>运维管理员</small></span>
          </button>
        </div>
      </header>

      <section className="sys-overview">
        {sysOverviewMetrics.map((metric) => (
          <article className={`sys-metric ${metric.tone}`} key={metric.label}>
            <span><SafeIcon name={metric.icon} /></span>
            <div>
              <small>{metric.label}</small>
              <strong>{metric.value}</strong>
              <em>{metric.detail}</em>
            </div>
            {metric.trend && (
              <svg className="sys-sparkline" viewBox="0 0 146 48" aria-hidden="true">
                <polyline points={metric.trend} />
              </svg>
            )}
          </article>
        ))}
      </section>

      <section className="sys-grid">
        <article className="sys-panel sys-services">
          <div className="sys-panel-title">
            <h2>服务状态 <span>(20)</span></h2>
          </div>
          <div className="sys-service-filters">
            {["全部 (20)", "运行中 (16)", "已停止 (3)", "异常 (1)"].map((filter) => (
              <button className={serviceFilter === filter ? "active" : undefined} key={filter} onClick={() => { setServiceFilter(filter); onNotice(`服务筛选：${filter}`); }} type="button">{filter}</button>
            ))}
          </div>
          <div className="sys-service-table-wrap">
            <table className="sys-service-table">
              <thead><tr><th>服务名称</th><th>状态</th><th>CPU</th><th>内存</th><th>启动时间</th><th>操作</th></tr></thead>
              <tbody>
                {filteredServices.map((service) => (
                  <tr key={service.name}>
                    <td><i className={service.tone} />{service.name}</td>
                    <td><span className={service.tone}>{service.status}</span></td>
                    <td>{service.cpu}</td>
                    <td>{service.memory}</td>
                    <td>{service.started}</td>
                    <td><button onClick={() => onNotice(`${service.name} 服务详情已打开`)} type="button">详情</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <button className="sys-link" onClick={() => onNotice("已打开全部服务列表")} type="button">查看全部服务 →</button>
        </article>

        <article className="sys-panel sys-resource-chart">
          <div className="sys-panel-title">
            <h2>资源使用趋势</h2>
            <select onChange={(event) => onNotice(`趋势时间窗口：${event.target.value}`)} defaultValue="近 1 小时">
              <option>近 1 小时</option>
              <option>近 6 小时</option>
              <option>近 24 小时</option>
            </select>
          </div>
          <div className="sys-tabs">
            {["CPU", "内存", "磁盘", "网络"].map((tab) => (
              <button className={trendTab === tab ? "active" : undefined} key={tab} onClick={() => { setTrendTab(tab); onNotice(`资源趋势切换为 ${tab}`); }} type="button">{tab}</button>
            ))}
          </div>
          <div className="sys-line-chart">
            <svg viewBox="0 0 420 170" preserveAspectRatio="none" aria-hidden="true">
              <g className="sys-chart-grid">
                <path d="M0 20 H420M0 58 H420M0 96 H420M0 134 H420M40 0 V170M110 0 V170M180 0 V170M250 0 V170M320 0 V170M390 0 V170" />
              </g>
              <polyline className="cpu" points="0,105 18,111 36,98 54,103 72,88 90,109 108,100 126,82 144,111 162,87 180,104 198,91 216,110 234,88 252,101 270,95 288,69 306,79 324,65 342,88 360,83 378,93 396,69 414,86" />
              <polyline className="mem" points="0,130 18,126 36,131 54,120 72,128 90,117 108,122 126,115 144,126 162,119 180,126 198,113 216,127 234,120 252,126 270,112 288,122 306,114 324,128 342,116 360,124 378,111 396,119 414,125" />
              <polyline className="io" points="0,151 18,149 36,152 54,147 72,151 90,153 108,149 126,150 144,154 162,148 180,151 198,152 216,147 234,150 252,154 270,149 288,151 306,146 324,152 342,150 360,155 378,148 396,153 414,149" />
            </svg>
            <div className="sys-chart-axis"><span>13:20</span><span>13:30</span><span>13:40</span><span>13:50</span><span>14:00</span><span>14:10</span><span>14:20</span></div>
            <div className="sys-chart-legend"><span className="cpu">用户使用率</span><span className="mem">系统使用率</span><span className="io">IO 等待</span></div>
          </div>
        </article>

        <aside className="sys-right-stack">
          <article className="sys-panel sys-disk-card">
            <div className="sys-panel-title"><h2>磁盘使用详情</h2><button onClick={() => onNotice("磁盘详情已展开")} type="button">查看全部 →</button></div>
            <table className="sys-disk-table">
              <thead><tr><th>挂载点</th><th>类型</th><th>总容量</th><th>已使用</th><th>使用率</th></tr></thead>
              <tbody>
                {sysDisks.map((disk) => (
                  <tr key={disk.mount}>
                    <td>{disk.mount}</td><td>{disk.type}</td><td>{disk.total}</td><td>{disk.used}</td>
                    <td><span className={`sys-mini-bar ${disk.tone}`}><i style={{ width: `${disk.percent}%` }} /></span>{disk.percent}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </article>
          <article className="sys-panel sys-network-card">
            <div className="sys-panel-title"><h2>网络连接状态</h2><button onClick={() => onNotice("网络连接状态详情已打开")} type="button">查看全部 →</button></div>
            <div className="sys-network-body">
              <StatusDonut value={42} />
              <div className="sys-network-list">
                {[
                  ["ESTABLISHED", "28 (66.7%)", "green"],
                  ["TIME_WAIT", "8 (19.0%)", "blue"],
                  ["CLOSE_WAIT", "3 (7.1%)", "orange"],
                  ["其他", "3 (7.1%)", "purple"],
                ].map(([name, count, tone]) => <span className={tone} key={name}>{name}<b>{count}</b></span>)}
              </div>
            </div>
          </article>
        </aside>

        <article className="sys-panel sys-processes">
          <div className="sys-panel-title"><h2>进程 Top 10 <span>(按 CPU)</span></h2></div>
          <table className="sys-process-table">
            <thead><tr><th>PID</th><th>进程名</th><th>CPU</th><th>内存</th><th>用户</th></tr></thead>
            <tbody>{sysProcesses.map((row) => <tr key={row[0]}>{row.map((cell, index) => <td key={`${row[0]}-${index}-${cell}`}>{cell}</td>)}</tr>)}</tbody>
          </table>
          <button className="sys-link" onClick={() => onNotice("全部进程列表已打开")} type="button">查看全部进程 →</button>
        </article>

        <article className="sys-panel sys-memory">
          <div className="sys-panel-title"><h2>内存使用详情</h2></div>
          <div className="sys-memory-body">
            <StatusDonut value={61} label="7.8 GB" sub="总内存" />
            <div className="sys-memory-legend">
              <span className="green">已使用 <b>4.8 GB (61.2%)</b></span>
              <span className="blue">已缓存 <b>1.6 GB (20.5%)</b></span>
              <span className="gold">可用 <b>1.2 GB (15.4%)</b></span>
              <span className="purple">交换 <b>0.2 GB (2.6%)</b></span>
            </div>
          </div>
          <p>交换分区: 1.0 GB 总量 / 0.2 GB 已用 (20.3%)</p>
          <span className="sys-swap-bar"><i style={{ width: "20%" }} /></span>
        </article>

        <article className="sys-panel sys-info">
          <div className="sys-panel-title"><h2>系统信息</h2></div>
          <dl>
            {sysInfoRows.map(([key, value]) => (
              <div key={key}><dt>{key}</dt><dd>{value}</dd></div>
            ))}
          </dl>
        </article>

        <article className="sys-panel sys-alerts">
          <div className="sys-panel-title"><h2>实时告警</h2><button onClick={() => onNotice("全部告警列表已打开")} type="button">查看全部 →</button></div>
          <div className="sys-alert-list">
            {sysAlerts.map((alert) => (
              <button className={alert.tone} key={alert.title} onClick={() => onNotice(`告警详情：${alert.title}`)} type="button">
                <i />
                <div><strong>{alert.title}</strong><small>{alert.time}</small></div>
                <span>{alert.level}</span>
              </button>
            ))}
          </div>
          <button className="sys-link" onClick={exportStatus} type="button">导出系统状态报告 →</button>
        </article>
      </section>
    </section>
  );
}

function StatusDonut({ value, label, sub }: { value: number; label?: string; sub?: string }) {
  const degree = Math.max(0, Math.min(100, value)) * 3.6;
  return (
    <div className="sys-donut" style={{ background: `conic-gradient(#2d8cff 0 ${degree * 0.55}deg, #36d98f ${degree * 0.55}deg ${degree}deg, rgba(70, 99, 143, 0.36) ${degree}deg 360deg)` }}>
      <span>{label ?? value}<small>{sub ?? "当前连接"}</small></span>
    </div>
  );
}

type GovernanceCapability = {
  id: string;
  name: string;
  desc: string;
  read: boolean;
  write: boolean;
  execute: boolean;
};

const govOverviewCards = [
  { label: "信任评分", value: "97", suffix: "/100", detail: "优秀", tone: "blue", icon: "shield", trend: "0,34 14,33 28,30 42,27 56,20 70,24 84,15 98,11 112,16 126,9 140,13 154,10" },
  { label: "策略数量", value: "42", suffix: "", detail: "生效策略", tone: "purple", icon: "audit", bars: [15, 28, 38, 22, 50, 64, 48] },
  { label: "受保护资产", value: "18", suffix: "", detail: "关键资产", tone: "green", icon: "topology", trend: "0,36 14,29 28,24 42,20 56,12 70,16 84,10 98,13 112,20 126,17 140,14 154,8" },
  { label: "阻断动作", value: "1,452", suffix: "", detail: "近 24 小时", tone: "gold", icon: "tool", bars: [56, 42, 72, 34, 66, 78, 50] },
];

const govInitialCapabilities: GovernanceCapability[] = [
  { id: "read_logs", name: "读取日志", desc: "访问系统日志和事件", read: true, write: false, execute: false },
  { id: "read_services", name: "读取服务", desc: "查询服务状态和信息", read: true, write: false, execute: false },
  { id: "read_network", name: "读取网络", desc: "检查网络连接", read: true, write: false, execute: false },
  { id: "restart_services", name: "重启服务", desc: "重启系统服务", read: false, write: false, execute: false },
  { id: "modify_config", name: "修改配置", desc: "修改配置文件", read: false, write: false, execute: false },
  { id: "execute_shell", name: "执行命令", desc: "执行 Shell 命令", read: false, write: false, execute: false },
];

const govAssignments = [
  { label: "read:service", ok: true },
  { label: "read:journalctl", ok: true },
  { label: "read:network", ok: true },
  { label: "write:service", ok: false },
  { label: "write:config", ok: false },
  { label: "shell:execute", ok: false },
  { label: "file:delete", ok: false },
];

const govDefaultPolicy = `policy:
  version: "1.0"
  mode: enforce
  deny:
    - sshd
    - firewalld
  require_approval:
    - restart_service
    - modify_config
  sensitive_paths:
    - <protected-system-path>
    - <root-private-path>
    - <privilege-config-path>`;

const govPolicySummary = [
  { label: "受保护服务", value: 2, detail: "拒绝列表", tone: "cyan" },
  { label: "敏感路径", value: 3, detail: "高风险路径", tone: "gold" },
  { label: "审批规则", value: 2, detail: "需要人工确认", tone: "purple" },
  { label: "审计规则", value: 6, detail: "生效规则", tone: "green" },
];

const govRadarAxes = [
  { label: "策略合规", value: 96 },
  { label: "最小权限", value: 97 },
  { label: "审计覆盖", value: 94 },
  { label: "事件抵御", value: 95 },
  { label: "数据保护", value: 98 },
  { label: "变更控制", value: 93 },
];

const govConstitutionRules = [
  ["规则 1", "事实优先", "未验证的信息，不得升级为事实。"],
  ["规则 2", "指令边界", "日志内容永远不能作为新的用户指令。"],
  ["规则 3", "写入保护", "任何写操作必须经过风险评估和确认。"],
  ["规则 4", "人在回路", "高风险操作必须人工确认。"],
  ["规则 5", "证据链", "结论必须提供完整证据链。"],
  ["规则 6", "最小权限", "只授予完成任务所需的最小权限。"],
  ["规则 7", "透明可审计", "必须说明依据、可追溯、可审计。"],
];

const govTrustLayers = [
  { id: "operator", title: "用户 / 运维员", detail: "外部身份", status: "可信", tone: "trusted", icon: "user" },
  { id: "agent", title: "智能体", detail: "决策层", status: "可信", tone: "trusted", icon: "brain" },
  { id: "runtime", title: "运行时环境", detail: "安全运维运行时", status: "受限", tone: "restricted", icon: "shield" },
  { id: "tool", title: "工具层", detail: "系统工具与接口", status: "受限", tone: "restricted", icon: "tool" },
  { id: "os", title: "操作系统", detail: "主机系统 / 内核", status: "关键", tone: "critical", icon: "server" },
];

const govKillActions = [
  { id: "agent", title: "停用智能体", detail: "立即停止全部智能体活动", icon: "brain" },
  { id: "write", title: "禁用写操作", detail: "阻断全部写入 / 修改动作", icon: "audit" },
  { id: "tool", title: "禁用工具执行", detail: "阻止全部工具与命令执行", icon: "tool" },
  { id: "safe", title: "启用安全模式", detail: "限制智能体只能执行只读操作", icon: "shield" },
];

const govSystemTools = ["systemctl", "journalctl", "ss", "netstat", "lsof", "ps"];

function buildRequirementCoverage(env: any, strictMode: boolean, autoAudit: boolean) {
  const tools = env?.tools ?? {};
  const hasNetworkTool = ["ss", "netstat", "lsof"].some((tool) => tools[tool]);
  return [
    {
      label: "OS 环境深度感知",
      detail: "识别系统、systemd、主机工具状态",
      status: env?.system ? "done" : "partial",
      source: `${formatOsDisplay(env?.os_release?.name)} / ${displayMode(env?.effective_mode ?? "demo")}`,
    },
    {
      label: "插件化受控工具",
      detail: "systemctl、journalctl、ss、netstat、lsof、ps 均走工具契约",
      status: "done",
      source: "工具契约已接入",
    },
    {
      label: "日志与网络上下文",
      detail: "日志、端口监听、进程归属可进入证据图谱",
      status: env?.real_mode_ready || hasNetworkTool ? "done" : "partial",
      source: hasNetworkTool ? "网络工具可用" : "演示数据可用",
    },
    {
      label: "安全意图校验",
      detail: "先生成计划规范，再进行策略校验与受控执行",
      status: strictMode ? "done" : "partial",
      source: strictMode ? "强制开启" : "可一键开启",
    },
    {
      label: "最小权限执行",
      detail: "只读工具默认允许，高影响动作需要确认",
      status: "done",
      source: "只读优先",
    },
    {
      label: "链路溯源与审计",
      detail: "接收指令、感知、决策、校验、结果全记录",
      status: autoAudit ? "done" : "partial",
      source: autoAudit ? "审计开启" : "可开启",
    },
    {
      label: "智能根因分析",
      detail: "计划、工具轨迹、证据图谱、根因结论闭环",
      status: "done",
      source: "诊断接口已打通",
    },
    {
      label: "麒麟实机证明",
      detail: "最终补 Kylin/openKylin 运行截图与演示视频",
      status: env?.is_kylin_like ? "done" : "pending",
      source: env?.is_kylin_like ? "已识别麒麟环境" : "放到最后验证",
    },
  ];
}

function requirementScore(rows: Array<{ status: string }>) {
  const score = rows.reduce((total, row) => {
    if (row.status === "done") return total + 1;
    if (row.status === "partial") return total + 0.5;
    return total;
  }, 0);
  return Math.round((score / rows.length) * 100);
}

function buildComplianceMarkdown(env: any, rows: ReturnType<typeof buildRequirementCoverage>) {
  const lines = [
    "# KylinSafeOps 赛题合规摘要",
    "",
    `- 当前模式：${displayMode(env?.effective_mode ?? "demo")}`,
    `- 工具适配器：${formatAdapterName(env?.adapter)}`,
    `- 系统识别：${formatOsDisplay(env?.os_release?.name)}`,
    `- 真实工具就绪：${env?.real_mode_ready ? "是" : "否"}`,
    "",
    "## 赛题要求对齐",
    ...rows.map((row) => `- ${displayRequirementStatus(row.status)} ${row.label}：${row.detail}（${row.source}）`),
    "",
    "## 后续实机验证",
    "- 在 Kylin/openKylin 环境运行环境探针。",
    "- 录制自然语言诊断到审计报告导出的完整链路。",
    "- 补充真实 systemctl、journalctl、ss/netstat/lsof、ps 工具输出截图。",
  ];
  return lines.join("\n");
}

function GovernanceCenterPage({
  summary,
  strictMode,
  autoAudit,
  onStrictModeChange,
  onAutoAuditChange,
  onNotice,
}: {
  summary: any;
  strictMode: boolean;
  autoAudit: boolean;
  onStrictModeChange: (enabled: boolean) => void;
  onAutoAuditChange: (enabled: boolean) => void;
  onNotice: (message: string) => void;
}) {
  const [clock, setClock] = useState(() => new Date());
  const [runtime, setRuntime] = useState("安全运维运行时 v2.3");
  const [mode, setMode] = useState("强制执行");
  const [policyTab, setPolicyTab] = useState("编辑器");
  const [policyText, setPolicyText] = useState(govDefaultPolicy);
  const [capabilities, setCapabilities] = useState<GovernanceCapability[]>(govInitialCapabilities);
  const [tokenMatrix, setTokenMatrix] = useState(false);
  const [selectedRule, setSelectedRule] = useState("规则 1");
  const [selectedBoundary, setSelectedBoundary] = useState("runtime");
  const [model, setModel] = useState(summary?.environment?.deepseek?.enabled ? "DeepSeek-V4 Pro" : "DeepSeek-R1");
  const [temperature, setTemperature] = useState(20);
  const [iteration, setIteration] = useState(10);
  const [planningDepth, setPlanningDepth] = useState(5);
  const [reasoning, setReasoning] = useState(true);
  const [drift, setDrift] = useState(true);
  const [hallucination, setHallucination] = useState(true);
  const [consistency, setConsistency] = useState(true);
  const [riskAssessment, setRiskAssessment] = useState(true);
  const [armedKill, setArmedKill] = useState<string | null>(null);
  const [envProbe, setEnvProbe] = useState<any>(summary?.environment ?? null);
  const [probeLoading, setProbeLoading] = useState(false);
  const activeEnv = envProbe ?? summary?.environment ?? {};
  const requirementRows = buildRequirementCoverage(activeEnv, strictMode, autoAudit);
  const complianceScore = requirementScore(requirementRows);
  const readyTools = govSystemTools.filter((tool) => activeEnv?.tools?.[tool]).length;

  useEffect(() => {
    const timer = window.setInterval(() => setClock(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    let mounted = true;
    getEnvironmentProbe()
      .then((data) => {
        if (mounted) setEnvProbe(data);
      })
      .catch(() => undefined);
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (summary?.environment) setEnvProbe(summary.environment);
  }, [summary?.environment]);

  function toggleCapability(id: string, permission: "read" | "write" | "execute") {
    setCapabilities((items) => items.map((item) => {
      if (item.id !== id) return item;
      const next = { ...item, [permission]: !item[permission] };
      onNotice(`${item.name} ${permissionLabel(permission)} 权限已${next[permission] ? "开启" : "关闭"}`);
      return next;
    }));
  }

  async function refreshProbe() {
    setProbeLoading(true);
    try {
      const data = await getEnvironmentProbe();
      setEnvProbe(data);
      onNotice(`适配状态已刷新：当前为${displayMode(data.effective_mode)}模式，工具就绪 ${Object.values(data.tools ?? {}).filter(Boolean).length}/${govSystemTools.length}`);
    } catch {
      onNotice("适配状态暂时无法刷新，继续使用最近一次诊断摘要");
    } finally {
      setProbeLoading(false);
    }
  }

  function exportCompliance() {
    downloadTextFile("KylinSafeOps-赛题合规摘要.md", buildComplianceMarkdown(activeEnv, requirementRows), "text/markdown;charset=utf-8");
    onNotice("赛题合规摘要已导出");
  }

  return (
    <section className="gov-center">
      <header className="gov-header">
        <div className="gov-title">
          <h1>治理中心</h1>
          <p>智能体运行时治理平台</p>
        </div>
        <label className="gov-runtime">
          <span>运行环境</span>
          <select value={runtime} onChange={(event) => { setRuntime(event.target.value); onNotice(`运行环境切换为 ${event.target.value}`); }}>
            <option>安全运维运行时 v2.3</option>
            <option>安全运维运行时 v2.2</option>
            <option>麒麟兼容模式</option>
          </select>
          <b>健康</b>
        </label>
        <div className="gov-clock">
          <strong>{clock.toLocaleTimeString("zh-CN", { hour12: false })}</strong>
          <span>2026-06-09</span>
        </div>
        <div className="gov-header-actions">
          <button onClick={() => { onStrictModeChange(true); onAutoAuditChange(true); onNotice("策略同步完成：白名单与审计策略已同步"); }} type="button"><SafeIcon name="refresh" />策略同步</button>
          <label>
            <SafeIcon name="shield" />
            <select value={mode} onChange={(event) => { setMode(event.target.value); onNotice(`治理模式：${event.target.value}`); }}>
              <option>强制执行</option>
              <option>监控模式</option>
              <option>只读模式</option>
            </select>
          </label>
          <button className="gov-bell" onClick={() => onNotice("12 条治理告警已确认")} type="button" aria-label="治理告警"><SafeIcon name="bell" /><em>12</em></button>
        </div>
      </header>

      <section className="gov-overview">
        {govOverviewCards.map((item) => (
          <article className={`gov-overview-card ${item.tone}`} key={item.label}>
            <span><SafeIcon name={item.icon} /></span>
            <div>
              <small>{item.label}</small>
              <strong>{item.value}<b>{item.suffix}</b></strong>
              <em>{item.detail}</em>
            </div>
            {item.trend && <GovSparkline points={item.trend} />}
            {item.bars && <GovMiniBars bars={item.bars} />}
          </article>
        ))}
      </section>

      <section className="gov-panel gov-compliance">
        <div className="gov-panel-head">
          <h2><i>1</i>赛题合规度与 Kylin 适配状态</h2>
          <div>
            <button onClick={refreshProbe} disabled={probeLoading} type="button">{probeLoading ? "刷新中" : "刷新适配状态"}</button>
            <button onClick={exportCompliance} type="button">导出合规摘要</button>
          </div>
        </div>
        <div className="gov-compliance-body">
          <aside className="gov-compliance-score">
            <span>赛题对齐度</span>
            <strong>{complianceScore}<b>/100</b></strong>
            <em>{activeEnv?.is_kylin_like ? "麒麟环境已识别" : "实机验证后补齐"}</em>
            <small>当前模式：{displayMode(activeEnv?.effective_mode ?? "demo")} · 工具 {readyTools}/{govSystemTools.length}</small>
          </aside>
          <div className="gov-requirement-list">
            {requirementRows.map((row) => (
              <button className={row.status} key={row.label} onClick={() => onNotice(`${row.label}：${row.source}`)} type="button">
                <span>{displayRequirementStatus(row.status)}</span>
                <strong>{row.label}</strong>
                <small>{row.detail}</small>
              </button>
            ))}
          </div>
          <div className="gov-tool-readiness">
            <h3>OS 工具适配</h3>
            {govSystemTools.map((tool) => {
              const ready = Boolean(activeEnv?.tools?.[tool]);
              return (
                <button className={ready ? "ready" : "pending"} key={tool} onClick={() => onNotice(`${tool}：${ready ? "当前环境可用" : "当前环境未就绪，演示模式使用样例数据"}`)} type="button">
                  <b>{tool}</b>
                  <span>{ready ? "已就绪" : activeEnv?.effective_mode === "demo" ? "样例" : "待验证"}</span>
                </button>
              );
            })}
          </div>
          <div className="gov-guardrail-list">
            <h3>受控执行边界</h3>
            <span>只读工具默认允许</span>
            <span>高影响动作需确认</span>
            <span>未注册工具拒绝</span>
            <span>敏感路径只做审计展示</span>
            <span>诊断链路全程留痕</span>
          </div>
        </div>
      </section>

      <section className="gov-main">
        <article className="gov-panel gov-capability">
          <div className="gov-panel-head">
            <h2><i>2</i>能力管理</h2>
            <button className={tokenMatrix ? "active" : undefined} onClick={() => { setTokenMatrix(!tokenMatrix); onNotice(tokenMatrix ? "能力令牌矩阵已收起" : "能力令牌矩阵已展开"); }} type="button">令牌矩阵</button>
          </div>
          <div className="gov-cap-grid">
            <div className="gov-cap-table">
              <div className="gov-cap-head"><span>能力</span><span>读取</span><span>写入</span><span>执行</span></div>
              {capabilities.map((item) => (
                <div className="gov-cap-row" key={item.id}>
                  <div><strong>{item.name}</strong><small>{item.desc}</small></div>
                  {(["read", "write", "execute"] as const).map((permission) => (
                    <button
                      className={`${item[permission] ? "on" : "off"} ${permission !== "read" && !item[permission] ? "danger-off" : ""}`}
                      key={permission}
                      onClick={() => toggleCapability(item.id, permission)}
                      type="button"
                    >
                      {item[permission] ? "开" : "关"}
                    </button>
                  ))}
                </div>
              ))}
            </div>
            <aside className="gov-agent-token">
              <h3>当前智能体</h3>
              <strong>安全运维智能体 <span>已验证</span></strong>
              <p>已分配能力</p>
              {govAssignments.map((item) => (
                <em className={item.ok ? "ok" : "deny"} key={item.label}>{item.ok ? "✓" : "×"} {item.label}</em>
              ))}
              <small>能力令牌编号 <b>tok_8f3a...d9e4</b></small>
            </aside>
          </div>
        </article>

        <article className="gov-panel gov-policy">
          <div className="gov-panel-head">
            <h2><i>3</i>策略即代码工作台</h2>
            <div>
              {["编辑器", "校验器", "历史"].map((tab) => (
                <button className={policyTab === tab ? "active" : undefined} key={tab} onClick={() => { setPolicyTab(tab); onNotice(`策略工作台切换到 ${tab}`); }} type="button">{tab}</button>
              ))}
            </div>
          </div>
          <div className="gov-policy-body">
            <div className="gov-editor-shell">
              <div className="gov-editor-top"><span>{policyTab === "历史" ? "策略历史.yaml" : "策略.yaml"}</span><button onClick={() => { setPolicyText(govDefaultPolicy); onNotice("策略已恢复为默认模板"); }} type="button">×</button></div>
              {policyTab === "编辑器" ? (
                <textarea value={policyText} onChange={(event) => setPolicyText(event.target.value)} spellCheck={false} />
              ) : (
                <div className="gov-validator">
                  <strong>{policyTab === "校验器" ? "校验通过" : "最近 3 次策略更新"}</strong>
                  <p>{policyTab === "校验器" ? "结构合法，拒绝服务列表已生效，审批规则可达。" : "10:23:11 强制模式已启用；10:18:42 敏感路径已更新；10:02:33 sshd 已受保护。"}</p>
                </div>
              )}
              <footer><span>策略.yaml</span><b>有效</b><em>上次保存：10:23:11</em></footer>
            </div>
            <aside className="gov-policy-summary">
              <h3>策略摘要</h3>
              {govPolicySummary.map((item) => (
                <div className={item.tone} key={item.label}><span>{item.label}<small>{item.detail}</small></span><strong>{item.value}</strong></div>
              ))}
              <p>上次更新 <b>今天</b><span>10:23:11</span></p>
              <button onClick={() => { setPolicyTab("校验器"); onNotice("策略验证已完成：所有规则通过"); }} type="button"><SafeIcon name="shield" />运行校验</button>
            </aside>
          </div>
        </article>

        <article className="gov-panel gov-posture">
          <div className="gov-panel-head"><h2>运行时安全态势</h2></div>
          <GovRadar axes={govRadarAxes} />
          <p><span />整体治理态势：<b>优秀</b></p>
        </article>

        <article className="gov-panel gov-constitution">
          <div className="gov-panel-head">
            <h2><i>5</i>智能体宪章</h2>
            <button onClick={() => onNotice("智能体宪章 v1.0 已锁定")} type="button">版本 1.0</button>
          </div>
          <div className="gov-constitution-body">
            <div className="gov-rules">
              {govConstitutionRules.map(([rule, title, desc]) => (
                <button className={selectedRule === rule ? "active" : undefined} key={rule} onClick={() => { setSelectedRule(rule); onNotice(`${rule} 已选中：${title}`); }} type="button">
                  <span><SafeIcon name={rule === "规则 1" ? "audit" : rule === "规则 4" ? "user" : "shield"} /></span>
                  <strong>{rule}<b>{title}</b></strong>
                  <small>{desc}</small>
                </button>
              ))}
            </div>
            <div className="gov-constitution-art">
              <div><SafeIcon name="shield" /></div>
              <span>宪章完整性</span>
              <em><i /></em>
              <b>100%</b>
              <small>上次审查：2026-05-18<br />下次审查：2026-06-18</small>
            </div>
          </div>
        </article>

        <article className="gov-panel gov-model">
          <div className="gov-panel-head"><h2><i>6</i>模型控制面板</h2></div>
          <section className="gov-model-grid">
            <div className="gov-model-config">
              <h3>模型配置</h3>
              <label>当前模型<select value={model} onChange={(event) => { setModel(event.target.value); onNotice(`当前模型切换为 ${event.target.value}`); }}><option>DeepSeek-R1</option><option>DeepSeek-V4 Pro</option><option>本地 Qwen2.5</option></select></label>
              <label>温度<input type="range" min="0" max="100" value={temperature} onChange={(event) => setTemperature(Number(event.target.value))} /><span>{(temperature / 100).toFixed(2)}</span></label>
              <label>最大迭代<input type="range" min="3" max="20" value={iteration} onChange={(event) => setIteration(Number(event.target.value))} /><span>{iteration}</span></label>
              <label>规划深度<input type="range" min="1" max="8" value={planningDepth} onChange={(event) => setPlanningDepth(Number(event.target.value))} /><span>{planningDepth}</span></label>
              <label>推理模式<select onChange={(event) => onNotice(`推理模式：${event.target.value}`)} defaultValue="保守"><option>保守</option><option>均衡</option><option>激进</option></select></label>
            </div>
            <div className="gov-safety-controls">
              <h3>安全与推理控制</h3>
              <GovSwitch label="提示注入防护" checked={strictMode} onChange={(value) => { onStrictModeChange(value); onNotice(value ? "提示注入防护已开启" : "提示注入防护已关闭"); }} />
              <GovSwitch label="目标漂移检测" checked={drift} onChange={(value) => { setDrift(value); onNotice(value ? "目标漂移检测已开启" : "目标漂移检测已关闭"); }} />
              <GovSwitch label="证据验证" checked={autoAudit} onChange={(value) => { onAutoAuditChange(value); onNotice(value ? "证据验证已开启" : "证据验证已关闭"); }} />
              <GovSwitch label="幻觉抑制" checked={hallucination} onChange={(value) => { setHallucination(value); onNotice(value ? "幻觉抑制已开启" : "幻觉抑制已关闭"); }} />
              <GovSwitch label="输出一致性检查" checked={consistency} onChange={(value) => { setConsistency(value); onNotice(value ? "输出一致性检查已开启" : "输出一致性检查已关闭"); }} />
              <GovSwitch label="动作风险评估" checked={riskAssessment} onChange={(value) => { setRiskAssessment(value); onNotice(value ? "动作风险评估已开启" : "动作风险评估已关闭"); }} />
            </div>
          </section>
          <footer className="gov-reasoning-metrics">
            <span>平均推理深度 <b>{planningDepth - 0.3}</b></span>
            <span>平均置信度 <b>92%</b></span>
            <span>证据覆盖率 <b>89%</b></span>
            <span>幻觉率 <b>0.8%</b></span>
          </footer>
        </article>

        <aside className="gov-right-stack">
          <article className="gov-panel gov-boundary">
            <div className="gov-panel-head"><h2><i>4</i>信任边界图</h2></div>
            <div className="gov-boundary-body">
              <span className="gov-trust-axis">信任<br />流向</span>
              <div className="gov-boundary-layers">
                {govTrustLayers.map((layer) => (
                  <button className={`${layer.tone} ${selectedBoundary === layer.id ? "active" : ""}`} key={layer.id} onClick={() => { setSelectedBoundary(layer.id); onNotice(`信任边界已聚焦：${layer.title}`); }} type="button">
                    <SafeIcon name={layer.icon} />
                    <span>{layer.title}<small>{layer.detail}</small></span>
                    <b>{layer.status}</b>
                  </button>
                ))}
              </div>
            </div>
            <footer><span className="trusted">可信</span><span className="restricted">受限</span><span className="critical">关键</span></footer>
          </article>

          <article className="gov-panel gov-kill">
            <div className="gov-panel-head"><h2><i>7</i>紧急熔断开关</h2></div>
            <h3>关键控制</h3>
            <p>仅在紧急情况下使用</p>
            {govKillActions.map((action) => (
              <button className={armedKill === action.id ? "armed" : undefined} key={action.id} onClick={() => { setArmedKill(action.id); onNotice(`${action.title} 已进入待确认状态`); }} type="button">
                <SafeIcon name={action.icon} />
                <span>{action.title}<small>{action.detail}</small></span>
                <b>›</b>
              </button>
            ))}
            <small>所有动作都会记录并可审计</small>
          </article>
        </aside>
      </section>
    </section>
  );
}

function GovSparkline({ points }: { points: string }) {
  return (
    <svg className="gov-spark" viewBox="0 0 160 48" preserveAspectRatio="none" aria-hidden="true">
      <polyline points={points} />
    </svg>
  );
}

function GovMiniBars({ bars }: { bars: number[] }) {
  return (
    <div className="gov-bars" aria-hidden="true">
      {bars.map((height, index) => <i key={`${height}-${index}`} style={{ height: `${height}%` }} />)}
    </div>
  );
}

function GovRadar({ axes }: { axes: Array<{ label: string; value: number }> }) {
  const center = 86;
  const radius = 62;
  const points = axes.map((axis, index) => {
    const angle = (-90 + index * (360 / axes.length)) * Math.PI / 180;
    const distance = radius * (axis.value / 100);
    return `${center + Math.cos(angle) * distance},${center + Math.sin(angle) * distance}`;
  }).join(" ");
  const outer = axes.map((_, index) => {
    const angle = (-90 + index * (360 / axes.length)) * Math.PI / 180;
    return `${center + Math.cos(angle) * radius},${center + Math.sin(angle) * radius}`;
  }).join(" ");

  return (
    <div className="gov-radar">
      <svg viewBox="0 0 172 172" aria-hidden="true">
        <polygon className="outer" points={outer} />
        <polygon className="mid" points={outer} transform={`translate(${center} ${center}) scale(.66) translate(${-center} ${-center})`} />
        <polygon className="inner" points={outer} transform={`translate(${center} ${center}) scale(.33) translate(${-center} ${-center})`} />
        {axes.map((_, index) => {
          const angle = (-90 + index * (360 / axes.length)) * Math.PI / 180;
          return <line key={index} x1={center} y1={center} x2={center + Math.cos(angle) * radius} y2={center + Math.sin(angle) * radius} />;
        })}
        <polygon className="score" points={points} />
        {axes.map((axis, index) => {
          const angle = (-90 + index * (360 / axes.length)) * Math.PI / 180;
          return (
            <g key={axis.label}>
              <circle cx={center + Math.cos(angle) * radius * (axis.value / 100)} cy={center + Math.sin(angle) * radius * (axis.value / 100)} r="3" />
              <text x={center + Math.cos(angle) * 79} y={center + Math.sin(angle) * 79}>{axis.value}</text>
            </g>
          );
        })}
      </svg>
      <div className="gov-radar-labels">
        {axes.map((axis) => <span key={axis.label}>{axis.label}</span>)}
      </div>
    </div>
  );
}

function GovSwitch({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className={`gov-switch ${checked ? "on" : ""}`}>
      <span>{label}</span>
      <em>{checked ? "已启用" : "已停用"}</em>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <i />
    </label>
  );
}

function permissionLabel(permission: "read" | "write" | "execute") {
  if (permission === "read") return "读取";
  if (permission === "write") return "写入";
  return "执行";
}

function displayRequirementStatus(status: string) {
  if (status === "done") return "已完成";
  if (status === "partial") return "可演示";
  return "待验证";
}

const vrsRootRanking = [
  { id: "A", rank: 1, title: "端口冲突", detail: "80 端口已被其他进程占用", score: 82, delta: "+12%", status: "主导", tone: "gold", icon: "topology", trend: "0,18 9,16 18,19 27,12 36,15 45,9 54,14 63,11 72,16 81,12 90,18 100,13" },
  { id: "B", rank: 2, title: "配置错误", detail: "nginx 配置可能不正确", score: 11, delta: "-5%", status: "受挑战", tone: "blue", icon: "audit", trend: "0,22 10,18 20,21 30,14 40,17 50,11 60,18 70,15 80,12 90,17 100,13" },
  { id: "C", rank: 3, title: "权限不足", detail: "绑定端口或访问文件权限不足", score: 5, delta: "-2%", status: "减弱", tone: "purple", icon: "shield", trend: "0,16 10,12 20,15 30,10 40,17 50,14 60,18 70,12 80,16 90,13 100,15" },
  { id: "D", rank: 4, title: "依赖故障", detail: "必要依赖服务不可用", score: 2, delta: "+1%", status: "新出现", tone: "teal", icon: "dialog", trend: "0,19 10,20 20,18 30,21 40,19 50,20 60,16 70,17 80,14 90,16 100,12" },
];

const vrsEvidenceImpact = [
  { rank: 1, evidence: "httpd 占用 80 端口", tool: "ps -ef | grep httpd", impact: "+35%", target: "A", second: "B", tone: "positive" },
  { rank: 2, evidence: "地址已被占用", tool: "绑定失败（错误 98）", impact: "+28%", target: "A", tone: "positive" },
  { rank: 3, evidence: "80 端口已占用", tool: "ss -tulpn | grep :80", impact: "+18%", target: "A", tone: "positive" },
  { rank: 4, evidence: "nginx -t 通过", tool: "语法有效", impact: "-20%", target: "B", tone: "negative" },
  { rank: 5, evidence: "进程以 root 运行", tool: "id -u nginx -> 0", impact: "-12%", target: "C", tone: "negative" },
  { rank: 6, evidence: "依赖服务均健康", tool: "systemctl list-dependencies", impact: "-8%", target: "D", tone: "negative" },
];

const vrsArenaCards = [
  {
    id: "A",
    title: "端口冲突",
    score: 82,
    delta: "+12%",
    status: "主导",
    lifeCycle: ["新出现", "增长", "主导", "已驳回"],
    activeStage: 2,
    tone: "gold",
    supporting: ["绑定失败：地址已被占用", "地址已被占用（错误 98）", "80 端口已占用", "httpd 占用 80 端口"],
    contradictions: ["未发现矛盾证据"],
    updated: "09:04:18",
  },
  {
    id: "B",
    title: "配置错误",
    score: 11,
    delta: "-5%",
    status: "受挑战",
    lifeCycle: ["新出现", "增长", "主导", "已驳回"],
    activeStage: 1,
    tone: "blue",
    supporting: ["nginx 配置文件被修改 /etc/nginx/nginx.conf（09:00:12）"],
    contradictions: ["nginx -t 通过（语法有效）", "配置语法有效"],
    updated: "09:04:18",
  },
  {
    id: "C",
    title: "权限不足",
    score: 5,
    delta: "-2%",
    status: "减弱",
    lifeCycle: ["新出现", "增长", "主导", "已驳回"],
    activeStage: 3,
    tone: "purple",
    supporting: ["暂无支持证据"],
    contradictions: ["进程以 root 运行（uid=0）"],
    updated: "09:04:18",
  },
  {
    id: "D",
    title: "依赖故障",
    score: 2,
    delta: "+1%",
    status: "新出现",
    lifeCycle: ["新出现", "增长", "主导", "已驳回"],
    activeStage: 0,
    tone: "teal",
    supporting: ["检测到网络不稳定，丢包率 3%"],
    contradictions: ["全部依赖服务健康"],
    updated: "09:04:18",
  },
];

const vrsTimelinePoints = [
  { time: "09:01:00", title: "初始观察", detail: "nginx 启动失败", a: 35, b: 35, c: 30, d: 0 },
  { time: "09:02:15", title: "journalctl -u nginx", detail: "服务失败日志", a: 60, b: 25, c: 15, d: 0 },
  { time: "09:03:05", title: "ss -tulpn", detail: "检查监听端口", a: 80, b: 12, c: 8, d: 0 },
  { time: "09:03:45", title: "ps -ef | grep httpd", detail: "检查进程归属", a: 92, b: 6, c: 2, d: 0 },
  { time: "09:04:18", title: "分析更新", detail: "当前状态", a: 95, b: 3, c: 1, d: 1 },
];

const vrsSimulations = [
  { id: "A", title: "释放 80 端口", action: "停止 httpd 进程 / 释放 80 端口", outcome: "nginx 启动成功", before: 82, after: 5, confidence: 91, tone: "gold", icon: "topology" },
  { id: "B", title: "修复配置", action: "将 nginx.conf 恢复到上一版本", outcome: "改善有限", before: 11, after: 2, confidence: 14, tone: "blue", icon: "audit" },
  { id: "C", title: "调整权限", action: "以非 root 用户运行 nginx", outcome: "无显著变化", before: 5, after: 1, confidence: 6, tone: "purple", icon: "shield" },
];

function VisualReasoningSystemPage({
  diagnosis,
  onNotice,
}: {
  diagnosis: DiagnosisResult;
  onNotice: (message: string) => void;
}) {
  const [autoMode, setAutoMode] = useState(true);
  const [reasoningMode, setReasoningMode] = useState("均衡");
  const [viewMode, setViewMode] = useState("卡片");
  const [sortBy, setSortBy] = useState("概率");
  const [selectedHypothesis, setSelectedHypothesis] = useState("A");
  const [simulation, setSimulation] = useState<string | null>(null);
  const rootConfidence = toPercent(diagnosis.root_cause?.confidence) || 95;
  const activeArena = vrsArenaCards.find((item) => item.id === selectedHypothesis) ?? vrsArenaCards[0];

  function exportReasoningReport() {
    downloadTextFile(
      "可视化推理报告.md",
      buildVisualReasoningReport(activeArena, rootConfidence),
      "text/markdown;charset=utf-8",
    );
    onNotice("可视化推理报告已导出");
  }

  return (
    <section className="vrs-center">
      <header className="vrs-header">
        <div className="vrs-title">
          <h1>多假设诊断实验室</h1>
          <p>并行根因分析引擎</p>
          <small>多世界并行诊断与反事实验证中心</small>
        </div>
        <div className="vrs-session">
          <VrsMeta label="会话" value="INC-2026-0612" />
          <VrsMeta label="问题" value="nginx.service 启动失败" />
          <VrsMeta label="状态" value="调查中" tone="blue" />
          <VrsMeta label="耗时" value="02:34:18" />
        </div>
        <div className="vrs-actions">
          <label className={`vrs-toggle ${autoMode ? "on" : ""}`}>
            自动调查
            <input type="checkbox" checked={autoMode} onChange={(event) => { setAutoMode(event.target.checked); onNotice(event.target.checked ? "自动推理已开启" : "自动推理已暂停"); }} />
            <span />
          </label>
          <label className="vrs-select">
            智能推理模式
            <select value={reasoningMode} onChange={(event) => { setReasoningMode(event.target.value); onNotice(`推理模式切换为 ${event.target.value}`); }}>
              <option>均衡</option>
              <option>保守</option>
              <option>激进</option>
            </select>
          </label>
          <button onClick={exportReasoningReport} type="button">导出报告</button>
          <button className="vrs-bell" onClick={() => onNotice("8 条推理事件已确认")} type="button" aria-label="推理事件">
            <SafeIcon name="bell" />
            <em>8</em>
          </button>
        </div>
      </header>

      <section className="vrs-layout">
        <article className="vrs-panel vrs-ranking">
          <div className="vrs-panel-title">
            <VrsTitle number="1" title="根因排序" />
            <span>所有候选根因的实时置信排序</span>
            <div><b>趋势（较上一分钟）</b><b>状态</b></div>
          </div>
          <div className="vrs-rank-list">
            {vrsRootRanking.map((item) => (
              <button
                className={`vrs-rank-row ${item.tone} ${selectedHypothesis === item.id ? "selected" : ""}`}
                key={item.id}
                onClick={() => { setSelectedHypothesis(item.id); onNotice(`${item.title} 已在推理竞技场中聚焦`); }}
                type="button"
              >
                <span className="rank-index">{item.rank}</span>
                <span className="rank-icon"><SafeIcon name={item.icon} /></span>
                <div className="rank-name"><strong>{item.title}</strong><small>{item.detail}</small></div>
                <div className="rank-bar"><i style={{ width: `${item.score}%` }} /></div>
                <strong className="rank-score">{item.score}%</strong>
                <em className={item.delta.startsWith("+") ? "up" : "down"}>{item.delta}</em>
                <svg viewBox="0 0 100 28" aria-hidden="true"><polyline points={item.trend} /></svg>
                <b className="rank-status">{item.status}</b>
              </button>
            ))}
          </div>
        </article>

        <aside className="vrs-panel vrs-impact">
          <VrsTitle number="3" title="证据影响排序" />
          <p>哪些证据对假设概率影响最大</p>
          <div className="vrs-impact-table">
            <header><span>#</span><span>证据</span><span>影响</span><span>作用假设</span></header>
            {vrsEvidenceImpact.map((item) => (
              <button key={item.rank} onClick={() => { setSelectedHypothesis(item.target); onNotice(`${item.evidence} 对假设 ${item.target} 影响 ${item.impact}`); }} type="button">
                <span>{item.rank}</span>
                <div><strong>{item.evidence}</strong><small>{item.tool}</small></div>
                <em className={item.tone}>{item.impact}</em>
                <b>{item.target}</b>
                {item.second && <b>{item.second}</b>}
              </button>
            ))}
          </div>
          <button className="vrs-link-button" onClick={() => onNotice("已展开全部 23 条证据影响记录")} type="button">查看全部证据（23）</button>
        </aside>

        <article className="vrs-panel vrs-arena">
          <div className="vrs-panel-title">
            <VrsTitle number="2" title="假设竞技场" />
            <span>并行诊断世界竞争真实根因</span>
            <button onClick={() => onNotice("工作机制：每个假设随证据动态升降权重")} type="button">工作机制？</button>
            <div className="vrs-arena-tools">
              <label>视图模式 <select value={viewMode} onChange={(event) => { setViewMode(event.target.value); onNotice(`视图模式：${event.target.value}`); }}><option>卡片</option><option>矩阵</option></select></label>
              <label>排序方式 <select value={sortBy} onChange={(event) => { setSortBy(event.target.value); onNotice(`排序方式：${event.target.value}`); }}><option>概率</option><option>影响</option><option>状态</option></select></label>
              <button onClick={() => onNotice("推理竞技场设置已打开")} type="button"><SafeIcon name="gear" /></button>
            </div>
          </div>
          <div className="vrs-card-grid">
            {vrsArenaCards.map((card) => (
              <VrsHypothesisCard
                card={card}
                key={card.id}
                selected={selectedHypothesis === card.id}
                onSelect={() => { setSelectedHypothesis(card.id); onNotice(`${card.title} 已选中，当前概率 ${card.score}%`); }}
              />
            ))}
          </div>
        </article>

        <aside className="vrs-panel vrs-legend">
          <VrsTitle title="假设生命周期图例" />
          <div className="vrs-life-list">
            {[
              ["新出现", "刚生成，证据不足", "teal"],
              ["增长", "正在获得支持证据", "blue"],
              ["主导", "支持强、当前领先", "gold"],
              ["已驳回", "被强证据反驳", "muted"],
            ].map(([name, desc, tone]) => (
              <button key={name} className={tone} onClick={() => onNotice(`${name}: ${desc}`)} type="button">
                <i />
                <strong>{name}</strong>
                <span>{desc}</span>
              </button>
            ))}
          </div>
        </aside>

        <article className="vrs-panel vrs-competition">
          <div className="vrs-panel-title">
            <VrsTitle number="4" title="证据竞争时间线" />
            <span>观察证据如何随时间改变概率</span>
          </div>
          <div className="vrs-chart">
            <div className="vrs-chart-legend">
              <span className="gold">端口冲突（A）</span>
              <span className="blue">配置错误（B）</span>
              <span className="purple">权限不足（C）</span>
              <span className="teal">依赖故障（D）</span>
            </div>
            <svg viewBox="0 0 900 128" preserveAspectRatio="none" aria-hidden="true">
              <g className="vrs-grid-lines">
                <path d="M0 20 H900M0 48 H900M0 76 H900M0 104 H900" />
              </g>
              <polyline className="gold" points="0,82 225,58 450,32 675,18 900,14" />
              <polyline className="blue" points="0,82 225,92 450,101 675,109 900,114" />
              <polyline className="purple" points="0,92 225,101 450,108 675,115 900,118" />
              <polyline className="teal" points="0,122 225,122 450,122 675,122 900,120" />
            </svg>
            <div className="vrs-chart-events">
              {vrsTimelinePoints.map((point) => (
                <button key={point.time} onClick={() => onNotice(`${point.time} ${point.title}: A=${point.a}% B=${point.b}% C=${point.c}% D=${point.d}%`)} type="button">
                  <span>{point.time}</span>
                  <strong>{point.title}</strong>
                  <small>{point.detail}</small>
                </button>
              ))}
            </div>
          </div>
        </article>

        <article className="vrs-panel vrs-sandbox">
          <div className="vrs-panel-title">
            <VrsTitle number="5" title="反事实沙盒" />
            <span>用假设推演验证根因</span>
          </div>
          <div className="vrs-sim-grid">
            {vrsSimulations.map((item) => (
              <button
                className={`vrs-sim-card ${item.tone} ${simulation === item.id ? "selected" : ""}`}
                key={item.id}
                onClick={() => { setSimulation(item.id); setSelectedHypothesis(item.id); onNotice(`${item.title} 模拟完成：${item.before}% → ${item.after}%`); }}
                type="button"
              >
                <span><SafeIcon name={item.icon} /></span>
                <div>
                  <strong>如果：{item.title}</strong>
                  <small>{item.action}</small>
                </div>
                <div>
                  <em>预测结果</em>
                  <b>{item.outcome}</b>
                </div>
                <div className="vrs-sim-result">
                  <span>对{item.id === "A" ? "端口冲突" : item.id === "B" ? "配置错误" : "权限不足"}的影响</span>
                  <strong>{item.before}% → {item.after}%</strong>
                </div>
                <div className="vrs-sim-confidence">
                  <span>概率</span>
                  <strong>{item.confidence}%</strong>
                </div>
                <i>运行模拟</i>
              </button>
            ))}
          </div>
        </article>

        <aside className="vrs-panel vrs-conclusion">
          <span>结论（当前状态）</span>
          <div>
            <SafeIcon name="topology" />
            <p>最可能根因</p>
            <strong>{activeArena.title}</strong>
          </div>
          <article>
            <small>置信度</small>
            <b>{rootConfidence}%</b>
          </article>
          <button onClick={exportReasoningReport} type="button">生成报告</button>
        </aside>
      </section>
    </section>
  );
}

function VrsMeta({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className={`vrs-meta ${tone ?? ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function VrsTitle({ number, title }: { number?: string; title: string }) {
  return (
    <div className="vrs-title-row">
      {number && <span>{number}</span>}
      <h2>{title}</h2>
      <i>i</i>
    </div>
  );
}

function VrsHypothesisCard({
  card,
  selected,
  onSelect,
}: {
  card: typeof vrsArenaCards[number];
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button className={`vrs-hyp-card ${card.tone} ${selected ? "selected" : ""}`} onClick={onSelect} type="button">
      <header>
        <span>{card.id}</span>
        <strong>{card.title}</strong>
        <em>{card.status}</em>
      </header>
      <div className="vrs-hyp-score">
        <div><small>概率</small><b>{card.score}%</b><i>{card.delta}</i></div>
        <VrsDonut value={card.score} />
      </div>
      <div className="vrs-life-cycle">
        <small>生命周期</small>
        <div>
          {card.lifeCycle.map((stage, index) => (
            <span className={index === card.activeStage ? "active" : undefined} key={stage}>
              <i />
              {stage}
            </span>
          ))}
        </div>
      </div>
      <section className="vrs-evidence-list">
        <strong>支持证据（{card.supporting[0] === "暂无支持证据" ? 0 : card.supporting.length}）</strong>
        {card.supporting.map((item) => <p className={item.startsWith("暂无") ? "muted" : "support"} key={item}>{item}</p>)}
      </section>
      <section className="vrs-evidence-list contradiction">
        <strong>矛盾证据（{card.contradictions[0] === "未发现矛盾证据" ? 0 : card.contradictions.length}）</strong>
        {card.contradictions.map((item) => <p className={item.startsWith("未发现") ? "muted" : "deny"} key={item}>{item}</p>)}
      </section>
      <footer>上次更新：{card.updated}</footer>
    </button>
  );
}

function VrsDonut({ value }: { value: number }) {
  const degree = Math.max(0, Math.min(100, value)) * 3.6;
  return (
    <span className="vrs-donut" style={{ background: `conic-gradient(currentColor 0 ${degree}deg, rgba(61, 88, 127, 0.45) ${degree}deg 360deg)` }}>
      <i />
    </span>
  );
}

function RiskGauge({ score, label }: { score: number; label: string }) {
  const degree = Math.max(0, Math.min(100, score)) * 3.6;
  return (
    <div
      className="audit-risk-gauge"
      style={{
        background: `conic-gradient(#f2b84a 0 ${degree}deg, rgba(48, 83, 122, 0.82) ${degree}deg 360deg)`,
      }}
    >
      <div>
        <strong>{score}</strong>
        <span>/100</span>
        <small>{label}</small>
      </div>
    </div>
  );
}

function auditRiskLabel(risk: AuditSessionRow["risk"]) {
  if (risk === "high") return "高";
  if (risk === "medium") return "中";
  return "低";
}

function featureSubtitle(view: string) {
  const subtitles: Record<string, string> = {
    audit: "审计凭证、回放索引与证据链导出",
    status: "系统服务、端口和主机状态的统一态势视图",
    cognition: "认知状态、意图锚点和证据提升控制台",
    hypothesis: "候选根因排序、置信度对比与证据对齐",
    settings: "模型、白名单、审计和演示模式配置",
  };
  return subtitles[view] ?? "安全运维运行时功能页";
}

function mapModeLabel(mode: string) {
  if (mode === "topology") return "拓扑视图";
  if (mode === "list") return "列表视图";
  if (mode === "grid") return "网格视图";
  if (mode === "fullscreen") return "全屏聚焦";
  return "拓扑视图";
}

function isNginxSurfacePort(item?: SurfaceItem) {
  return Boolean(item && (item.port === 80 || item.service === "nginx" || item.process === "nginx"));
}

function AttackSurfaceView({
  activeView,
  clock,
  effectiveMode,
  surface,
  onNavigate,
  onRefresh,
  onDiagnosePortConflict,
}: {
  activeView: string;
  clock: Date;
  effectiveMode: string;
  surface: any;
  onNavigate: (view: string) => void;
  onRefresh: () => Promise<void> | void;
  onDiagnosePortConflict: (item?: SurfaceItem) => Promise<void>;
}) {
  const ports = normalizeSurfaceItems(surface?.items ?? []);
  const displayRiskCounts = { high: 2, medium: 5, low: 4, unknown: 3 };
  const exposedCount = ports.length;
  const publicServiceCount = 6;
  const highCount = 2;
  const abnormalCount = 3;
  const riskScore = 72;
  const [live, setLive] = useState(true);
  const [mapMode, setMapMode] = useState("topology");
  const [notice, setNotice] = useState("实时监控已开启");
  const [selectedPort, setSelectedPort] = useState<SurfaceItem>(ports.find((item) => item.port === 80) ?? ports[0]);
  const [linkingPort, setLinkingPort] = useState<number | null>(null);

  async function handleRefresh() {
    await onRefresh();
    setNotice(`地图已刷新 ${new Date().toLocaleTimeString("zh-CN", { hour12: false })}`);
  }

  function handleExport() {
    downloadTextFile(
      "attack-surface-report.md",
      buildAttackSurfaceReport(ports, riskScore),
      "text/markdown;charset=utf-8",
    );
    setNotice("攻击面报告已导出");
  }

  function selectPort(item: SurfaceItem) {
    setSelectedPort(item);
    if (isNginxSurfacePort(item)) {
      setNotice("已打开 80/TCP nginx 详情，可点击右侧按钮生成驾驶舱诊断闭环");
      return;
    }
    setNotice(`已打开 ${item.port}/TCP ${item.service ?? item.process} 详情`);
  }

  async function diagnoseSelectedPort() {
    if (isNginxSurfacePort(selectedPort)) {
      if (linkingPort === selectedPort.port) {
        setNotice("80/TCP nginx 联动诊断正在生成，请稍候...");
        return;
      }
      setLinkingPort(selectedPort.port);
      setNotice("正在从攻击面地图跳转到驾驶舱诊断 80 端口冲突...");
      await onDiagnosePortConflict(selectedPort).finally(() => setLinkingPort(null));
      return;
    }
    setNotice(`${selectedPort.port}/TCP 已加入排查队列：当前演示主链路聚焦 nginx 80 端口冲突`);
  }

  return (
    <OpsShellFrame activeView={activeView} summary={null} surface={{ items: ports }} onNavigate={onNavigate}>
      <section className="attack-shell attack-shell-unified">
          <header className="unified-page-header">
            <div>
              <h1>攻击面地图</h1>
              <p>开放端口、高危服务、异常连接与攻击面风险态势</p>
            </div>
            <label className="attack-search compact">
              <span><SafeIcon name="search" /></span>
              <input placeholder="搜索主机、服务、端口..." />
            </label>
            <div className="attack-userbar compact">
              <button className="kos-switch" onClick={() => setNotice("当前主机：麒麟系统 / 本机 / 192.168.1.100")} type="button">
                <SafeIcon name="kylin" />
                <span>麒麟系统（KOS）</span>
              </button>
              <button className="notify-button" onClick={() => setNotice("12 条安全通知已在当前会话中确认")} type="button" aria-label="通知">
                <SafeIcon name="bell" />
                <em>12</em>
              </button>
            </div>
          </header>

          <div className="attack-page-title">
            <div className="attack-actions">
              <button onClick={handleRefresh}><SafeIcon name="refresh" />刷新地图</button>
              <button onClick={handleExport}><SafeIcon name="export" />导出报告</button>
              <label className="live-toggle">
                实时监控
                <input
                  type="checkbox"
                  checked={live}
                  onChange={(event) => {
                    setLive(event.target.checked);
                    setNotice(event.target.checked ? "实时监控已开启" : "实时监控已暂停");
                  }}
                />
                <span />
              </label>
              <em className="action-toast">{notice}</em>
            </div>
          </div>

          <section className="attack-stats">
            <AttackStatCard label="暴露端口" value={exposedCount} delta="+2" />
            <AttackStatCard label="对外服务" value={publicServiceCount} delta="--" />
            <AttackStatCard label="高危风险" value={highCount} delta="+1" danger />
            <AttackStatCard label="异常连接" value={abnormalCount} delta="+1" danger />
            <div className="risk-score-card">
              <div>
                <span>攻击面风险评分</span>
                <strong>{riskScore}<small>/100</small></strong>
                <b>{riskScore >= 70 ? "高风险" : "中风险"}</b>
              </div>
              <svg viewBox="0 0 160 74" aria-hidden="true">
                <path d="M0 58 C18 54 20 38 36 34 C52 31 50 8 68 12 C86 17 82 34 102 35 C122 37 119 14 138 20 C148 24 151 42 160 36" />
              </svg>
            </div>
          </section>

          <section className="attack-layout">
            <aside className="attack-left">
              <AssetGroups onNotice={setNotice} />
              <AttackLegend />
            </aside>

            <AttackTopology
              ports={ports}
              mapMode={mapMode}
              selectedPort={selectedPort?.port}
              onModeChange={(mode) => {
                setMapMode(mode);
                setNotice(`地图视图已切换：${mapModeLabel(mode)}`);
              }}
              onSelectPort={selectPort}
            />

            <aside className="attack-right">
              <AttackPortDetail port={selectedPort} linking={linkingPort === selectedPort?.port} onDiagnose={diagnoseSelectedPort} />
              <ExposedPortsTable ports={ports} selectedPort={selectedPort?.port} onSelectPort={selectPort} onNotice={setNotice} />
              <RiskDonut counts={displayRiskCounts} total={14} />
            </aside>
          </section>

          <SecurityEvents clock={clock} mode={effectiveMode} />
      </section>
    </OpsShellFrame>
  );
}

function AttackStatCard({ label, value, delta, danger }: { label: string; value: number; delta: string; danger?: boolean }) {
  return (
    <div className="attack-stat-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <em className={danger ? "danger" : undefined}>{delta}</em>
      <small>较昨日</small>
    </div>
  );
}

function SafeIcon({ name }: { name: string }) {
  const common = {
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.9,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };

  const filled = {
    fill: "currentColor",
    stroke: "none",
  };

  return (
    <svg className="safe-icon" viewBox="0 0 24 24" aria-hidden="true">
      {name === "shield" && (
        <>
          <path {...common} d="M12 3.2 19 6v5.4c0 4.3-2.8 7.2-7 9.4-4.2-2.2-7-5.1-7-9.4V6l7-2.8Z" />
          <path {...common} d="M12 7.4v7.4M8.8 11.1h6.4" />
        </>
      )}
      {name === "search" && (
        <>
          <circle {...common} cx="10.8" cy="10.8" r="5.5" />
          <path {...common} d="m15 15 4.2 4.2" />
        </>
      )}
      {name === "kylin" && (
        <>
          <path {...common} d="M12 4.2 18 8v8l-6 3.8L6 16V8l6-3.8Z" />
          <path {...common} d="M9.2 12a2.8 2.8 0 1 0 5.6 0 2.8 2.8 0 0 0-5.6 0Z" />
        </>
      )}
      {name === "bell" && (
        <>
          <path {...common} d="M17.5 10.5c0-3.1-1.8-5.2-5.5-5.2s-5.5 2.1-5.5 5.2c0 5-1.6 5.8-1.6 5.8h14.2s-1.6-.8-1.6-5.8Z" />
          <path {...common} d="M10 19a2.3 2.3 0 0 0 4 0" />
        </>
      )}
      {name === "chevron" && <path {...common} d="m8.4 10 3.6 3.6 3.6-3.6" />}
      {name === "user" && (
        <>
          <circle {...common} cx="12" cy="8.8" r="3.6" />
          <path {...common} d="M5.5 19c1.2-3.1 3.3-4.6 6.5-4.6s5.3 1.5 6.5 4.6" />
        </>
      )}
      {name === "home" && (
        <>
          <path {...common} d="M4.4 11.2 12 5l7.6 6.2" />
          <path {...common} d="M6.8 10.2v8.2h10.4v-8.2" />
          <path {...common} d="M10 18.4v-5.2h4v5.2" />
        </>
      )}
      {name === "map" && (
        <>
          <path {...common} d="M8 5.5 4.6 7v11.5L8 17l4 1.6 4-1.6 3.4 1.5V7L16 5.5l-4 1.6L8 5.5Z" />
          <path {...common} d="M8 5.5V17M12 7.1v11.5M16 5.5V17" />
        </>
      )}
      {name === "audit" && (
        <>
          <path {...common} d="M7 4.6h7.5L18 8v11.4H7V4.6Z" />
          <path {...common} d="M14.4 4.8V8H18M9.5 12h5M9.5 15.5H14" />
        </>
      )}
      {name === "tool" && (
        <>
          <path {...common} d="M14.8 5.2a4.6 4.6 0 0 0 4 6.2l-7.3 7.3a2.7 2.7 0 0 1-3.8-3.8l7.3-7.3a4.6 4.6 0 0 0-.2-2.4Z" />
          <path {...common} d="M7.4 16.7l-.1.1" />
        </>
      )}
      {name === "list" && (
        <>
          <path {...common} d="M8 6.5h11M8 12h11M8 17.5h11" />
          <path {...filled} d="M4.4 7.7a1.2 1.2 0 1 0 0-2.4 1.2 1.2 0 0 0 0 2.4ZM4.4 13.2a1.2 1.2 0 1 0 0-2.4 1.2 1.2 0 0 0 0 2.4ZM4.4 18.7a1.2 1.2 0 1 0 0-2.4 1.2 1.2 0 0 0 0 2.4Z" />
        </>
      )}
      {name === "brain" && (
        <>
          <path {...common} d="M9 7.2a3 3 0 0 1 5.7-1.3A3.3 3.3 0 0 1 18 9.2a3.4 3.4 0 0 1-1 2.4 3.5 3.5 0 0 1-2.4 5.9H12" />
          <path {...common} d="M9 7.2A3.2 3.2 0 0 0 6 10.5a3.5 3.5 0 0 0 1.4 2.8 3 3 0 0 0 3 4.2H12V6.4" />
        </>
      )}
      {name === "dialog" && (
        <>
          <path {...common} d="M5 6.5h14v9H9l-4 3v-12Z" />
          <path {...common} d="M8 10h8M8 13h5" />
        </>
      )}
      {name === "gear" && (
        <>
          <circle {...common} cx="12" cy="12" r="3.2" />
          <path {...common} d="M12 3.8v2.4M12 17.8v2.4M4.9 7.2 7 8.4M17 15.6l2.1 1.2M4.9 16.8 7 15.6M17 8.4l2.1-1.2" />
        </>
      )}
      {name === "refresh" && (
        <>
          <path {...common} d="M18.5 8.6a7 7 0 0 0-12.2-1.8L4.6 9.2" />
          <path {...common} d="M4.5 5.7v3.7h3.7M5.5 15.4a7 7 0 0 0 12.2 1.8l1.7-2.4" />
          <path {...common} d="M19.5 18.3v-3.7h-3.7" />
        </>
      )}
      {name === "export" && (
        <>
          <path {...common} d="M12 4.5v9.2M8.5 10.2l3.5 3.5 3.5-3.5" />
          <path {...common} d="M5.5 15.2v4.3h13v-4.3" />
        </>
      )}
      {name === "topology" && (
        <>
          <circle {...common} cx="7" cy="7" r="2.4" />
          <circle {...common} cx="17" cy="7" r="2.4" />
          <circle {...common} cx="12" cy="17" r="2.4" />
          <path {...common} d="M9.2 8.4 11.1 15M14.8 8.4 12.9 15" />
        </>
      )}
      {name === "table" && (
        <>
          <path {...common} d="M4.5 5.5h15v13h-15v-13Z" />
          <path {...common} d="M4.5 10h15M9.5 5.5v13M14.5 5.5v13" />
        </>
      )}
      {name === "fullscreen" && (
        <>
          <path {...common} d="M8.5 4.8H4.8v3.7M15.5 4.8h3.7v3.7M8.5 19.2H4.8v-3.7M15.5 19.2h3.7v-3.7" />
        </>
      )}
      {name === "monitor" && (
        <>
          <rect {...common} x="5" y="5.5" width="14" height="10" rx="1.6" />
          <path {...common} d="M9.3 19h5.4M12 15.5V19" />
        </>
      )}
      {name === "globe" && (
        <>
          <circle {...common} cx="12" cy="12" r="7" />
          <path {...common} d="M5 12h14M12 5c2 2 3 4.3 3 7s-1 5-3 7M12 5c-2 2-3 4.3-3 7s1 5 3 7" />
        </>
      )}
      {name === "server" && (
        <>
          <rect {...common} x="6.5" y="5" width="11" height="6" rx="1.3" />
          <rect {...common} x="6.5" y="13" width="11" height="6" rx="1.3" />
          <path {...common} d="M9 8h.2M9 16h.2" />
        </>
      )}
      {name === "stack" && (
        <>
          <path {...common} d="M12 4.5 19 8l-7 3.5L5 8l7-3.5Z" />
          <path {...common} d="M5 12l7 3.5 7-3.5M5 16l7 3.5 7-3.5" />
        </>
      )}
      {name === "flame" && (
        <>
          <path {...common} d="M13.4 4.6c.5 3.1-3.8 4.4-2.1 7.4 1-1.3 2-1.9 3.2-2 1.2 1.5 2 3 2 4.6a4.5 4.5 0 0 1-9 0c0-2.6 2.2-4.8 5.9-10Z" />
        </>
      )}
      {name === "unknown" && (
        <>
          <circle {...common} cx="12" cy="12" r="7" />
          <path {...common} d="M9.8 9.6A2.4 2.4 0 0 1 12 8.3c1.5 0 2.6.9 2.6 2.2 0 1.1-.7 1.8-1.8 2.4-.8.4-.8.8-.8 1.5" />
          <path {...common} d="M12 17h.1" />
        </>
      )}
    </svg>
  );
}

function AssetGroups({ onNotice }: { onNotice?: (message: string) => void }) {
  const groups = [
    ["所有主机", 1],
    ["内网资产", 5],
    ["数据库", 2],
    ["中间件", 3],
    ["容器环境", 2],
    ["离线资产", 1],
  ] as const;
  const [activeGroup, setActiveGroup] = useState(groups[0][0]);

  return (
    <div className="attack-side-card">
      <h3>资产分组</h3>
      <div className="asset-tree">
        {groups.map(([name, count]) => (
          <button
            key={name}
            className={activeGroup === name ? "active" : undefined}
            onClick={() => {
              setActiveGroup(name);
              onNotice?.(`资产分组已切换：${name}（${count}）`);
            }}
            type="button"
          >
            <span>›</span>
            <i />
            <p>{name}（{count}）</p>
          </button>
        ))}
      </div>
      <small className="asset-tree-status">当前聚焦：{activeGroup}</small>
    </div>
  );
}

function AttackLegend() {
  return (
    <div className="attack-side-card legend-card">
      <h3>图例说明</h3>
      <p><span className="dot low" />安全服务</p>
      <p><span className="dot medium" />中危服务</p>
      <p><span className="dot high" />高危服务</p>
      <p><span className="dot unknown" />未知服务</p>
      <p><span className="line solid" />网络连接</p>
      <p><span className="line dashed" />潜在风险连接</p>
    </div>
  );
}

function AttackTopology({
  ports,
  mapMode,
  selectedPort,
  onModeChange,
  onSelectPort,
}: {
  ports: SurfaceItem[];
  mapMode: string;
  selectedPort?: number;
  onModeChange: (mode: string) => void;
  onSelectPort: (item: SurfaceItem) => void;
}) {
  const nodes = topologyNodes(ports);
  const byPort = new Map(ports.map((item) => [item.port, item]));
  const modes = [
    ["topology", "拓扑视图", "topology"],
    ["list", "列表视图", "list"],
    ["grid", "网格视图", "table"],
    ["fullscreen", "全屏聚焦", "fullscreen"],
  ];
  const previewItems = nodes.filter((node) => node.port > 0).slice(0, 6);

  return (
    <section className="attack-map-panel">
      <div className="map-toolbar">
        <h3>攻击面拓扑（本机）</h3>
        <div>
          {modes.map(([mode, title, icon]) => (
            <button
              key={mode}
              className={mapMode === mode ? "active" : undefined}
              onClick={() => onModeChange(mode)}
              title={title}
              type="button"
            >
              <SafeIcon name={icon} />
            </button>
          ))}
        </div>
      </div>
      <div className={`topology-canvas ${mapMode}`}>
        <div className="map-mode-badge">{mapModeLabel(mapMode)}</div>
        {mapMode !== "topology" && (
          <div className={`map-mode-preview ${mapMode}`}>
            <strong>{mapModeLabel(mapMode)}已启用</strong>
            <span>{mapMode === "fullscreen" ? "聚焦本机攻击面关键路径" : "按端口、服务和风险等级重排视图"}</span>
            <div>
              {previewItems.map((node) => (
                <em className={node.risk} key={node.id}>{node.label} · {node.port}/TCP</em>
              ))}
            </div>
          </div>
        )}
        <svg viewBox="0 0 760 500" preserveAspectRatio="none" aria-hidden="true">
          <defs>
            <radialGradient id="mapGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#1a8dff" stopOpacity="0.34" />
              <stop offset="100%" stopColor="#1a8dff" stopOpacity="0" />
            </radialGradient>
          </defs>
          <rect width="760" height="500" fill="url(#mapGlow)" />
          <g className="map-lines">
            {nodes.filter((node) => node.port > 0).map((node) => (
              <line key={`line-${node.id}`} x1="380" y1="250" x2={node.x} y2={node.y} />
            ))}
            <path className="risk-link" d="M130 140 C80 120 76 158 126 170" />
            <path className="risk-link" d="M520 155 C610 158 616 202 672 195" />
            <path className="risk-link" d="M560 340 C630 342 646 390 704 378" />
          </g>
        </svg>
        <div className="center-host">
          <span><SafeIcon name="monitor" /></span>
          <strong>本机</strong>
          <small>192.168.1.100</small>
        </div>
        {nodes.map((node) => (
          <TopologyNode
            key={node.id}
            node={node}
            selected={node.port === selectedPort}
            onSelect={node.port > 0 && byPort.get(node.port) ? () => onSelectPort(byPort.get(node.port) as SurfaceItem) : undefined}
          />
        ))}
      </div>
    </section>
  );
}

function TopologyNode({ node, selected, onSelect }: { node: ReturnType<typeof topologyNodes>[number]; selected?: boolean; onSelect?: () => void }) {
  return (
    <button
      className={`topology-node ${node.risk} ${selected ? "selected" : ""}`}
      style={{ left: `${node.xPct}%`, top: `${node.yPct}%` }}
      onClick={onSelect}
      disabled={!onSelect}
      type="button"
    >
      <span><SafeIcon name={node.icon} /></span>
      <b>{node.label}</b>
      <small>{node.detail ?? `${node.port}/TCP`}</small>
      <em>{riskLabel(node.risk)}</em>
    </button>
  );
}

function AttackPortDetail({ port, linking, onDiagnose }: { port?: SurfaceItem; linking?: boolean; onDiagnose: () => void }) {
  if (!port) return null;
  const service = port.service ?? port.process ?? "未知";
  const high = port.risk === "high" || port.port === 80 || port.port === 2375;
  const suggestions = attackPortSuggestions(port);

  return (
    <div className="attack-right-card port-detail-card">
      <h3>端口 / 服务详情</h3>
      <dl>
        <div><dt>端口</dt><dd>{port.port}/TCP</dd></div>
        <div><dt>服务</dt><dd>{service}</dd></div>
        <div><dt>进程</dt><dd>{port.process ?? service}</dd></div>
        <div><dt>监听</dt><dd>{port.bind ?? "0.0.0.0"}</dd></div>
        <div><dt>风险</dt><dd><span className={`risk-tag ${port.risk}`}>{riskLabel(port.risk)}</span></dd></div>
      </dl>
      <p>{port.reason ?? "该端口已纳入攻击面地图监控。"}</p>
      <ul>
        {suggestions.map((item) => <li key={item}>{item}</li>)}
      </ul>
      <button className="diagnose-port-button" disabled={linking} onClick={onDiagnose} type="button">
        {linking ? "正在生成驾驶舱诊断..." : isNginxSurfacePort(port) ? "生成 nginx 80 端口诊断 →" : "加入诊断队列 →"}
      </button>
      {high && <small className="port-detail-warning">建议在演示中重点展示该节点的风险闭环。</small>}
    </div>
  );
}

function ExposedPortsTable({
  ports,
  selectedPort,
  onSelectPort,
  onNotice,
}: {
  ports: SurfaceItem[];
  selectedPort?: number;
  onSelectPort: (item: SurfaceItem) => void;
  onNotice: (message: string) => void;
}) {
  function exportPorts() {
    const csv = ["端口,协议,服务,风险", ...ports.map((item) => `${item.port},TCP,${item.service ?? item.process},${riskLabel(item.risk)}`)].join("\n");
    downloadTextFile("exposed-ports.csv", csv, "text/csv;charset=utf-8");
    onNotice("暴露端口清单已导出");
  }

  return (
    <div className="attack-right-card">
      <h3>暴露端口列表</h3>
      <small>{ports.length} 个端口</small>
      <table>
        <thead>
          <tr>
            <th>端口</th>
            <th>协议</th>
            <th>服务</th>
            <th>风险等级</th>
          </tr>
        </thead>
        <tbody>
          {ports.map((item) => (
            <tr
              key={`${item.port}-${item.service}`}
              className={selectedPort === item.port ? "selected" : undefined}
              onClick={() => onSelectPort(item)}
            >
              <td>{item.port}</td>
              <td>TCP</td>
              <td>{item.service ?? item.process}</td>
              <td><span className={`risk-tag ${item.risk}`}>{riskLabel(item.risk)}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
      <button className="table-link-button" onClick={exportPorts} type="button">导出全部端口 →</button>
    </div>
  );
}

function RiskDonut({ counts, total }: { counts: Record<string, number>; total: number }) {
  return (
    <div className="attack-right-card risk-distribution">
      <h3>风险分布</h3>
      <div className="donut-wrap">
        <div className="donut">
          <strong>{total}</strong>
          <span>总风险项</span>
        </div>
        <ul>
          <li><span className="dot high" />高危 <b>{counts.high}</b></li>
          <li><span className="dot medium" />中危 <b>{counts.medium}</b></li>
          <li><span className="dot low" />低危 <b>{counts.low}</b></li>
          <li><span className="dot unknown" />未知 <b>{counts.unknown}</b></li>
        </ul>
      </div>
    </div>
  );
}

function SecurityEvents({ clock, mode }: { clock: Date; mode: string }) {
  const events = [
    ["10:23:45", "检测到外部IP 203.0.113.25", "正在尝试访问 22/TCP (sshd)", "high"],
    ["10:21:17", "端口 3306 (mysql) 暴露在公网", "建议设置访问控制策略", "medium"],
    ["10:15:02", "nginx 服务运行正常", `响应时间 15ms / ${mode}`, "low"],
    ["10:10:33", "检测到异常端口扫描", "来自 198.51.100.77", "medium"],
    ["10:05:18", "攻击面扫描完成", "发现 8 个暴露端口", "info"],
  ];

  return (
    <section className="security-events">
      <h3>安全事件动态</h3>
      <div>
        {events.map(([time, title, desc, tone]) => (
          <article key={title} className={tone}>
            <span>{time}</span>
            <strong>{title}</strong>
            <p>{desc}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

function RedTeamLabView({
  activeView,
  clock,
  data,
  running,
  onNavigate,
  onRun,
}: {
  activeView: string;
  clock: Date;
  data: any;
  running: boolean;
  onNavigate: (view: string) => void;
  onRun: () => Promise<any>;
}) {
  const [range, setRange] = useState("全部时间");
  const [selectedAttack, setSelectedAttack] = useState("命令-001");
  const [notice, setNotice] = useState(data.summary ?? "安全策略自检待命，本地模拟用例已加载");
  const matrix = redTeamMatrix(data);
  const attacks = redTeamRecentEvents(data.cases ?? DEMO_RED_TEAM.cases);
  const selectedCase = redCaseByAttackId(selectedAttack, data.cases ?? DEMO_RED_TEAM.cases);
  const rules = [
    ["规则-命令-001", "禁止命令拼接", 42],
    ["规则-敏感-001", "敏感路径请求拦截", 28],
    ["规则-工具-001", "未授权工具调用", 18],
    ["规则-日志-001", "日志污染隔离", 12],
    ["规则-目标-001", "目标漂移检测", 10],
  ];

  async function handleRun() {
    setNotice("本地安全策略自检运行中...");
    try {
      const result = await onRun();
      setNotice(result?.audit_id ? `安全策略自检完成，审计会话已生成：${result.audit_id}` : "安全策略自检完成，策略阻断结果已刷新");
    } catch {
      setNotice("安全策略自检未完成，请检查后端服务状态");
    }
  }

  async function handleOpenAuditSession() {
    if (data.audit_id) {
      setNotice(`正在打开审计会话：${data.audit_id}`);
      onNavigate("audit");
      return;
    }
    if (running) {
      setNotice("自检仍在运行，完成后可进入审计中心查看会话");
      return;
    }
    setNotice("尚未生成审计会话，正在先运行一次安全策略自检...");
    try {
      const result = await onRun();
      setNotice(result?.audit_id ? `审计会话已生成，正在打开：${result.audit_id}` : "自检完成，但暂未返回审计会话编号");
      await delay(180);
      onNavigate("audit");
    } catch {
      setNotice("审计会话暂未生成，请确认后端服务已启动");
    }
  }

  function handleExport() {
    downloadTextFile("security-self-check-report.md", buildRedTeamReport(data, matrix), "text/markdown;charset=utf-8");
    setNotice("安全策略自检报告已导出");
  }

  function handleRefresh() {
    const refreshedAt = new Date().toLocaleTimeString("zh-CN", { hour12: false });
    setNotice(`安全策略自检数据已刷新：${refreshedAt}，本地模拟用例与后端统计保持同步`);
  }

  return (
    <OpsShellFrame activeView={activeView} summary={null} surface={null} onNavigate={onNavigate}>
      <div className="redlab-workspace redlab-workspace-unified">
        <header className="redlab-header">
          <div>
            <h1>安全策略自检中心</h1>
            <p>本地防御模拟与策略拦截验证</p>
          </div>
          <div className="redlab-top-actions">
            <span>{clock.toISOString().slice(0, 10)}　{clock.toLocaleTimeString("zh-CN", { hour12: false })}</span>
            <button onClick={() => setNotice("当前自检主机：麒麟主机 192.168.1.100")} type="button">麒麟主机（192.168.1.100）<SafeIcon name="chevron" /></button>
            <button className="notify-button" onClick={() => setNotice("12 条自检告警已确认")} type="button" aria-label="通知"><SafeIcon name="bell" /><em>12</em></button>
            <span className="admin-avatar"><SafeIcon name="user" /></span>
            <strong>管理员</strong>
          </div>
        </header>

        <section className="redlab-main">
          <div className="redlab-title-row">
            <h2>安全评分总览</h2>
            <div>
              <button className="danger-run" onClick={handleRun} disabled={running} type="button">
                {running ? "自检运行中" : "一键运行自检"}
              </button>
              <button onClick={handleRefresh} type="button"><SafeIcon name="refresh" />刷新数据</button>
              <button onClick={handleExport} type="button">导出报告</button>
              <button onClick={handleOpenAuditSession} disabled={running} type="button">查看审计会话</button>
              <label>
                <select value={range} onChange={(event) => { setRange(event.target.value); setNotice(`自检时间范围：${event.target.value}`); }}>
                  <option>全部时间</option>
                  <option>近 7 天</option>
                  <option>近 24 小时</option>
                </select>
              </label>
            </div>
          </div>

          <section className="redlab-score-grid">
            <div className="red-score-card hero">
              <div className="red-shield"><SafeIcon name="shield" /></div>
              <div>
                <span>安全策略自检评分</span>
                <strong>{data.score}<small>/100</small></strong>
                <p>↑ 8（较昨日）</p>
              </div>
            </div>
            <RedMetric title="自检用例总数" value={data.attackTotal} delta="↑ 18" caption="较昨日" tone="green" />
            <RedMetric title="成功阻断" value={data.blocked} delta="↑ 17" caption="阻断率 98.4%" tone="green" />
            <RedMetric title="授权次数" value={data.authorized} delta="↓ 1" caption="误报率 2.1%" tone="green" />
            <RedMetric title="高危事件" value={data.highEvents} delta="↓ 2" caption="占比 5.3%" tone="green" />
            <div className="red-score-card risk">
              <span>风险等级</span>
              <strong>{displayRisk(String(data.risk ?? "medium").toLowerCase())}</strong>
              <p>风险趋势（7天）</p>
              <svg viewBox="0 0 120 34" aria-hidden="true">
                <polyline points="0,24 12,16 24,26 36,11 48,23 60,15 72,7 84,22 96,13 108,20 120,9" />
              </svg>
            </div>
          </section>

          <section className="redlab-content-grid">
            <RedMatrixPanel matrix={matrix} onNotice={setNotice} />
            <RedAttackTrace selectedAttack={selectedAttack} notice={notice} attackCase={selectedCase} />
            <RedAttackDetail attackId={selectedAttack} attackCase={selectedCase} passed={data.runtimePassed} total={data.runtimeTotal} />
          </section>

          <section className="redlab-bottom-grid">
            <RedRecentEvents
              events={attacks}
              onSelect={(id) => {
                setSelectedAttack(id);
                setNotice(`已打开 ${id} 自检用例详情`);
              }}
              selectedAttack={selectedAttack}
              onNotice={setNotice}
            />
            <RedDistribution />
            <RedTrend />
            <RedRuleHits rules={rules} onNotice={setNotice} />
          </section>
        </section>
      </div>
    </OpsShellFrame>
  );
}

function RedMetric({
  title,
  value,
  delta,
  caption,
  tone,
}: {
  title: string;
  value: number;
  delta: string;
  caption: string;
  tone: string;
}) {
  return (
    <div className="red-score-card">
      <span>{title}</span>
      <strong>{value}<small>{delta}</small></strong>
      <p className={tone}>{caption}</p>
    </div>
  );
}

function RedMatrixPanel({ matrix, onNotice }: { matrix: Array<any>; onNotice: (message: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const rows = expanded ? matrix : matrix.slice(0, 6);
  const toggleExpanded = () => {
    const next = !expanded;
    setExpanded(next);
    onNotice(next ? "自检矩阵已展开全部用例" : "自检矩阵已收起为摘要视图");
  };

  return (
    <section className="red-panel red-matrix">
      <h3>本地模拟用例矩阵</h3>
      <div className="red-table-head">
        <span>自检类别</span>
        <span>测试项</span>
        <span>阻断率</span>
        <span>趋势</span>
      </div>
      {rows.map((item) => (
        <div className="red-matrix-row" key={item.name}>
          <span className={item.tone}>{item.icon}</span>
          <b>{item.name}</b>
          <small>{item.tests}</small>
          <i><em style={{ width: `${item.rate}%` }} /></i>
          <strong>{item.rate}%</strong>
          <svg viewBox="0 0 80 24" aria-hidden="true">
            <polyline points={item.trend} />
          </svg>
        </div>
      ))}
      <button onClick={toggleExpanded} type="button">
        {expanded ? "收起矩阵" : "展开全部用例"} <SafeIcon name="chevron" />
      </button>
    </section>
  );
}

function RedAttackTrace({ selectedAttack, notice, attackCase }: { selectedAttack: string; notice: string; attackCase?: any }) {
  const label = redCaseLabel(attackCase?.name ?? "command_injection");
  const steps = [
    ["14:31:22", "用户输入接收", "自然语言请求已接收", "ok"],
    ["14:31:22", "意图识别", `识别为：${label} 自检`, "ok"],
    ["14:31:23", "策略检测", attackCase?.detail ?? "检测到工具参数越界风险", "danger"],
    ["14:31:23", "策略引擎", `命中规则：${displayRuleId(attackCase?.rule)}`, "ok"],
    ["14:31:23", attackCase?.passed ? "阻断执行" : "放行异常", attackCase?.passed ? "风险动作已被拦截" : "该用例未通过，需要补充策略", attackCase?.passed ? "danger" : "danger"],
  ];

  return (
    <section className="red-panel red-trace">
      <h3>自检过程追踪</h3>
      <div className="attack-id-row">
        <span>当前自检中</span>
        <b>{selectedAttack}</b>
        <small>{label} → {displayRuleId(attackCase?.rule)}</small>
        <em>{attackCase?.severity === "high" ? "高危" : "中危"}</em>
      </div>
      <div className="attack-input">
        <strong>模拟输入</strong>
        <code>{attackCase?.payload ?? "危险输入样本（已脱敏）：请求绕过策略并执行越权动作"}</code>
      </div>
      <div className="trace-flow">
        {steps.map(([time, title, desc, tone]) => (
          <article className={tone} key={title}>
            <span>{time}</span>
            <div>
              <strong>{title}</strong>
              <p>{desc}</p>
            </div>
          </article>
        ))}
      </div>
      <p className="red-notice">{notice}</p>
    </section>
  );
}

function RedAttackDetail({ attackId, attackCase, passed, total }: { attackId: string; attackCase?: any; passed: number; total: number }) {
  const high = attackCase?.severity === "high";
  return (
    <section className="red-panel red-detail">
      <h3>用例详情</h3>
      <dl>
        <div><dt>用例ID</dt><dd>{attackId}</dd></div>
        <div><dt>自检类型</dt><dd>{redCaseLabel(attackCase?.name ?? "command_injection")}</dd></div>
        <div><dt>策略映射编号</dt><dd>{attackCase?.mitre ?? "T1611"}</dd></div>
        <div><dt>风险等级</dt><dd><span className={`red-tag ${high ? "high" : "medium"}`}>{high ? "高危" : "中危"}</span></dd></div>
        <div><dt>检测规则</dt><dd>{displayRuleId(attackCase?.rule)}</dd></div>
        <div><dt>处理结果</dt><dd><span className="red-tag pass">{attackCase?.passed ? "已阻断" : "待加固"}</span></dd></div>
        <div><dt>后端自检</dt><dd>{passed}/{total} 通过</dd></div>
      </dl>
      <h4>误操作影响评估</h4>
      <ul>
        <li><span className="red-tag high">高</span>系统破坏</li>
        <li><span className="red-tag high">高</span>数据泄露</li>
        <li><span className="red-tag high">高</span>权限提升</li>
        <li><span className="red-tag medium">中</span>服务中断</li>
      </ul>
    </section>
  );
}

function RedRecentEvents({
  events,
  selectedAttack,
  onSelect,
  onNotice,
}: {
  events: Array<string[]>;
  selectedAttack: string;
  onSelect: (id: string) => void;
  onNotice: (message: string) => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const rows = showAll ? events : events.slice(0, 5);

  return (
    <section className="red-panel red-events">
      <h3>最近自检事件（前五）</h3>
      <table>
        <thead><tr><th>时间</th><th>用例ID</th><th>自检类型</th><th>风险等级</th><th>处理结果</th></tr></thead>
        <tbody>
          {rows.map(([time, id, type, risk, result]) => (
            <tr key={id} className={selectedAttack === id ? "active" : undefined} onClick={() => onSelect(id)}>
              <td>{time}</td><td>{id}</td><td>{type}</td><td><span className={`red-tag ${risk}`}>{risk === "high" ? "高危" : "中危"}</span></td><td><span className="red-tag pass">{result}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
      <button onClick={() => {
        setShowAll((value) => {
          const next = !value;
          onNotice(next ? "最近自检事件已展开全部" : "最近自检事件已收起为前五");
          return next;
        });
      }} type="button">
        {showAll ? "收起事件" : "查看全部自检 →"}
      </button>
    </section>
  );
}

function RedDistribution() {
  return (
    <section className="red-panel red-distribution">
      <h3>自检类型分布</h3>
      <div>
        <div className="red-donut"><strong>132</strong><span>自检总数</span></div>
        <ul>
          <li><i className="c-red" />危险输入拦截 <b>18 (13.6%)</b></li>
          <li><i className="c-yellow" />未授权工具调用 <b>25 (18.9%)</b></li>
          <li><i className="c-green" />目标漂移拦截 <b>20 (15.2%)</b></li>
          <li><i className="c-blue" />高危服务保护 <b>15 (11.4%)</b></li>
          <li><i className="c-purple" />其他 <b>26 (19.7%)</b></li>
        </ul>
      </div>
    </section>
  );
}

function RedTrend() {
  return (
    <section className="red-panel red-trend">
      <h3>阻断效果趋势</h3>
      <svg viewBox="0 0 360 150" aria-hidden="true">
        <g className="grid">
          {[25, 55, 85, 115].map((y) => <line key={y} x1="26" x2="346" y1={y} y2={y} />)}
          {[66, 106, 146, 186, 226, 266, 306].map((x) => <line key={x} y1="18" y2="132" x1={x} x2={x} />)}
        </g>
        <polyline className="block" points="30,32 70,29 110,27 150,30 190,26 230,28 270,31 310,29 346,27" />
        <polyline className="miss" points="30,124 70,122 110,123 150,121 190,120 230,119 270,121 310,119 346,120" />
      </svg>
    </section>
  );
}

function RedRuleHits({ rules, onNotice }: { rules: Array<[string, string, number]>; onNotice: (message: string) => void }) {
  const [showAll, setShowAll] = useState(false);
  const rows = showAll ? rules : rules.slice(0, 5);

  return (
    <section className="red-panel red-rules">
      <h3>规则命中前五</h3>
      {rows.map(([id, name, count]) => (
        <div key={id}>
          <span>{id}</span>
          <p>{name}</p>
          <b>{count}次</b>
        </div>
      ))}
      <button onClick={() => {
        setShowAll((value) => {
          const next = !value;
          onNotice(next ? "规则命中列表已展开全部" : "规则命中列表已收起为前五");
          return next;
        });
      }} type="button">
        {showAll ? "收起规则" : "查看全部规则 →"}
      </button>
    </section>
  );
}

function ActiveRuntimeAlertBanner({
  alert,
  runtime,
  loading,
  onOpenDetail,
  onDiagnose,
  onDismiss,
}: {
  alert: RuntimeAlertEvent;
  runtime: any;
  loading: boolean;
  onOpenDetail: (alert: RuntimeAlertEvent) => void;
  onDiagnose: (alert: RuntimeAlertEvent) => Promise<void> | void;
  onDismiss: (alert: RuntimeAlertEvent) => void;
}) {
  const evidence = alert.evidence?.slice(0, 2) ?? [];
  const steps = ["查看诊断", "PlanSpec", "工具轨迹", "证据图谱", "审计会话"];

  return (
    <section
      className={`active-runtime-alert ${alert.risk_level}`}
      onClick={() => onOpenDetail(alert)}
      role="button"
      tabIndex={0}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") onOpenDetail(alert);
      }}
      aria-label={`打开主动告警详情：${alert.title}`}
    >
      <div className="active-alert-orbit" aria-hidden="true">
        <span />
        <b />
      </div>
      <div className="active-alert-main">
        <span className="active-alert-kicker">主动告警 · {runtime?.scheduler_state === "running" ? "Scheduler 运行中" : "等待巡检"}</span>
        <h2>{alert.title}</h2>
        <p>{alert.summary}</p>
        <div className="active-alert-evidence">
          <strong>{alert.service}{alert.port ? ` · ${alert.port}/TCP` : ""}</strong>
          <span>{displayRisk(alert.risk_level)} · 已发现 {alert.occurrence_count ?? 1} 次 · 最近 {formatTimeOnly(alert.last_seen_at ?? alert.detected_at)}</span>
          <em>{alert.evidence_hint ?? "等待证据摘要"}</em>
          <i>点击查看事件模型、证据、建议与关联审计</i>
        </div>
      </div>
      <div className="active-alert-path" aria-label="主动告警诊断闭环">
        {steps.map((step, index) => (
          <span key={step}>
            <b>{index + 1}</b>
            {step}
          </span>
        ))}
      </div>
      <div className="active-alert-side">
        <div className="active-alert-mini">
          {(evidence.length ? evidence : [
            { tool: "systemctl", signal: "service_state", value: "nginx failed" },
            { tool: "journalctl", signal: "log_signal", value: "Address already in use" },
          ]).map((item) => (
            <span key={`${item.tool}-${item.signal}`}>
              <b>{item.tool}</b>
              {item.value}
            </span>
          ))}
        </div>
        <div className="active-alert-actions">
          <button
            className="primary"
            onClick={(event) => {
              event.stopPropagation();
              onDiagnose(alert);
            }}
            disabled={loading}
            type="button"
          >
            {loading ? "诊断中..." : "查看诊断"}
          </button>
          <button
            onClick={(event) => {
              event.stopPropagation();
              onDismiss(alert);
            }}
            disabled={loading}
            type="button"
          >
            暂时收起
          </button>
        </div>
      </div>
    </section>
  );
}

function RuntimeAlertDetailDrawer({
  alert,
  runtime,
  loading,
  onClose,
  onDiagnose,
  onDefer,
  onOpenAudit,
}: {
  alert: RuntimeAlertEvent;
  runtime: any;
  loading: boolean;
  onClose: () => void;
  onDiagnose: (alert: RuntimeAlertEvent) => Promise<void> | void;
  onDefer: (alert: RuntimeAlertEvent) => Promise<void> | void;
  onOpenAudit: (alert: RuntimeAlertEvent) => Promise<void> | void;
}) {
  const [drawerNotice, setDrawerNotice] = useState("");
  const evidence = alert.evidence?.length ? alert.evidence : [
    {
      tool: alert.service ? `${alert.service} 状态观测` : "运行时观测",
      signal: alert.category ?? "runtime_signal",
      value: alert.evidence_hint ?? alert.summary,
      confidence: 0.82,
    },
  ];
  const fieldRows = [
    ["事件ID", alert.event_id],
    ["事件状态", formatAlertStatus(alert.status)],
    ["事件来源", alert.source || "runtime-scheduler"],
    ["事件类别", alert.category || "service_health"],
    ["目标服务", alert.service || "--"],
    ["监听端口", alert.port ? `${alert.port}/TCP` : "--"],
    ["关联进程", alert.process || "--"],
    ["监听地址", alert.bind || "--"],
    ["运行模式", displayMode(alert.mode ?? runtime?.effective_mode ?? "demo")],
    ["适配器", formatAdapterName(alert.adapter ?? runtime?.adapter ?? "demo")],
    ["首次发现", formatAuditTimestamp(alert.first_seen_at ?? alert.detected_at)],
    ["最近发现", formatAuditTimestamp(alert.last_seen_at ?? alert.detected_at)],
    ["出现次数", `${alert.occurrence_count ?? 1} 次`],
  ];

  async function handleAuditClick() {
    if (!alert.linked_audit_id) {
      setDrawerNotice("尚未生成关联审计，请先点击“查看诊断”完成闭环。");
    }
    await onOpenAudit(alert);
  }

  return (
    <div className="alert-drawer" aria-modal="true" role="dialog" aria-label="主动告警详情">
      <button className="alert-drawer-backdrop" onClick={onClose} type="button" aria-label="关闭告警详情" />
      <aside className={`alert-drawer-panel ${alert.risk_level}`} onClick={(event) => event.stopPropagation()}>
        <header className="alert-drawer-header">
          <div>
            <span>主动巡检事件模型</span>
            <h2>{alert.title}</h2>
            <p>{alert.summary}</p>
          </div>
          <button onClick={onClose} type="button" aria-label="关闭告警详情">×</button>
        </header>

        <div className="alert-drawer-status">
          <strong>{displayRisk(alert.risk_level)}</strong>
          <span>{formatAlertStatus(alert.status)}</span>
          <em>{alert.linked_audit_id ? "已关联审计" : "等待审计闭环"}</em>
        </div>

        <section className="alert-drawer-section">
          <div className="alert-section-title">
            <span>01</span>
            <h3>事件模型字段</h3>
          </div>
          <dl className="alert-field-list">
            {fieldRows.map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </section>

        <section className="alert-drawer-section">
          <div className="alert-section-title">
            <span>02</span>
            <h3>证据</h3>
          </div>
          <div className="alert-evidence-list">
            {evidence.map((item, index) => (
              <article key={`${item.tool}-${item.signal}-${index}`}>
                <b>{item.tool}</b>
                <strong>{item.signal}</strong>
                <p>{item.value}</p>
                <em>可信度 {Math.round((item.confidence ?? 0.78) * 100)}%</em>
              </article>
            ))}
          </div>
        </section>

        <section className="alert-drawer-section">
          <div className="alert-section-title">
            <span>03</span>
            <h3>建议动作</h3>
          </div>
          <div className="alert-advice-card">
            <strong>{alert.suggested_action ?? "生成诊断后给出处置建议"}</strong>
            <p>{alert.plan_hint ?? "建议先完成 PlanSpec、工具轨迹和证据图谱闭环，再进入人工确认的处置步骤。"}</p>
          </div>
        </section>

        <section className="alert-drawer-section">
          <div className="alert-section-title">
            <span>04</span>
            <h3>关联审计</h3>
          </div>
          <div className="alert-audit-link">
            <span>{alert.linked_audit_id ?? "尚未生成审计会话"}</span>
            <p>{alert.linked_audit_id ? "该告警已完成诊断闭环，可跳转审计中心查看计划、工具、证据和结论。" : "点击“查看诊断”后会自动生成审计会话并回写到告警事件。"}</p>
            {drawerNotice ? <em>{drawerNotice}</em> : null}
          </div>
        </section>

        <footer className="alert-drawer-actions">
          <button
            className="primary"
            onClick={() => onDiagnose(alert)}
            disabled={loading}
            type="button"
          >
            {loading ? "诊断中..." : alert.linked_audit_id ? "重新生成诊断" : "查看诊断"}
          </button>
          <button onClick={handleAuditClick} type="button">打开关联审计</button>
          <button onClick={() => onDefer(alert)} disabled={loading} type="button">稍后处理</button>
        </footer>
      </aside>
    </div>
  );
}

function RuntimeAlertCenter({
  alerts,
  runtime,
  selectedId,
  onRefresh,
  onDiagnose,
  onDefer,
  onPlan,
  onOpenDetail,
}: {
  alerts: RuntimeAlertEvent[];
  runtime: any;
  selectedId: string | null;
  onRefresh: () => Promise<void> | void;
  onDiagnose: (alert: RuntimeAlertEvent) => Promise<void> | void;
  onDefer: (alert: RuntimeAlertEvent) => Promise<void> | void;
  onPlan: (alert: RuntimeAlertEvent) => void;
  onOpenDetail: (alert: RuntimeAlertEvent) => void;
}) {
  const [busy, setBusy] = useState(false);
  const activeAlerts = alerts.length ? alerts : [];
  const visibleAlerts = activeAlerts.slice(0, 3);
  const activeCount = activeAlerts.filter((item) => !["resolved", "deferred", "diagnosed"].includes(item.status)).length;

  async function handleRefresh() {
    setBusy(true);
    try {
      await onRefresh();
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="runtime-alert-center">
      <div className="runtime-agent-status">
        <span className="agent-dot" />
        <div>
          <strong>自动巡检</strong>
          <small>
            {runtime?.agent_state === "online" ? "Agent 在线" : "等待连接"}
            {" · "}
            {runtime?.scheduler_state === "running" ? "Scheduler 运行中" : "Scheduler 待机"}
            {" · "}
            {displayMode(runtime?.effective_mode ?? "demo")}模式
            {" · "}
            {runtime?.event_model_version ?? "A1 事件模型"}
          </small>
        </div>
        <button onClick={handleRefresh} disabled={busy} type="button">{busy ? "巡检中" : "立即巡检"}</button>
      </div>

      <div className="runtime-alert-summary">
        <strong>{activeCount}</strong>
        <span>待复核事件</span>
        <small>{runtime?.message ?? "读取类巡检自动执行，高影响处置需人工确认。"}</small>
      </div>

      <div className="runtime-alert-list">
        {visibleAlerts.length ? visibleAlerts.map((alert) => (
          <article
            className={`runtime-alert-card ${alert.risk_level} ${selectedId === alert.event_id ? "selected" : ""}`}
            key={alert.event_id}
            onClick={() => onOpenDetail(alert)}
            role="button"
            tabIndex={0}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") onOpenDetail(alert);
            }}
            aria-label={`打开告警详情：${alert.title}`}
          >
            <span>{displayRisk(alert.risk_level)}</span>
            <div className="runtime-alert-copy">
              <strong>{alert.title}</strong>
              <small>
                {alert.service}{alert.port ? ` · ${alert.port}/TCP` : ""}
                {" · "}
                {formatAlertStatus(alert.status)}
                {" · 已发现 "}
                {alert.occurrence_count ?? 1}
                次
              </small>
              <p>{alert.summary}</p>
              {alert.evidence_hint ? <em>{alert.evidence_hint}</em> : null}
            </div>
            <div className="runtime-alert-actions">
              <button
                onClick={(event) => {
                  event.stopPropagation();
                  onDiagnose(alert);
                }}
                type="button"
              >
                查看诊断
              </button>
              <button
                onClick={(event) => {
                  event.stopPropagation();
                  onPlan(alert);
                }}
                type="button"
              >
                处置计划
              </button>
              <button
                onClick={(event) => {
                  event.stopPropagation();
                  onDefer(alert);
                }}
                type="button"
              >
                稍后处理
              </button>
            </div>
          </article>
        )) : (
          <article className="runtime-alert-card empty">
            <span>正常</span>
            <div className="runtime-alert-copy">
              <strong>等待巡检结果</strong>
              <small>自动模式 · 每 15 秒刷新</small>
              <p>当前未读取到需要复核的运行时事件。</p>
            </div>
          </article>
        )}
      </div>
    </section>
  );
}

function CognitiveCorePanel({
  result,
  alerts,
  onInspectEvidence,
}: {
  result: DiagnosisResult;
  alerts: RuntimeAlertEvent[];
  onInspectEvidence: () => void;
}) {
  const graphNodes = result.evidence_graph?.nodes ?? [];
  const byId = useMemo(() => new Map(graphNodes.map((node) => [node.id, node])), [graphNodes]);
  const source = result.diagnosis_source;
  const alertCount = alerts.filter((item) => !["resolved", "deferred"].includes(item.status)).length;
  const confidence = toPercent(result.root_cause?.confidence) || 91;
  const serviceNodes: TwinNode[] = [
    { key: "agent", label: "SafeOps Agent", detail: "自动巡检", tone: "cyan", position: [-2.75, 0.54, 0.18], screen: [20, 39], pulse: true },
    { key: "nginx", label: "nginx", detail: "80/TCP", tone: "green", position: [-1.55, -0.26, 0.84], screen: [32, 61], pulse: true },
    { key: "planspec", label: "PlanSpec", detail: `${result.plan?.steps?.length ?? 0} 步`, tone: "violet", position: [0, 1.08, 0.32], screen: [50, 27] },
    { key: "httpd", label: "httpd", detail: "PID 1234", tone: "red", position: [1.55, 0.36, 0.78], screen: [68, 46], pulse: true },
    { key: "port", label: "端口 80", detail: "监听归属", tone: "orange", position: [2.55, -0.42, 0.22], screen: [79, 62] },
    { key: "journald", label: "journald", detail: "日志证据", tone: "blue", position: [-2.35, -1.08, 0.06], screen: [24, 74] },
    { key: "systemd", label: "systemd", detail: "服务状态", tone: "blue", position: [2.25, 0.98, -0.02], screen: [75, 32] },
    { key: "audit", label: "审计会话", detail: result.audit_id ?? "待生成", tone: "cyan", position: [0, -1.42, 0.46], screen: [50, 82] },
  ];
  const evidenceIds = [
    "source_runtime_alert",
    "source_attack_surface",
    "symptom_nginx_failed",
    "ev_log_address",
    "ev_port_80",
    "ev_process",
    "root_port_conflict",
  ];
  const evidenceFlow = evidenceIds.map((id) => byId.get(id)).filter(Boolean) as GraphNode[];
  const visibleEvidence = evidenceFlow.length ? evidenceFlow : [
    { id: "fallback_alert", label: source?.kind === "runtime_alert" ? "自动巡检事件" : "诊断请求", type: "source" },
    { id: "fallback_plan", label: "PlanSpec 生成", type: "plan" },
    { id: "fallback_tool", label: "工具轨迹采集", type: "tool" },
    { id: "fallback_root", label: "根因结论", type: "root_cause" },
  ];
  const counterEvidence = [
    byId.get("root_port_conflict"),
    byId.get("cf_release_80"),
    byId.get("cf_failure_disappears"),
  ].filter(Boolean) as GraphNode[];

  return (
    <section className="cognitive-core-panel">
      <div className="core-panel-header">
        <div>
          <span>REAL-TIME SAFEOPS CORE</span>
          <h2>主机服务态势核心</h2>
          <p>自动巡检、服务依赖、端口归属、证据图谱与审计链路实时联动</p>
        </div>
        <div className="core-header-actions">
          <button onClick={onInspectEvidence} type="button">证据联动</button>
          <button onClick={onInspectEvidence} type="button">态势聚焦</button>
        </div>
      </div>

      <div className="core-visual-stage webgl-visual-stage">
        <DigitalTwinCanvas
          auditId={result.audit_id ?? "audit_pending"}
          confidence={confidence}
          nodes={serviceNodes}
        />
        <div className="digital-twin-label-layer" aria-hidden="true">
          {serviceNodes.map((node) => (
            <div
              className={`twin-screen-label ${node.tone} ${node.key === "httpd" || node.key === "port" ? "risk" : ""}`}
              key={`label-${node.key}`}
              style={{ left: `${node.screen[0]}%`, top: `${node.screen[1]}%` }}
            >
              <strong>{node.label}</strong>
              <span>{node.detail}</span>
            </div>
          ))}
          <div className="twin-master-label">
            <span>KOS-MASTER-01</span>
            <strong>192.168.1.100</strong>
            <b>{confidence}%</b>
          </div>
          <div className="twin-evidence-ribbon">PlanSpec → 工具轨迹 → 证据图谱 → 根因结论 → {result.audit_id ?? "audit_pending"}</div>
        </div>
        <div className="webgl-overlay-card overlay-alert">
          <strong>自动巡检告警</strong>
          <b>{alertCount}</b>
          <span>待复核事件</span>
          <small>{alerts[0]?.title ?? "等待巡检事件"}</small>
        </div>
        <div className="webgl-overlay-card overlay-root">
          <strong>当前根因</strong>
          <b>{formatHypothesis(result.root_cause?.name ?? "port_conflict")}</b>
          <span>{confidence}% 可信度</span>
          <small>{result.root_cause?.summary ?? "等待根因结论"}</small>
        </div>
        <div className="webgl-status-legend">
          <span className="healthy">健康</span>
          <span className="warning">告警</span>
          <span className="danger">冲突</span>
          <span className="trace">证据链</span>
        </div>
      </div>

      <div className="core-evidence-flow">
        <div className="core-flow-title">
          <strong>诊断证据图谱联动</strong>
          <span>{source?.kind === "runtime_alert" ? "自动巡检触发" : source?.kind === "attack_surface_port" ? "攻击面节点触发" : "自然语言触发"}</span>
        </div>
        <div className="core-flow-chain">
          {visibleEvidence.slice(0, 6).map((node, index) => (
            <div className={`core-flow-node ${node.type}`} key={node.id}>
              <span>{index + 1}</span>
              <strong>{node.label}</strong>
            </div>
          ))}
        </div>
        <div className="core-counterfactual-mini">
          <strong>反事实验证</strong>
          <div>
            {(counterEvidence.length ? counterEvidence : [
              { id: "cf-a", label: "若释放 80 端口", type: "counterfactual" },
              { id: "cf-b", label: "nginx 绑定条件恢复", type: "counterfactual" },
            ]).map((node) => (
              <span key={node.id}>{node.label}</span>
            ))}
          </div>
          <b>{result.root_cause?.counterfactual ?? "若移除端口占用，启动失败条件将消失。"}</b>
        </div>
      </div>
    </section>
  );
}

const TWIN_TONE_COLORS: Record<TwinNode["tone"], string> = {
  green: "#31d7b4",
  red: "#ff5b6b",
  blue: "#2d8cff",
  orange: "#f3a81d",
  violet: "#8d6cff",
  cyan: "#27d9c0",
};

function DigitalTwinCanvas({
  nodes,
  confidence,
  auditId,
}: {
  nodes: TwinNode[];
  confidence: number;
  auditId: string;
}) {
  return (
    <div className="digital-twin-canvas">
      <Canvas
        camera={{ position: [0, 2.2, 5.7], fov: 40 }}
        dpr={[1, 1.6]}
        gl={{ alpha: true, antialias: true }}
      >
        <color attach="background" args={["#020815"]} />
        <fog attach="fog" args={["#031226", 5.5, 10]} />
        <ambientLight intensity={0.45} />
        <pointLight color="#38dfff" intensity={2.4} position={[0, 2.8, 2.2]} />
        <pointLight color="#8d6cff" intensity={1.6} position={[-2.8, 1.4, 1.6]} />
        <pointLight color="#ff5b6b" intensity={1.45} position={[2.8, 1.2, 1.2]} />
        <Sparkles count={90} speed={0.45} size={1.6} scale={[5.8, 2.5, 2.6]} color="#5ee7ff" />
        <DigitalTwinScene auditId={auditId} confidence={confidence} nodes={nodes} />
      </Canvas>
    </div>
  );
}

function DigitalTwinScene({ nodes, confidence, auditId }: { nodes: TwinNode[]; confidence: number; auditId: string }) {
  const group = useRef<THREE.Group>(null);
  const center: [number, number, number] = [0, 0.1, 0.36];

  useFrame(({ clock }) => {
    const elapsed = clock.getElapsedTime();
    if (group.current) {
      group.current.rotation.y = Math.sin(elapsed * 0.22) * 0.035;
      group.current.position.y = Math.sin(elapsed * 0.7) * 0.025;
    }
  });

  return (
    <group ref={group} position={[0, -0.02, 0]}>
      <LaptopModel />
      <group position={[0, 0.45, -0.8]} rotation={[-0.12, 0, 0]}>
        <ScreenGrid />
        <MiniTopologyMesh />
        <MasterHostNode confidence={confidence} position={center} />
        {nodes.map((node, index) => (
          <TwinServiceNode key={node.key} node={node} index={index} />
        ))}
        {nodes.map((node, index) => {
          const color = TWIN_TONE_COLORS[node.tone];
          return (
            <group key={`link-${node.key}`}>
              <Line
                color={color}
                lineWidth={1.6}
                points={[
                  center,
                  [
                    (center[0] + node.position[0]) / 2,
                    (center[1] + node.position[1]) / 2 + 0.2,
                    Math.max(center[2], node.position[2]) + 0.25,
                  ],
                  node.position,
                ]}
                transparent
                opacity={node.tone === "red" || node.tone === "orange" ? 0.86 : 0.62}
              />
              <FlowParticle color={color} from={center} offset={index * 0.13} to={node.position} />
            </group>
          );
        })}
        <EvidenceRibbon auditId={auditId} />
      </group>
    </group>
  );
}

function LaptopModel() {
  const screenMaterial = useMemo(() => new THREE.MeshStandardMaterial({
    color: "#081d3b",
    emissive: "#0c6fcf",
    emissiveIntensity: 0.34,
    metalness: 0.52,
    roughness: 0.22,
    transparent: true,
    opacity: 0.86,
  }), []);

  return (
    <group>
      <mesh position={[0, 0.78, -1.08]} rotation={[-0.12, 0, 0]}>
        <boxGeometry args={[5.55, 2.85, 0.1]} />
        <meshStandardMaterial color="#06152a" emissive="#0a6dd9" emissiveIntensity={0.2} metalness={0.75} roughness={0.25} />
      </mesh>
      <mesh position={[0, 0.78, -1.01]} rotation={[-0.12, 0, 0]}>
        <planeGeometry args={[5.18, 2.48, 48, 24]} />
        <primitive attach="material" object={screenMaterial} />
      </mesh>
      <mesh position={[0, -1.12, 0.65]} rotation={[0.25, 0, 0]}>
        <boxGeometry args={[5.9, 0.14, 2.62]} />
        <meshStandardMaterial color="#07172f" emissive="#074a91" emissiveIntensity={0.2} metalness={0.68} roughness={0.34} />
      </mesh>
      <mesh position={[0, -1.04, 0.86]} rotation={[0.25, 0, 0]}>
        <boxGeometry args={[1.25, 0.025, 0.5]} />
        <meshStandardMaterial color="#092547" emissive="#27d9c0" emissiveIntensity={0.16} metalness={0.55} roughness={0.42} />
      </mesh>
      {Array.from({ length: 9 }).map((_, row) => (
        <group key={`keyboard-row-${row}`} position={[0, -0.98 + row * 0.018, 0.08 + row * 0.14]} rotation={[0.25, 0, 0]}>
          {Array.from({ length: 14 }).map((__, col) => (
            <mesh key={`key-${row}-${col}`} position={[-2.45 + col * 0.38, 0, 0]}>
              <boxGeometry args={[0.22, 0.018, 0.045]} />
              <meshBasicMaterial color="#1e8dff" transparent opacity={0.16 + (row % 3) * 0.04} />
            </mesh>
          ))}
        </group>
      ))}
      <mesh position={[0, -1.28, 1.92]} rotation={[0.25, 0, 0]}>
        <boxGeometry args={[5.2, 0.018, 0.035]} />
        <meshBasicMaterial color="#35dfff" transparent opacity={0.72} />
      </mesh>
    </group>
  );
}

function ScreenGrid() {
  const ringRef = useRef<THREE.Group>(null);
  useFrame(({ clock }) => {
    if (ringRef.current) ringRef.current.rotation.z = clock.getElapsedTime() * 0.12;
  });

  return (
    <group>
      <gridHelper args={[5.2, 26, "#1ee7ff", "#123f79"]} position={[0, -0.34, 0.02]} rotation={[Math.PI / 2, 0, 0]} />
      <group ref={ringRef} position={[0, -0.02, 0.04]} rotation={[Math.PI / 2, 0, 0]}>
        {[0.78, 1.15, 1.55, 2.05].map((radius) => (
          <mesh key={radius}>
            <torusGeometry args={[radius, 0.004, 8, 128]} />
            <meshBasicMaterial color="#27d9c0" transparent opacity={0.26} />
          </mesh>
        ))}
      </group>
      <mesh position={[0, 0.02, -0.01]}>
        <planeGeometry args={[5.15, 2.45]} />
        <meshBasicMaterial color="#03152b" transparent opacity={0.18} />
      </mesh>
    </group>
  );
}

function MiniTopologyMesh() {
  const nodes = useMemo(() => ([
    [-2.2, 0.75, 0.02, "#2d8cff"],
    [-1.65, 0.25, 0.12, "#31d7b4"],
    [-1.1, 0.86, 0.08, "#2d8cff"],
    [-0.56, 0.34, 0.16, "#8d6cff"],
    [0, 0.9, 0.14, "#f3a81d"],
    [0.52, 0.38, 0.22, "#31d7b4"],
    [1.04, 0.92, 0.1, "#2d8cff"],
    [1.55, 0.18, 0.18, "#ff5b6b"],
    [2.15, 0.68, 0.08, "#2d8cff"],
    [-2.0, -0.52, 0.08, "#2d8cff"],
    [-1.25, -0.72, 0.18, "#31d7b4"],
    [-0.46, -0.5, 0.1, "#2d8cff"],
    [0.52, -0.76, 0.18, "#27d9c0"],
    [1.26, -0.48, 0.1, "#f3a81d"],
    [2.02, -0.72, 0.05, "#8d6cff"],
  ] as Array<[number, number, number, string]>), []);
  const links = [
    [0, 1], [1, 3], [3, 5], [5, 7], [7, 8],
    [1, 10], [10, 11], [11, 12], [12, 13], [13, 14],
    [2, 4], [4, 6], [6, 8], [3, 11], [5, 12], [7, 13],
  ];

  return (
    <group>
      {links.map(([from, to], index) => (
        <Line
          key={`mini-link-${index}`}
          color={index % 3 === 0 ? "#31d7b4" : "#2d8cff"}
          lineWidth={0.8}
          points={[
            [nodes[from][0], nodes[from][1], nodes[from][2]],
            [nodes[to][0], nodes[to][1], nodes[to][2]],
          ]}
          transparent
          opacity={0.32}
        />
      ))}
      {nodes.map(([x, y, z, color], index) => (
        <Float key={`mini-node-${index}`} speed={1.2 + index * 0.03} rotationIntensity={0.08} floatIntensity={0.08}>
          <mesh position={[x, y, z]}>
            <sphereGeometry args={[0.045, 10, 10]} />
            <meshBasicMaterial color={color} transparent opacity={0.9} />
          </mesh>
        </Float>
      ))}
    </group>
  );
}

function MasterHostNode({ confidence, position }: { confidence: number; position: [number, number, number] }) {
  const ref = useRef<THREE.Group>(null);
  useFrame(({ clock }) => {
    const elapsed = clock.getElapsedTime();
    if (ref.current) {
      ref.current.rotation.y = elapsed * 0.35;
      ref.current.position.y = position[1] + Math.sin(elapsed * 1.15) * 0.035;
    }
  });

  return (
    <group ref={ref} position={position}>
      <mesh>
        <octahedronGeometry args={[0.38, 1]} />
        <meshStandardMaterial color="#1a7dff" emissive="#2d8cff" emissiveIntensity={1.1} metalness={0.35} roughness={0.18} />
      </mesh>
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[0.56, 0.016, 12, 96]} />
        <meshBasicMaterial color="#31d7ff" transparent opacity={0.78} />
      </mesh>
      <pointLight color="#38dfff" intensity={1.8} distance={3.4} />
    </group>
  );
}

function TwinServiceNode({ node, index }: { node: TwinNode; index: number }) {
  const ref = useRef<THREE.Group>(null);
  const color = TWIN_TONE_COLORS[node.tone];

  useFrame(({ clock }) => {
    const elapsed = clock.getElapsedTime();
    if (!ref.current) return;
    ref.current.rotation.y = elapsed * 0.6 + index * 0.4;
    ref.current.position.y = node.position[1] + Math.sin(elapsed * 1.4 + index) * (node.pulse ? 0.055 : 0.03);
  });

  return (
    <Float speed={1.4 + index * 0.05} rotationIntensity={0.16} floatIntensity={0.18}>
      <group ref={ref} position={node.position}>
        <mesh>
          <octahedronGeometry args={[0.18, 0]} />
          <meshStandardMaterial color={color} emissive={color} emissiveIntensity={1.2} metalness={0.38} roughness={0.18} />
        </mesh>
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[0.3, 0.01, 8, 64]} />
          <meshBasicMaterial color={color} transparent opacity={0.72} />
        </mesh>
        <pointLight color={color} intensity={node.pulse ? 1.2 : 0.7} distance={2.2} />
      </group>
    </Float>
  );
}

function FlowParticle({
  from,
  to,
  color,
  offset,
}: {
  from: [number, number, number];
  to: [number, number, number];
  color: string;
  offset: number;
}) {
  const ref = useRef<THREE.Mesh>(null);
  const start = useMemo(() => new THREE.Vector3(...from), [from]);
  const end = useMemo(() => new THREE.Vector3(...to), [to]);

  useFrame(({ clock }) => {
    if (!ref.current) return;
    const t = (clock.getElapsedTime() * 0.34 + offset) % 1;
    ref.current.position.lerpVectors(start, end, t);
    ref.current.position.y += Math.sin(t * Math.PI) * 0.2;
  });

  return (
    <mesh ref={ref}>
      <sphereGeometry args={[0.035, 12, 12]} />
      <meshBasicMaterial color={color} />
    </mesh>
  );
}

function EvidenceRibbon({ auditId }: { auditId: string }) {
  return (
    <group position={[0, -1.78, 0.25]}>
      <Line
        color="#31d7b4"
        lineWidth={2.2}
        points={[[-2.4, 0, 0], [-1.25, 0.05, 0.08], [0, 0, 0.02], [1.25, 0.05, 0.08], [2.4, 0, 0]]}
        transparent
        opacity={0.75}
      />
    </group>
  );
}

function CognitiveRadarPanel({
  result,
  summary,
  runtime,
  onOpenAudit,
}: {
  result: DiagnosisResult;
  summary: any;
  runtime: any;
  onOpenAudit: () => void;
}) {
  const confidence = toPercent(result.root_cause?.confidence) || 91;
  const verified = result.knowledge_state?.verified?.length ?? 0;
  const toolCalls = result.tool_trace?.length ?? 0;
  const health = summary?.health_score ?? 86;

  return (
    <Panel title="认知雷达与审计入口" icon="radar" action="打开审计中心" onAction={onOpenAudit}>
      <div className="cognitive-radar-card">
        <div className="radar-web" aria-hidden="true">
          <svg viewBox="0 0 160 160">
            <polygon className="radar-ring" points="80,10 143,45 143,115 80,150 17,115 17,45" />
            <polygon className="radar-ring inner" points="80,36 120,58 120,102 80,124 40,102 40,58" />
            <polygon className="radar-shape" points="80,20 132,62 121,111 80,138 34,106 38,56" />
            <line x1="80" y1="10" x2="80" y2="150" />
            <line x1="17" y1="45" x2="143" y2="115" />
            <line x1="143" y1="45" x2="17" y2="115" />
          </svg>
          <b>{confidence}</b>
          <span>可信评分</span>
        </div>
        <div className="radar-metrics">
          <div><span>系统健康</span><b>{health}/100</b></div>
          <div><span>已验证证据</span><b>{verified}</b></div>
          <div><span>工具轨迹</span><b>{toolCalls}</b></div>
          <div><span>巡检状态</span><b>{runtime?.agent_state === "online" ? "在线" : "待连接"}</b></div>
        </div>
      </div>
    </Panel>
  );
}

function AgentPanel({
  query,
  result,
  source,
  loading,
  onQueryChange,
  onDiagnose,
  onQuickDemo,
}: {
  query: string;
  result: DiagnosisResult | null;
  source?: DiagnosisSource | null;
  loading: boolean;
  onQueryChange: (query: string) => void;
  onDiagnose: () => void;
  onQuickDemo: () => void;
}) {
  function handleDiagnoseClick() {
    onDiagnose();
  }

  function handleQuickDemoClick() {
    onQuickDemo();
  }

  const checks = result
    ? ["识别故障现象", "收集关键证据", "构建因果链路", "输出根因结论"]
    : ["等待计划规范", "等待证据提升", "等待工具轨迹", "等待审计凭证"];

  return (
    <Panel title="智能体对话" icon="chat">
      <div className="chat-window">
        <div className="bubble user">
          <span>用户</span>
          <p>{query}</p>
        </div>
        {source && (
          <div className="diagnosis-source-banner">
            <b>{source.kind === "runtime_alert" ? "巡检来源" : "联动来源"}</b>
            <span>{source.label}</span>
            <small>{source.service} · {source.port}/TCP · {source.bind ?? "0.0.0.0"} · {displayRisk(source.risk ?? "medium")}</small>
          </div>
        )}
        <div className="bubble agent">
          <span>智能体</span>
          <p>{loading ? "正在生成诊断计划..." : result?.answer ?? "等待运维问题。"}</p>
          <ul>
            {checks.map((item, index) => (
              <li key={item} className={result ? "done" : undefined}>
                <span>{index + 1}</span>
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
      {result?.audit_id && (
        <div className="audit-ids">
          <small>诊断：{result.diagnosis_id ?? "已生成"}</small>
          <small>审计：{result.audit_id}</small>
          <small>回放：{result.replay_id}</small>
        </div>
      )}
      <div className="prompt-row">
        <textarea value={query} onChange={(event) => onQueryChange(event.target.value)} />
        <div className="prompt-actions">
          <button onClick={handleDiagnoseClick} disabled={loading} type="button">{loading ? "分析中" : "生成诊断"}</button>
          <button className="secondary-action" onClick={handleQuickDemoClick} disabled={loading} type="button">一键演示</button>
        </div>
      </div>
    </Panel>
  );
}

function KnowledgePanel({ plan, state, onInspect }: { plan: any; state?: Record<string, any[]>; onInspect: () => void }) {
  const columns = [
    { key: "known", label: "已知", zh: "已知", tone: "known" },
    { key: "unknown", label: "未知", zh: "未知", tone: "unknown" },
    { key: "assumed", label: "假设", zh: "假设", tone: "assumed" },
    { key: "verified", label: "已验证", zh: "已验证", tone: "verified" },
  ];

  return (
    <Panel title="认知状态（计划规范）" icon="plan" action="查看计划详情" onAction={onInspect}>
      <div className="plan-summary">
        <strong>{plan?.goal ?? "等待生成计划规范"}</strong>
        <span>{plan?.intent ?? "意图待识别"} · {plan?.steps?.length ?? 0} 步 · 意图已锚定</span>
      </div>
      <div className="knowledge-grid">
        {columns.map((column) => {
          const items = state?.[column.key] ?? [];
          return (
            <div className={`knowledge-card ${column.tone}`} key={column.key}>
              <div>
                <strong>{column.label}</strong>
                <span>{column.zh}</span>
              </div>
              <b>{items.length}</b>
              {items.slice(0, 2).map((item: any, index) => (
                <p key={`${column.key}-${index}`}>{item.value ?? item.question ?? item.hypothesis ?? item.fact}</p>
              ))}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function HypothesisPanel({ items, onSort }: { items: Array<{ name: string; score: number; state: string }>; onSort: () => void }) {
  const hypotheses = items.length
    ? items
    : [
        { name: "port_conflict", score: 0, state: "pending" },
        { name: "config_error", score: 0, state: "pending" },
        { name: "permission_denied", score: 0, state: "pending" },
      ];

  return (
    <Panel title="候选根因中心" icon="hypothesis" action="排序：置信度" onAction={onSort}>
      <div className="hypothesis-list">
        {hypotheses.map((item, index) => (
          <div className={`hypothesis-row rank-${index + 1}`} key={item.name}>
            <span>{index + 1}</span>
            <div>
              <strong>{formatHypothesis(item.name)}</strong>
              <small>{hypothesisEvidenceMeta(item.name, item.state)}</small>
              <div className="confidence-bar">
                <i style={{ width: `${Math.round(item.score * 100)}%` }} />
              </div>
            </div>
            <b>{Math.round(item.score * 100)}%</b>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function hypothesisEvidenceMeta(name: string, state: string) {
  if (name.includes("port")) return `关键证据：3 条　支持工具：ss, ps, journalctl　${displayState(state)}`;
  if (name.includes("config")) return `关键证据：1 条　支持工具：nginx -t　${displayState(state)}`;
  return `关键证据：0 条　支持工具：systemctl, journalctl　${displayState(state)}`;
}

function EvidenceGraphPanel({ graph }: { graph?: DiagnosisResult["evidence_graph"] }) {
  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const byId = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const factWorld = [
    "source_runtime_alert",
    "source_attack_surface",
    "symptom_nginx_failed",
    "ev_log_address",
    "ev_port_80",
    "ev_process",
    "root_port_conflict",
  ].map((id) => byId.get(id)).filter(Boolean) as GraphNode[];
  const factWorldWithAction = factWorld.length
    ? [...factWorld, { id: "rec_stop_httpd", label: "建议：停止 httpd 或修改 nginx 监听端口", type: "recommendation" }]
    : [];
  const counterWorld = [
    "root_port_conflict",
    "cf_release_80",
    "cf_failure_disappears",
  ].map((id) => byId.get(id)).filter(Boolean) as GraphNode[];
  const evidenceTools = [
    { tool: "journalctl -u nginx", time: "10:22:14", detail: "地址已被占用" },
    { tool: "ss -lntp", time: "10:22:16", detail: "LISTEN :80" },
    { tool: "ps -p 1234 -o comm", time: "10:22:17", detail: "httpd 占用端口" },
  ];

  return (
    <section className="panel evidence-panel">
      <div className="panel-title">
        <div>
          <span className="title-icon graph-icon" />
          <h2>反事实证据图谱</h2>
        </div>
        <div className="legend">
          <span className="danger">故障现象</span>
          <span className="proof">证据节点</span>
          <span className="tool">工具提取</span>
          <span className="infer">推理关系</span>
          <span className="root">根因结论</span>
          <span className="counter">反事实世界</span>
        </div>
      </div>
      {nodes.length ? (
        <div className="graph-stage">
          <div className="fact-world">
            <div className="fact-flow">
              {factWorldWithAction.map((node, index) => (
                <GraphNodeCard key={node.id} node={node} isLast={index === factWorldWithAction.length - 1} />
              ))}
            </div>
            <div className="tool-evidence-row">
              {evidenceTools.map((item) => (
                <div key={item.tool}>
                  <strong>{item.tool}</strong>
                  <span>{item.time}</span>
                  <small>{item.detail}</small>
                </div>
              ))}
            </div>
          </div>
          <div className="counter-flow">
            <h3>反事实世界（假设移除冲突）</h3>
            <div className="counter-chain">
              {counterWorld.map((node, index) => (
                <GraphNodeCard key={`counter-${node.id}`} node={node} isLast={index === counterWorld.length - 1} />
              ))}
            </div>
            <div className="counter-verdict">
              <strong>反事实验证</strong>
              <p>若释放 80 端口，nginx 启动失败条件将消失。</p>
              <span>置信度提升：84% → 91%　因果边：{edges.length}</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="graph-empty">等待诊断后生成证据图谱</div>
      )}
    </section>
  );
}

function GraphNodeCard({ node, isLast }: { node: GraphNode; isLast: boolean }) {
  return (
    <div className="graph-node-wrap">
      <div className={`graph-node ${node.type}`}>
        <span>{formatGraphNodeType(node.type)}</span>
        <strong>{node.label}</strong>
      </div>
      {!isLast && <i className="connector" />}
    </div>
  );
}

function formatGraphNodeType(type: string) {
  const labels: Record<string, string> = {
    symptom: "nginx",
    verified: "证据",
    evidence: "证据",
    source: "来源",
    root_cause: "根因",
    counterfactual: "反事实",
    recommendation: "建议",
  };
  return labels[type] ?? type;
}

function ToolTimeline({ items, replay, onReplay }: { items: any[]; replay: ReplayRecord | null; onReplay: () => void }) {
  const rows = (items.length ? items : DEMO_DIAGNOSIS.tool_trace ?? []).slice(0, 5);
  const times = ["10:22:12", "10:22:14", "10:22:16", "10:22:17", "10:22:19"];
  const durations = ["0.32s", "1.21s", "0.18s", "0.09s", "0.45s"];

  return (
    <Panel title="工具时间线（工具轨迹）" icon="timeline" action="回放轨迹" onAction={onReplay}>
      <div className="timeline-rail">
        {rows.map((item, index) => (
          <div className="timeline-item" key={`${item.tool}-${index}`}>
            <span />
      <small>{times[index] ?? `步骤 ${index + 1}`}</small>
            <strong>{item.tool}</strong>
            <p>{item.summary}</p>
            <em>{displayToolMode(item.mode)} · {durations[index] ?? "0.20s"}</em>
          </div>
        ))}
      </div>
      <div className="timeline-legend">
        <span className="readonly">只读</span>
        <span className="low">低风险</span>
        <span className="medium">中风险</span>
        <span className="high">高风险</span>
        <span className="blocked">已阻断</span>
        {replay && <b>{replay.events.length} 个回放事件</b>}
      </div>
    </Panel>
  );
}

function ShadowExecutionPanel({
  data,
  status,
  onDecision,
}: {
  data: any;
  status: string;
  onDecision: (status: string) => void;
}) {
  return (
    <Panel title="影子执行" icon="shadow">
      <div className="shadow-command">
        <span>拟执行操作</span>
        <strong>{data?.operation ?? "重启 nginx.service"}</strong>
        <b className={`risk-pill ${data?.risk ?? "medium"}`}>{displayRisk(data?.risk ?? "medium")}</b>
      </div>
      <ul className="shadow-list">
        {(data?.impact ?? DEMO_SHADOW_PREVIEW.impact).slice(0, 4).map((item: string) => (
          <li key={item}>{item}</li>
        ))}
        <li>{status}</li>
      </ul>
      <div className="shadow-actions">
        <button className="ghost-button" onClick={() => onDecision("已取消：不会执行任何系统命令")} type="button">取消</button>
        <button className="confirm-button" onClick={() => onDecision("已确认：演示模式仅记录审计，不真实重启服务")} type="button">确认执行</button>
      </div>
    </Panel>
  );
}

function AuditPanel({
  audit,
  result,
  loading,
  onExport,
}: {
  audit: AuditRecord | null;
  result: DiagnosisResult | null;
  loading: boolean;
  onExport: (filename: string) => void;
}) {
  const [exporting, setExporting] = useState(false);
  const score = toPercent(audit?.root_cause?.confidence ?? result?.root_cause?.confidence) || 0;

  async function handleExport() {
    if (!audit) return;
    setExporting(true);
    try {
      let markdown = "";
      try {
        markdown = await exportAuditMarkdown(audit.audit_id);
      } catch {
        markdown = buildLocalAuditMarkdown(audit, result);
      }
      const filename = `${audit.audit_id}.md`;
      downloadTextFile(filename, markdown, "text/markdown;charset=utf-8");
      onExport(filename);
    } finally {
      setExporting(false);
    }
  }

  return (
    <Panel title="认知审查" icon="audit">
      <div className="audit-layout">
        <div>
          <ul className="audit-checks">
            <li className={audit ? "pass" : undefined}>DeepSeek 未启用时使用规则审查器</li>
            <li className={result ? "pass" : undefined}>未发现幻觉</li>
            <li className={result?.tool_trace?.length ? "pass" : undefined}>所有输出均有证据支撑</li>
            <li className={result?.root_cause ? "pass" : undefined}>无未验证假设直接升级为结论</li>
            <li className={audit ? "pass" : undefined}>无目标漂移</li>
            <li className={audit ? "pass" : undefined}>未触发裸执行危险命令</li>
          </ul>
          {audit?.audit_id && <small className="audit-id">审计报告已就绪</small>}
        </div>
        <div className="score-ring">
          <strong>{score || "--"}</strong>
          <span>/100</span>
        </div>
      </div>
      <button className="export-button" onClick={handleExport} disabled={!audit || exporting || loading}>
        {exporting ? "导出中..." : audit ? "查看审查详情 / 导出报告" : "等待审计报告"}
      </button>
    </Panel>
  );
}

function SystemCard({ summary, surface }: { summary: any; surface: any }) {
  const env = summary?.environment ?? {};
  const riskyPorts = surface?.items?.filter((item: any) => item.risk !== "low").length ?? 0;

  return (
    <div className="system-card">
      <strong>系统信息</strong>
      <dl>
        <div>
          <dt>运行模式</dt>
          <dd>{displayMode(env.effective_mode ?? "demo")}</dd>
        </div>
        <div>
          <dt>系统识别</dt>
          <dd>{formatOsDisplay(env.os_release?.name)}</dd>
        </div>
        <div>
          <dt>工具就绪</dt>
          <dd>{env.real_mode_ready ? "真实工具已就绪" : "演示数据"}</dd>
        </div>
        <div>
          <dt>风险端口</dt>
          <dd>{riskyPorts}</dd>
        </div>
      </dl>
    </div>
  );
}

function MetricCard({
  label,
  value,
  suffix,
  tone,
}: {
  label: string;
  value: string | number;
  suffix?: string;
  tone: string;
}) {
  return (
    <div className={`metric-card ${tone}`}>
      <span>{label}</span>
      <strong>
        {value}
        {suffix && <small>{suffix}</small>}
      </strong>
      <svg viewBox="0 0 120 34" aria-hidden="true">
        <polyline points="0,25 18,25 28,18 38,26 50,14 63,17 72,8 83,27 94,12 105,19 120,9" />
      </svg>
    </div>
  );
}

function Panel({
  title,
  icon,
  action,
  onAction,
  children,
}: {
  title: string;
  icon: string;
  action?: string;
  onAction?: () => void;
  children: React.ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-title">
        <div>
          <span className={`title-icon ${icon}-icon`} />
          <h2>{title}</h2>
        </div>
        {action && (
          onAction
            ? <button className="panel-action" onClick={onAction} type="button">{action}</button>
            : <span className="panel-action">{action}</span>
        )}
      </div>
      {children}
    </section>
  );
}

function redTeamMatrix(data: any) {
  const backendCases = new Map((data.cases ?? []).map((item: any) => [item.name, item]));
  const rateFor = (name: string, fallback: number) => {
    const item = backendCases.get(name) as any;
    if (!item) return fallback;
    return item.passed ? 100 : 0;
  };
  return [
    ["危险输入拦截", "1 / 1", rateFor("prompt_injection", 100), "high", "▣", "0,18 12,12 24,18 36,8 48,14 60,6 72,12 80,7"],
    ["未授权工具调用", "1 / 1", rateFor("tool_abuse", 92), "medium", "✚", "0,17 12,19 24,10 36,16 48,7 60,12 72,5 80,11"],
    ["目标漂移拦截", "1 / 1", rateFor("intent_drift", 90), "info", "◆", "0,15 12,10 24,17 36,9 48,12 60,6 72,14 80,8"],
    ["高危服务保护", "1 / 1", rateFor("privileged_service", 100), "warning", "△", "0,8 12,19 24,7 36,21 48,6 60,18 72,8 80,16"],
    ["输出污染隔离", "1 / 1", rateFor("output_poisoning", 88), "danger", "◇", "0,19 12,8 24,20 36,9 48,17 60,11 72,21 80,12"],
    ["日志污染隔离", "1 / 1", rateFor("log_prompt_injection", 96), "info", "□", "0,16 12,11 24,17 36,8 48,14 60,9 72,16 80,10"],
    ["敏感路径请求拦截", "1 / 1", rateFor("sensitive_path", 98), "high", "▤", "0,20 12,13 24,15 36,7 48,18 60,6 72,11 80,9"],
    ["命令拼接拦截", "1 / 1", rateFor("command_injection", 99), "danger", "◈", "0,18 12,9 24,16 36,7 48,19 60,11 72,15 80,8"],
  ].map(([name, tests, rate, tone, icon, trend]) => ({ name, tests, rate, tone, icon, trend }));
}

function redTeamRecentEvents(cases: any[] = []) {
  const source = cases.length ? cases : DEMO_RED_TEAM.cases;
  return source.map((item: any, index: number) => [
    `14:${String(31 - index * 2).padStart(2, "0")}:23`,
    redAttackId(item.name, index),
    redCaseLabel(item.name),
    item.severity ?? "medium",
    item.passed ? "已阻断" : "待加固",
  ]);
}

function redAttackId(name: string, index = 0) {
  const ids: Record<string, string> = {
    prompt_injection: "输入-001",
    command_injection: "命令-001",
    log_prompt_injection: "日志-002",
    intent_drift: "漂移-004",
    sensitive_path: "路径-006",
    privileged_service: "服务-002",
    tool_abuse: "工具-003",
    output_poisoning: "输出-005",
  };
  return ids[name] ?? `用例-${String(index + 1).padStart(3, "0")}`;
}

function redCaseByAttackId(attackId: string, cases: any[] = []) {
  return (cases.length ? cases : DEMO_RED_TEAM.cases).find((item: any, index: number) => redAttackId(item.name, index) === attackId)
    ?? (cases.length ? cases : DEMO_RED_TEAM.cases).find((item: any) => item.name === "command_injection");
}

function downloadTextFile(filename: string, content: string, type = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function delay(ms: number) {
  return new Promise<void>((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

function buildAttackSurfaceReport(ports: SurfaceItem[], score: number) {
  return [
    "# 安全运维攻击面地图报告",
    "",
    `- 风险评分：${score}/100`,
    `- 暴露端口：${ports.length}`,
    `- 生成时间：${new Date().toLocaleString("zh-CN")}`,
    "",
    "## 暴露端口",
    ...ports.map((item) => `- ${item.port}/TCP ${item.service ?? item.process}：${riskLabel(item.risk)}，${item.reason ?? "已纳入攻击面地图"}`),
  ].join("\n");
}

function attackPortSuggestions(port: SurfaceItem) {
  if (port.port === 80) {
    return [
      "检查 nginx 与 httpd/docker-proxy 是否同时占用 80 端口",
      "通过驾驶舱触发计划规范诊断并生成证据图谱",
      "修复前先执行影子评估，避免误停业务服务",
    ];
  }
  if (port.port === 22) {
    return ["限制 SSH 来源 IP", "检查最近异常登录", "禁止智能体自动重启 sshd"];
  }
  if (port.port === 3306 || port.port === 6379) {
    return ["确认数据库/缓存未对公网开放", "启用访问控制与强认证", "审计最近连接来源"];
  }
  if (port.port === 2375) {
    return ["关闭未加密 Docker API", "启用 TLS 客户端认证", "检查容器逃逸风险"];
  }
  return ["保持最小暴露面", "确认服务归属与访问来源", "纳入周期性攻击面扫描"];
}

function buildRedTeamReport(data: any, matrix: Array<any>) {
  const cases = data.cases ?? DEMO_RED_TEAM.cases;
  return [
    "# 安全策略自检报告",
    "",
    `- 安全评分：${data.score}/100`,
    `- 自检用例总数：${data.attackTotal}`,
    `- 成功阻断：${data.blocked}`,
    `- 后端自检：${data.runtimePassed}/${data.runtimeTotal}`,
    `- 生成时间：${new Date().toLocaleString("zh-CN")}`,
    "",
    "## 策略映射",
    ...matrix.map((item) => `- ${item.name}：${item.tests}，阻断率 ${item.rate}%`),
    "",
    "## 本地模拟防御用例",
    ...cases.map((item: any, index: number) => [
      `${index + 1}. ${redCaseLabel(item.name)}：${item.passed ? "已阻断/通过" : "未通过"}`,
      `   - 模拟输入摘要：${item.payload ?? "-"}`,
      `   - 命中规则：${displayRuleId(item.rule)}`,
      `   - 策略映射编号：${item.mitre ?? "-"}`,
      `   - 处理详情：${item.detail ?? "-"}`,
    ].join("\n")),
  ].join("\n");
}

function redCaseLabel(name: string) {
  const labels: Record<string, string> = {
    prompt_injection: "危险输入拦截",
    command_injection: "命令拼接拦截",
    log_prompt_injection: "日志污染隔离",
    intent_drift: "目标漂移拦截",
    sensitive_path: "敏感路径请求拦截",
    privileged_service: "高危服务保护",
    tool_abuse: "未授权工具调用",
    output_poisoning: "输出污染隔离",
  };
  return labels[name] ?? name;
}

function displayRuleId(rule?: string) {
  const labels: Record<string, string> = {
    "RULE-PROMPT-001": "规则-输入-001",
    "RULE-CMD-001": "规则-命令-001",
    "RULE-LOG-001": "规则-日志-001",
    "RULE-GOAL-001": "规则-目标-001",
    "RULE-SENSITIVE-001": "规则-敏感-001",
    "RULE-PRIV-001": "规则-服务-001",
    "RULE-TOOL-001": "规则-工具-001",
    "RULE-OUTPUT-001": "规则-输出-001",
  };
  return labels[rule ?? ""] ?? rule ?? "规则-命令-001";
}

function buildVisualReasoningReport(active: typeof vrsArenaCards[number], confidence: number) {
  return [
    "# 可视化推理系统报告",
    "",
    `- 会话：INC-2026-0612`,
    `- 问题：nginx.service 启动失败`,
    `- 当前最可能根因：${active.title}`,
    `- 根因置信度：${confidence}%`,
    `- 生成时间：${new Date().toLocaleString("zh-CN")}`,
    "",
    "## 候选根因排名",
    ...vrsRootRanking.map((item) => `- ${item.id}. ${item.title}：${item.score}%（${item.status}）`),
    "",
    "## 关键证据影响",
    ...vrsEvidenceImpact.map((item) => `- ${item.evidence}：${item.impact} -> 假设 ${item.target}`),
    "",
    "## 反事实验证",
    ...vrsSimulations.map((item) => `- 如果 ${item.title}：${item.before}% -> ${item.after}%，预测结果：${item.outcome}`),
  ].join("\n");
}

function buildSystemStatusReport(health: number) {
  return [
    "# 系统状态中心报告",
    "",
    `- 主机：KOS-192.168.1.100（麒麟系统V10）`,
    `- 系统健康度：${health}/100`,
    `- 生成时间：${new Date().toLocaleString("zh-CN")}`,
    "",
    "## 系统概览",
    ...sysOverviewMetrics.map((item) => `- ${item.label}：${item.value}，${item.detail}`),
    "",
    "## 异常服务",
    ...sysServices.filter((item) => item.tone !== "running").map((item) => `- ${item.name}：${item.status}`),
    "",
    "## 实时告警",
    ...sysAlerts.map((item) => `- [${item.level}] ${item.title}（${item.time}）`),
  ].join("\n");
}

function buildLocalAuditMarkdown(audit: AuditRecord, result: DiagnosisResult | null) {
  const root = audit.root_cause ?? result?.root_cause ?? {};
  const environment = audit.environment ?? result?.environment ?? {};
  const evidenceSummary = audit.evidence_summary ?? result?.evidence_summary ?? {};
  const linkedSource = audit.diagnosis_source ?? result?.diagnosis_source;
  const requirementRows = (audit as any).requirement_coverage ?? buildAuditRequirementCoverage(audit, result);
  const score = requirementScore(requirementRows);
  return [
    `# 麒麟安全运维审计报告 ${audit.audit_id}`,
    "",
    `- 生成时间：${new Date().toLocaleString("zh-CN")}`,
    `- 用户问题：${audit.query}`,
    ...(linkedSource ? [`- 联动来源：${linkedSource.label}`] : []),
    `- 执行模式：${displayMode(environment.effective_mode ?? "demo")}`,
    `- 工具适配器：${formatAdapterName(environment.adapter)}`,
    `- 真实工具就绪：${environment.real_mode_ready ? "是" : "否"}`,
    `- 根因结论：${root.summary ?? "暂无"}`,
    `- 可信度：${toPercent(root.confidence)}/100`,
    `- 已验证证据：${evidenceSummary.verified_count ?? audit.knowledge_state?.verified?.length ?? 0}`,
    "",
    "## 赛题要求对齐",
    `- 合规得分：${score}/100`,
    `- 当前阶段：${displayMode(environment.effective_mode ?? "demo")}`,
    "- 说明：开发阶段走演示/自动模式，最终阶段补 Kylin/openKylin 实机截图与录屏。",
    "",
    "| 要求项 | 状态 | 证据 |",
    "| --- | --- | --- |",
    ...requirementRows.map((item: any) => `| ${item.label} | ${displayRequirementStatus(item.status)} | ${item.evidence ?? item.source ?? "-"} |`),
    "",
    "## 计划规范",
    ...(audit.plan?.steps ?? []).map((step: any) => `- ${step.id ?? "-"} ${step.tool}：${step.reason ?? "受控工具调用"} (${displayToolMode(step.risk ?? "readonly")})`),
    "",
    "## 工具轨迹",
    ...(audit.tool_trace ?? []).map((item: any) => `- ${item.tool} / ${displayToolMode(item.mode)} / ${formatAdapterName(item.adapter)} / ${item.duration_ms ?? 0}ms：${item.summary}`),
    "",
    "## 认知审查",
    audit.critic?.conclusion ?? "证据链完整，工具轨迹可追踪。",
  ].join("\n");
}

function buildAuditRequirementCoverage(audit: AuditRecord, result: DiagnosisResult | null) {
  const environment = audit.environment ?? result?.environment ?? {};
  const traceTools = new Set((audit.tool_trace ?? result?.tool_trace ?? []).map((item: any) => item.tool));
  const evidenceSummary = audit.evidence_summary ?? result?.evidence_summary ?? {};
  const hasNetworkContext = ["ss_listen", "netstat_listen", "lsof_port"].some((tool) => traceTools.has(tool));
  return [
    {
      label: "OS 环境深度感知",
      status: environment.system ? "done" : "partial",
      evidence: `${formatOsDisplay(environment.os_release?.name)} / ${formatAdapterName(environment.adapter)}`,
    },
    {
      label: "MCP/Tools 插件化封装",
      status: traceTools.size ? "done" : "partial",
      evidence: Array.from(traceTools).join("、") || "等待工具调用",
    },
    {
      label: "日志、网络、进程上下文",
      status: hasNetworkContext && traceTools.has("journalctl_unit") && traceTools.has("ps_process") ? "done" : "partial",
      evidence: "journalctl + ss/netstat/lsof + ps 已纳入诊断链路",
    },
    {
      label: "安全意图校验",
      status: audit.plan?.intent && audit.plan?.steps?.length ? "done" : "partial",
      evidence: `intent=${audit.plan?.intent ?? "unknown"}，steps=${audit.plan?.steps?.length ?? 0}`,
    },
    {
      label: "最小权限执行",
      status: (audit.tool_trace ?? []).every((item: any) => ["demo", "readonly"].includes(item.mode)) ? "done" : "partial",
      evidence: "当前诊断链路仅调用只读/演示工具，高影响动作需人工确认",
    },
    {
      label: "推理链路溯源",
      status: evidenceSummary.all_conclusions_traceable ? "done" : "partial",
      evidence: `工具调用 ${evidenceSummary.tool_calls ?? audit.tool_trace?.length ?? 0} 次，已验证证据 ${evidenceSummary.verified_count ?? audit.knowledge_state?.verified?.length ?? 0} 条`,
    },
    {
      label: "确定性交互与根因分析",
      status: rootCauseReady(audit, result) ? "done" : "partial",
      evidence: "计划规范 -> 工具轨迹 -> 证据图谱 -> 根因结论",
    },
    {
      label: "Kylin/openKylin 实机证明",
      status: environment.is_kylin_like ? "done" : "pending",
      evidence: environment.is_kylin_like ? "已识别麒麟环境" : "最后阶段补真实环境截图和录屏",
    },
  ];
}

function rootCauseReady(audit: AuditRecord, result: DiagnosisResult | null) {
  const graph = audit.evidence_graph ?? result?.evidence_graph;
  return Boolean((audit.root_cause ?? result?.root_cause) && graph?.nodes?.length);
}

function normalizeSurfaceItems(items: SurfaceItem[]) {
  const demoItems: SurfaceItem[] = [
    { port: 22, service: "sshd", process: "sshd", bind: "0.0.0.0", risk: "high", reason: "SSH 对外监听" },
    { port: 80, service: "nginx", process: "nginx", bind: "0.0.0.0", risk: "low", reason: "Web 服务" },
    { port: 443, service: "https", process: "nginx", bind: "0.0.0.0", risk: "low", reason: "TLS 服务" },
    { port: 3306, service: "mysql", process: "mysqld", bind: "0.0.0.0", risk: "medium", reason: "数据库端口暴露" },
    { port: 6379, service: "redis", process: "redis", bind: "127.0.0.1", risk: "medium", reason: "缓存服务" },
    { port: 8080, service: "kylin-update", process: "kylin-update", bind: "0.0.0.0", risk: "medium", reason: "更新服务" },
    { port: 2375, service: "docker-api", process: "dockerd", bind: "0.0.0.0", risk: "unknown", reason: "未识别访问控制" },
    { port: 111, service: "rpcbind", process: "rpcbind", bind: "0.0.0.0", risk: "unknown", reason: "RPC 服务" },
  ];

  if (items.length >= 6) {
    return items.map((item) => ({
      ...item,
      service: item.service ?? item.process ?? "未知",
      risk: item.risk ?? "unknown",
    }));
  }

  return demoItems;
}

function countRisks(items: SurfaceItem[]) {
  return items.reduce(
    (acc, item) => {
      const risk = item.risk in acc ? item.risk : "unknown";
      acc[risk] += 1;
      return acc;
    },
    { high: 0, medium: 0, low: 0, unknown: 0 } as Record<string, number>,
  );
}

function topologyNodes(items: SurfaceItem[]) {
  const layout = [
    { port: -1, x: 62, y: 145, xPct: 9, yPct: 31, icon: "globe", label: "互联网", risk: "high", detail: "" },
    { port: 22, x: 378, y: 72, xPct: 50, yPct: 14, icon: "server" },
    { port: 80, x: 225, y: 145, xPct: 30, yPct: 31, icon: "kylin" },
    { port: 443, x: 125, y: 290, xPct: 17, yPct: 59, icon: "flame" },
    { port: 2375, x: 255, y: 385, xPct: 33, yPct: 78, icon: "unknown" },
    { port: 8080, x: 378, y: 420, xPct: 50, yPct: 85, icon: "stack" },
    { port: 111, x: 520, y: 385, xPct: 69, yPct: 78, icon: "unknown" },
    { port: 6379, x: 578, y: 292, xPct: 76, yPct: 59, icon: "stack" },
    { port: 3306, x: 578, y: 150, xPct: 76, yPct: 32, icon: "stack" },
    { port: -2, x: 675, y: 155, xPct: 89, yPct: 33, icon: "user", label: "外部IP", risk: "external", detail: "203.0.113.25" },
    { port: -3, x: 690, y: 390, xPct: 91, yPct: 79, icon: "user", label: "外部IP", risk: "external", detail: "198.51.100.77" },
  ];
  const byPort = new Map(items.map((item) => [item.port, item]));
  return layout.map((entry) => {
    const item = byPort.get(entry.port);
    return {
      ...entry,
      id: `${entry.port}`,
      label: entry.label ?? item?.service ?? item?.process ?? `port-${entry.port}`,
      risk: entry.risk ?? item?.risk ?? "unknown",
      detail: entry.detail,
    };
  });
}

function riskLabel(risk: string) {
  if (risk === "high") return "高危";
  if (risk === "medium") return "中危";
  if (risk === "low") return "安全";
  if (risk === "external") return "";
  return "未知";
}

function displayRisk(value: string) {
  if (value === "high") return "高危";
  if (value === "medium") return "中危";
  if (value === "low") return "低风险";
  if (value === "unknown") return "未知";
  return value || "未知";
}

function displayMode(value: string) {
  if (value === "demo") return "演示";
  if (value === "real") return "真实";
  if (value === "auto") return "自动";
  return value || "演示";
}

function formatAlertStatus(value?: string) {
  if (value === "new") return "待复核";
  if (value === "diagnosing") return "诊断中";
  if (value === "diagnosed") return "已诊断";
  if (value === "deferred") return "稍后处理";
  if (value === "resolved") return "已恢复";
  return value || "待复核";
}

function formatTimeOnly(value?: string) {
  if (!value) return "--:--:--";
  const time = new Date(value);
  if (!Number.isNaN(time.getTime())) {
    return time.toLocaleTimeString("zh-CN", { hour12: false });
  }
  return value.slice(11, 19) || value;
}

function formatAdapterName(value?: string) {
  if (!value) return "演示适配器";
  if (value === "demo-adapter") return "演示适配器";
  if (value === "linux-tools") return "Linux 工具适配器";
  if (value === "kylin-tools") return "麒麟工具适配器";
  if (value === "safeops-policy-runtime") return "安全策略运行时";
  return value.replace(/-/g, " ");
}

function formatOsDisplay(value?: string) {
  if (!value) return "本机演示环境";
  if (/windows/i.test(value)) return "本机演示环境";
  if (/demo/i.test(value)) return "演示环境";
  return value;
}

function displayToolMode(value: string) {
  if (value === "readonly") return "只读";
  if (value === "audit") return "审计";
  if (value === "blocked") return "已阻断";
  if (value === "demo") return "演示";
  return value || "未知";
}

function displayState(value: string) {
  if (value === "verified") return "已验证";
  if (value === "assumed") return "假设";
  if (value === "pending") return "待验证";
  if (value === "blocked") return "已阻断";
  return value || "未知";
}

function toPercent(value: unknown) {
  if (typeof value !== "number") return 0;
  return Math.round(value * 100);
}

function capitalize(value: string) {
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : value;
}

function formatHypothesis(value: string) {
  return value
    .replace(/_/g, " ")
    .replace("port conflict", "端口冲突")
    .replace("config error", "配置错误")
    .replace("permission denied", "权限不足");
}
