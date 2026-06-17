const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

export async function diagnose(query: string, source?: Record<string, unknown>) {
  const response = await fetch(`${API_BASE}/api/agent/diagnose`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(source ? {query, source} : {query})
  });

  if (!response.ok) {
    throw new Error("diagnose request failed");
  }

  return response.json();
}

export async function getReplay(replayId: string) {
  const response = await fetch(`${API_BASE}/api/replay/${replayId}`);

  if (!response.ok) {
    throw new Error("replay request failed");
  }

  return response.json();
}

export async function getAudit(auditId: string) {
  const response = await fetch(`${API_BASE}/api/audit/${auditId}`);

  if (!response.ok) {
    throw new Error("audit request failed");
  }

  return response.json();
}

export async function listAudits(limit = 30) {
  const response = await fetch(`${API_BASE}/api/audit?limit=${limit}`);

  if (!response.ok) {
    throw new Error("audit list request failed");
  }

  return response.json();
}

export async function exportAuditMarkdown(auditId: string) {
  const response = await fetch(`${API_BASE}/api/audit/${auditId}/export`);

  if (!response.ok) {
    throw new Error("audit export request failed");
  }

  return response.text();
}

export async function getDashboardSummary() {
  const response = await fetch(`${API_BASE}/api/dashboard/summary`);

  if (!response.ok) {
    throw new Error("dashboard request failed");
  }

  return response.json();
}

export async function getEnvironmentProbe() {
  const response = await fetch(`${API_BASE}/api/environment/probe`);

  if (!response.ok) {
    throw new Error("environment probe request failed");
  }

  return response.json();
}

export async function getShadowPreview(service = "nginx") {
  const response = await fetch(`${API_BASE}/api/shadow/preview`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({service})
  });

  if (!response.ok) {
    throw new Error("shadow preview request failed");
  }

  return response.json();
}

export async function runRedTeam() {
  const response = await fetch(`${API_BASE}/api/redteam/run`, {method: "POST"});

  if (!response.ok) {
    throw new Error("redteam request failed");
  }

  return response.json();
}

export async function getAttackSurface() {
  const response = await fetch(`${API_BASE}/api/attack-surface`);

  if (!response.ok) {
    throw new Error("attack surface request failed");
  }

  return response.json();
}

export async function getRuntimeAlerts() {
  const response = await fetch(`${API_BASE}/api/runtime/alerts`);

  if (!response.ok) {
    throw new Error("runtime alerts request failed");
  }

  return response.json();
}

export async function runRuntimeScan() {
  const response = await fetch(`${API_BASE}/api/runtime/scan`, {method: "POST"});

  if (!response.ok) {
    throw new Error("runtime scan request failed");
  }

  return response.json();
}

export async function updateRuntimeAlertStatus(eventId: string, status: string, linkedAuditId?: string) {
  const response = await fetch(`${API_BASE}/api/runtime/alerts/${eventId}/status`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({status, linked_audit_id: linkedAuditId}),
  });

  if (!response.ok) {
    throw new Error("runtime alert status request failed");
  }

  return response.json();
}
