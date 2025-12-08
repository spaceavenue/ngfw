const express = require("express");
const morgan = require("morgan");
const axios = require("axios");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

const BACKEND = "http://localhost:9000";
const auditLogs = [];

// ================= STATEFUL CONNECTION TRACKING =================
const connectionState = new Map(); // IP -> session state
const MAX_REQS_PER_MIN = 100; // Rate limiting baseline
const SUSPICIOUS_CIPHERS = ['TLS_AES_128_GCM_SHA256', 'TLS_CHACHA20_POLY1305_SHA256']; // Weak/modern ciphers trigger analysis

function getConnectionState(ip) {
  if (!connectionState.has(ip)) {
    connectionState.set(ip, {
      reqCount: 0,
      lastReq: Date.now(),
      tlsFingerprint: null,
      sni: null,
      cipherSuites: [],
      sessionId: crypto.randomUUID(),
      riskBoost: 0
    });
  }
  return connectionState.get(ip);
}

function updateConnectionState(ip, tlsInfo = {}) {
  const state = getConnectionState(ip);
  state.reqCount++;
  state.lastReq = Date.now();
  
  // Rate limiting check
  const minuteAgo = Date.now() - 60000;
  if ((state.lastReq - minuteAgo) / 60000 > 1) {
    state.reqCount = 1; // Reset window
  }
  
  // TLS fingerprinting (JA3-like from ClientHello)
  if (tlsInfo.ja3 || tlsInfo.sni || tlsInfo.cipher) {
    state.tlsFingerprint = tlsInfo.ja3 || state.tlsFingerprint;
    state.sni = tlsInfo.sni || state.sni;
    state.cipherSuites.push(tlsInfo.cipher);
    
    // Risk boost for suspicious TLS patterns
    if (SUSPICIOUS_CIPHERS.includes(tlsInfo.cipher)) {
      state.riskBoost += 0.15;
    }
    if (state.cipherSuites.length > 10) { // Rapid cipher negotiation
      state.riskBoost += 0.25;
    }
  }
  
  // Decay risk boost over time
  if (Date.now() - state.lastReq > 300000) { // 5min
    state.riskBoost *= 0.9;
  }
  
  connectionState.set(ip, state);
  return state;
}

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "AI-NGFW Gateway (DPI-Enhanced)",
    time: new Date().toISOString(),
    activeConnections: connectionState.size
  });
});

function buildContext(req) {
  const ip = req.ip || req.connection.remoteAddress;
  const state = updateConnectionState(ip, {
    ja3: req.headers['x-tls-ja3'], // From reverse proxy
    sni: req.headers['x-tls-sni'],
    cipher: req.headers['x-tls-cipher']
  });
  
  return {
    ip,
    method: req.method,
    path: req.path,
    userAgent: req.headers["user-agent"] || "unknown",
    timestamp: new Date().toISOString(),
    userId: req.headers["x-user-id"] || "anonymous",
    role: req.headers["x-user-role"] || "guest",
    sessionId: state.sessionId,
    reqRate: state.reqCount,
    tlsFingerprint: state.tlsFingerprint,
    tlsRisk: state.riskBoost,
    connAge: Date.now() - state.lastReq
  };
}

// -------------- ENHANCED RULE RISK ENGINE (DPI-AWARE) --------------
async function checkRiskRule(ctx) {
  let risk = 0.0;
  const reasons = [];

  // Original rules preserved
  if (!ctx.userId || ctx.userId === "anonymous") {
    risk += 0.2;
    reasons.push("no_user_id");
  }
  if (ctx.path.startsWith("/admin")) {
    risk += 0.5;
    reasons.push("admin_path");
  }
  if (ctx.path.startsWith("/admin") && ctx.role === "guest") {
    risk += 0.3;
    reasons.push("guest_on_admin_path");
  }
  if (ctx.path.startsWith("/honeypot")) {
    risk += 0.8;
    reasons.push("honeypot_path");
  }

  // ================= NEW DPI/STATEFUL RULES =================
  // Rate limiting anomaly
  if (ctx.reqRate > MAX_REQS_PER_MIN) {
    risk += 0.4;
    reasons.push("rate_limit_exceeded");
  }
  
  // Suspicious TLS fingerprint
  if (ctx.tlsRisk > 0.3) {
    risk += ctx.tlsRisk;
    reasons.push("suspicious_tls_fingerprint");
  }
  
  // Session hijacking (new session on sensitive path)
  if (ctx.path.startsWith("/admin") && ctx.connAge < 5000) {
    risk += 0.35;
    reasons.push("new_session_sensitive_path");
  }

  let label = "normal";
  if (risk >= 0.7) label = "high_risk";
  else if (risk >= 0.4) label = "medium_risk";

  return { risk, label, reasons };
}

// -------------- ML RISK ENGINE (Enhanced with DPI data) ----------------
async function scoreWithML(ctx) {
  try {
    const res = await axios.post(
      "http://localhost:5000/score",
      {
        method: ctx.method,
        path: ctx.path,
        role: ctx.role,
        userId: ctx.userId,
        userAgent: ctx.userAgent,
        risk_rule: ctx.risk_rule,
        tls_fingerprint: ctx.tlsFingerprint,
        req_rate: ctx.reqRate,
        tls_risk: ctx.tlsRisk
      },
      { validateStatus: () => true }
    );
    return {
      ml_risk: res.data.ml_risk,
      ml_label: res.data.ml_label,
    };
  } catch (err) {
    console.error("ML service error:", err.message);
    return { ml_risk: 0.0, ml_label: "normal" };
  }
}

// ---------------- RBAC TABLE -------------------
const RBAC = {
  guest: {
    allow: ["/info"],
    deny: ["/admin", "/admin/secret", "/admin/*"],
  },
  user: {
    allow: ["/info", "/profile"],
    deny: ["/admin", "/admin/*"],
  },
  admin: {
    allow: ["*"],
    deny: [],
  },
};

function checkRBAC(role, pathReq) {
  const rules = RBAC[role] || RBAC["guest"];
  if (pathReq.startsWith("/honeypot")) return true;
  if (rules.allow.includes("*")) return true;

  for (const d of rules.deny) {
    if (pathReq.startsWith(d.replace("*", ""))) return false;
  }
  for (const a of rules.allow) {
    if (pathReq.startsWith(a.replace("*", ""))) return true;
  }
  return false;
}

// -------------- ADMIN ENDPOINTS ---------------
app.get("/admin/logs", (req, res) => {
  res.json(auditLogs);
});

app.get("/admin/connections", (req, res) => {
  res.json(Array.from(connectionState.entries()).map(([ip, state]) => ({
    ip,
    reqCount: state.reqCount,
    tlsFingerprint: state.tlsFingerprint,
    riskBoost: state.riskBoost
  })));
});

// ================= MAIN FIREWALL MIDDLEWARE =================
app.use("/fw", async (req, res, next) => {
  const ctx = buildContext(req);
  const forwardPath = req.originalUrl.replace(/^\/fw/, "");
  const target = BACKEND + forwardPath;

  // Run risk engines
  const ruleDecision = await checkRiskRule(ctx);
  const ml = await scoreWithML({ ...ctx, risk_rule: ruleDecision.risk });
  const finalRisk = Math.max(ruleDecision.risk, ml.ml_risk);
  const finalLabel = finalRisk >= 0.7 ? "high_risk" : finalRisk >= 0.4 ? "medium_risk" : "normal";

  // RBAC check
  const rbacAllowed = checkRBAC(ctx.role, forwardPath);

  const entry = {
    time: new Date().toISOString(),
    context: ctx,
    decision: {
      allow: rbacAllowed && finalRisk < 0.9,
      label: finalLabel,
      rbac: rbacAllowed,
      risk: finalRisk
    },
    targetPath: forwardPath,
    ruleRisk: ruleDecision.risk,
    mlRisk: ml.ml_risk,
    reasons: ruleDecision.reasons
  };

  auditLogs.push(entry);

  // BLOCK high-risk or RBAC violations
  if (!rbacAllowed || finalRisk >= 0.9) {
    return res.status(403).json({
      error: "Access denied by AI-NGFW",
      reason: !rbacAllowed ? "RBAC violation" : "High risk score",
      risk: finalRisk,
      reasons: ruleDecision.reasons
    });
  }

  try {
    const response = await axios({
      method: req.method,
      url: target,
      data: req.body,
      headers: { ...req.headers, host: undefined },
      validateStatus: () => true,
    });

    // Add security headers
    res.set("x-ngfw-rule-risk", ruleDecision.risk.toString());
    res.set("x-ngfw-ml-risk", ml.ml_risk.toString());
    res.set("x-ngfw-tls-risk", ctx.tlsRisk.toString());
    res.set("x-ngfw-final-risk", finalRisk.toString());
    res.set("x-ngfw-label", finalLabel);

    return res.status(response.status).json(response.data);
  } catch (err) {
    console.error("Error forwarding to backend:", err.message);
    const errorEntry = { ...entry, statusCode: 500, error: err.message };
    auditLogs.push(errorEntry);
    return res.status(500).json({
      error: "Error forwarding to backend",
      details: err.message,
    });
  }
});

app.listen(4000, () => {
  console.log("AI-NGFW Gateway (DPI-Enhanced) running at http://localhost:4000");
  console.log("New endpoints: /admin/connections for stateful tracking");
});
