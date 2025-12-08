import React, { useEffect, useState } from "react";
import axios from "axios";
import {
  AppBar,
  Toolbar,
  Typography,
  Container,
  Box,
  Paper,
  Button,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  ToggleButton,
  ToggleButtonGroup,
} from "@mui/material";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  ResponsiveContainer,
} from "recharts";

const GATEWAY_URL = "http://localhost:4000";

function App() {
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState("all");
  const [chainOK, setChainOK] = useState(true);

  // ---------- LOAD LOGS FROM GATEWAY ----------

  const loadLogs = async () => {
    try {
      const res = await axios.get(`${GATEWAY_URL}/admin/logs`);
      setLogs(res.data || []);
    } catch (err) {
      console.error("Error fetching logs", err);
      alert("Could not load logs from gateway.");
    }
  };

  useEffect(() => {
    loadLogs();
    // refresh every 1s to make the feed feel "live"
    const id = setInterval(loadLogs, 1000);
    return () => clearInterval(id);
  }, []);

  // ---------- CHAIN INTEGRITY STATUS ----------

  const checkChainStatus = async () => {
    try {
      const res = await axios.get(`${GATEWAY_URL}/verify-chain`);
      setChainOK(!!res.data.valid);
    } catch (err) {
      console.error("Error checking chain status", err);
      setChainOK(false);
    }
  };

  useEffect(() => {
    checkChainStatus();
    const id = setInterval(checkChainStatus, 5000);
    return () => clearInterval(id);
  }, []);

  // ---------- TRAFFIC SIMULATOR HELPERS ----------

  const simulateRequest = async ({ path, userId, role }) => {
    try {
      console.log("Simulating", { path, userId, role });

      const res = await axios.get(`${GATEWAY_URL}/fw${path}`, {
        headers: {
          "x-user-id": userId,
          "x-user-role": role,
        },
        // accept all HTTP codes (200, 403, 500...) as non-errors
        validateStatus: () => true,
      });

      console.log("Simulation response status:", res.status);
      await loadLogs();
    } catch (err) {
      if (!err.response) {
        alert(
          "Simulation request failed. Check that gateway + backend are running."
        );
      }
      console.error("Simulation error:", err);
    }
  };

  const simulateNormalUserInfo = () =>
    simulateRequest({ path: "/info", userId: "alice", role: "user" });

  const simulateSuspiciousGuestAdmin = () =>
    simulateRequest({
      path: "/admin/secret",
      userId: "anonymous",
      role: "guest",
    });

  const simulateGuestAdminRBAC = () =>
    simulateRequest({
      path: "/admin/secret",
      userId: "guest123",
      role: "guest",
    });

  // ---------- EXPORT LOGS (JSON / CSV) ----------

  const handleExport = async (format) => {
    try {
      const res = await axios.get(
        `${GATEWAY_URL}/admin/logs/export?format=${format}`,
        {
          responseType: "blob", // get file as Blob
        }
      );

      const blob = res.data;
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = url;
      link.download = format === "csv" ? "logs.csv" : "logs.json";

      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Error exporting logs", err);
      alert("Failed to export logs. Check gateway console for details.");
    }
  };

  // ---------- FILTERED LOGS + STATS ----------

  const filteredLogs = logs.filter((entry) => {
    if (filter === "all") return true;
    if (filter === "allowed") return entry.statusCode && entry.statusCode < 400;
    if (filter === "blocked") return entry.statusCode && entry.statusCode >= 400;
    return true;
  });

  // NEWEST FIRST for table + live feed
  const displayLogs = [...filteredLogs].sort(
    (a, b) => new Date(b.time) - new Date(a.time)
  );

  const totalRequests = logs.length;
  const allowedCount = logs.filter(
    (e) => e.statusCode && e.statusCode < 400
  ).length;
  const highRiskCount = logs.filter(
    (e) =>
      e.decision &&
      (e.decision.label === "high_risk" || e.decision.label === "rbac_block")
  ).length;

  // ---------- PER-USER SUMMARY ----------

  const userSummaryMap = {};

  logs.forEach((e) => {
    const uid = e.context?.userId || "anonymous";
    if (!userSummaryMap[uid]) {
      userSummaryMap[uid] = { total: 0, blocked: 0, highRisk: 0 };
    }
    userSummaryMap[uid].total += 1;

    if (e.statusCode && e.statusCode >= 400) {
      userSummaryMap[uid].blocked += 1;
    }

    if (
      e.decision &&
      (e.decision.label === "high_risk" ||
        e.decision.label === "rbac_block")
    ) {
      userSummaryMap[uid].highRisk += 1;
    }
  });

  const userSummary = Object.entries(userSummaryMap).map(([userId, stats]) => ({
    userId,
    ...stats,
  }));

  // ---------- HELPERS ----------

  const formatTime = (iso) => {
    if (!iso) return "-";
    try {
      return new Date(iso).toLocaleTimeString();
    } catch {
      return iso;
    }
  };

  const shortPath = (p) => {
    if (!p) return "/";
    if (p.length > 30) return p.slice(0, 27) + "...";
    return p;
  };

  // ---------- ANALYTICS DATA (for charts) ----------

  // Sort logs by time ASC for timeline
  const logsSortedByTime = [...logs].sort(
    (a, b) => new Date(a.time) - new Date(b.time)
  );

  const timeSeriesData = logsSortedByTime.map((e, idx) => {
    const risk = e.decision?.risk ?? 0;
    const isAllowed =
      e.statusCode && e.statusCode < 400 ? 1 : 0;
    const isBlocked =
      e.statusCode && e.statusCode >= 400 ? 1 : 0;

    return {
      index: idx + 1,
      timeLabel: formatTime(e.time),
      risk,
      allowed: isAllowed,
      blocked: isBlocked,
    };
  });

  // Aggregate per-path stats
  const pathMap = {};
  logs.forEach((e) => {
    const p = e.context?.path || "/";
    if (!pathMap[p]) {
      pathMap[p] = { path: p, total: 0, allowed: 0, blocked: 0 };
    }
    pathMap[p].total += 1;
    if (e.statusCode && e.statusCode < 400) {
      pathMap[p].allowed += 1;
    } else if (e.statusCode && e.statusCode >= 400) {
      pathMap[p].blocked += 1;
    }
  });
  const pathStats = Object.values(pathMap);

  // ---------- UI ----------

  return (
    <>
      <AppBar position="static" color="primary">
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            AI–NGFW Dashboard
          </Typography>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
        {/* Stats cards */}
        <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
          <Paper sx={{ flex: 1, p: 2, background: "#111827", color: "white" }}>
            <Typography variant="subtitle2">Total Requests</Typography>
            <Typography variant="h4">{totalRequests}</Typography>
          </Paper>
          <Paper sx={{ flex: 1, p: 2, background: "#065f46", color: "white" }}>
            <Typography variant="subtitle2">Allowed</Typography>
            <Typography variant="h4">{allowedCount}</Typography>
          </Paper>
          <Paper sx={{ flex: 1, p: 2, background: "#7f1d1d", color: "white" }}>
            <Typography variant="subtitle2">High-Risk / RBAC Blocks</Typography>
            <Typography variant="h4">{highRiskCount}</Typography>
          </Paper>
          <Paper
            sx={{
              flex: 1,
              p: 2,
              background: chainOK ? "#064e3b" : "#b91c1c",
              color: "white",
            }}
          >
            <Typography variant="subtitle2">Log Integrity</Typography>
            <Typography variant="h4">
              {chainOK ? "Verified" : "TAMPERED!"}
            </Typography>
          </Paper>
        </Box>

        {/* ANALYTICS: Risk over time + Requests per path */}
        <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
          {/* Risk over time */}
          <Paper
            sx={{
              flex: 1,
              p: 2,
              minWidth: 300,
              background: "#020617",
              color: "white",
            }}
          >
            <Typography variant="h6" gutterBottom>
              Risk Over Time
            </Typography>
            <Typography variant="body2" sx={{ mb: 1, color: "#9ca3af" }}>
              Shows how the combined risk score changes across recent requests.
            </Typography>
            {timeSeriesData.length === 0 ? (
              <Typography variant="body2" sx={{ color: "#6b7280" }}>
                No data yet. Generate some traffic to see the risk trend.
              </Typography>
            ) : (
              <Box sx={{ width: "100%", height: 260 }}>
                <ResponsiveContainer>
                  <LineChart data={timeSeriesData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="timeLabel" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Line
                      type="monotone"
                      dataKey="risk"
                      name="Final Risk"
                      dot={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </Box>
            )}
          </Paper>

          {/* Requests per path */}
          <Paper
            sx={{
              flex: 1,
              p: 2,
              minWidth: 300,
              background: "#020617",
              color: "white",
            }}
          >
            <Typography variant="h6" gutterBottom>
              Requests per Path
            </Typography>
            <Typography variant="body2" sx={{ mb: 1, color: "#9ca3af" }}>
              Compare how many requests were allowed vs blocked for each path.
            </Typography>
            {pathStats.length === 0 ? (
              <Typography variant="body2" sx={{ color: "#6b7280" }}>
                No data yet. Generate some traffic to see per-path stats.
              </Typography>
            ) : (
              <Box sx={{ width: "100%", height: 260 }}>
                <ResponsiveContainer>
                  <BarChart data={pathStats}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="path" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="allowed" name="Allowed" />
                    <Bar dataKey="blocked" name="Blocked" />
                  </BarChart>
                </ResponsiveContainer>
              </Box>
            )}
          </Paper>
        </Box>

        {/* TOP ROW: Live Feed + Traffic Simulator */}
        <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
          {/* Live Traffic Feed */}
          <Paper
            sx={{
              flex: 2,
              p: 2,
              background: "#020617",
              color: "white",
              fontFamily: "monospace",
            }}
          >
            <Typography variant="h6" gutterBottom>
              Live Traffic Feed
            </Typography>
            <Typography variant="body2" sx={{ mb: 1, color: "#9ca3af" }}>
              Newest events at the top. Use the simulator or hit the API to see
              real-time firewall decisions.
            </Typography>

            <Box
              sx={{
                mt: 1,
                maxHeight: 200,
                overflowY: "auto",
                borderRadius: 1,
                border: "1px solid #1f2937",
                p: 1,
                background: "#020617",
              }}
            >
              {displayLogs.slice(0, 10).map((entry, idx) => {
                const isAllowed =
                  entry.statusCode && entry.statusCode < 400;
                const finalLabel = entry.decision?.label || "normal";
                const mlLabel = entry.decision?.ml_label || "normal";

                return (
                  <Box
                    key={idx}
                    sx={{
                      display: "flex",
                      alignItems: "center",
                      gap: 1,
                      mb: 0.5,
                      fontSize: 12,
                    }}
                  >
                    <span style={{ color: "#6b7280" }}>
                      [{formatTime(entry.time)}]
                    </span>
                    <span>
                      {entry.context?.method || "GET"}{" "}
                      {shortPath(entry.context?.path)}
                    </span>
                    <span style={{ color: "#9ca3af" }}>
                      (user: {entry.context?.userId || "?"},{" "}
                      role: {entry.context?.role || "?"})
                    </span>
                    <span>
                      {isAllowed ? (
                        <span style={{ color: "#4ade80" }}>→ ALLOWED</span>
                      ) : (
                        <span style={{ color: "#f87171" }}>→ BLOCKED</span>
                      )}
                    </span>
                    <span style={{ color: "#e5e7eb" }}>
                      [{finalLabel} / ML: {mlLabel}]
                    </span>
                  </Box>
                );
              })}

              {displayLogs.length === 0 && (
                <Typography variant="body2" sx={{ color: "#6b7280" }}>
                  No traffic yet. Use the simulator buttons on the right to
                  generate some live events.
                </Typography>
              )}
            </Box>
          </Paper>

          {/* Traffic Simulator */}
          <Paper
            sx={{
              flex: 1,
              p: 2,
              background: "#020617",
              color: "white",
              minWidth: 260,
            }}
          >
            <Typography variant="h6" gutterBottom>
              Traffic Simulator
            </Typography>
            <Typography variant="body2" sx={{ mb: 2, color: "#9ca3af" }}>
              Use these buttons during the presentation to generate live traffic
              and show how the firewall reacts.
            </Typography>

            <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
              <Button
                variant="contained"
                color="success"
                onClick={simulateNormalUserInfo}
              >
                NORMAL USER → /INFO (ALLOWED)
              </Button>

              <Button
                variant="contained"
                color="warning"
                onClick={simulateSuspiciousGuestAdmin}
              >
                SUSPICIOUS GUEST → /ADMIN/SECRET (HIGH RISK BLOCK)
              </Button>

              <Button
                variant="contained"
                color="error"
                onClick={simulateGuestAdminRBAC}
              >
                GUEST → /ADMIN/SECRET (RBAC BLOCK)
              </Button>
            </Box>
          </Paper>
        </Box>

        {/* Logs table */}
        <Paper sx={{ p: 2, background: "#020617" }}>
          <Box
            sx={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              mb: 2,
              gap: 2,
            }}
          >
            <Typography variant="h6" color="white">
              Firewall Traffic Logs
            </Typography>

            <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
              {/* Export buttons */}
              <Button
                variant="outlined"
                size="small"
                onClick={() => handleExport("json")}
                sx={{
                  borderColor: "#4b5563",
                  color: "white",
                  "&:hover": { borderColor: "#9ca3af" },
                }}
              >
                Export JSON
              </Button>
              <Button
                variant="outlined"
                size="small"
                onClick={() => handleExport("csv")}
                sx={{
                  borderColor: "#4b5563",
                  color: "white",
                  "&:hover": { borderColor: "#9ca3af" },
                }}
              >
                Export CSV
              </Button>

              {/* Filter buttons */}
              <ToggleButtonGroup
                value={filter}
                exclusive
                onChange={(_, v) => v && setFilter(v)}
                size="small"
                color="primary"
              >
                <ToggleButton
                  value="all"
                  sx={{
                    color: "white",
                    borderColor: "#4b5563",
                    "&.Mui-selected": {
                      backgroundColor: "#2563eb",
                      color: "#fff",
                    },
                  }}
                >
                  ALL
                </ToggleButton>
                <ToggleButton
                  value="allowed"
                  sx={{
                    color: "white",
                    borderColor: "#4b5563",
                    "&.Mui-selected": {
                      backgroundColor: "#16a34a",
                      color: "#fff",
                    },
                  }}
                >
                  ALLOWED
                </ToggleButton>
                <ToggleButton
                  value="blocked"
                  sx={{
                    color: "white",
                    borderColor: "#4b5563",
                    "&.Mui-selected": {
                      backgroundColor: "#b91c1c",
                      color: "#fff",
                    },
                  }}
                >
                  BLOCKED
                </ToggleButton>
              </ToggleButtonGroup>
            </Box>
          </Box>

          <TableContainer sx={{ maxHeight: 420 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    Time
                  </TableCell>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    Path
                  </TableCell>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    User
                  </TableCell>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    Role
                  </TableCell>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    Risk (Final)
                  </TableCell>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    ML Label
                  </TableCell>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    Decision
                  </TableCell>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    Status
                  </TableCell>
                </TableRow>
              </TableHead>

              <TableBody>
                {displayLogs.map((entry, idx) => (
                  <TableRow key={idx}>
                    <TableCell sx={{ color: "white" }}>{entry.time}</TableCell>
                    <TableCell sx={{ color: "white" }}>
                      {entry.context?.path}
                    </TableCell>
                    <TableCell sx={{ color: "white" }}>
                      {entry.context?.userId}
                    </TableCell>
                    <TableCell sx={{ color: "white" }}>
                      {entry.context?.role}
                    </TableCell>

                    {/* Final combined risk label */}
                    <TableCell sx={{ color: "white" }}>
                      <Chip
                        label={entry.decision?.label || "normal"}
                        size="small"
                        color={
                          entry.decision?.label === "high_risk" ||
                          entry.decision?.label === "rbac_block"
                            ? "error"
                            : entry.decision?.label === "medium_risk"
                            ? "warning"
                            : "success"
                        }
                      />
                    </TableCell>

                    {/* ML label from model */}
                    <TableCell sx={{ color: "white" }}>
                      <Chip
                        label={entry.decision?.ml_label || "normal"}
                        size="small"
                        variant="outlined"
                        color={
                          entry.decision?.ml_label === "high_risk"
                            ? "error"
                            : entry.decision?.ml_label === "medium_risk"
                            ? "warning"
                            : "success"
                        }
                      />
                    </TableCell>

                    {/* Allowed / Blocked */}
                    <TableCell sx={{ color: "white" }}>
                      <Chip
                        label={
                          entry.statusCode && entry.statusCode < 400
                            ? "Allowed"
                            : "Blocked"
                        }
                        size="small"
                        color={
                          entry.statusCode && entry.statusCode < 400
                            ? "success"
                            : "error"
                        }
                      />
                    </TableCell>

                    {/* Status code */}
                    <TableCell sx={{ color: "white" }}>
                      {entry.statusCode}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* PER-USER RISK SUMMARY */}
        <Paper sx={{ p: 2, background: "#020617", mt: 3 }}>
          <Typography variant="h6" color="white" sx={{ mb: 2 }}>
            Per-User Risk Summary
          </Typography>
          <TableContainer sx={{ maxHeight: 260 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    User
                  </TableCell>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    Total Requests
                  </TableCell>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    Blocked
                  </TableCell>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    High-Risk / RBAC Blocks
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {userSummary.map((u) => (
                  <TableRow key={u.userId}>
                    <TableCell sx={{ color: "white" }}>{u.userId}</TableCell>
                    <TableCell sx={{ color: "white" }}>{u.total}</TableCell>
                    <TableCell sx={{ color: "white" }}>{u.blocked}</TableCell>
                    <TableCell sx={{ color: "white" }}>{u.highRisk}</TableCell>
                  </TableRow>
                ))}
                {userSummary.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={4}
                      sx={{ color: "white", textAlign: "center" }}
                    >
                      No data yet. Generate some traffic to see user risk
                      summary.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      </Container>
    </>
  );
}

export default App;