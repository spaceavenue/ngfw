import React, { useEffect, useState } from "react";
import axios from "axios";
import {
  AppBar,
  Toolbar,
  Typography,
  Container,
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from "@mui/material";

const GATEWAY_URL = "http://localhost:4000";

function App() {
  const [logs, setLogs] = useState([]);

  // ---------- LOAD LOGS FROM GATEWAY ----------

  const loadLogs = async () => {
    try {
      const res = await axios.get(`${GATEWAY_URL}/admin/logs`);
      setLogs(res.data || []);
    } catch (err) {
      console.error("Error fetching logs", err);
    }
  };

  useEffect(() => {
    loadLogs();
    const id = setInterval(loadLogs, 1000);
    return () => clearInterval(id);
  }, []);

  // ---------- BASIC STATS ----------

  const totalRequests = logs.length;
  const allowedCount = logs.filter(
    (e) => e.statusCode !== undefined && e.statusCode < 400
  ).length;

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
    if (p.length > 40) return p.slice(0, 37) + "...";
    return p;
  };

  const displayLogs = [...logs].sort(
    (a, b) => new Date(b.time) - new Date(a.time)
  );

  return (
    <>
      <AppBar position="static" color="primary">
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            AI–NGFW Dashboard (CP1)
          </Typography>
          <Typography variant="body2">
            Simple pass-through logging view
          </Typography>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
        {/* Top stats row */}
        <Box sx={{ display: "flex", gap: 2, mb: 3, flexWrap: "wrap" }}>
          <Paper sx={{ flex: 1, p: 2, background: "#111827", color: "white" }}>
            <Typography variant="subtitle2">Total Requests</Typography>
            <Typography variant="h4">{totalRequests}</Typography>
          </Paper>
          <Paper sx={{ flex: 1, p: 2, background: "#065f46", color: "white" }}>
            <Typography variant="subtitle2">Allowed</Typography>
            <Typography variant="h4">{allowedCount}</Typography>
          </Paper>
        </Box>

        {/* Logs table */}
        <Paper sx={{ p: 2, background: "#020617" }}>
          <Typography variant="h6" color="white" sx={{ mb: 2 }}>
            Gateway Traffic Logs
          </Typography>

          <TableContainer sx={{ maxHeight: 500 }}>
            <Table stickyHeader size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    Time
                  </TableCell>
                  <TableCell sx={{ color: "white", background: "#020617" }}>
                    Method
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
                    Status
                  </TableCell>
                </TableRow>
              </TableHead>

              <TableBody>
                {displayLogs.map((entry, idx) => (
                  <TableRow key={idx}>
                    <TableCell sx={{ color: "white" }}>
                      {formatTime(entry.time)}
                    </TableCell>
                    <TableCell sx={{ color: "white" }}>
                      {entry.context?.method || "-"}
                    </TableCell>
                    <TableCell sx={{ color: "white" }}>
                      {shortPath(entry.context?.path)}
                    </TableCell>
                    <TableCell sx={{ color: "white" }}>
                      {entry.context?.userId || "anonymous"}
                    </TableCell>
                    <TableCell sx={{ color: "white" }}>
                      {entry.context?.role || "guest"}
                    </TableCell>
                    <TableCell sx={{ color: "white" }}>
                      {entry.statusCode ?? "-"}
                    </TableCell>
                  </TableRow>
                ))}

                {displayLogs.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={6}
                      sx={{ color: "white", textAlign: "center" }}
                    >
                      No traffic yet. Call the API via the dummy app to see
                      logs here.
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
