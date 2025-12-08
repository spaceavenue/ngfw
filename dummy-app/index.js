const express = require("express");
const morgan = require("morgan");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

// ---------------- BASIC DUMMY BACKEND ----------------

// This is the backend that our AI–NGFW gateway is protecting.
// For CP1 it's intentionally simple and does not use a database yet.

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "Dummy backend (CP1)",
    time: new Date().toISOString(),
  });
});

app.get("/info", (req, res) => {
  res.json({
    message: "Public info from dummy backend",
    version: "cp1",
  });
});

app.get("/profile", (req, res) => {
  // In a real app this would depend on the authenticated user.
  res.json({
    user: "demo-user",
    plan: "basic",
    features: ["view_profile", "view_public_info"],
  });
});

app.get("/admin/secret", (req, res) => {
  res.json({
    message: "Top secret admin data from dummy backend.",
    tip: "Your firewall should eventually protect this path more strictly.",
  });
});

// ---------------- START SERVER -------------------

const PORT = 9000;
app.listen(PORT, () => {
  console.log(`Dummy backend (CP1) running at http://localhost:${PORT}`);
});
