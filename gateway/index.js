const express = require("express");
const morgan = require("morgan");
const axios = require("axios");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

const BACKEND = "http://localhost:9000";

const auditLogs = [];


app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "AI-NGFW Gateway (CP1)",
    time: new Date().toISOString(),
  });
});



function buildContext(req) {
  return {
    ip: req.ip,
    method: req.method,

    path: req.path,
    userAgent: req.headers["user-agent"] || "unknown",
    timestamp: new Date().toISOString(),
    userId: req.headers["x-user-id"] || "anonymous",
    role: req.headers["x-user-role"] || "guest",
  };
}



app.get("/admin/logs", (req, res) => {
  res.json(auditLogs);
});


app.use("/fw", async (req, res) => {
  const ctx = buildContext(req);


  const forwardPath = req.originalUrl.replace(/^\/fw/, "");
  const target = BACKEND + forwardPath;

  try {
    const response = await axios({
      method: req.method,
      url: target,
      data: req.body,
      headers: { ...req.headers, host: undefined },
      validateStatus: () => true, 
    });

    const entry = {
      time: new Date().toISOString(),
      context: ctx,

      decision: {
        allow: true,
        label: "pass_through",
      },
      targetPath: forwardPath,
      statusCode: response.status,
    };

    auditLogs.push(entry);

    return res.status(response.status).json(response.data);
  } catch (err) {
    console.error("Error forwarding to backend:", err.message);

    const errorEntry = {
      time: new Date().toISOString(),
      context: ctx,
      decision: {
        allow: false,
        label: "gateway_error",
      },
      targetPath: forwardPath,
      statusCode: 500,
      error: err.message,
    };

    auditLogs.push(errorEntry);

    return res.status(500).json({
      error: "Error forwarding to backend",
      details: err.message,
    });
  }
});


app.listen(4000, () => {
  console.log("AI-NGFW Gateway (CP1) running at http://localhost:4000");
  console.log("Forwarding all /fw/* traffic to", BACKEND);
});
