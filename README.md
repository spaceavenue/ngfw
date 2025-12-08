# AI-NGFW — AI-Powered Next-Generation Firewall

A Smart India Hackathon 2025 Project

AI-NGFW is an intelligent API-layer firewall that protects backend services using:

- RBAC (Role-Based Access Control)

- AI Risk Analysis (Rule-based + ML model)

- Tamper-Evident Blockchain-Style Audit Logs

- Real-Time Monitoring Dashboard (React + MUI)

- Live Traffic Feed and User Risk Analytics

This system sits between the client and back-end and evaluates every request before forwarding it.

## Features 
### 1. Intelligent Request Filtering

- RBAC-based access control

- Rule-based risk engine (path, privilege, suspicious behavior)

- ML-assisted risk scoring

### 2. AI Risk Engine

- Two layered analysis:

	- Rule Engine → detects known risky patterns

	- Machine Learning Model → detects statistical anomalies

	- Final risk = max(ruleRisk, mlRisk)

### 3. Tamper-Proof Audit Logging

Every request is added as a block in an append-only, hash-linked chain. Each block contains:

- timestamp, context, decision, status

- prevHash → hash chain

`/verify-chain endpoint` validates integrity

Corrupted/missing blocks are instantly detected

### 4. Real-Time Admin Dashboard (React)

Live monitoring features:

- Traffic Feed (auto-updating)

- Total Requests / Allowed / High-Risk / Integrity Status

- Per-User Risk Summary

- Log Explorer

- Built-in Traffic Simulator (for demo)
## Folder Structure

 ai-ngfw/
├── gateway/ # Node.js firewall gateway
│    ├── gateway.js # main firewall logic
│    ├── package.json
│    ├── ... 
├── admin-dashboard/ # React dashboard (MUI + axios)
│    ├── src/
│    ├── public/
│    ├── package.json
├── ml/ `// ML service`
│    ├── ml_server.py
│    ├── train_model.py 
│    ├── model.joblib
│    ├── dataset.csv 
└── README.md

## Installation & Setup

1. Clone the repository:
```
	`git clone https://github.com/Sh-real29/Ai-driven-Ngfw.git`
	`cd Ai-driven-Ngfw`
```

2. 3️Start the gateway (firewall component):
```
	cd gateway
	npm install
	node gateway.js
```

- Gateway runs on port 4000: `http://localhost:4000`

3. Start the back-end app:
```
	cd dummy-app
	npm install
	node index.js
```

4. Start the ML component:
```
	cd ml
	python ml_server.py
```

5. Start the dummy website:
```
	cd dummy-site
	npm install 
	npm start
```

6. Start the admin dashboard:
```
	cd admin-dashboard
	npm install
	npm start
```

- Dashboard runs on port 3000: `http://localhost:3000`

## Traffic Simulator (Built-In)

From the dashboard, you can try to access:

- Normal User → /info

 - Suspicious Guest → /admin/secret

 - Unauthorized Guest → /admin/secret (RBAC Block)

These generate live logs and show risk behavior.

## API Endpoints at `https:/localhost:4000/fw/*`

Main gateway endpoints. Forwards request to dummy website only if allowed.

- /admin/logs

	Get in-memory logs.

- /verify-chain

	Full blockchain-style tamper-check.

- /admin/chain/status

	Lightweight integrity indicator.

-  /health

	Gateway health check.

## Tech Stack:
- ### Backend:

	- Node.js (Express)

	- Axios

	- Crypto (SHA-256 hashing)

- ### Frontend

	- React

	- Material-UI (MUI)

	- Axios

	- Realtime Log Streaming

	- AI / ML

	- Python (Flask)

	- scikit-learn

	- joblib

## Team

This project was built as part of Smart India Hackathon 2025 Team Name:

### Members:

- Nimit Hirani

- Bishwanath Kumam

- Shreya Kumari

- Farwa Fatma

- Shubham Saini

- Nitin Kumar Verma

## Future Scope

- Explainable AI for risk decisions

- Geographic threat visualization

- Adaptive self-learning firewall rules

## Final Notes

This repository contains the full working version of the AI-NGFW system. For hackathon demo purposes, additional simplified prototype screens or disabled features may be shown depending on the stage (mid-eval vs final).