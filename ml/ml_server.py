from fastapi import FastAPI
import joblib
import uvicorn
import os
import pandas as pd
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "model.joblib")
model = joblib.load(model_path)

app = FastAPI(title="AI-NGFW ML Scoring Service")

class RequestContext(BaseModel):
    method: str
    path: str
    role: str
    userId: str
    userAgent: str
    risk_rule: float

@app.post("/score")
def score(context: RequestContext):

    row = pd.DataFrame([{
        "method": context.method,
        "path": context.path,
        "role": context.role,
        "userId": context.userId,
        "userAgent": context.userAgent,
        "risk_rule": context.risk_rule,
    }])

    proba = float(model.predict_proba(row)[0][1])

    if proba < 0.20:
        label = "normal"
    elif proba < 0.50:
        label = "medium_risk"
    else:
        label = "high_risk"

    return {"ml_risk": proba, "ml_label": label}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
