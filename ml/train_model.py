import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.utils import shuffle
import joblib
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(BASE_DIR, "dataset.csv")

print("Loading dataset from:", csv_path)
df = pd.read_csv(csv_path)

# -----------------------------
# IMPROVED ATTACK LABEL
# -----------------------------
df["is_attack"] = (
    (df["statusCode"] >= 400) |
    (df["risk_rule"] >= 0.4) |
    (df["path"].str.contains("honeypot"))
).astype(int)

print("Attack label distribution:\n", df["is_attack"].value_counts())

# -----------------------------
# SYNTHETIC DATA GENERATION
# -----------------------------
synthetic_rows = []

roles = ["guest", "user", "admin"]
methods = ["GET", "POST"]
user_agents = ["Chrome", "Firefox", "Safari", "Edge", "Bot"]

for _ in range(300):
    role = np.random.choice(roles)
    method = np.random.choice(methods)
    ua = np.random.choice(user_agents)

    if np.random.rand() < 0.6:
        path = "/info"
        risk = 0.1
        attack = 0
    elif np.random.rand() < 0.4:
        path = "/profile"
        risk = 0.2 if role == "user" else 0.4
        attack = 0
    elif np.random.rand() < 0.2:
        path = "/admin/secret"
        risk = 0.8
        attack = 1
    else:
        path = "/honeypot/db-export"
        risk = 0.9
        attack = 1

    synthetic_rows.append({
        "method": method,
        "path": path,
        "role": role,
        "userId": "auto_user",
        "userAgent": ua,
        "risk_rule": risk,
        "is_attack": attack
    })

synthetic_df = pd.DataFrame(synthetic_rows)

# Keep only the needed columns from real df
df = df[["method","path","role","userId","userAgent","risk_rule","is_attack"]]

# Merge
df = pd.concat([df, synthetic_df], ignore_index=True)
df = shuffle(df)

print("Final dataset size:", len(df))

# -----------------------------
# ML PIPELINE
# -----------------------------
feature_cols = ["method", "path", "role", "userId", "userAgent", "risk_rule"]
X = df[feature_cols]
y = df["is_attack"]

categorical_cols = ["method", "path", "role", "userId", "userAgent"]
numeric_cols = ["risk_rule"]

preprocess = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
        ("num", "passthrough", numeric_cols),
    ]
)

model = RandomForestClassifier(
    n_estimators=150,
    max_depth=12,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42
)

clf = Pipeline(steps=[("preprocess", preprocess), ("model", model)])

# -----------------------------
# TRAIN
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

clf.fit(X_train, y_train)

print("Train accuracy:", clf.score(X_train, y_train))
print("Test accuracy:", clf.score(X_test, y_test))

model_path = os.path.join(BASE_DIR, "model.joblib")
joblib.dump(clf, model_path)
print("Saved improved model to:", model_path)
