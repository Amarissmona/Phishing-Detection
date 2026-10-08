"""Train, evaluate and save a model that uses URL-only features."""
import os
import urllib.request

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_auc_score)
from sklearn.model_selection import cross_val_score, train_test_split

from features import FEATURES

CSV = "phishing_dataset.csv"
URL = ("https://raw.githubusercontent.com/GregaVrbancic/"
       "Phishing-Dataset/master/dataset_full.csv")

# Download the dataset if it is not already in the folder
if not os.path.exists(CSV):
    urllib.request.urlretrieve(URL, CSV)

df = pd.read_csv(CSV)

# Remove duplicate rows to avoid train/test leakage
before = len(df)
df = df.drop_duplicates()
print(f"Duplicates removed: {before - len(df)}")

X = df[FEATURES]
y = df["phishing"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=150, max_depth=18, n_jobs=-1, class_weight="balanced", random_state=42
)

# 5-fold cross-validation on the training set
cv = cross_val_score(model, X_train, y_train, cv=5, scoring="f1", n_jobs=-1)
print(f"5-fold CV F1: {cv.mean():.4f} +/- {cv.std():.4f}")

# Final training and evaluation on the held-out test set
model.fit(X_train, y_train)
pred = model.predict(X_test)
proba = model.predict_proba(X_test)[:, 1]

print(classification_report(y_test, pred))
print("Confusion matrix:\n", confusion_matrix(y_test, pred))
print("ROC-AUC:", round(roc_auc_score(y_test, proba), 4))

# Save the model together with its feature list
joblib.dump({"model": model, "features": FEATURES}, "phishing_model.pkl", compress=3)
print("Saved phishing_model.pkl")