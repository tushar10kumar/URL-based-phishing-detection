"""
Model Training Script for URL-Based Phishing Detection.
Trains an ensemble Random Forest model on the benchmark 5,000+ real-world URL dataset.
"""

import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

from feature_extraction import FEATURE_NAMES
from generate_dataset import build_dataset

DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset", "phishing_urls.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

def train_phishing_model():
    if not os.path.exists(DATASET_PATH):
        print("[*] Generating dataset from benchmark sources...")
        build_dataset()

    print(f"[*] Loading dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    print(f"[+] Loaded {len(df)} samples ({sum(df['label'] == 1)} Phishing, {sum(df['label'] == 0)} Legitimate).")

    X = df[FEATURE_NAMES]
    y = df['label']

    # 80/20 Stratified train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Training Optimized Random Forest on {len(X_train)} samples...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=16,
        min_samples_split=4,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 55)
    print(f"       BENCHMARK MODEL EVALUATION RESULTS")
    print("=" * 55)
    print(f"Test Accuracy: {acc * 100:.2f}%\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"], digits=4))
    print("Confusion Matrix:")
    print(f"  True Negative (Legit): {cm[0][0]:<5} | False Positive: {cm[0][1]}")
    print(f"  False Negative:        {cm[1][0]:<5} | True Positive (Phish): {cm[1][1]}")
    print("=" * 55)

    # Feature Importance
    importances = clf.feature_importances_
    sorted_idx = importances.argsort()[::-1]
    print("\nFeature Importances:")
    for i in range(len(sorted_idx)):
        idx = sorted_idx[i]
        print(f"  {i+1:>2}. {FEATURE_NAMES[idx]:<26}: {importances[idx]:.4f}")

    # Save artifact
    model_data = {
        'model': clf,
        'feature_names': FEATURE_NAMES,
        'accuracy': acc
    }
    joblib.dump(model_data, MODEL_PATH)
    print(f"\n[+] Successfully saved trained benchmark model to: {MODEL_PATH}")

if __name__ == "__main__":
    train_phishing_model()
