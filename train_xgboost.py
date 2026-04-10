import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pickle
import os

DATA_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\ProcessedData"
MODEL_FOLDER = r"C:\Users\modey\Documents\RansomwareProject\Model"

os.makedirs(MODEL_FOLDER, exist_ok=True)

print("Loading features...")
X = np.load(os.path.join(DATA_FOLDER, 'X_features.npy'))
y = np.load(os.path.join(DATA_FOLDER, 'y_labels.npy'))

print(f"Total samples: {len(X)}")
print(f"Features per sample: {X.shape[1]}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Training: {len(X_train)}, Testing: {len(X_test)}")

print("\n=== TRAINING XGBOOST ===\n")

model = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=10,
    learning_rate=0.1,
    random_state=42,
    n_jobs=-1,
    eval_metric='logloss'
)

model.fit(X_train, y_train, verbose=True)

print("\n=== EVALUATION ===\n")

y_pred = model.predict(X_test)
y_pred_proba = model.predict_proba(X_test)

acc = accuracy_score(y_test, y_pred)
print(f"Test Accuracy: {acc*100:.2f}%")

print("\n=== CLASSIFICATION REPORT ===")
print(classification_report(y_test, y_pred, target_names=['Benign', 'Ransomware']))

print("\n=== CONFUSION MATRIX ===")
cm = confusion_matrix(y_test, y_pred)
print(f"True Negatives (Benign correctly identified): {cm[0][0]}")
print(f"False Positives (Benign flagged as Ransomware): {cm[0][1]}")
print(f"False Negatives (Ransomware missed): {cm[1][0]}")
print(f"True Positives (Ransomware correctly detected): {cm[1][1]}")

# Feature importance
print("\n=== TOP 10 MOST IMPORTANT FEATURES ===")
feature_importance = model.feature_importances_
top_10_idx = np.argsort(feature_importance)[-10:][::-1]
for i, idx in enumerate(top_10_idx, 1):
    if idx < 256:
        feature_name = f"Byte_{idx}_frequency"
    elif idx == 256:
        feature_name = "Entropy"
    elif idx == 257:
        feature_name = "File_size"
    else:
        feature_name = "Printable_ratio"
    print(f"{i}. {feature_name}: {feature_importance[idx]:.4f}")

# Save model
model_path = os.path.join(MODEL_FOLDER, 'ransomware_detector_xgboost.pkl')
with open(model_path, 'wb') as f:
    pickle.dump(model, f)

print(f"\n✅ MODEL SAVED: {model_path}")
print(f"Model size: {os.path.getsize(model_path) / 1024 / 1024:.2f} MB")