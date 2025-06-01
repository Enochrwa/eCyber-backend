import os
import json
from pathlib import Path
from datetime import datetime
from fastapi import APIRouter, HTTPException

router = APIRouter()

# Define paths to model directories
BASE_MODEL_PATH = Path("backend/ml/models")
CLASSIFIER_MODELS_PATH = BASE_MODEL_PATH / "eCyber_classifier_models"
ANOMALY_MODEL_PATH = BASE_MODEL_PATH / "eCyber_anomaly_isolation"

@router.get("/list", summary="List all ML models", description="Retrieves a list of all machine learning models with their metadata.")
async def list_models():
    models_data = []

    # Process Classifier Models
    if CLASSIFIER_MODELS_PATH.exists() and CLASSIFIER_MODELS_PATH.is_dir():
        for model_dir in CLASSIFIER_MODELS_PATH.iterdir():
            if model_dir.is_dir():
                model_name = model_dir.name
                metrics_path = model_dir / "metrics.json"
                training_path = model_dir / "training.json"
                model_file_path = model_dir / "model.pkl.gz"
                scaler_file_path = model_dir / "scaler.pkl.gz" # Assuming scaler has a standard name

                metrics_data = {}
                if metrics_path.exists():
                    with open(metrics_path, 'r') as f:
                        metrics_data = json.load(f)

                training_data = {}
                if training_path.exists():
                    with open(training_path, 'r') as f:
                        training_data = json.load(f)

                last_trained = None
                if model_file_path.exists():
                    try:
                        last_trained_timestamp = model_file_path.stat().st_mtime
                        last_trained = datetime.fromtimestamp(last_trained_timestamp).isoformat()
                    except Exception:
                        last_trained = None # Fallback if modification time cannot be read

                model_info = {
                    "id": model_name, # Assuming model_name is unique
                    "name": model_name.replace("_", " ").title(),
                    "status": "active", # Default status
                    "accuracy": metrics_data.get("accuracy"),
                    "lastTrained": last_trained,
                    "description": metrics_data.get("description", f"Classifier model: {model_name}"),
                    "type": metrics_data.get("model_type", model_name.split('_')[0].upper()), # Infer type or get from metrics
                    "features": training_data.get("features_list", []), # training.json might contain "features_list"
                    "model_file": str(model_file_path),
                    "scaler_file": str(scaler_file_path) if scaler_file_path.exists() else None,
                    "metadata_file": str(metrics_path) if metrics_path.exists() else None,
                    "auc": metrics_data.get("auc"),
                    "precision": metrics_data.get("precision"),
                    "recall": metrics_data.get("recall"),
                    "f1Score": metrics_data.get("f1_score"), # metrics.json might use "f1_score"
                    "confusionMatrixData": metrics_data.get("confusion_matrix"), # metrics.json might contain "confusion_matrix"
                    "featureImportanceData": training_data.get("feature_importance") # training.json might contain "feature_importance"
                }
                models_data.append(model_info)

    # Process Anomaly Model
    anomaly_meta_file = ANOMALY_MODEL_PATH / "anomaly_meta.json"
    anomaly_model_file = ANOMALY_MODEL_PATH / "anomaly_model.pkl" # Assuming standard name
    
    if anomaly_meta_file.exists():
        with open(anomaly_meta_file, 'r') as f:
            anomaly_meta = json.load(f)

        last_trained_anomaly = None
        if anomaly_model_file.exists():
            try:
                last_trained_timestamp = anomaly_model_file.stat().st_mtime
                last_trained_anomaly = datetime.fromtimestamp(last_trained_timestamp).isoformat()
            except Exception:
                last_trained_anomaly = None

        anomaly_model_info = {
            "id": anomaly_meta.get("model_id", "anomaly_detector"),
            "name": anomaly_meta.get("model_name", "Anomaly Detection Model"),
            "status": "active",
            "accuracy": anomaly_meta.get("accuracy"), # Or relevant performance metric
            "lastTrained": last_trained_anomaly,
            "description": anomaly_meta.get("description", "Detects anomalies in network traffic."),
            "type": anomaly_meta.get("model_type", "IsolationForest"), # Default or from meta
            "features": anomaly_meta.get("features", []),
            "model_file": str(anomaly_model_file) if anomaly_model_file.exists() else None,
            "scaler_file": None, # Anomaly models might not always have a separate scaler
            "metadata_file": str(anomaly_meta_file),
            "auc": anomaly_meta.get("auc"), # Anomaly models might have different metrics
            "precision": anomaly_meta.get("precision"),
            "recall": anomaly_meta.get("recall"),
            "f1Score": anomaly_meta.get("f1_score"),
            "confusionMatrixData": anomaly_meta.get("confusion_matrix"), # Might not be applicable or available
            "featureImportanceData": None # Typically not available for Isolation Forest
        }
        models_data.append(anomaly_model_info)
    
    if not models_data:
        # You could return a 404 if no models are found, or an empty list.
        # For now, returning an empty list.
        pass

    return models_data
