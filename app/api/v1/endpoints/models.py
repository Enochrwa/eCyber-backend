from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import pathlib
import json
from datetime import datetime
import os
import logging

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


router = APIRouter()


# Define Pydantic model for the response
class ModelInfo(BaseModel):
    id: str
    name: str
    type: str  # Algorithm type e.g. XGBoost
    description: str
    accuracy: Optional[float] = None
    f1_score: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    auc: Optional[float] = None
    confusion_matrix_data: Optional[List[Dict[str, Any]]] = None
    lastTrained: Optional[str] = None  # ISO datetime string
    features: List[str] = []
    model_file: str  # Filename
    scaler_file: str  # Filename
    metadata_file: str  # Filename
    status: str = "active"  # Default status


# Define paths to model directories
CLASSIFIER_MODELS_METRICS_DIR = (
    pathlib.Path(__file__).resolve().parent.parent.parent.parent.parent
    / "ml"
    / "models"
    / "eCyber_classifier_models"
)
ANOMALY_MODELS_DIR = (
    pathlib.Path(__file__).resolve().parent.parent.parent.parent.parent
    / "ml"
    / "models"
    / "eCyber_anomaly_isolation"
)


def get_file_mod_time(file_path: pathlib.Path) -> Optional[str]:
    """Gets the last modification time of a file as an ISO string, or None if not found."""
    try:
        mod_timestamp = os.path.getmtime(file_path)
        return datetime.fromtimestamp(mod_timestamp).isoformat() + "Z"
    except FileNotFoundError:
        logger.warning(
            f"File not found when trying to get modification time: {file_path}"
        )
        return None
    except Exception as e:
        logger.error(f"Error getting modification time for {file_path}: {e}")
        return None


@router.get("/list", response_model=List[ModelInfo])
async def list_models():
    """
    Lists available ML models and their metadata by scanning specific model directories.
    """
    model_infos: List[ModelInfo] = []

    # Process Classifier Models
    if (
        CLASSIFIER_MODELS_METRICS_DIR.exists()
        and CLASSIFIER_MODELS_METRICS_DIR.is_dir()
    ):
        logger.info(
            f"Scanning for classifier models in: {CLASSIFIER_MODELS_METRICS_DIR}"
        )
        for model_dir in CLASSIFIER_MODELS_METRICS_DIR.iterdir():
            if model_dir.is_dir():
                model_name_from_dir = model_dir.name
                model_id = model_name_from_dir  # Use directory name as ID

                metrics_json_path = model_dir / "metrics.json"
                training_json_path = model_dir / "training.json"
                model_pkl_path = model_dir / "model.pkl.gz"
                scaler_pkl_path = model_dir / "scaler.pkl.gz"

                # Initialize defaults
                accuracy, f1_score, precision, recall, auc, confusion_matrix_data = (
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                algorithm, features_list, last_trained_str = "Unknown", [], None
                description = f"Machine learning model for {model_name_from_dir.replace('_', ' ').title()} analysis."
                display_name = model_name_from_dir.replace("_", " ").title()
                metadata_filename = "metrics.json"

                if not metrics_json_path.exists():
                    logger.warning(
                        f"Metrics file ({metrics_json_path}) not found for classifier model {model_name_from_dir}. Skipping this model."
                    )
                    continue  # Essential metrics are missing

                try:
                    with open(metrics_json_path, "r", encoding="utf-8") as f:
                        metrics_data = json.load(f)
                    logger.info(
                        f"Successfully loaded metrics from {metrics_json_path} for {model_name_from_dir}"
                    )

                    accuracy = metrics_data.get("accuracy")
                    f1_score = metrics_data.get("f1_score")
                    precision = metrics_data.get("precision")
                    recall = metrics_data.get("recall")
                    auc = metrics_data.get("auc")
                    raw_cm = metrics_data.get("confusion_matrix")
                    if isinstance(raw_cm, list) and all(
                        isinstance(row, list) for row in raw_cm
                    ):
                        confusion_matrix_data = [
                            {"label": f"Actual Class {i}", "values": row_values}
                            for i, row_values in enumerate(raw_cm)
                        ]
                    else:
                        logger.warning(
                            f"Confusion matrix for {model_id} in {metrics_json_path} is not in the expected format. Raw: {raw_cm}"
                        )

                except json.JSONDecodeError:
                    logger.error(
                        f"Malformed JSON in metrics file: {metrics_json_path}",
                        exc_info=True,
                    )
                    continue  # Skip if metrics JSON is unreadable
                except Exception as e:
                    logger.error(
                        f"Could not process metrics file {metrics_json_path}: {e}",
                        exc_info=True,
                    )
                    continue

                if training_json_path.exists():
                    try:
                        with open(training_json_path, "r", encoding="utf-8") as f:
                            training_data = json.load(f)
                        algorithm = training_data.get("algorithm", algorithm)
                        features_list = training_data.get("features", features_list)
                        if isinstance(features_list, str):
                            features_list = [
                                f.strip() for f in features_list.split(",") if f.strip()
                            ]
                        last_trained_str = training_data.get(
                            "training_date", last_trained_str
                        )
                        # Potentially override display_name or description if present in training.json
                        display_name = training_data.get("name", display_name)
                        description = training_data.get("description", description)
                    except json.JSONDecodeError:
                        logger.error(
                            f"Malformed JSON in training file: {training_json_path}",
                            exc_info=True,
                        )
                    except Exception as e:
                        logger.error(
                            f"Could not process training file {training_json_path}: {e}",
                            exc_info=True,
                        )
                else:
                    logger.warning(
                        f"Training.json not found for {model_name_from_dir} at {training_json_path}. Using defaults."
                    )

                if not last_trained_str and model_pkl_path.exists():
                    last_trained_str = get_file_mod_time(model_pkl_path)

                model_info = ModelInfo(
                    id=model_id,
                    name=display_name,
                    type=algorithm,
                    description=description,
                    accuracy=float(accuracy) if accuracy is not None else None,
                    f1_score=f1_score,
                    precision=precision,
                    recall=recall,
                    auc=auc,
                    confusion_matrix_data=confusion_matrix_data,
                    lastTrained=last_trained_str,
                    features=features_list,
                    model_file="model.pkl.gz" if model_pkl_path.exists() else "N/A",
                    scaler_file="scaler.pkl.gz" if scaler_pkl_path.exists() else "N/A",
                    metadata_file=metadata_filename,  # primarily metrics.json
                    status="active",
                )
                model_infos.append(model_info)
                logger.debug(f"Successfully processed classifier model: {model_id}")
    else:
        logger.warning(
            f"Classifier models directory not found or is not a directory: {CLASSIFIER_MODELS_METRICS_DIR}"
        )

    # Process Anomaly Isolation Model
    if ANOMALY_MODELS_DIR.exists() and ANOMALY_MODELS_DIR.is_dir():
        # logger.info(f"Scanning for anomaly model in: {ANOMALY_MODELS_DIR}")
        anomaly_meta_path = ANOMALY_MODELS_DIR / "anomaly_meta.json"
        model_pkl_path = ANOMALY_MODELS_DIR / "anomaly_model.pkl.gz"
        scaler_pkl_path = ANOMALY_MODELS_DIR / "anomaly_scaler.pkl.gz"

        model_id = ANOMALY_MODELS_DIR.name
        display_name = model_id.replace("_", " ").title()
        description = f"Machine learning model for {display_name} analysis."
        algorithm, features_list, last_trained_str, accuracy = "Unknown", [], None, None
        metadata_filename = "anomaly_meta.json"

        if anomaly_meta_path.exists():
            try:
                with open(anomaly_meta_path, "r", encoding="utf-8") as f:
                    meta_data = json.load(f)
                logger.info(
                    f"Successfully loaded metadata from {anomaly_meta_path} for {model_id}"
                )

                algorithm = meta_data.get("algorithm", algorithm)
                features_list = meta_data.get("features", features_list)
                if isinstance(features_list, str):
                    features_list = [
                        f.strip() for f in features_list.split(",") if f.strip()
                    ]
                last_trained_str = meta_data.get("training_date", last_trained_str)
                accuracy = meta_data.get(
                    "threshold", meta_data.get("accuracy")
                )  # Use threshold as accuracy
                display_name = meta_data.get("name", display_name)
                description = meta_data.get("description", description)

            except json.JSONDecodeError:
                logger.error(
                    f"Malformed JSON in anomaly metadata file: {anomaly_meta_path}",
                    exc_info=True,
                )
            except Exception as e:
                logger.error(
                    f"Could not process anomaly metadata file {anomaly_meta_path}: {e}",
                    exc_info=True,
                )
        else:
            logger.warning(
                f"Anomaly metadata file ({anomaly_meta_path}) not found for {model_id}. Using defaults."
            )

        if not last_trained_str and model_pkl_path.exists():
            last_trained_str = get_file_mod_time(model_pkl_path)

        model_info = ModelInfo(
            id=model_id,
            name=display_name,
            type=algorithm,
            description=description,
            accuracy=float(accuracy) if accuracy is not None else None,
            f1_score=None,  # Typically not applicable or not provided for basic anomaly
            precision=None,
            recall=None,
            auc=None,
            confusion_matrix_data=None,
            lastTrained=last_trained_str,
            features=features_list,
            model_file="anomaly_model.pkl.gz" if model_pkl_path.exists() else "N/A",
            scaler_file="anomaly_scaler.pkl.gz" if scaler_pkl_path.exists() else "N/A",
            metadata_file=metadata_filename,
            status="active",
        )
        model_infos.append(model_info)
        logger.debug(f"Successfully processed anomaly model: {model_id}")
    else:
        logger.warning(
            f"Anomaly model directory not found or is not a directory: {ANOMALY_MODELS_DIR}"
        )

    if not model_infos:
        logger.info("No models found after scanning all configured directories.")

    return model_infos


# Example usage (for local testing if needed, not part of the FastAPI app itself)
# ... (Keep example usage code block if desired, but ensure it's updated or removed if no longer relevant)
# For this refactoring, the old example usage based on MODEL_BUNDLE_DIR is no longer directly applicable.
# A new test setup would be needed to reflect the new directory structure if local testing of list_models is desired here.
# For now, let's assume the example block will be removed or updated separately.
# The provided diff will implicitly remove it if it's part of the SEARCH block.
# (The old example usage block is removed as part of this refactoring)
