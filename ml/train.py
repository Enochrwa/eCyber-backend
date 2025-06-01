# Individual Attack Detection Models using LightGBM
# This notebook creates binary classifiers for each attack type

import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns
from google.colab import drive
from collections import Counter
from imblearn.over_sampling import SMOTE
import warnings
warnings.filterwarnings('ignore')

# Mount Google Drive
drive.mount('/content/drive')

print("=== Individual Attack Detection Models ===")

# Load preprocessed data
print("Loading preprocessed data...")
df = pd.read_csv('/content/drive/MyDrive/CICIDS2017_preprocessed.csv')
print(f"Data loaded. Shape: {df.shape}")

# Define attack types
ATTACK_TYPES = [
    'DDoS', 'FTP-Patator', 'SSH-Patator', 'DoS slowloris', 
    'DoS Slowhttptest', 'DoS Hulk', 'DoS GoldenEye', 'Heartbleed', 
    'Web Attack – Brute Force', 'Web Attack – XSS', 'Web Attack – Sql Injection'
]

# Create models directory
models_dir = '/content/drive/MyDrive/ids_models'
os.makedirs(models_dir, exist_ok=True)

# LightGBM parameters (optimized for speed and size)
lgb_params = {
    'objective': 'binary',
    'metric': 'binary_logloss',
    'boosting_type': 'gbdt',
    'num_leaves': 31,
    'learning_rate': 0.1,
    'feature_fraction': 0.8,
    'bagging_fraction': 0.8,
    'bagging_freq': 5,
    'verbose': -1,
    'random_state': 42,
    'n_estimators': 100  # Keep it light
}

def create_binary_classifier(attack_type, df):
    """Create binary classifier for specific attack type"""
    print(f"\n=== Training {attack_type} Classifier ===")
    
    # Prepare binary labels
    y = (df['Label'] == attack_type).astype(int)
    X = df.drop('Label', axis=1)
    
    print(f"Positive samples ({attack_type}): {y.sum()}")
    print(f"Negative samples (Others): {len(y) - y.sum()}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Handle class imbalance with SMOTE (only if needed)
    class_ratio = Counter(y_train)
    if class_ratio[1] < class_ratio[0] * 0.1:  # If positive class < 10% of negative
        print("Applying SMOTE for class balancing...")
        smote = SMOTE(random_state=42, k_neighbors=min(5, class_ratio[1]-1))
        X_train_scaled, y_train = smote.fit_resample(X_train_scaled, y_train)
        print(f"After SMOTE - Positive: {sum(y_train)}, Negative: {len(y_train) - sum(y_train)}")
    
    # Train model
    print("Training LightGBM model...")
    model = lgb.LGBMClassifier(**lgb_params)
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_scaled)
    y_prob = model.predict_proba(X_test_scaled)[:, 1]
    
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    try:
        auc_score = roc_auc_score(y_test, y_prob)
        print(f"AUC Score: {auc_score:.4f}")
    except:
        auc_score = 0.5
        print("AUC Score: Could not calculate (likely due to single class in test set)")
    
    # Save model and scaler
    safe_name = attack_type.replace(' ', '_').replace('–', '-')
    model_path = f"{models_dir}/{safe_name}_model.joblib"
    scaler_path = f"{models_dir}/{safe_name}_scaler.joblib"
    
    joblib.dump(model, model_path, compress=3)
    joblib.dump(scaler, scaler_path, compress=3)
    
    print(f"Model saved: {model_path}")
    print(f"Scaler saved: {scaler_path}")
    
    return {
        'attack_type': attack_type,
        'model': model,
        'scaler': scaler,
        'auc_score': auc_score,
        'model_path': model_path,
        'scaler_path': scaler_path
    }

# Train models for each attack type
models_info = []
for attack_type in ATTACK_TYPES:
    try:
        model_info = create_binary_classifier(attack_type, df)
        models_info.append(model_info)
    except Exception as e:
        print(f"Error training {attack_type} model: {str(e)}")
        continue

print("\n=== Model Training Summary ===")
print(f"Successfully trained {len(models_info)} models:")
for info in models_info:
    print(f"  {info['attack_type']}: AUC = {info['auc_score']:.4f}")

# Create a prediction function template
prediction_code = '''
# Prediction Function for Individual Models
import joblib
import numpy as np
import pandas as pd

class AttackDetector:
    def __init__(self, models_dir):
        self.models_dir = models_dir
        self.models = {}
        self.scalers = {}
        self.attack_types = [
            'DDoS', 'FTP-Patator', 'SSH-Patator', 'DoS_slowloris', 
            'DoS_Slowhttptest', 'DoS_Hulk', 'DoS_GoldenEye', 'Heartbleed', 
            'Web_Attack_-_Brute_Force', 'Web_Attack_-_XSS', 'Web_Attack_-_Sql_Injection'
        ]
        self.load_models()
    
    def load_models(self):
        """Load all trained models and scalers"""
        for attack_type in self.attack_types:
            try:
                model_path = f"{self.models_dir}/{attack_type}_model.joblib"
                scaler_path = f"{self.models_dir}/{attack_type}_scaler.joblib"
                
                self.models[attack_type] = joblib.load(model_path)
                self.scalers[attack_type] = joblib.load(scaler_path)
                print(f"Loaded {attack_type} model")
            except Exception as e:
                print(f"Error loading {attack_type} model: {e}")
    
    def predict_single(self, features):
        """
        Predict attack type for a single network flow
        
        Args:
            features: List or array of feature values (40 features expected)
        
        Returns:
            dict: Predictions and probabilities for each attack type
        """
        if len(features) != 40:  # Adjust based on your selected features
            raise ValueError(f"Expected 40 features, got {len(features)}")
        
        features = np.array(features).reshape(1, -1)
        predictions = {}
        
        for attack_type in self.attack_types:
            if attack_type in self.models:
                # Scale features
                features_scaled = self.scalers[attack_type].transform(features)
                
                # Predict
                prob = self.models[attack_type].predict_proba(features_scaled)[0][1]
                pred = self.models[attack_type].predict(features_scaled)[0]
                
                predictions[attack_type] = {
                    'prediction': bool(pred),
                    'probability': float(prob)
                }
        
        # Find highest probability attack
        max_prob_attack = max(predictions.items(), 
                            key=lambda x: x[1]['probability'])
        
        return {
            'predictions': predictions,
            'most_likely_attack': max_prob_attack[0],
            'max_probability': max_prob_attack[1]['probability'],
            'is_attack': max_prob_attack[1]['probability'] > 0.5
        }

# Usage example:
# detector = AttackDetector('/path/to/models')
# result = detector.predict_single(feature_vector)
# print(result)
'''

# Save prediction function
with open(f"{models_dir}/prediction_template.py", 'w') as f:
    f.write(prediction_code)

print(f"\nPrediction template saved: {models_dir}/prediction_template.py")

# Create model summary file
summary_data = []
for info in models_info:
    summary_data.append({
        'Attack_Type': info['attack_type'],
        'AUC_Score': info['auc_score'],
        'Model_Path': info['model_path'],
        'Scaler_Path': info['scaler_path']
    })

summary_df = pd.DataFrame(summary_data)
summary_df.to_csv(f"{models_dir}/models_summary.csv", index=False)
print(f"Models summary saved: {models_dir}/models_summary.csv")

print("\n=== Individual Models Training Complete ===")
print("Files created:")
print(f"  - {len(models_info)} model files (.joblib)")
print(f"  - {len(models_info)} scaler files (.joblib)")
print(f"  - prediction_template.py")
print(f"  - models_summary.csv")
print(f"\nAll files are in: {models_dir}")