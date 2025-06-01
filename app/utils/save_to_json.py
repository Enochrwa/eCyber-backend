import json
import psutil
from datetime import datetime
import os


def save_telemetry_to_json(telemetry,file_path="telemetry_log.json"):

    # Load existing data if file exists
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    data.append(telemetry)

    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)

    print(f"Telemetry data saved to {file_path}")


def save_http_data_to_json(telemetry, file_path="http_data_log.json"):

    # Load existing data if file exists
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    data.append(telemetry)

    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)

    print(f"http_data data saved to {file_path}")
    
    
def save_packet_data_to_json(packets, file_path="packets_data_log.json"):

    # Load existing data if file exists
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    data.append(packets)

    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)

    print(f"packets data saved to {file_path}")
    
    
def save_features_to_json(packets, file_path="extracted_features.json"):

    # Load existing data if file exists
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    data.append(packets)

    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)

    print(f"features added to {file_path}")
    
def save_feature_vectors_to_json(packets, file_path="extracted_feature_vectors.json"):

    # Load existing data if file exists
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    data.append(packets)

    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)

    print(f"feature vectors added to {file_path}")
