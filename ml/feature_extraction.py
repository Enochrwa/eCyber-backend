import json
from collections.abc import MutableMapping,MutableSequence
from typing import Any, Dict, List, Union
import inspect

def map_to_cicids2017_features(event: dict) -> dict:
    """
    Converts your custom schema to match CICIDS2017's 80+ feature names.
    Preserves all original data while aligning with CICIDS2017's naming conventions.
    """
    feature_map = {
        # Network Layer
        'network_metrics_source_port': 'Src Port',
        'network_metrics_destination_port': 'Dst Port',
        'network_metrics_protocol': 'Protocol',
        'network_metrics_packet_size': 'TotLen Fwd Pkts',
        'network_metrics_inter_arrival_time': 'Flow IAT Mean',
        'network_metrics_tcp_metrics_flags_ack': 'ACK Flag Cnt',
        'network_metrics_tcp_metrics_flags_syn': 'SYN Flag Cnt',
        'network_metrics_ttl': 'Bwd Header Len',
        
        # Behavioral Indicators
        'behavioral_indicators_unusual_timing_rapid_requests': 'Fwd Pkt/s',
        'behavioral_indicators_protocol_violations_invalid_method': 'Invalid Method Count',
        
        # Security Headers
        'header_analysis_security_headers_missing_csp': 'Missing Security Headers',
        'header_analysis_header_manipulation_invalid_format': 'Header Format Errors',
        
        # Session Context
        'session_context_flow_duration': 'Flow Duration',
        'session_context_request_count_total_requests': 'Tot Fwd Pkts',
        'network_metrics_bytes_per_second': 'Flow Bytes/s',
        
        # Threat Analysis
        'threat_analysis_threat_score': 'Label'  # Map to attack labels
    }

    # Create CICIDS2017-compatible dict with default values
    cicids_data = {v: 0 for v in feature_map.values()}

    # Direct mappings
    for custom_feat, cicids_feat in feature_map.items():
        if custom_feat in event:
            cicids_data[cicids_feat] = event[custom_feat]

    # Special handling for threat labels
    if 'threat_analysis_risk_level' in event:
        cicids_data['Label'] = 1 if event['threat_analysis_risk_level'] in ['medium','high'] else 0

    # Preserve all original data in '_original' namespace
    cicids_data['_original'] = event

    return cicids_data


def map_to_cse_cic_ids2018_features(event: dict) -> dict:
    """
    Converts your schema to match CSE-CIC-IDS2018's enhanced feature set.
    Maintains full backward compatibility with your original structure.
    """
    reverse_feature_map = {
        # Network Features
        "Src Port": "network_metrics_source_port",
        "Dst Port": "network_metrics_destination_port",
        "Protocol": "network_metrics_protocol",
        "Flow Duration": "session_context_flow_duration",
        "Tot Fwd Pkts": "session_context_request_count_total_requests",
        "Bwd Header Len": "network_metrics_ttl",
        # Advanced Features
        "Fwd Pkt Len Mean": "network_metrics_packet_size",
        "Flow Bytes/s": "network_metrics_bytes_per_second",
        "Init Fwd Win Byts": "network_metrics_tcp_metrics_window_size",
        # Security Features
        "Header Format Errors": "header_analysis_header_manipulation_invalid_format",
        "Missing Security Headers": "header_analysis_security_headers_missing_csp",
        # Behavioral Features
        "Fwd Pkt/s": "behavioral_indicators_unusual_timing_rapid_requests",
        "Idle Mean": "behavioral_indicators_unusual_timing_slowloris_indicator",
    }

    # Initialize with default CSE-CIC-IDS2018 structure
    cse_cic_data = {k: 0 for k in reverse_feature_map.keys()}

    # Map known features
    for cse_feat, custom_feat in reverse_feature_map.items():
        if custom_feat in event:
            cse_cic_data[cse_feat] = event[custom_feat]

    # Handle nested structures
    cse_cic_data["Timestamp"] = event.get("timestamp", "")
    cse_cic_data["Source IP"] = event.get("source_ip", "")
    cse_cic_data["Destination IP"] = event.get("destination_ip", "")

    # Convert threat indicators
    if "threat_analysis_contributing_indicators" in event:
        cse_cic_data["Attack Type"] = ", ".join(
            event["threat_analysis_contributing_indicators"]
        )

    # Preserve original data hierarchy
    cse_cic_data["Custom Features"] = event

    return cse_cic_data


def flatten_complex_data(
    data: Any,
    parent_key: str = "",
    separator: str = ".",
    max_depth: int = 20,
    current_depth: int = 0,
    preserve_methods: bool = True,
    visited_objects: List[int] = None,
) -> Dict[str, Any]:
    """
    Flatten complex nested data structures (dicts, lists, objects) into a single level dictionary.

    Args:
        data: The complex nested data structure to flatten
        parent_key: Used for recursion to build nested keys
        separator: String to separate keys in the flattened output
        max_depth: Maximum recursion depth to prevent stack overflow
        current_depth: Current recursion depth (used internally)
        preserve_methods: Whether to preserve methods in the output
        visited_objects: List of object ids to prevent circular references

    Returns:
        A flattened dictionary where keys represent the path to the value in the original structure
    """
    if visited_objects is None:
        visited_objects = []

    if current_depth >= max_depth:
        return {
            parent_key: f"[Max depth {max_depth} reached]" if parent_key else str(data)
        }

    flattened = {}

    # Handle dictionaries and dictionary-like objects
    if isinstance(data, MutableMapping):
        # Avoid circular references
        if id(data) in visited_objects:
            flattened[parent_key] = "[Circular reference]"
            return flattened

        visited_objects.append(id(data))

        for k, v in data.items():
            new_key = f"{parent_key}{separator}{k}" if parent_key else str(k)
            flattened.update(
                flatten_complex_data(
                    v,
                    new_key,
                    separator,
                    max_depth,
                    current_depth + 1,
                    preserve_methods,
                    visited_objects.copy(),
                )
            )

    # Handle lists, tuples, and other sequence-like objects
    elif isinstance(data, (MutableSequence, tuple)) and not isinstance(data, str):
        # Avoid circular references
        if id(data) in visited_objects:
            flattened[parent_key] = "[Circular reference]"
            return flattened

        visited_objects.append(id(data))

        for i, item in enumerate(data):
            new_key = f"{parent_key}{separator}{i}" if parent_key else str(i)
            flattened.update(
                flatten_complex_data(
                    item,
                    new_key,
                    separator,
                    max_depth,
                    current_depth + 1,
                    preserve_methods,
                    visited_objects.copy(),
                )
            )

    # Handle objects with attributes
    elif hasattr(data, "__dict__") or hasattr(data, "__slots__"):
        # Avoid circular references
        if id(data) in visited_objects:
            flattened[parent_key] = "[Circular reference]"
            return flattened

        visited_objects.append(id(data))

        # Get all attributes including properties
        attrs = {}

        # Handle regular attributes
        if hasattr(data, "__dict__"):
            attrs.update(data.__dict__)

        # Handle slots
        if hasattr(data, "__slots__"):
            for slot in data.__slots__:
                if hasattr(data, slot):
                    attrs[slot] = getattr(data, slot)

        # Handle properties
        for name, value in inspect.getmembers(data):
            if isinstance(value, property):
                try:
                    attrs[name] = value.fget(data)
                except Exception:
                    attrs[name] = "[Property access error]"

        # Handle methods if preserve_methods is True
        if preserve_methods:
            for name, member in inspect.getmembers(data):
                if inspect.ismethod(member) or inspect.isfunction(member):
                    attrs[name] = member

        # Recursively flatten the attributes
        for k, v in attrs.items():
            new_key = f"{parent_key}{separator}{k}" if parent_key else str(k)
            flattened.update(
                flatten_complex_data(
                    v,
                    new_key,
                    separator,
                    max_depth,
                    current_depth + 1,
                    preserve_methods,
                    visited_objects.copy(),
                )
            )

    # Handle primitive types
    else:
        if parent_key:
            flattened[parent_key] = data
        else:
            flattened["value"] = data

    return flattened


def unflatten_data(flattened_data: Dict[str, Any], separator: str = ".") -> Any:
    """
    Reconstruct the original nested structure from flattened data.

    Args:
        flattened_data: The flattened dictionary to unflatten
        separator: The separator used in the flattened keys

    Returns:
        The reconstructed nested data structure
    """
    result = {}

    for key, value in flattened_data.items():
        parts = key.split(separator)
        current = result

        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]

        current[parts[-1]] = value

    # Convert numeric keys to lists where appropriate
    def convert_to_lists(data):
        if isinstance(data, dict):
            # Check if all keys are numeric strings that could form a contiguous list
            keys = [k for k in data.keys() if isinstance(k, str) and k.isdigit()]
            if len(keys) == len(data) and all(int(k) in range(len(keys)) for k in keys):
                return [convert_to_lists(data[str(i)]) for i in range(len(keys))]
            else:
                return {k: convert_to_lists(v) for k, v in data.items()}
        return data

    return convert_to_lists(result)


# Example usage with the telemetry data
if __name__ == "__main__":
    # Sample complex nested data (simplified version of your telemetry data)
    complex_data = {
        "timestamp": "2025-05-21T16:04:24.161455",
        "cpu": {
            "cores": {"logical": 4, "physical": 2},
            "frequency": {"current": 1190, "max": 1190, "min": 0},
            "load_avg": None,
            "times": {
                "dpc": 0.7,
                "idle": 65,
                "interrupt": 0.7,
                "system": 8.4,
                "user": 25.2,
            },
            "usage": 24.3,
        },
        "memory": {
            "available": 484749312,
            "percent": 94.2,
            "swap": {"percent": 19.1, "total": 8589934592, "used": 1636409344},
            "total": 8361132032,
            "used": 7876382720,
        },
        "processes": [
            {
                "pid": 0,
                "name": "System Idle Process",
                "user": "NT AUTHORITY\\SYSTEM",
                "cpu": 0,
                "cmdline": "",
            },
            {
                "pid": 4,
                "name": "System",
                "user": "NT AUTHORITY\\SYSTEM",
                "cpu": 0,
                "memory": 0.11027329749981873,
            },
        ],
    }


def flatten_data(
    data: Union[Dict, List, Any],
    parent_key: str = '',
    sep: str = '.',
    preserve_objects: bool = True,
    max_depth: int = 20,
    current_depth: int = 0
) -> Dict[str, Any]:
    """
    Flatten a nested dictionary or list into a single level dictionary with compound keys.
    
    Args:
        data: The input data to flatten (dict, list, or other)
        parent_key: Used internally for recursion (prefix for keys)
        sep: Separator between key levels
        preserve_objects: If True, will preserve non-serializable objects as strings
        max_depth: Maximum recursion depth to prevent stack overflow
        current_depth: Used internally to track recursion depth
        
    Returns:
        A flattened dictionary with compound keys
    """
    if current_depth >= max_depth:
        return {parent_key: str(data) if preserve_objects else data}
    
    items: Dict[str, Any] = {}
    
    if isinstance(data, MutableMapping):
        # Handle dictionaries
        for k, v in data.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, (MutableMapping, list)):
                items.update(flatten_data(v, new_key, sep, preserve_objects, max_depth, current_depth + 1))
            else:
                # Handle special cases for non-serializable objects
                try:
                    json.dumps(v)
                    items[new_key] = v
                except (TypeError, ValueError):
                    items[new_key] = str(v) if preserve_objects else v
    elif isinstance(data, list):
        # Handle lists
        for i, v in enumerate(data):
            new_key = f"{parent_key}{sep}{i}" if parent_key else str(i)
            if isinstance(v, (MutableMapping, list)):
                items.update(flatten_data(v, new_key, sep, preserve_objects, max_depth, current_depth + 1))
            else:
                try:
                    json.dumps(v)
                    items[new_key] = v
                except (TypeError, ValueError):
                    items[new_key] = str(v) if preserve_objects else v
    else:
        # Handle primitive types and objects
        try:
            json.dumps(data)
            items[parent_key] = data
        except (TypeError, ValueError):
            items[parent_key] = str(data) if preserve_objects else data
    
    return items


def analyze_and_flatten(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Advanced function that analyzes and flattens complex security event data,
    preserving methods and special attributes while making the structure more accessible.
    
    Args:
        data: The input security event data
        
    Returns:
        A flattened dictionary with all data and methods preserved
    """
    # First flatten the main structure
    flattened = flatten_data(data, sep='_')
    
    # Handle special cases and preserve methods
    for key, value in data.items():
        if callable(value) and key not in flattened:
            flattened[f'method_{key}'] = str(value)
    
    # Add metadata about the flattening process
    flattened['_flattened_original_type'] = type(data).__name__
    flattened['_flattened_keys_count'] = len(flattened)
    
    return flattened


def extract_http_features(packet):
    return {
        # Threat Indicators
        "threat_score": packet["threat_analysis"].get("threat_score", 0),
        "risk_level": packet["threat_analysis"].get("risk_level", "none") == "high",
        # Behavioral Indicators
        "beaconing": int(packet["behavioral_indicators"]["beaconing"]),
        "rapid_requests": int(
            packet["behavioral_indicators"]["unusual_timing"]["rapid_requests"]
        ),
        "slowloris": int(
            packet["behavioral_indicators"]["unusual_timing"]["slowloris_indicator"]
        ),
        "invalid_method": int(
            packet["behavioral_indicators"]["protocol_violations"].get(
                "invalid_method", False
            )
        ),
        # Header Analysis
        "invalid_format": int(
            packet["header_analysis"]["header_manipulation"]["invalid_format"]
        ),
        "unusual_casing": int(
            packet["header_analysis"]["header_manipulation"]["unusual_casing"]
        ),
        "missing_csp": int(
            packet["header_analysis"]["security_headers"]["missing_csp"]
        ),
        "missing_hsts": int(
            packet["header_analysis"]["security_headers"]["missing_hsts"]
        ),
        # Payload Characteristics
        "entropy": packet["payload_characteristics"].get("entropy", 0),
        "non_printable_ratio": packet["payload_characteristics"].get(
            "non_printable_ratio", 0
        ),
        "printable_ratio": packet["payload_characteristics"].get("printable_ratio", 0),
        "compression_ratio": packet["payload_characteristics"].get(
            "compression_ratio", 0
        ),
        "header_field_count": packet["payload_characteristics"].get(
            "header_field_count", 0
        ),
        "header_length": packet["payload_characteristics"].get("header_length", 0),
        # TCP Metrics
        "window_ratio": packet["tcp_metrics"]["seq_analysis"].get("window_ratio", 0),
        "window_size": packet["tcp_metrics"].get("window_size", 0),
        "ack_flag": int(packet["tcp_metrics"]["flags"].get("ack", False)),
        "psh_flag": int(packet["tcp_metrics"]["flags"].get("psh", False)),
        # Network Metrics
        "packet_size": packet["network_metrics"].get("packet_size", 0),
        "inter_arrival_time": packet["network_metrics"].get("inter_arrival_time", 0),
        "bytes_per_second": packet["network_metrics"].get("bytes_per_second", 0),
        "packets_per_second": packet["network_metrics"].get("packets_per_second", 0),
        # Session Context
        "flow_duration": packet["session_context"].get("flow_duration", 0),
        "total_requests": packet["session_context"].get("total_requests", 0),
        "protocol_http_ratio": packet["session_context"]["protocol_distribution"].get(
            "HTTP", 0
        ),
        # Contextual
        "method_CONNECT": int(packet.get("method", "") == "CONNECT"),
        "user_agent_contains_electron": int(
            "Electron" in str(packet.get("user_agent", ""))
        ),
    }


def extract_system_telemetry_features(telemetry):
    cpu = telemetry["cpu"]
    memory = telemetry["memory"]
    disk = telemetry["disk"]
    net = telemetry["network"]
    sec = telemetry["security"]

    return {
        # CPU Metrics
        "cpu_usage": cpu["usage"],
        "cpu_user": cpu["times"]["user"],
        "cpu_system": cpu["times"]["system"],
        "cpu_idle": cpu["times"]["idle"],
        "cpu_interrupt": cpu["times"]["interrupt"],
        # Memory Metrics
        "memory_used": memory["used"],
        "memory_available": memory["available"],
        "memory_percent": memory["percent"],
        "swap_percent": memory["swap"]["percent"],
        # Disk Metrics
        "disk_read_bytes": disk["io"]["read_bytes"],
        "disk_write_bytes": disk["io"]["write_bytes"],
        "disk_read_time": disk["io"]["read_time"],
        "disk_write_time": disk["io"]["write_time"],
        # Network I/O
        "net_bytes_recv": net["io"]["bytes_recv"],
        "net_bytes_sent": net["io"]["bytes_sent"],
        "net_packets_recv": net["io"]["packets_recv"],
        "net_packets_sent": net["io"]["packets_sent"],
        # Process Stats
        "num_processes": telemetry.get("process_count", 0),
        "suspicious_processes": int(sec["suspicious"]["processes"] > 0),
        "suspicious_connections": int(sec["suspicious"]["connections"] > 0),
        # ARP Table
        "arp_entry_count": len(net.get("arp_table", [])),
        # System Uptime
        "uptime_seconds": telemetry["system"]["uptime"],
    }
