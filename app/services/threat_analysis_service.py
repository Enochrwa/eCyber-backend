import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession # Assuming async based on project context
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text # Added for potential raw SQL, though ORM is preferred

# Adjust these imports to match your project's actual structure
from app.models.threat import ThreatLog
from app.schemas.threat_analysis import (
    ThreatAnalysisSummary,
    ThreatAnalysisTopType,
    ThreatAnalysisTrends,
    ThreatAnalysisTrendPoint,
    ThreatAnalysisScoreHeatmapPoint,
    ThreatAnalysisOriginPoint,
    ThreatAnalysisModelDecisionPoint,
    PaginatedThreatAnalysisTableResponse,
    ThreatAnalysisTableRow,
    ThreatAnalysisDetailResponse,
    ThreatFlowFeature,
    ThreatFlowMetadataDetail,
)
from sqlalchemy import asc # Added for sorting
from collections import defaultdict # Added for GeoIP aggregation
from app.utils.geoip_utils import get_country_from_ip # Added for GeoIP lookup

logger = logging.getLogger(__name__)

def _parse_raw_data(raw_data_str: Optional[str]) -> Dict[str, Any]:
    if not raw_data_str:
        return {}
    try:
        return json.loads(raw_data_str)
    except json.JSONDecodeError as e:
        logger.warning(f"JSON parsing error for raw_data: {e}. Data prefix: {raw_data_str[:100]}...")
        return {}

async def get_threat_summary(db: AsyncSession, threat_type_filter: Optional[str] = None) -> ThreatAnalysisSummary:
    try:
        # Base queries
        total_threats_query = select(func.count(ThreatLog.id))
        malicious_count_query = select(func.count(ThreatLog.id)).filter(ThreatLog.severity.in_(["High", "Critical", "Medium"]))

        twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
        anomaly_logs_query = select(ThreatLog.raw_data).filter(ThreatLog.timestamp >= twenty_four_hours_ago)

        if threat_type_filter:
            total_threats_query = total_threats_query.filter(ThreatLog.threat_type == threat_type_filter)
            malicious_count_query = malicious_count_query.filter(ThreatLog.threat_type == threat_type_filter)
            anomaly_logs_query = anomaly_logs_query.filter(ThreatLog.threat_type == threat_type_filter)

        # Execute total threats count
        total_threats_result = await db.execute(total_threats_query)
        total_threats = total_threats_result.scalar_one_or_none() or 0

        # Execute malicious count
        malicious_count_result = await db.execute(malicious_count_query)
        malicious_count = malicious_count_result.scalar_one_or_none() or 0

        benign_count = total_threats - malicious_count

        benign_percentage = (benign_count / total_threats * 100) if total_threats > 0 else 0.0
        malicious_percentage = (malicious_count / total_threats * 100) if total_threats > 0 else 0.0

        # Average Anomaly Score (Last 24h)
        avg_anomaly_score: Optional[float] = None
        anomaly_logs_results = await db.execute(anomaly_logs_query)

        scores = []
        for raw_data_item_str in anomaly_logs_results.scalars().all():
            data = _parse_raw_data(raw_data_item_str)
            score = data.get("anomaly_score")
            if score is None:
                metadata_dict = data.get("metadata")
                if isinstance(metadata_dict, dict):
                    score = metadata_dict.get("anomaly_score")

            if isinstance(score, (str, float, int)): # Handle string scores that might need conversion
                try:
                    scores.append(float(score))
                except ValueError:
                    logger.warning(f"Could not convert anomaly_score '{score}' to float.")

        if scores:
            avg_anomaly_score = sum(scores) / len(scores)

        # Retraining last occurred - Placeholder
        retraining_last_occurred = "Not available"

        # Top 3 Attack Types / Sub-types
        if threat_type_filter:
            # If filtered by a threat_type, group by rule_id to get sub-types or specific rules
            top_3_query = (
                select(ThreatLog.rule_id, func.count(ThreatLog.rule_id).label("count"))
                .filter(ThreatLog.threat_type == threat_type_filter) # Apply the main filter
                .filter(ThreatLog.rule_id.isnot(None)) # Ensure rule_id is not null for meaningful grouping
                .group_by(ThreatLog.rule_id)
                .order_by(desc("count"))
                .limit(3)
            )
            group_by_field_name = "rule_id"
        else:
            # Default: group by threat_type
            top_3_query = (
                select(ThreatLog.threat_type, func.count(ThreatLog.threat_type).label("count"))
                .group_by(ThreatLog.threat_type)
                .order_by(desc("count"))
                .limit(3)
            )
            group_by_field_name = "threat_type"

        top_3_results = await db.execute(top_3_query)
        top_3_attack_types_list = [
            ThreatAnalysisTopType(type=getattr(row, group_by_field_name) if getattr(row, group_by_field_name) else "Unknown", count=row.count)
            for row in top_3_results.all()
        ]

        return ThreatAnalysisSummary(
            total_threats=total_threats,
            benign_percentage=round(benign_percentage, 2),
            malicious_percentage=round(malicious_percentage, 2),
            average_anomaly_score_24h=round(avg_anomaly_score, 4) if avg_anomaly_score is not None else None,
            retraining_last_occurred=retraining_last_occurred,
            top_3_attack_types=top_3_attack_types_list,
        )
    except SQLAlchemyError as e:
        logger.error(f"Database error encountered in get_threat_summary: {e}", exc_info=True)
        raise  # Re-raise to allow endpoint to handle HTTP response
    except Exception as e:
        logger.error(f"An unexpected error occurred in get_threat_summary: {e}", exc_info=True)
        raise # Re-raise

async def get_threat_trends(db: AsyncSession, threat_type_filter: Optional[str] = None) -> ThreatAnalysisTrends:
    try:
        seven_days_ago = datetime.utcnow() - timedelta(days=7)

        # 1. Threats Over Time
        threats_over_time_query = (
            select(
                func.strftime('%Y-%m-%d %H:00:00', ThreatLog.timestamp).label("time_bucket"),
                func.count(ThreatLog.id).label("count")
            )
            .filter(ThreatLog.timestamp >= seven_days_ago)
        )
        if threat_type_filter:
            threats_over_time_query = threats_over_time_query.filter(ThreatLog.threat_type == threat_type_filter)

        threats_over_time_query = threats_over_time_query.group_by("time_bucket").order_by("time_bucket")
        threats_over_time_results = await db.execute(threats_over_time_query)
        threats_over_time_data = [
            ThreatAnalysisTrendPoint(time_bucket=datetime.strptime(row.time_bucket, '%Y-%m-%d %H:%M:%S'), count=row.count)
            for row in threats_over_time_results.all()
        ]

        # 2. Anomaly Score Heatmap Data
        anomaly_score_heatmap_data = []
        score_bins = [(i / 10, (i + 1) / 10) for i in range(10)]

        heatmap_logs_query = select(ThreatLog.timestamp, ThreatLog.raw_data).filter(ThreatLog.timestamp >= seven_days_ago)
        if threat_type_filter:
            heatmap_logs_query = heatmap_logs_query.filter(ThreatLog.threat_type == threat_type_filter)

        heatmap_logs_results = await db.execute(heatmap_logs_query)
        heatmap_counts: Dict[str, Dict[str, int]] = {}

        for log_timestamp, raw_data_item_str in heatmap_logs_results.all():
            data = _parse_raw_data(raw_data_item_str)
            score = data.get("anomaly_score")
            if score is None:
                metadata_dict = data.get("metadata")
                if isinstance(metadata_dict, dict):
                    score = metadata_dict.get("anomaly_score")

            if isinstance(score, (float, int)): # TODO: Consider string score conversion like in summary
                score = float(score)
                day_bucket_str = log_timestamp.strftime('%Y-%m-%d')

                for low, high in score_bins:
                    if low <= score < high or (score == 1.0 and high == 1.0):
                        score_range_str = f"{low:.1f}-{high:.1f}"
                        heatmap_counts.setdefault(day_bucket_str, {}).setdefault(score_range_str, 0)
                        heatmap_counts[day_bucket_str][score_range_str] += 1
                        break

        for day_bucket, scores_map in heatmap_counts.items():
            for score_range, count in scores_map.items():
                anomaly_score_heatmap_data.append(
                    ThreatAnalysisScoreHeatmapPoint(time_bucket=day_bucket, score_range=score_range, count=count)
                )

        # 3. Threat Origins
        country_counts: Dict[str, int] = defaultdict(int)
        stmt_ips = (
            select(ThreatLog.source_ip, func.count(ThreatLog.id).label("threat_count"))
            .filter(ThreatLog.timestamp >= seven_days_ago)
            .filter(ThreatLog.source_ip.isnot(None))
        )
        if threat_type_filter:
            stmt_ips = stmt_ips.filter(ThreatLog.threat_type == threat_type_filter)

        stmt_ips = stmt_ips.group_by(ThreatLog.source_ip)
        ip_counts_results = await db.execute(stmt_ips)

        for row in ip_counts_results.all():
            source_ip = row.source_ip
            count = row.threat_count
            if source_ip:
                country_name = get_country_from_ip(source_ip)
                country_counts[country_name if country_name else "Unknown"] += count

        top_countries = sorted(country_counts.items(), key=lambda item: item[1], reverse=True)[:10]
        threat_origins_data = [
            ThreatAnalysisOriginPoint(country=country_name, count=count)
            for country_name, count in top_countries
        ]

        # 4. Model Decision Stats
        model_decision_stats_data = []
        model_logs_query = select(ThreatLog.raw_data, ThreatLog.rule_id).filter(ThreatLog.timestamp >= seven_days_ago)
        if threat_type_filter:
            model_logs_query = model_logs_query.filter(ThreatLog.threat_type == threat_type_filter)

        model_logs_results = await db.execute(model_logs_query)
        model_decisions: Dict[str, Dict[str, int]] = {}

        for raw_data_item_str, rule_id_val in model_logs_results.all():
            data = _parse_raw_data(raw_data_item_str)
            metadata = data.get("metadata", {})

            model_name = metadata.get("model_name")
            # If model_name is not directly in metadata, try to infer from rule_id or other fields
            if not model_name and rule_id_val:
                 model_name = f"Rule-based: {rule_id_val.split(':')[0]}" # Example inference

            if not model_name:
                model_name = "Unknown Model"

            score = metadata.get("anomaly_score", data.get("anomaly_score")) # Check both
            threshold = metadata.get("threshold", data.get("threshold")) # Check both

            if isinstance(score, (float, int)) and isinstance(threshold, (float, int)):
                model_decisions.setdefault(model_name, {"above_threshold_count": 0, "below_threshold_count": 0})
                if float(score) >= float(threshold):
                    model_decisions[model_name]["above_threshold_count"] += 1
                else:
                    model_decisions[model_name]["below_threshold_count"] += 1
            elif rule_id_val and not isinstance(score, (float, int)): # If it's a rule_id based alert without score, count as above.
                 model_decisions.setdefault(model_name, {"above_threshold_count": 0, "below_threshold_count": 0})
                 model_decisions[model_name]["above_threshold_count"] += 1


        for name, counts in model_decisions.items():
            model_decision_stats_data.append(
                ThreatAnalysisModelDecisionPoint(
                    model_name=name,
                    above_threshold_count=counts["above_threshold_count"],
                    below_threshold_count=counts["below_threshold_count"]
                )
            )

        return ThreatAnalysisTrends(
            threats_over_time=threats_over_time_data,
            anomaly_score_heatmap_data=anomaly_score_heatmap_data,
            threat_origins=threat_origins_data,
            model_decision_stats=model_decision_stats_data
        )
    except SQLAlchemyError as e:
        logger.error(f"Database error encountered in get_threat_trends: {e}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred in get_threat_trends: {e}", exc_info=True)
        raise

# Placeholder for other service functions to be added in subsequent subtasks:
async def list_threats_paginated(
    db: AsyncSession,
    page: int = 1,
    size: int = 20,
    sort_by: Optional[str] = None,
    sort_desc: bool = False,
    threat_type_filter: Optional[str] = None,
    start_date_filter: Optional[datetime] = None,
    end_date_filter: Optional[datetime] = None,
    verdict_filter: Optional[str] = None
) -> PaginatedThreatAnalysisTableResponse:
    try:
        query = select(ThreatLog)

        # Filtering
        if threat_type_filter:
            query = query.filter(ThreatLog.threat_type == threat_type_filter)
        if start_date_filter:
            query = query.filter(ThreatLog.timestamp >= start_date_filter)
        if end_date_filter:
            # Add time component to end_date_filter to include the whole day
            end_date_filter_inclusive = datetime.combine(end_date_filter, datetime.max.time())
            query = query.filter(ThreatLog.timestamp <= end_date_filter_inclusive)

        malicious_severities = ["High", "Critical", "Medium"]
        if verdict_filter:
            if verdict_filter.lower() == "malicious":
                query = query.filter(ThreatLog.severity.in_(malicious_severities))
            elif verdict_filter.lower() == "benign":
                query = query.filter(ThreatLog.severity.notin_(malicious_severities))
            # 'Suspicious' or other verdicts might need more complex logic or raw_data parsing,
            # which is hard to do efficiently in this SQL query for now.
            # logger.info(f"Verdict filter for '{verdict_filter}' using severity as proxy.")


        # Total Count
        count_query = select(func.count()).select_from(query.subquery())
        total_items_result = await db.execute(count_query)
        total_items = total_items_result.scalar_one_or_none() or 0

        # Sorting
        sort_column = ThreatLog.timestamp # Default sort column
        if sort_by:
            if hasattr(ThreatLog, sort_by):
                sort_column = getattr(ThreatLog, sort_by)
            elif sort_by in ["anomaly_score", "verdict"]:
                # Sorting by derived fields 'anomaly_score' or 'verdict' is complex with ORM alone
                # as they require parsing raw_data. Defaulting to timestamp or logging a TODO.
                logger.warning(f"Sorting by '{sort_by}' is not directly supported by database columns. Defaulting to timestamp.")
                sort_column = ThreatLog.timestamp # Fallback
            else: # Unknown sort_by field
                logger.warning(f"Unknown sort_by field: '{sort_by}'. Defaulting to timestamp.")
                sort_column = ThreatLog.timestamp


        order_func = desc if sort_desc else asc
        query = query.order_by(order_func(sort_column))

        # Pagination
        query = query.offset((page - 1) * size).limit(size)

        results = await db.execute(query)
        threat_logs = results.scalars().all()

        # Data Transformation
        table_rows: List[ThreatAnalysisTableRow] = []
        for log in threat_logs:
            parsed_data = _parse_raw_data(log.raw_data)

            anomaly_score = parsed_data.get("anomaly_score")
            if anomaly_score is None:
                metadata = parsed_data.get("metadata", {})
                if isinstance(metadata, dict):
                    anomaly_score = metadata.get("anomaly_score")

            verdict = "Unknown"
            threshold = parsed_data.get("threshold")
            if threshold is None:
                 metadata = parsed_data.get("metadata", {})
                 if isinstance(metadata, dict):
                    threshold = metadata.get("threshold")

            if anomaly_score is not None and threshold is not None:
                try:
                    if float(anomaly_score) >= float(threshold):
                        verdict = "Malicious"
                    else:
                        verdict = "Benign"
                except ValueError:
                    logger.warning(f"Could not parse anomaly_score or threshold for log id {log.id}")
                    # Fallback to severity-based verdict
                    if log.severity in malicious_severities:
                        verdict = "Malicious"
                    elif log.severity: # If severity exists and not in malicious_severities
                        verdict = "Benign"
            elif log.severity:
                if log.severity in malicious_severities:
                    verdict = "Malicious"
                else:
                    verdict = "Benign"

            # If verdict_filter was applied, this verdict should align, but this is a re-calculation for display
            # For 'Suspicious', one might check if score is close to threshold or specific rules.

            table_rows.append(
                ThreatAnalysisTableRow(
                    id=str(log.id), # Ensure ID is string
                    timestamp=log.timestamp,
                    threat_type=log.threat_type or "N/A",
                    anomaly_score=float(anomaly_score) if isinstance(anomaly_score, (float, int)) else None,
                    verdict=verdict,
                    source_ip=log.source_ip or "N/A",
                    destination_ip=log.destination_ip,
                    destination_port=log.destination_port,
                    protocol=log.protocol
                )
            )

        total_pages = (total_items + size - 1) // size if size > 0 else 0

        return PaginatedThreatAnalysisTableResponse(
            total=total_items,
            items=table_rows,
            page=page,
            size=size,
            pages=total_pages
        )

    except SQLAlchemyError as e:
        logger.error(f"Database error in list_threats_paginated: {e}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error in list_threats_paginated: {e}", exc_info=True)
        raise

async def get_threat_detail(db: AsyncSession, threat_id: str) -> Optional[ThreatAnalysisDetailResponse]:
    try:
        # Assuming ThreatLog.id is an integer. If it's UUID, adjust conversion.
        try:
            db_threat_id = int(threat_id)
        except ValueError:
            logger.warning(f"Invalid threat_id format: '{threat_id}'. Must be an integer.")
            return None

        stmt = select(ThreatLog).filter(ThreatLog.id == db_threat_id)
        result = await db.execute(stmt)
        log = result.scalar_one_or_none()

        if not log:
            logger.warning(f"Threat log with id '{threat_id}' not found.")
            return None

        parsed_raw_data = _parse_raw_data(log.raw_data)
        metadata = parsed_raw_data.get("metadata", {}) if isinstance(parsed_raw_data, dict) else {}

        # Anomaly Score
        anomaly_score_val = parsed_raw_data.get("anomaly_score")
        if anomaly_score_val is None and isinstance(metadata, dict):
            anomaly_score_val = metadata.get("anomaly_score")

        final_anomaly_score = None
        if isinstance(anomaly_score_val, (float, int)):
            final_anomaly_score = float(anomaly_score_val)
        elif isinstance(anomaly_score_val, str):
            try:
                final_anomaly_score = float(anomaly_score_val)
            except ValueError:
                logger.warning(f"Could not parse anomaly_score string '{anomaly_score_val}' to float for log id {log.id}")


        # Verdict
        verdict = "Unknown"
        malicious_severities = ["High", "Critical", "Medium"]
        threshold_val = parsed_raw_data.get("threshold")
        if threshold_val is None and isinstance(metadata, dict):
            threshold_val = metadata.get("threshold")

        if final_anomaly_score is not None and threshold_val is not None:
            try:
                if final_anomaly_score >= float(threshold_val):
                    verdict = "Malicious"
                else:
                    verdict = "Benign"
            except ValueError:
                logger.warning(f"Could not parse threshold value '{threshold_val}' for log id {log.id}")
                if log.severity in malicious_severities:
                    verdict = "Malicious"
                elif log.severity:
                    verdict = "Benign"
        elif log.severity:
            if log.severity in malicious_severities:
                verdict = "Malicious"
            else:
                verdict = "Benign"

        # Feature Contributions
        feature_contributions: List[ThreatFlowFeature] = []
        contributing_features_data = metadata.get("features_contributing") if isinstance(metadata, dict) else None
        if isinstance(contributing_features_data, dict):
            for name, value in contributing_features_data.items():
                try:
                    feature_contributions.append(ThreatFlowFeature(feature_name=name, value=float(value)))
                except (ValueError, TypeError):
                    logger.warning(f"Could not parse feature value '{value}' for feature '{name}' in log id {log.id}")

        # Flow Metadata
        # Best-effort mapping from common fields in parsed_raw_data or its metadata
        flow_meta_obj = ThreatFlowMetadataDetail(
            packet_counts=parsed_raw_data.get("packet_counts", metadata.get("packet_counts")), # e.g. {"total": 10, "fwd": 5, "bwd": 5}
            duration_seconds=parsed_raw_data.get("duration", metadata.get("duration", metadata.get("duration_sec"))),
            flags_summary=parsed_raw_data.get("flags", metadata.get("flags_summary")), # e.g. {"SYN": 1, "ACK": 10}
            active_idle_stats=metadata.get("active_idle_stats"), # e.g. {"active_mean": 1.0, "idle_min": 0.5}
            payload_length_stats=metadata.get("payload_stats", parsed_raw_data.get("payload_length_stats")), # e.g. {"mean": 100, "std": 10}
            raw_features=metadata.get("key_features", parsed_raw_data.get("selected_features")) # Select subset of features
        )
        # Clean None values from flow_meta_obj if they were not found
        flow_meta_dict = flow_meta_obj.model_dump(exclude_none=True)
        final_flow_metadata = ThreatFlowMetadataDetail(**flow_meta_dict) if flow_meta_dict else None


        return ThreatAnalysisDetailResponse(
            id=str(log.id),
            timestamp=log.timestamp,
            threat_type=log.threat_type or "N/A",
            anomaly_score=final_anomaly_score,
            verdict=verdict,
            source_ip=log.source_ip or "N/A",
            destination_ip=log.destination_ip,
            destination_port=log.destination_port,
            protocol=log.protocol,
            description=log.description,
            rule_id=log.rule_id,
            category=log.category,
            severity=log.severity,
            feature_contributions=feature_contributions if feature_contributions else None,
            flow_metadata=final_flow_metadata,
            raw_alert_data=parsed_raw_data
        )

    except ValueError as ve: # Handles threat_id conversion error specifically
        logger.error(f"ValueError in get_threat_detail (likely threat_id format): {ve}", exc_info=True)
        raise # Re-raise for endpoint to potentially return 400
    except SQLAlchemyError as e:
        logger.error(f"Database error in get_threat_detail for id '{threat_id}': {e}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error in get_threat_detail for id '{threat_id}': {e}", exc_info=True)
        raise