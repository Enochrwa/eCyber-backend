# backend/app/services/logging/database_logger.py
from sqlalchemy.orm import Session
from datetime import datetime
from ...models.network import NetworkEvent, ThreatLog, FirewallLog
from typing import Optional, Dict


class DatabaseLogger:
    def __init__(self, db: Session):
        self.db = db

    def log_network_event(self, event_data: Dict):
        """Log general network events"""
        event = NetworkEvent(
            event_type=event_data.get("event_type"),
            source_ip=event_data.get("source_ip"),
            destination_ip=event_data.get("destination_ip"),
            protocol=event_data.get("protocol"),
            port=event_data.get("port"),
            payload_summary=event_data.get("payload_summary"),
            severity=event_data.get("severity", "low"),
        )
        self.db.add(event)
        self.db.commit()
        return event

    def log_threat(self, threat_data: Dict) -> ThreatLog:
        """Log security threats"""
        threat = ThreatLog(
            threat_type=threat_data.get("threat_type"),
            description=threat_data.get("description"),
            action_taken=threat_data.get("action_taken", "detected"),
        )
        self.db.add(threat)
        self.db.commit()

        # Link related network events if provided
        if "network_event_ids" in threat_data:
            events = (
                self.db.query(NetworkEvent)
                .filter(NetworkEvent.id.in_(threat_data["network_event_ids"]))
                .all()
            )
            for event in events:
                event.threat_id = threat.id
        self.db.commit()

        return threat

    def log_firewall_action(self, action_data: Dict) -> FirewallLog:
        """Log firewall actions (blocks/allows)"""
        log = FirewallLog(
            source_ip=action_data.get("source_ip"),
            destination_ip=action_data.get("destination_ip"),
            port=action_data.get("port"),
            protocol=action_data.get("protocol"),
            action=action_data.get("action"),
            reason=action_data.get("reason"),
        )

        # Link to threat if provided
        if "threat_id" in action_data:
            log.threat_id = action_data["threat_id"]

        self.db.add(log)
        self.db.commit()
        return log

    def add_firewall_rule(self, rule_data: Dict):
        """Add new firewall rule to database"""
        rule = FirewallRule(
            rule_name=rule_data.get("rule_name"),
            source_ip=rule_data.get("source_ip", "any"),
            destination_ip=rule_data.get("destination_ip", "any"),
            port=rule_data.get("port"),
            protocol=rule_data.get("protocol", "any"),
            action=rule_data.get("action", "block"),
        )
        self.db.add(rule)
        self.db.commit()
        return rule
