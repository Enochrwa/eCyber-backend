# backend/app/services/logging/log_rotation.py
from sqlalchemy import and_
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from ...models.network import NetworkEvent, ThreatLog, FirewallLog


class LogRotator:
    def __init__(self, db: Session):
        self.db = db

    def rotate_logs(self, days_to_keep=30):
        """Archive logs older than specified days"""
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

        # Rotate network events
        old_events = (
            self.db.query(NetworkEvent)
            .filter(NetworkEvent.timestamp < cutoff_date)
            .delete()
        )

        # Rotate threat logs
        old_threats = (
            self.db.query(ThreatLog).filter(ThreatLog.timestamp < cutoff_date).delete()
        )

        # Rotate firewall logs
        old_firewall = (
            self.db.query(FirewallLog)
            .filter(FirewallLog.timestamp < cutoff_date)
            .delete()
        )

        self.db.commit()
        return {
            "network_events": old_events,
            "threat_logs": old_threats,
            "firewall_logs": old_firewall,
        }
