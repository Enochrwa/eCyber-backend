# backend/app/services/database/autofill.py
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from app.models.threat import ThreatLog
from app.models.firewall import FirewallLog
from app.models.network import NetworkEvent
import random
import json
from app.models.user import User
from faker import Faker
import random
from sqlalchemy.sql import func, select

fake = Faker()

class DatabaseAutofiller:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_random_user(self):
        result = await self.db.execute(select(User).order_by(func.random()).limit(1))
        return result.scalars().first()

    async def generate_threat_log(self, user=None):
        threat_types = ["malware", "ddos", "intrusion", "phishing", "scanning"]
        protocols = ["TCP", "UDP", "ICMP"]

        # Get a random user if none provided
        if user is None:
            user = await self._get_random_user()

        threat = ThreatLog(
            timestamp=datetime.now(),
            threat_type=random.choice(threat_types),
            category=random.choice(["network", "endpoint", "application"]),
            source_ip=fake.ipv4(),
            source_mac=fake.mac_address(),
            destination_ip=fake.ipv4(),
            destination_port=random.randint(1, 65535),
            protocol=random.choice(protocols),
            severity=random.choice(["critical", "high", "medium", "low"]),
            confidence=round(random.uniform(0.5, 1.0), 2),
            description=fake.sentence(),
            raw_packet=fake.hexify(text="^^^^ ^^^^ ^^^^ ^^^^", upper=True),
            action_taken=random.choice(["blocked", "alerted", "quarantined"]),
            mitigation_status=random.choice(["pending", "completed", "failed"]),
            rule_id=f"RULE-{fake.random_number(digits=4)}",
            sensor_id=f"SENSOR-{fake.random_number(digits=2)}",
            enrichment_data=json.dumps({
                "threat_intel": {
                    "reputation": random.choice(["malicious", "suspicious", "clean"]),
                    "sources": [fake.domain_name() for _ in range(2)]
                }
            }),
        )
        self.db.add(threat)
        await self.db.commit()
        await self.db.refresh(threat)
        return threat

    async def generate_firewall_log(self):
        firewall_log = FirewallLog(
            timestamp=datetime.now(),
            action=random.choice(["allow", "deny"]),
            source_ip=fake.ipv4(),
            destination_ip=fake.ipv4(),
            protocol=random.choice(["TCP", "UDP", "ICMP"]),
            matched_rule=f"MATCHED-{fake.random_number(digits=4)}",
        )
        self.db.add(firewall_log)
        await self.db.commit()
        await self.db.refresh(firewall_log)
        return firewall_log

    async def generate_network_event(self):
        event_types = ["connection", "dns_query", "http_request", "ssh_login"]

        event = NetworkEvent(
            timestamp=datetime.now(),
            event_type=random.choice(event_types),
            source_ip=fake.ipv4(),
            source_mac=fake.mac_address(),
            destination_ip=fake.ipv4(),
            destination_port=random.randint(1, 65535),
            protocol=random.choice(["TCP", "UDP", "ICMP"]),
            packet_size=random.randint(64, 1500),
            service=random.choice(["HTTP", "DNS", "SSH", "SMTP"]),
            payload_summary=fake.sentence(),
            geo_data=json.dumps({
                "country": fake.country(),
                "city": fake.city(),
                "isp": fake.company()
            }),
        )
        self.db.add(event)
        await self.db.commit()
        await self.db.refresh(event)
        return event

    async def autofill_all(self, count=10):
        """Generate sample data for all tables"""
        results = []
        for _ in range(count):
            results.append(await self.generate_threat_log())
            results.append(await self.generate_firewall_log())
            results.append(await self.generate_network_event())
        return results