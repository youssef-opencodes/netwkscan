"""Device model - represents a network device tracked by NMD."""
from datetime import datetime

from sqlalchemy import String, Integer, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # MODIFIED (plan2): device classification + discovered open ports
    device_type: Mapped[str | None] = mapped_column(String(50), nullable=True, default="Unknown")
    ports: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)  # {"22": "ssh", "80": "http"}
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    status: Mapped[str] = mapped_column(String(20), default="new")  # online / offline / new
    custom_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    appearance_count: Mapped[int] = mapped_column(Integer, default=1)

    def __repr__(self) -> str:
        return f"<Device(ip={self.ip!r}, status={self.status!r}, type={self.device_type!r})>"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "hostname": self.hostname,
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "os": self.os,
            "device_type": self.device_type,
            "ports": self.ports or {},
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "status": self.status,
            "custom_label": self.custom_label,
            "appearance_count": self.appearance_count,
        }
