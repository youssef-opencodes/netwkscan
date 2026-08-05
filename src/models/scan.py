"""Scan model - represents one network scan run."""
from datetime import datetime

from sqlalchemy import Integer, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_date: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    duration: Mapped[float] = mapped_column(Float, default=0.0)
    total_devices: Mapped[int] = mapped_column(Integer, default=0)
    new_devices: Mapped[int] = mapped_column(Integer, default=0)
    disconnected_devices: Mapped[int] = mapped_column(Integer, default=0)
    # MODIFIED (plan2): audit trail of the exact Nmap command used
    scan_command: Mapped[str | None] = mapped_column(String(500), nullable=True)

    def __repr__(self) -> str:
        return f"<Scan(date={self.scan_date}, total={self.total_devices})>"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_date": self.scan_date.isoformat() if self.scan_date else None,
            "duration": self.duration,
            "total_devices": self.total_devices,
            "new_devices": self.new_devices,
            "disconnected_devices": self.disconnected_devices,
            "scan_command": self.scan_command,
        }
