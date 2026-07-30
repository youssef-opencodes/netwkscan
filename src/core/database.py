"""Database connection and CRUD operations for NMD (SQLite via SQLAlchemy)."""
import os
from datetime import datetime

from sqlalchemy import create_engine, desc
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# --- Base must be defined before importing models (avoids circular import) ---
Base = declarative_base()

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "nmd.db")

os.makedirs(DB_DIR, exist_ok=True)
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)

# Import models AFTER Base is defined, so their metaclass can register on it.
from models.device import Device  # noqa: E402
from models.scan import Scan  # noqa: E402


def init_db() -> None:
    """Create all tables if they don't already exist."""
    Base.metadata.create_all(engine)


def get_session() -> Session:
    """Return a new SQLAlchemy session."""
    return SessionLocal()


# --------------------------------------------------------------------------
# Device CRUD
# --------------------------------------------------------------------------
def add_device(device_data: dict) -> Device:
    """Insert a new device. Expects keys matching Device columns (ip required)."""
    with get_session() as session:
        device = Device(**device_data)
        session.add(device)
        session.commit()
        session.refresh(device)
        return device


def get_all_devices() -> list[Device]:
    """Return all devices, most recently seen first."""
    with get_session() as session:
        return session.query(Device).order_by(desc(Device.last_seen)).all()


def get_device_by_ip(ip: str) -> Device | None:
    """Fetch a single device by its IP address."""
    with get_session() as session:
        return session.query(Device).filter(Device.ip == ip).first()


def update_device_status(ip: str, status: str, **extra_fields) -> Device | None:
    """Update a device's status (and optionally other fields) by IP.

    extra_fields may include hostname, mac, vendor, os, custom_label, appearance_count.
    last_seen is always refreshed to now.
    """
    with get_session() as session:
        device = session.query(Device).filter(Device.ip == ip).first()
        if device is None:
            return None
        device.status = status
        device.last_seen = datetime.utcnow()
        for key, value in extra_fields.items():
            if hasattr(device, key):
                setattr(device, key, value)
        session.commit()
        session.refresh(device)
        return device


def delete_device(ip: str) -> bool:
    """Remove a device from the database by IP. Returns True if deleted."""
    with get_session() as session:
        device = session.query(Device).filter(Device.ip == ip).first()
        if device is None:
            return False
        session.delete(device)
        session.commit()
        return True


# --------------------------------------------------------------------------
# Scan CRUD
# --------------------------------------------------------------------------
def add_scan(scan_data: dict) -> Scan:
    """Insert a new scan record. Expects keys matching Scan columns."""
    with get_session() as session:
        scan = Scan(**scan_data)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan


def get_scan_history(limit: int = 50) -> list[Scan]:
    """Return the most recent scans, newest first."""
    with get_session() as session:
        return (
            session.query(Scan)
            .order_by(desc(Scan.scan_date))
            .limit(limit)
            .all()
        )


def get_device_history(ip: str) -> dict:
    """Return a device's own record plus contextual info for its detail popup."""
    with get_session() as session:
        device = session.query(Device).filter(Device.ip == ip).first()
        if device is None:
            return {}
        return device.to_dict()
