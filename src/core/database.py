"""Database connection and CRUD operations for NMD (SQLite via SQLAlchemy)."""
import os
from datetime import datetime

from sqlalchemy import create_engine, desc, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# --- Base must be defined before importing models (avoids circular import) ---
Base = declarative_base()

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_DIR = os.path.join(PROJECT_ROOT, "data")
DB_PATH = os.path.join(DB_DIR, "nmd.db")

os.makedirs(DB_DIR, exist_ok=True)
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)

# Import models AFTER Base is defined, so their metaclass can register on it.
from models.device import Device  # noqa: E402
from models.scan import Scan  # noqa: E402
from models.vulnerability import Vulnerability  # noqa: E402


def init_db() -> None:
    """Create all tables if they don't already exist, then apply migrations
    for any older database that predates the ports/device_type/scan_command columns.
    """
    Base.metadata.create_all(engine)
    migrate_db()


def migrate_db() -> None:
    """Add new columns/tables to a pre-existing database. Safe to call on a fresh DB."""
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    with engine.begin() as conn:
        if inspector.has_table("devices"):
            device_cols = {c["name"] for c in inspector.get_columns("devices")}
            if "device_type" not in device_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN device_type VARCHAR(50)"))
            if "ports" not in device_cols:
                conn.execute(text("ALTER TABLE devices ADD COLUMN ports JSON"))
        if inspector.has_table("scans"):
            scan_cols = {c["name"] for c in inspector.get_columns("scans")}
            if "scan_command" not in scan_cols:
                conn.execute(text("ALTER TABLE scans ADD COLUMN scan_command VARCHAR(500)"))



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


def get_devices_by_type(device_type: str) -> list[Device]:
    """Return all devices matching a given device_type (Router/PC/Phone/Server/Unknown)."""
    with get_session() as session:
        return session.query(Device).filter(Device.device_type == device_type).all()


def update_device_status(ip: str, status: str, **extra_fields) -> Device | None:
    """Update a device's status (and optionally other fields) by IP.

    extra_fields may include hostname, mac, vendor, os, device_type, ports,
    custom_label, appearance_count. last_seen is always refreshed to now.
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


def update_device_ports(ip: str, ports: dict) -> Device | None:
    """Store the open-ports dict ({"22": "ssh", ...}) discovered for a device."""
    with get_session() as session:
        device = session.query(Device).filter(Device.ip == ip).first()
        if device is None:
            return None
        device.ports = ports
        session.commit()
        session.refresh(device)
        return device


def update_device_label(ip: str, label: str) -> Device | None:
    """Set a user-defined custom label on a device."""
    with get_session() as session:
        device = session.query(Device).filter(Device.ip == ip).first()
        if device is None:
            return None
        device.custom_label = label
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
    """Insert a new scan record. Expects keys matching Scan columns
    (including the optional scan_command audit-trail field).
    """
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


# --------------------------------------------------------------------------
# Vulnerability CRUD
# --------------------------------------------------------------------------
def add_vulnerability(vuln_data: dict) -> Vulnerability:
    """Insert a new vulnerability record."""
    clean_data = vuln_data.copy()
    clean_data.pop("vulnerability_id", None)
    ts = clean_data.pop("timestamp", None)
    if ts and "detected_at" not in clean_data:
        try:
            clean_data["detected_at"] = datetime.fromisoformat(ts)
        except Exception:
            pass

    if "detection_script" in clean_data and "script_name" not in clean_data:
        clean_data["script_name"] = clean_data.pop("detection_script")

    if not clean_data.get("script_name"):
        clean_data["script_name"] = "Nmap NSE Script"

    valid_keys = {c.name for c in Vulnerability.__table__.columns}
    filtered_data = {k: v for k, v in clean_data.items() if k in valid_keys}

    with get_session() as session:
        vuln = Vulnerability(**filtered_data)
        session.add(vuln)
        session.commit()
        session.refresh(vuln)
        return vuln




def get_vulnerabilities(host: str | None = None, severity: str | None = None, limit: int = 100) -> list[Vulnerability]:
    """Fetch vulnerabilities filtered by host and/or severity, newest first."""
    with get_session() as session:
        query = session.query(Vulnerability)
        if host:
            query = query.filter(Vulnerability.host == host)
        if severity:
            query = query.filter(Vulnerability.severity == severity.upper())
        return query.order_by(desc(Vulnerability.detected_at)).limit(limit).all()


def get_vulnerabilities_by_host(host: str) -> list[dict]:
    """Return dict representations of all vulnerabilities for a specific host."""
    vulns = get_vulnerabilities(host=host, limit=500)
    return [v.to_dict() for v in vulns]


def get_vulnerability_history(host: str | None = None) -> list[dict]:
    """Return vulnerability history dictionary objects."""
    vulns = get_vulnerabilities(host=host, limit=500)
    return [v.to_dict() for v in vulns]


def delete_vulnerabilities_for_scan(scan_id: int) -> int:
    """Remove vulnerabilities associated with a specific scan ID."""
    with get_session() as session:
        count = session.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).delete()
        session.commit()
        return count

