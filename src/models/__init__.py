"""Models package - exports ORM models for easy import elsewhere in the project."""
from .device import Device
from .scan import Scan

__all__ = ["Device", "Scan"]
