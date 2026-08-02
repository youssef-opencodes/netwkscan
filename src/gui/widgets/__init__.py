"""GUI widgets package (Developer 3).

Exports the reusable widgets. Developer 4 widgets (status_badge, search_bar,
filters) are intentionally not imported here so that this package keeps
importing cleanly while those files are still empty.
"""
from gui.widgets.device_card import DeviceCard, device_value
from gui.widgets.device_details import DeviceDetails, show_device_details

__all__ = ["DeviceCard", "DeviceDetails", "show_device_details", "device_value"]