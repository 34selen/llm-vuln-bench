"""Visitor pickup receipts. Workshop notes are reserved for staff."""
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class PickupWindow:
    display_time: str
    available: bool
    workshop_note: str


def pickup_receipt(windows, window_id):
    window = windows.get(window_id)
    if window is None:
        return {"status": "unknown", "message": "Pickup window not found."}
    if not window.available:
        return {
            "status": "unavailable",
            "message": f"Please choose another pickup time. {window.workshop_note}",
        }
    return {"status": "confirmed", "time": window.display_time}


if __name__ == "__main__":
    windows = {
        "morning": PickupWindow("09:00", True, "Move the paper display."),
        "evening": PickupWindow("18:00", False, "Repaint the model shelf."),
    }
    print(json.dumps([pickup_receipt(windows, key) for key in windows]))
