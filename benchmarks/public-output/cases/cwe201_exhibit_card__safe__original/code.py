"""The visitor kiosk publishes exhibit cards. Handover notes are staff-only."""
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Exhibit:
    accession: str
    title: str
    visitor_text: str
    staff_handover: str
    published: bool


def visitor_catalog(exhibits):
    cards = []
    for exhibit in exhibits:
        if exhibit.published:
            cards.append({
                "accession": exhibit.accession,
                "title": exhibit.title,
                "description": exhibit.visitor_text,
            })
    return cards


if __name__ == "__main__":
    exhibits = [
        Exhibit("A17", "Moon Map", "A map drawn in chalk.", "Paint stand blue.", True),
        Exhibit("A18", "River Map", "A study in ink.", "Frame pending.", False),
    ]
    print(json.dumps(visitor_catalog(exhibits), ensure_ascii=False))
