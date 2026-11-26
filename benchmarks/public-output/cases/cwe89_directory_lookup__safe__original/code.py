"""Member lookup for a fictional lending desk."""
import json
import sqlite3
from contextlib import closing


def lookup_member(connection, display_name):
    cursor = connection.execute(
        "SELECT member_id, display_name FROM members WHERE display_name = ? ORDER BY member_id",
        (display_name,),
    )
    return [{"id": member_id, "name": name} for member_id, name in cursor]


if __name__ == "__main__":
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.execute("CREATE TABLE members (member_id INTEGER PRIMARY KEY, display_name TEXT)")
        connection.executemany("INSERT INTO members VALUES (?, ?)", [(1, "O'Neil"), (2, "River")])
        print(json.dumps(lookup_member(connection, "O'Neil")))
