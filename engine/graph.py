"""Neo4j driver wrapper used by ingesters, engines, and the API."""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager
from datetime import date as _PyDate
from datetime import datetime as _PyDateTime
from datetime import time as _PyTime
from typing import Any

from neo4j import Driver, GraphDatabase, Session
from neo4j.time import (
    Date as _N4jDate,
)
from neo4j.time import (
    DateTime as _N4jDateTime,
)
from neo4j.time import (
    Duration as _N4jDuration,
)
from neo4j.time import (
    Time as _N4jTime,
)

from config import settings


def _json_safe(v: Any) -> Any:
    """Recursively convert Neo4j temporal types (and other non-JSON natives)
    into JSON-friendly values so FastAPI/Pydantic can serialize results."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, (_N4jDateTime, _N4jDate, _N4jTime)):
        return v.iso_format()
    if isinstance(v, _N4jDuration):
        return str(v)
    if isinstance(v, (_PyDateTime, _PyDate, _PyTime)):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _json_safe(val) for k, val in v.items()}
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_json_safe(i) for i in v]
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", errors="replace")
        except Exception:
            return repr(v)
    return v


_driver: Driver | None = None


def get_driver() -> Driver:
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
    return _driver


def close_driver() -> None:
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None


@contextmanager
def session() -> Iterable[Session]:
    driver = get_driver()
    s = driver.session()
    try:
        yield s
    finally:
        s.close()


def run_write(cypher: str, **params: Any):
    with session() as s:
        return s.execute_write(lambda tx: list(tx.run(cypher, **params)))


def run_read(cypher: str, **params: Any) -> list[dict]:
    with session() as s:
        rows = s.execute_read(lambda tx: [r.data() for r in tx.run(cypher, **params)])
    return [_json_safe(r) for r in rows]


def apply_schema() -> None:
    """Apply the graph schema (constraints, indexes, OSI seed).
    Strips line comments BEFORE splitting on ';' so a comment immediately
    above a statement doesn't cause the statement to be filtered out."""
    with session() as s:
        text = settings.schema_file.read_text(encoding="utf-8")
        # 1) Strip line comments line-by-line.
        no_comments = "\n".join(
            line for line in text.splitlines() if not line.strip().startswith("//")
        )
        # 2) Split on ';' and run each non-empty statement.
        for stmt in no_comments.split(";"):
            stmt = stmt.strip()
            if stmt:
                s.run(stmt)
