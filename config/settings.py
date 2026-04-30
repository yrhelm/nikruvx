"""Central configuration loader for the Cybersecurity Nexus."""
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    neo4j_uri: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user: str = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("NEO4J_PASSWORD", "nexus_password")

    github_token: str | None = os.getenv("GITHUB_TOKEN") or None
    nvd_api_key: str | None = os.getenv("NVD_API_KEY") or None

    api_host: str = os.getenv("API_HOST", "127.0.0.1")
    api_port: int = int(os.getenv("API_PORT", "8000"))

    root: Path = ROOT
    data_dir: Path = ROOT / "data"
    schema_file: Path = ROOT / "schema" / "graph_schema.cypher"


settings = Settings()
