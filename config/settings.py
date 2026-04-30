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
    # Pin the target database name so deployments don't depend on the server's
    # `dbms.default_database` setting.
    neo4j_database: str = os.getenv("NEO4J_DATABASE", "neo4j")

    github_token: str | None = os.getenv("GITHUB_TOKEN") or None
    nvd_api_key: str | None = os.getenv("NVD_API_KEY") or None

    api_host: str = os.getenv("API_HOST", "127.0.0.1")
    api_port: int = int(os.getenv("API_PORT", "8000"))

    # Security: bearer token required for mutating endpoints (POST/DELETE/PUT).
    # If empty, mutations are allowed without auth — convenient for local dev,
    # but you should set NEXUS_API_TOKEN in .env for any non-loopback exposure.
    api_token: str | None = os.getenv("NEXUS_API_TOKEN") or None

    # Comma-separated list of allowed CORS origins. Defaults to same-origin only.
    cors_origins: str = os.getenv(
        "NEXUS_CORS_ORIGINS",
        f"http://{os.getenv('API_HOST', '127.0.0.1')}:{os.getenv('API_PORT', '8000')}",
    )

    root: Path = ROOT
    data_dir: Path = ROOT / "data"
    schema_file: Path = ROOT / "schema" / "graph_schema.cypher"


settings = Settings()
