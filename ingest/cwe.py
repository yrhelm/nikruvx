"""
MITRE CWE ingester
==================
Downloads the official CWE list (XML) from MITRE and loads CWE nodes,
parent-child hierarchy, and maps each CWE to OSI layers.

Source: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
"""

from __future__ import annotations

import argparse
import io
import xml.etree.ElementTree as ET
import zipfile

from rich.progress import Progress

from engine.graph import session
from engine.osi_classifier import CWE_TO_LAYERS

from .common import console, http_client

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
NS = {"c": "http://cwe.mitre.org/cwe-7"}


def _layers_for(cwe_id: str, name: str, description: str) -> list[int]:
    if cwe_id in CWE_TO_LAYERS:
        return CWE_TO_LAYERS[cwe_id]
    # Fall back to text classification using the CWE name + description
    from engine.osi_classifier import classify

    return [hit["layer"] for hit in classify(f"{name}. {description}", [cwe_id])]


def _upsert(
    cwe_id: str, name: str, description: str, abstraction: str, status: str, parents: list[str]
) -> None:
    layers = _layers_for(cwe_id, name, description)
    cypher = """
    MERGE (w:CWE {id: $cwe_id})
    SET w.name = $name, w.description = $description,
        w.abstraction = $abstraction, w.status = $status,
        w.last_ingested = datetime()
    WITH w
    UNWIND $parents AS parent_id
        MERGE (p:CWE {id: parent_id})
        MERGE (w)-[:CHILD_OF]->(p)
    WITH w
    UNWIND $layers AS layer_num
        MATCH (l:OSILayer {number: layer_num})
        MERGE (w)-[:MAPS_TO]->(l)
    """
    with session() as s:
        s.run(
            cypher,
            cwe_id=cwe_id,
            name=name,
            description=description,
            abstraction=abstraction,
            status=status,
            parents=parents,
            layers=layers,
        )


def ingest() -> int:
    console.print("[cyan]Downloading MITRE CWE catalog…")
    with http_client(timeout=60) as c:
        resp = c.get(CWE_URL)
        resp.raise_for_status()
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        xml_bytes = zf.read(zf.namelist()[0])

    root = ET.fromstring(xml_bytes)
    weaknesses = root.findall(".//c:Weaknesses/c:Weakness", NS)
    count = 0
    with Progress() as bar:
        task = bar.add_task("[cyan]CWE", total=len(weaknesses))
        for w in weaknesses:
            wid = "CWE-" + w.attrib["ID"]
            name = w.attrib.get("Name", "")
            abstraction = w.attrib.get("Abstraction", "")
            status = w.attrib.get("Status", "")
            descr_el = w.find("c:Description", NS)
            description = (descr_el.text or "").strip() if descr_el is not None else ""
            parents: list[str] = []
            for rel in w.findall("c:Related_Weaknesses/c:Related_Weakness", NS):
                if rel.attrib.get("Nature") == "ChildOf":
                    parents.append("CWE-" + rel.attrib["CWE_ID"])
            _upsert(wid, name, description, abstraction, status, parents)
            count += 1
            bar.update(task, advance=1)
    console.print(f"[green]CWE ingested {count} weaknesses")
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest MITRE CWE")
    parser.parse_args()
    ingest()


if __name__ == "__main__":
    main()
