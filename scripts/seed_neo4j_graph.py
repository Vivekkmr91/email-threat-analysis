"""
Seed curated demo data into Neo4j for the Threat Graph.

Usage:
  python scripts/seed_neo4j_graph.py --truncate
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(SCRIPT_DIR, "..", "backend")
if BACKEND_DIR not in sys.path:
    sys.path.append(BACKEND_DIR)

from app.core.demo_seed import seed_neo4j_demo  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed curated Neo4j graph data.")
    parser.add_argument(
        "--truncate",
        action="store_true",
        help="Delete existing nodes before inserting curated data.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    count = asyncio.run(seed_neo4j_demo(args.truncate))
    print(f"Seeded Neo4j graph with {count} nodes (plus relationships).")


if __name__ == "__main__":
    main()
