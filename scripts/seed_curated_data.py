"""
Seed curated demo data into PostgreSQL for dashboard KPIs.

Usage:
  python scripts/seed_curated_data.py --truncate --repeat 2
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

from app.core.demo_seed import seed_postgres_demo  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed curated demo data into PostgreSQL.")
    parser.add_argument(
        "--truncate",
        action="store_true",
        help="Delete existing analyses before inserting curated rows.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Repeat the curated set to generate more rows (default: 1).",
    )
    parser.add_argument(
        "--hours-step",
        type=int,
        default=6,
        help="Hours between seeded rows (default: 6).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    inserted = asyncio.run(seed_postgres_demo(args.truncate, args.repeat, args.hours_step))
    print(f"Inserted {inserted} curated analyses into PostgreSQL.")


if __name__ == "__main__":
    main()
