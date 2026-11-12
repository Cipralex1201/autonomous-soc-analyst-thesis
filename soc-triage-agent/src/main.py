"""Command-line entry point for Milestones 1 and 2."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .config import Settings
from .elastic_client import ElasticAccessError, ElasticClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SOC Level 1 alert investigation agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="validate Elasticsearch connectivity")
    investigate = subparsers.add_parser("investigate", help="retrieve a historical alert by ID")
    investigate.add_argument("--alert-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings.from_env()
    logging.basicConfig(level=settings.log_level, format="%(levelname)s %(message)s")
    try:
        client = ElasticClient(settings)
        if args.command == "check":
            client.check_read_access()
            print("Elasticsearch connection OK")
            return 0
        alert = client.get_alert(args.alert_id)
        print(json.dumps(alert.model_dump(mode="json"), indent=2))
        return 0
    except ElasticAccessError as exc:
        logging.error("%s", exc)
        return 1
    except (OSError, ValueError, RuntimeError) as exc:
        logging.error("Elasticsearch operation failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
