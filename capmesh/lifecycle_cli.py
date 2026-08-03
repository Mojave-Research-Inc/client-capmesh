"""Operator CLI for catalog-wide lifecycle verification and explicit approval."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .index import connect
from .lifecycle import approve_catalog, verify_catalog
from .models import Principal


def _write_result(result: dict[str, Any], output: str | None) -> None:
    rendered = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
    print(rendered, end="")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Verify or explicitly approve the full Capability Mesh catalog.")
    parser.add_argument("--db", required=True)
    parser.add_argument("--actor", default=os.environ.get("CAPMESH_DEPLOY_ACTOR", "deployer@example.com"))
    parser.add_argument("--apply", action="store_true", help="Persist approvals for passing draft/pending/incomplete capabilities.")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    con = connect(args.db)
    try:
        principal = Principal(subject=args.actor, tenant_id="asg", roles=("org_admin",))
        result = approve_catalog(con, principal) if args.apply else verify_catalog(con, principal)
    finally:
        con.close()
    _write_result(result, args.output)
    passed = result["catalogApproved"] if args.apply else result["catalogPassed"]
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
