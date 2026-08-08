#!/usr/bin/env python3
"""
Run the lightweight Python HTTP/2 reverse bridge locally.
"""

import argparse
from pathlib import Path
import sys

import uvicorn

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.python_http2_bridge import create_bridge_app


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a lightweight local HTTP/1.1 -> HTTP/2 reverse bridge"
    )
    parser.add_argument("--origin", required=True, help="Upstream origin base URL, e.g. https://example.com")
    parser.add_argument("--listen-host", default="127.0.0.1", help="Local listen host (default: 127.0.0.1)")
    parser.add_argument("--listen-port", type=int, default=3000, help="Local listen port (default: 3000)")
    parser.add_argument("--timeout", type=float, default=20.0, help="Upstream timeout in seconds (default: 20.0)")
    args = parser.parse_args()

    app = create_bridge_app(args.origin, timeout=args.timeout)
    print(
        "[+] Starting Python HTTP/2 bridge on "
        f"http://{args.listen_host}:{args.listen_port} -> {args.origin}"
    )
    uvicorn.run(app, host=args.listen_host, port=args.listen_port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
