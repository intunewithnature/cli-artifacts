#!/usr/bin/env python3
"""
cli-artifacts: Windows Event Log parser for people who hate Event Viewer
"""

import argparse
import sys
from pathlib import Path


def parse_evtx(filepath):
    """Parse a Windows Event Log file and return events."""
    # TODO: actually implement this lol
    pass


def main():
    parser = argparse.ArgumentParser(
        description="Parse Windows Event Logs without the GUI nightmare"
    )
    parser.add_argument("logfile", type=Path, help="Path to .evtx file")
    parser.add_argument(
        "-e", "--event-id", 
        type=int, 
        help="Filter by specific event ID"
    )
    parser.add_argument(
        "-l", "--level",
        choices=["critical", "error", "warning", "info"],
        help="Filter by severity level"
    )
    
    args = parser.parse_args()
    
    if not args.logfile.exists():
        print(f"Error: {args.logfile} not found", file=sys.stderr)
        sys.exit(1)
    
    # TODO: wire this up
    print(f"Would parse: {args.logfile}")


if __name__ == "__main__":
    main()
