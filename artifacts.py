#!/usr/bin/env python3
"""
cli-artifacts: Windows Event Log parser for people who hate Event Viewer
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx


# Windows event levels - these are the standard ones
LEVELS = {
    1: "critical",
    2: "error",
    3: "warning",
    4: "info",
    0: "info",  # 0 is "LogAlways", basically info
}


def parse_event_xml(xml_str):
    """Pull the useful bits out of the event XML."""
    try:
        root = ET.fromstring(xml_str)
        
        # namespace bs - Windows events use this everywhere
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        
        system = root.find("ns:System", ns)
        if system is None:
            return None
        
        event_id_elem = system.find("ns:EventID", ns)
        event_id = int(event_id_elem.text) if event_id_elem is not None else 0
        
        level_elem = system.find("ns:Level", ns)
        level_num = int(level_elem.text) if level_elem is not None else 4
        level = LEVELS.get(level_num, "info")
        
        time_elem = system.find("ns:TimeCreated", ns)
        timestamp = time_elem.get("SystemTime") if time_elem is not None else "unknown"
        
        provider_elem = system.find("ns:Provider", ns)
        provider = provider_elem.get("Name") if provider_elem is not None else "unknown"
        
        # try to get the actual message from EventData
        event_data = root.find("ns:EventData", ns)
        message = ""
        if event_data is not None:
            data_items = event_data.findall("ns:Data", ns)
            message = " | ".join([d.text for d in data_items if d.text])
        
        return {
            "event_id": event_id,
            "level": level,
            "timestamp": timestamp,
            "provider": provider,
            "message": message[:200] if message else ""  # truncate long messages
        }
    except ET.ParseError:
        return None


def parse_evtx(filepath):
    """Parse a Windows Event Log file and yield events."""
    with Evtx(str(filepath)) as log:
        for record in log.records():
            try:
                event = parse_event_xml(record.xml())
                if event:
                    yield event
            except Exception:
                # some records are just broken, skip em
                continue


def print_event(event):
    """Print a single event in a readable format."""
    level_display = event["level"].upper().ljust(8)
    print(f"[{event['timestamp']}] {level_display} Event {event['event_id']} ({event['provider']})")
    if event["message"]:
        print(f"    {event['message']}")


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
    
    if not str(args.logfile).lower().endswith(".evtx"):
        print(f"Warning: {args.logfile} doesn't look like an .evtx file", file=sys.stderr)
    
    count = 0
    shown = 0
    for event in parse_evtx(args.logfile):
        count += 1
        
        # filter by level if specified
        if args.level and event["level"] != args.level:
            continue
        
        print_event(event)
        shown += 1
    
    if args.level:
        print(f"\n--- {shown} of {count} events (filtered: {args.level}) ---")
    else:
        print(f"\n--- {count} events ---")


if __name__ == "__main__":
    main()
