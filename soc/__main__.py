"""Run with python -m soc from the repository root."""

import argparse
import sys
from pathlib import Path

from .config import Config
from .incidents import run
from .response import save_new, update


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="AI Cybersecurity SOC — synthetic offline lab")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("run", help="Analyze local synthetic telemetry")
    analyze.add_argument("--data", type=Path, default=Path("data"))
    analyze.add_argument("--config", type=Path, default=Path("config/lab.json"))
    analyze.add_argument("--output", type=Path, default=Path("reports/incidents.json"))
    review = sub.add_parser("review", help="Record an explicit analyst decision")
    review.add_argument("report", type=Path)
    review.add_argument("--incident", type=int, required=True)
    review.add_argument("--decision", choices=("approve", "reject"), required=True)
    review.add_argument("--analyst", required=True)
    review.add_argument("--reason", required=True)
    respond = sub.add_parser("respond", help="Record a simulation after approval")
    respond.add_argument("report", type=Path)
    respond.add_argument("--incident", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            report = run(args.data, Config.load(args.config))
            save_new(args.output, report)
            print("AI CYBERSECURITY SOC — SYNTHETIC OFFLINE LAB")
            for source, count in report["telemetry_counts"].items():
                print(f"  {source}: {count} events")
            print(f"Normalized: {report['event_count']} | Signals: {report['signal_count']}")
            for incident in report["incidents"]:
                print(f"\nINCIDENT #{incident['incident_id']} — {incident['category']}")
                print(f"Risk: {incident['risk']['level']} ({incident['risk']['score']}/100)")
                print("Investigation: MOCK | Confidence: MEDIUM (fixed teaching label)")
                for signal in incident["signals"]:
                    print(f"  +{signal['points']}: {signal['detail']}")
                print("Response: PENDING HUMAN APPROVAL")
            if not report["incidents"]:
                print("No credential-attack candidates met the configured correlation rule.")
            print(f"\nReport: {args.output}")
        elif args.command == "review":
            print(update(args.report, args.incident, args.decision, args.analyst, args.reason))
        else:
            print(update(args.report, args.incident, "respond"))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        # Input telemetry lines and secrets are never printed by parser diagnostics.
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
