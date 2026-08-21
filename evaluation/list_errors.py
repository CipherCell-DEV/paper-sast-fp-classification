#!/usr/bin/env python3
"""Print the cases a run got wrong, with the ground truth's reasoning and the model's.

    python3 list_errors.py                          # leading model, both corpora
    python3 list_errors.py --corpus realvuln
    python3 list_errors.py --model "Gemma 4 31B" --outcome missed_trap

Outcomes: dangerous_suppression (real vulnerability called a false positive),
missed_trap (trap let through), undecided (UNCERTAIN), unclassified (no verdict).
"""

from __future__ import annotations

import argparse
import json
import signal
import textwrap
from pathlib import Path

if hasattr(signal, "SIGPIPE"):  # let `| head` close the pipe without a traceback
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

HERE = Path(__file__).resolve().parent
OUTCOMES = ("dangerous_suppression", "missed_trap", "undecided", "unclassified")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--summary", type=Path, default=HERE / "evaluation_summary.json")
    parser.add_argument("--model", default="Qwen 3.8 27B")
    parser.add_argument("--corpus", choices=("owasp", "realvuln"), action="append", default=None)
    parser.add_argument("--outcome", choices=OUTCOMES, action="append", default=None)
    parser.add_argument("--width", type=int, default=100)
    args = parser.parse_args()

    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    corpora = args.corpus or ["owasp", "realvuln"]
    wanted = args.outcome or ["dangerous_suppression", "missed_trap"]

    def wrap(prefix: str, text: str) -> str:
        body = " ".join((text or "").split())
        return textwrap.fill(
            f"{prefix}{body}", width=args.width, subsequent_indent=" " * len(prefix)
        )

    for corpus in corpora:
        cases = [c for c in summary["cases"][corpus][args.model] if c["outcome"] in wanted]
        print(f"\n{'=' * args.width}")
        print(f"{corpus} / {args.model} / {len(cases)} case(s): {', '.join(wanted)}")
        print("=" * args.width)
        for i, c in enumerate(cases, 1):
            escalated = " escalated" if c["was_escalated"] else ""
            print(f"\n[{i}] {c['finding_id']}  {c['cwe']} {c['vulnerability_class']} "
                  f"severity={c['severity']} certainty={c['certainty'] or '-'}{escalated}")
            print(f"    {c['file']}:{c['start_line']}   outcome={c['outcome']}")
            print(wrap("    ground truth: ", c.get("ground_truth_reason", "")))
            print(wrap("    model:        ", c.get("model_reasoning", "")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
