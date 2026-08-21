#!/usr/bin/env python3
"""Score the benchmark runs under data/ and write evaluation_summary.json.

Verdicts come from each run's polygraph.sarif, keyed to the ground truth by
properties.benchmark.caseId. Tokens, latency and the escalation flag come from
audit.jsonl. A FALSE_POSITIVE verdict is the positive class. See README.md.

    python3 evaluate.py [evaluation_summary.json]
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"

MODELS = {
    "Qwen 3.8 27B": "run4",
    "Gemma 4 31B": "run8",
    "Qwen 3.6 35B": "run3",
    "Qwen3-Next-80B": "run7",
}

CORPORA = ("owasp", "realvuln")

TRUE_POSITIVE = "TRUE_POSITIVE"
FALSE_POSITIVE = "FALSE_POSITIVE"
UNCERTAIN = "UNCERTAIN"

KEPT = "kept"
DANGEROUS_SUPPRESSION = "dangerous_suppression"
SUPPRESSED = "suppressed"
MISSED_TRAP = "missed_trap"
UNDECIDED = "undecided"
UNCLASSIFIED = "unclassified"


@dataclass
class Case:
    """A ground-truth finding and the run's verdict on it."""

    finding_id: str
    truth: str  # "true_positive" | "false_positive"
    reason: str
    repo: str
    file: str
    start_line: int
    end_line: int | None
    cwe: str
    vulnerability_class: str
    severity: str
    language: str | None

    verdict: str | None = None
    certainty: str = ""
    reasoning: str = ""
    was_escalated: bool = False
    cache_hit: bool = False
    duration_seconds: float = 0.0
    escalation_seconds: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    escalation_input_tokens: int = 0
    escalation_output_tokens: int = 0
    audit: dict[str, Any] = field(default_factory=dict)

    @property
    def truth_is_real(self) -> bool:
        return self.truth == "true_positive"

    @property
    def outcome(self) -> str:
        if self.verdict is None:
            return UNCLASSIFIED
        if self.verdict == UNCERTAIN:
            return UNDECIDED
        if self.truth_is_real:
            return KEPT if self.verdict == TRUE_POSITIVE else DANGEROUS_SUPPRESSION
        return SUPPRESSED if self.verdict == FALSE_POSITIVE else MISSED_TRAP


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_ground_truth(path: Path) -> dict[str, Case]:
    cases: dict[str, Case] = {}
    for row in read_jsonl(path):
        cases[row["finding_id"]] = Case(
            finding_id=row["finding_id"],
            truth=row["verdict"],
            reason=row.get("reason", ""),
            repo=row["repo"],
            file=row["file"],
            start_line=row["start_line"],
            end_line=row.get("end_line"),
            cwe=row["cwe"],
            vulnerability_class=row["vulnerability_class"],
            severity=row["severity"],
            language=row.get("language"),
        )
    if not cases:
        raise SystemExit(f"no ground-truth rows in {path}")
    return cases


def attach_verdicts(cases: dict[str, Case], sarif_path: Path) -> None:
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    seen = 0
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            properties = result.get("properties", {})
            case_id = properties.get("benchmark", {}).get("caseId")
            if case_id is None:
                continue
            seen += 1
            case = cases.get(case_id)
            polygraph = properties.get("polygraph")
            if case is None or polygraph is None:
                continue
            case.verdict = polygraph.get("verdict")
            case.certainty = polygraph.get("certainty") or ""
            case.reasoning = polygraph.get("reasoning") or ""
    if seen == 0:
        raise SystemExit(f"{sarif_path} carries no properties.benchmark.caseId")


def _apply_audit(case: Case, record: dict[str, Any]) -> None:
    case.audit = record
    case.was_escalated = bool(record.get("was_escalated"))
    case.cache_hit = bool(record.get("cache_hit"))
    case.duration_seconds = float(record.get("duration_seconds") or 0.0)
    case.escalation_seconds = float(record.get("escalation_seconds") or 0.0)
    case.input_tokens = int(record.get("input_tokens") or 0)
    case.output_tokens = int(record.get("output_tokens") or 0)
    case.escalation_input_tokens = int(record.get("escalation_input_tokens") or 0)
    case.escalation_output_tokens = int(record.get("escalation_output_tokens") or 0)
    if not case.reasoning:
        case.reasoning = record.get("reasoning") or ""
    if case.verdict is None:
        case.verdict = record.get("verdict")
    if not case.certainty:
        case.certainty = record.get("certainty") or ""


def attach_audit_records(cases: Iterable[Case], audit_path: Path) -> tuple[int, int, str, str]:
    """Attach cost and escalation data. Returns (repaired, unmatched, model, agent_model).

    Pass one matches on (file, line, rule_id), consuming records in order so two
    findings on one line pair up one-for-one. Pass two matches the leftovers on
    (file, line), which recovers the rows whose CWE changed after the run.
    """
    records = read_jsonl(audit_path)
    model = str(records[0].get("llm_model") or "unknown") if records else "unknown"
    agent_model = str(records[0].get("agent_model") or "unknown") if records else "unknown"

    index: dict[tuple[str, int, str], deque[dict[str, Any]]] = defaultdict(deque)
    for record in records:
        index[(record["file"], record["line"], record["rule_id"])].append(record)

    cases = list(cases)
    for case in cases:
        bucket = index.get((case.file, case.start_line, case.cwe))
        if bucket:
            _apply_audit(case, bucket.popleft())

    leftover: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for (file, line, _rule), bucket in index.items():
        leftover[(file, line)].extend(bucket)

    repaired = 0
    for case in cases:
        if case.audit or case.verdict is None:
            continue
        bucket = leftover.get((case.file, case.start_line))
        if len(bucket or []) != 1:
            continue
        _apply_audit(case, bucket.pop())
        repaired += 1

    return repaired, sum(len(b) for b in leftover.values()), model, agent_model


def load_run(gt_path: Path, sarif_path: Path, audit_path: Path) -> dict[str, Any]:
    cases = load_ground_truth(gt_path)
    attach_verdicts(cases, sarif_path)
    ordered = list(cases.values())
    repaired, unmatched, model, agent_model = attach_audit_records(ordered, audit_path)
    return {
        "cases": ordered,
        "model": model,
        "agent_model": agent_model,
        "repaired": repaired,
        "unmatched": unmatched,
    }


def summarise(cases: Iterable[Case]) -> dict[str, Any]:
    """Classification metrics for a set of cases."""
    cases = list(cases)
    outcomes = Counter(case.outcome for case in cases)

    real = sum(1 for case in cases if case.truth_is_real)
    traps = len(cases) - real

    kept = outcomes[KEPT]
    dangerous = outcomes[DANGEROUS_SUPPRESSION]
    suppressed = outcomes[SUPPRESSED]
    missed = outcomes[MISSED_TRAP]
    undecided = outcomes[UNDECIDED]

    decided = kept + dangerous + suppressed + missed
    correct = kept + suppressed

    suppression_calls = suppressed + dangerous
    precision = suppressed / suppression_calls if suppression_calls else 0.0
    recall = suppressed / traps if traps else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    trap_rate = recall
    real_rate = kept / real if real else 0.0
    balanced = (trap_rate + real_rate) / 2 if (traps and real) else 0.0

    tp, fp, fn, tn = suppressed, dangerous, missed, kept
    denominator = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    mcc = ((tp * tn - fp * fn) / denominator) if denominator else 0.0

    return {
        "total": len(cases),
        "real": real,
        "traps": traps,
        "kept": kept,
        "dangerous_suppression": dangerous,
        "suppressed": suppressed,
        "missed_trap": missed,
        "undecided": undecided,
        "undecided_real": sum(1 for c in cases if c.outcome == UNDECIDED and c.truth_is_real),
        "undecided_trap": sum(1 for c in cases if c.outcome == UNDECIDED and not c.truth_is_real),
        "unclassified": outcomes[UNCLASSIFIED],
        "decided": decided,
        "correct": correct,
        "fp_suppression_recall": recall,
        "dangerous_suppression_rate": dangerous / real if real else 0.0,
        "tp_retention": real_rate,
        "trap_miss_rate": missed / traps if traps else 0.0,
        "suppression_precision": precision,
        "f1": f1,
        "accuracy_overall": correct / len(cases) if cases else 0.0,
        "accuracy_decided": correct / decided if decided else 0.0,
        "balanced_accuracy": balanced,
        "mcc": mcc,
        "uncertain_rate": undecided / len(cases) if cases else 0.0,
    }


def case_row(case: Case) -> dict[str, Any]:
    return {
        "finding_id": case.finding_id,
        "truth": case.truth,
        "verdict": case.verdict,
        "certainty": case.certainty,
        "outcome": case.outcome,
        "was_escalated": case.was_escalated,
        "cache_hit": case.cache_hit,
        "repo": case.repo,
        "file": case.file,
        "start_line": case.start_line,
        "cwe": case.cwe,
        "vulnerability_class": case.vulnerability_class,
        "severity": case.severity,
        "duration_seconds": case.duration_seconds,
        "escalation_seconds": case.escalation_seconds,
        "input_tokens": case.input_tokens,
        "output_tokens": case.output_tokens,
        "escalation_input_tokens": case.escalation_input_tokens,
        "escalation_output_tokens": case.escalation_output_tokens,
        "ground_truth_reason": case.reason,
        "model_reasoning": case.reasoning,
    }


def cost_block(cases: list[Case]) -> dict[str, Any]:
    """Cost over the joined cases, per all findings and per classified findings."""
    classified = [c for c in cases if c.verdict is not None]
    n_all, n_cls = len(cases), len(classified)

    tokens = sum(c.input_tokens + c.output_tokens for c in cases)
    seconds = sum(c.duration_seconds for c in cases)
    escalated = [c for c in cases if c.was_escalated]

    return {
        "findings_total": n_all,
        "findings_classified": n_cls,
        "input_tokens": sum(c.input_tokens for c in cases),
        "output_tokens": sum(c.output_tokens for c in cases),
        "total_tokens": tokens,
        "escalation_input_tokens": sum(c.escalation_input_tokens for c in cases),
        "escalation_output_tokens": sum(c.escalation_output_tokens for c in cases),
        "escalation_tokens": sum(c.escalation_input_tokens + c.escalation_output_tokens for c in cases),
        "tokens_per_finding_all": tokens / n_all if n_all else 0.0,
        "tokens_per_finding_classified": tokens / n_cls if n_cls else 0.0,
        "seconds_total": seconds,
        "hours_total": seconds / 3600,
        "escalation_seconds_total": sum(c.escalation_seconds for c in cases),
        "seconds_per_finding_all": seconds / n_all if n_all else 0.0,
        "seconds_per_finding_classified": seconds / n_cls if n_cls else 0.0,
        "escalated_count": len(escalated),
        "escalation_rate_all": len(escalated) / n_all if n_all else 0.0,
        "escalation_rate_classified": len(escalated) / n_cls if n_cls else 0.0,
        "cache_hits": sum(1 for c in cases if c.cache_hit),
        "cache_hit_rate": sum(1 for c in cases if c.cache_hit) / n_all if n_all else 0.0,
    }


def audit_cost_block(audit_path: Path) -> dict[str, Any]:
    """Cost off the audit log alone. The basis of the paper's cost table."""
    records = read_jsonl(audit_path)
    n = len(records)
    tokens = sum(r["input_tokens"] + r["output_tokens"] for r in records)
    seconds = sum(r["duration_seconds"] for r in records)
    escalated = sum(1 for r in records if r.get("was_escalated"))
    return {
        "records": n,
        "escalated": escalated,
        "escalation_rate": escalated / n if n else 0.0,
        "input_tokens": sum(r["input_tokens"] for r in records),
        "output_tokens": sum(r["output_tokens"] for r in records),
        "total_tokens": tokens,
        "tokens_per_finding": tokens / n if n else 0.0,
        "seconds_total": seconds,
        "seconds_per_finding": seconds / n if n else 0.0,
        "hours_total": seconds / 3600,
        "cache_hits": sum(1 for r in records if r.get("cache_hit")),
    }


def escalation_block(cases: list[Case]) -> dict[str, Any]:
    """Outcomes of the escalated findings.

    Escalation fires on UNCERTAIN or on FALSE_POSITIVE below HIGH certainty, so an
    escalated finding ending as TRUE_POSITIVE is one the agent overturned.
    """
    esc = [c for c in cases if c.was_escalated]
    overturned = [c for c in esc if c.verdict == TRUE_POSITIVE]
    confirmed = [c for c in esc if c.verdict == FALSE_POSITIVE]
    return {
        "escalated": len(esc),
        "escalated_real": sum(1 for c in esc if c.truth_is_real),
        "escalated_trap": sum(1 for c in esc if not c.truth_is_real),
        "overturned_to_true_positive": len(overturned),
        "overturned_real": sum(1 for c in overturned if c.truth_is_real),
        "overturned_trap": sum(1 for c in overturned if not c.truth_is_real),
        "confirmed_false_positive": len(confirmed),
        "confirmed_trap": sum(1 for c in confirmed if not c.truth_is_real),
        "confirmed_real": sum(1 for c in confirmed if c.truth_is_real),
        "still_uncertain": sum(1 for c in esc if c.verdict == UNCERTAIN),
        "no_verdict": sum(1 for c in esc if c.verdict is None),
        "mistakes_among_escalated": sum(
            1 for c in esc if c.outcome in (DANGEROUS_SUPPRESSION, MISSED_TRAP)
        ),
        "dangerous_suppressions_escalated": sum(
            1 for c in cases if c.outcome == DANGEROUS_SUPPRESSION and c.was_escalated
        ),
        "dangerous_suppressions_first_stage": sum(
            1 for c in cases if c.outcome == DANGEROUS_SUPPRESSION and not c.was_escalated
        ),
        "missed_traps_escalated": sum(1 for c in cases if c.outcome == MISSED_TRAP and c.was_escalated),
        "missed_traps_first_stage": sum(
            1 for c in cases if c.outcome == MISSED_TRAP and not c.was_escalated
        ),
    }


def certainty_block(cases: list[Case]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for level in ("HIGH", "MEDIUM", "LOW", ""):
        group = [c for c in cases if (c.certainty or "") == level]
        if not group:
            continue
        out[level or "none"] = {
            "n": len(group),
            "escalated": sum(1 for c in group if c.was_escalated),
            **{
                name: sum(1 for c in group if c.outcome == name)
                for name in (KEPT, DANGEROUS_SUPPRESSION, SUPPRESSED, MISSED_TRAP, UNDECIDED, UNCLASSIFIED)
            },
        }
    return out


def breakdown(cases: list[Case], key: Callable[[Case], str]) -> dict[str, Any]:
    groups: dict[str, list[Case]] = defaultdict(list)
    for case in cases:
        groups[key(case)].append(case)
    return {name: summarise(group) for name, group in sorted(groups.items())}


def main() -> int:
    summary: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "methodology": {
            "positive_class": "FALSE_POSITIVE verdict (suppression)",
            "verdict_join": "polygraph.sarif properties.benchmark.caseId -> ground-truth finding_id",
            "cost_join": "audit.jsonl matched on (file, line, rule_id), leftovers re-matched on (file, line)",
            "definitions": {
                "kept": "ground truth real, verdict TRUE_POSITIVE",
                "dangerous_suppression": "ground truth real, verdict FALSE_POSITIVE",
                "suppressed": "ground truth trap, verdict FALSE_POSITIVE",
                "missed_trap": "ground truth trap, verdict TRUE_POSITIVE",
                "undecided": "verdict UNCERTAIN",
                "unclassified": "no verdict produced",
                "fp_suppression_recall": "suppressed / traps",
                "suppression_precision": "suppressed / (suppressed + dangerous_suppression)",
                "f1": "harmonic mean of suppression precision and recall",
                "dangerous_suppression_rate": "dangerous_suppression / real",
                "tp_retention": "kept / real",
                "balanced_accuracy": "0.5 * (suppressed/traps + kept/real)",
                "mcc": "Matthews correlation, tp=suppressed fp=dangerous fn=missed_trap tn=kept",
                "accuracy_decided": "(kept + suppressed) / decided",
                "accuracy_overall": "(kept + suppressed) / total",
                "uncertain_rate": "undecided / total",
            },
        },
        "inputs": {},
        "corpora": {},
        "models": {},
        "results": {},
        "cases": {},
        "breakdowns": {},
    }

    for corpus in CORPORA:
        root = DATA / corpus
        gt_path = root / "ground_truth.jsonl"
        rows = read_jsonl(gt_path)
        counts = Counter(r["verdict"] for r in rows)
        summary["corpora"][corpus] = {
            "ground_truth": str(gt_path.relative_to(HERE)),
            "ground_truth_sha256": sha256(gt_path),
            "input_sarif": str((root / "input.sarif").relative_to(HERE)),
            "input_sarif_sha256": sha256(root / "input.sarif"),
            "findings": len(rows),
            "real": counts["true_positive"],
            "traps": counts["false_positive"],
            "files": len({r["file"] for r in rows}),
            "repos": len({r["repo"] for r in rows}),
            "cwes": len({r["cwe"] for r in rows}),
        }

    for corpus in CORPORA:
        root = DATA / corpus
        summary["results"][corpus] = {}
        summary["cases"][corpus] = {}
        summary["inputs"][corpus] = {}
        for label, run_dir in MODELS.items():
            d = root / "runs" / run_dir
            run = load_run(root / "ground_truth.jsonl", d / "polygraph.sarif", d / "audit.jsonl")
            cases: list[Case] = run["cases"]
            stats = summarise(cases)

            summary["models"].setdefault(
                label, {"run_dir": run_dir, "audit_model": run["model"], "audit_agent_model": run["agent_model"]}
            )
            summary["inputs"][corpus][label] = {
                "run_dir": str(d.relative_to(HERE)),
                "polygraph_sarif_sha256": sha256(d / "polygraph.sarif"),
                "audit_jsonl_sha256": sha256(d / "audit.jsonl"),
                "config_sha256": sha256(d / "polygraph.yaml"),
            }
            summary["results"][corpus][label] = {
                "run_dir": str(d.relative_to(HERE)),
                "model_id": run["model"],
                "agent_model_id": run["agent_model"],
                "confusion": {
                    "real_kept_tp": stats["kept"],
                    "real_verdict_fp": stats["dangerous_suppression"],
                    "real_uncertain": stats["undecided_real"],
                    "trap_verdict_fp": stats["suppressed"],
                    "trap_verdict_tp": stats["missed_trap"],
                    "trap_uncertain": stats["undecided_trap"],
                    "unclassified": stats["unclassified"],
                    "real_total": stats["real"],
                    "trap_total": stats["traps"],
                },
                "metrics": {
                    k: stats[k]
                    for k in (
                        "fp_suppression_recall",
                        "suppression_precision",
                        "f1",
                        "dangerous_suppression_rate",
                        "tp_retention",
                        "trap_miss_rate",
                        "balanced_accuracy",
                        "mcc",
                        "accuracy_overall",
                        "accuracy_decided",
                        "uncertain_rate",
                        "decided",
                        "correct",
                    )
                },
                "cost": cost_block(cases),
                "cost_audit_log": audit_cost_block(d / "audit.jsonl"),
                "escalation": escalation_block(cases),
                "certainty": certainty_block(cases),
                "audit_records_repaired_by_file_line": run["repaired"],
                "unmatched_audit_records": run["unmatched"],
            }
            summary["cases"][corpus][label] = [
                case_row(c) for c in cases if c.outcome not in (KEPT, SUPPRESSED)
            ]

    # Breakdowns for the model the paper discusses.
    for corpus in CORPORA:
        root = DATA / corpus
        d = root / "runs" / MODELS["Qwen 3.8 27B"]
        run = load_run(root / "ground_truth.jsonl", d / "polygraph.sarif", d / "audit.jsonl")
        summary["breakdowns"][corpus] = {
            "by_cwe": breakdown(run["cases"], lambda c: c.cwe),
            "by_repo": breakdown(run["cases"], lambda c: c.repo),
            "by_certainty": breakdown(run["cases"], lambda c: c.certainty or "unclassified"),
            "by_stage": breakdown(run["cases"], lambda c: "escalated" if c.was_escalated else "first-stage"),
        }

    previous = DATA / "realvuln" / "ground_truth.previous.jsonl"
    if previous.exists():
        now = {r["finding_id"]: r for r in read_jsonl(DATA / "realvuln" / "ground_truth.jsonl")}
        before = {r["finding_id"]: r for r in read_jsonl(previous)}
        flipped = sorted(k for k in now if k in before and now[k]["verdict"] != before[k]["verdict"])
        summary["ground_truth_revision"] = {
            "corpus": "realvuln",
            "previous_file": str(previous.relative_to(HERE)),
            "previous_file_sha256": sha256(previous),
            "previous_real": sum(1 for r in before.values() if r["verdict"] == "true_positive"),
            "previous_traps": sum(1 for r in before.values() if r["verdict"] == "false_positive"),
            "fields_changed": sorted(
                {
                    f
                    for k in now
                    if k in before
                    for f in set(now[k]) | set(before[k])
                    if now[k].get(f) != before[k].get(f)
                }
            ),
            "relabelled": [
                {
                    "finding_id": k,
                    "from": before[k]["verdict"],
                    "to": now[k]["verdict"],
                    "cwe": now[k]["cwe"],
                    "file": now[k]["file"],
                    "start_line": now[k]["start_line"],
                    "previous_reason": before[k].get("reason", ""),
                    "reason": now[k]["reason"],
                }
                for k in flipped
            ],
        }

    # Each figure the paper prints, rounded as it prints it.
    lead = "Qwen 3.8 27B"
    ow, rv = summary["results"]["owasp"], summary["results"]["realvuln"]
    summary["paper_values"] = {
        "note": "Cost-table rows come from cost_audit_log. The escalation prose comes "
        "from the ground-truth join, whose outcomes it analyses; both counts agree.",
        "abstract_and_intro": {
            "owasp_trap_suppression_pct": round(100 * ow[lead]["metrics"]["fp_suppression_recall"], 1),
            "owasp_suppression_precision": round(ow[lead]["metrics"]["suppression_precision"], 3),
            "owasp_f1": round(ow[lead]["metrics"]["f1"], 3),
            "owasp_balanced_accuracy": round(ow[lead]["metrics"]["balanced_accuracy"], 3),
            "owasp_dangerous_suppression_pct": round(100 * ow[lead]["metrics"]["dangerous_suppression_rate"], 1),
            "realvuln_f1": round(rv[lead]["metrics"]["f1"], 3),
            "realvuln_balanced_accuracy": round(rv[lead]["metrics"]["balanced_accuracy"], 3),
            "realvuln_trap_suppression_pct": round(100 * rv[lead]["metrics"]["fp_suppression_recall"], 1),
            "realvuln_dangerous_suppression_pct": round(
                100 * rv[lead]["metrics"]["dangerous_suppression_rate"], 1
            ),
        },
        "corpus_sentence": {
            "realvuln_findings": summary["corpora"]["realvuln"]["findings"],
            "realvuln_files": summary["corpora"]["realvuln"]["files"],
            "realvuln_cwes": summary["corpora"]["realvuln"]["cwes"],
            "realvuln_real": summary["corpora"]["realvuln"]["real"],
            "realvuln_traps": summary["corpora"]["realvuln"]["traps"],
            "owasp_findings": summary["corpora"]["owasp"]["findings"],
            "owasp_real": summary["corpora"]["owasp"]["real"],
            "owasp_traps": summary["corpora"]["owasp"]["traps"],
        },
        "table_confusion": {corpus: results[lead]["confusion"] for corpus, results in (("owasp", ow), ("realvuln", rv))},
        "figure_quality": {
            corpus: {
                label: {
                    "f1": round(r["metrics"]["f1"], 2),
                    "balanced_accuracy": round(r["metrics"]["balanced_accuracy"], 2),
                }
                for label, r in results.items()
            }
            for corpus, results in (("owasp", ow), ("realvuln", rv))
        },
        "table_cost": {
            label: {
                corpus: {
                    "escalation_pct": round(100 * results[label]["cost_audit_log"]["escalation_rate"], 1),
                    "seconds_per_finding": round(results[label]["cost_audit_log"]["seconds_per_finding"], 1),
                    "tokens_per_finding": round(results[label]["cost_audit_log"]["tokens_per_finding"]),
                }
                for corpus, results in (("owasp", ow), ("realvuln", rv))
            }
            for label in MODELS
        },
        "escalation_prose": {
            corpus: results[lead]["escalation"] for corpus, results in (("owasp", ow), ("realvuln", rv))
        },
        "spreads": {
            "owasp_f1_top3": round(
                max(r["metrics"]["f1"] for r in ow.values())
                - sorted((r["metrics"]["f1"] for r in ow.values()), reverse=True)[2],
                3,
            ),
            "realvuln_f1_top3": round(
                max(r["metrics"]["f1"] for r in rv.values())
                - sorted((r["metrics"]["f1"] for r in rv.values()), reverse=True)[2],
                3,
            ),
            "owasp_recall_range": [
                round(min(r["metrics"]["fp_suppression_recall"] for r in ow.values()), 3),
                round(max(r["metrics"]["fp_suppression_recall"] for r in ow.values()), 3),
            ],
            "owasp_precision_range": [
                round(min(r["metrics"]["suppression_precision"] for r in ow.values()), 4),
                round(max(r["metrics"]["suppression_precision"] for r in ow.values()), 4),
            ],
            "realvuln_recall_range": [
                round(min(r["metrics"]["fp_suppression_recall"] for r in rv.values()), 3),
                round(max(r["metrics"]["fp_suppression_recall"] for r in rv.values()), 3),
            ],
            "realvuln_dangerous_rate_range_pct": [
                round(100 * min(r["metrics"]["dangerous_suppression_rate"] for r in rv.values()), 1),
                round(100 * max(r["metrics"]["dangerous_suppression_rate"] for r in rv.values()), 1),
            ],
            "f1_ranking_owasp": [l for l, _ in sorted(ow.items(), key=lambda kv: -kv[1]["metrics"]["f1"])],
            "f1_ranking_realvuln": [l for l, _ in sorted(rv.items(), key=lambda kv: -kv[1]["metrics"]["f1"])],
        },
    }

    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "evaluation_summary.json"
    out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
