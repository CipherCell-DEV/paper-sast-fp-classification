# Evaluation

Inputs and scripts for the numbers in the Polygraph paper. Needs Python 3.9+.

```
cd evaluation
python3 evaluate.py     # recompute -> evaluation_summary.json
python3 list_errors.py  # the mistakes, with both sides' reasoning
```

## Contents

| Path | Contents |
|---|---|
| `evaluate.py` | Joins each run against the ground truth, computes the metrics. |
| `list_errors.py` | Dangerous suppressions and surviving traps, with the ground truth's justification and the model's. |
| `evaluation_summary.json` | Corpus sizes, per-model confusion matrices and metrics, cost, escalation outcomes, certainty breakdowns, per-CWE / per-repo / per-stage breakdowns, every non-correct case, the ground-truth revision, and a `paper_values` section with each figure rounded as the paper prints it. |
| `data/<corpus>/ground_truth.jsonl` | Labels. One finding per line: `finding_id`, `verdict`, `reason`, location, CWE, class, severity. |
| `data/<corpus>/input.sarif` | The report handed to Polygraph. One SARIF result per ground-truth row, carrying `properties.benchmark.caseId` and no label. |
| `data/<corpus>/runs/<run>/polygraph.sarif` | Run output. `properties.polygraph.{verdict,certainty,reasoning}` per result. All classification metrics come from here. |
| `data/<corpus>/runs/<run>/audit.jsonl` | Per-finding tokens, latency, escalation flag, cache hit, model ids, reasoning, thinking. |
| `data/<corpus>/runs/<run>/polygraph.yaml` | The configuration the run used. |
| `data/realvuln/ground_truth.previous.jsonl` | The ground truth before the correction. |

## Runs

| Paper label | Run | `llm_model` in the audit log |
|---|---|---|
| Qwen 3.8 27B | `run4` | `ai005` |
| Gemma 4 31B | `run8` | `innkube/gemma4-31b` |
| Qwen 3.6 35B | `run3` | `ai005` |
| Qwen3-Next-80B | `run7` | `innkube/qwen3-next-80b-instruct` |

`run3` and `run4` were served under the same deployment name and are told apart by
the run, per the benchmark repo's `notes.md`. Both stages use the same model in
every run.

## Cost bases

`cost` aggregates the ground-truth-joined cases. `cost_audit_log` aggregates the
audit log directly and is what the paper's cost table uses, since it covers every
classification the run performed. The two agree exactly.

They only agree because the audit join runs twice. Audit records identify a
finding by `(file, line, rule_id)`. The eight `vulnpy/trigger/ssrf.py` rows were
reclassified from CWE-918 to CWE-20 in an earlier revision, so their records match
nothing on `rule_id` although the pipeline did classify them: the verdict still
arrives through the SARIF `caseId`, but tokens, latency and the escalation flag
drop out, and the escalation count falls short of the audit log.
`attach_audit_records` re-matches the leftovers on `(file, line)` where that is
unambiguous and reports the count as `audit_records_repaired_by_file_line`.
Verdicts are not touched by that pass.

## Metrics

A `FALSE_POSITIVE` verdict (a suppression) is the positive class. Each finding
lands in one outcome:

| Outcome | Ground truth | Verdict |
|---|---|---|
| `kept` | real | `TRUE_POSITIVE` |
| `dangerous_suppression` | real | `FALSE_POSITIVE` |
| `suppressed` | trap | `FALSE_POSITIVE` |
| `missed_trap` | trap | `TRUE_POSITIVE` |
| `undecided` | either | `UNCERTAIN` |
| `unclassified` | either | none produced |

With `decided = kept + dangerous + suppressed + missed`:

- suppression recall = `suppressed / traps`
- suppression precision = `suppressed / (suppressed + dangerous)`
- F1 = harmonic mean of the two
- dangerous-suppression rate = `dangerous / real`
- TP retention = `kept / real`
- balanced accuracy = `½ · (suppressed/traps + kept/real)`
- MCC over `tp=suppressed, fp=dangerous, fn=missed, tn=kept`
- accuracy (decided) = `(kept + suppressed) / decided`

`undecided` and `unclassified` count towards `total` but not `decided`, so they
cannot inflate a quality metric. Balanced accuracy and MCC accompany accuracy
because the corpora are imbalanced in opposite directions (OWASP 37 % real,
RealVuln 83 % real).
