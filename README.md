# Polygraph: SAST False-Positive Classification

LaTeX source for the paper *Polygraph*, a tool that classifies SAST findings
(from SARIF reports) as true or false positives using an LLM, escalating
ambiguous cases to an autonomous agent that explores the repository.

📄 **[Read the rendered paper](Polygraph_Paper.pdf)**

## Contents

| Path | Contents |
|---|---|
| `main.tex` | Paper entry point. |
| `sections/` | Introduction, related work, approach, evaluation, conclusion. |
| `acronyms.tex`, `refs.bib` | Acronym definitions and bibliography. |
| `IEEEtran.cls` | IEEE conference LaTeX class used for typesetting. |
| `evaluation/` | Scripts and data behind the paper's numbers (OWASP Benchmark, RealVuln); see [evaluation/README.md](evaluation/README.md). |

## Building the PDF

```
latexmk -pdf main.tex
```
