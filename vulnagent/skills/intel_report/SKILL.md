---
name: intel_report
description: Known-vulnerability intelligence correlation and final evidence reporting. Use when the user asks whether a candidate has a CVE, whether it is publicly known, whether a public PoC exists, whether sibling models or SKUs are affected, or wants a final vulnerability report.
---

# Intel Report Skill

Use this skill after a candidate or confirmed finding exists. Correlate firmware
evidence with public references, deduplicate across models, and structure the final
report. Do not invent CVE IDs, vendors, products, or PoC facts from memory.

## Intelligence Lookup

- Use `search_vulnerability_intel` for CVE.org website-backed data, NVD, and
  GitHub public PoC/exploit search.
- Pass only observed evidence from firmware triage, IDA tools, taint tracing, or
  validated findings: vendor, product, firmware_version, component,
  vulnerability_type, route, sink, and comma-separated symbols/keywords.
- Leave a field empty rather than guessing a vendor or model. A wrong or invented
  identifier corrupts keyword construction and scoring.
- Use `sources` to include or exclude `cveorg`, `nvd`, and `github`. GitHub adds
  PoC/exploit-oriented queries; NVD and CVE.org use official-record queries.

## Score Interpretation

- Score >= 70 (`likely_known_vulnerability`): strong public-record match. Report the
  matched reference, URL, reasons, and confidence, and confirm the version and
  component overlap instead of assuming the firmware is affected.
- Score 40-69 (`possible_known_vulnerability`): keyword overlap only. State which
  terms matched and what is still missing (exact version, affected function, patch
  diff) before treating the CVE as applicable.
- Score < 40 or no matches (`no_strong_match`): no strong public intelligence. This
  does not prove the finding is novel; it only means the public sources did not
  return a strong match. Report it as unresolved.
- `lookup_failed`: record the per-source lookup errors and treat the query as
  inconclusive, not as "no CVE exists".

## Evidence Rules

- A public CVE is not a substitute for source-to-sink validation of the current
  binary. Same function names can contain different routes, parameters, or bug
  classes.
- Do not cite CVE IDs from memory; only report identifiers returned by the tool.
- If lookup results are weak, state the missing terms and re-run with better
  evidence from IDA or validation before writing the report.

## Cross-Model And SKU Dedup

- When a candidate affects one model, run the same query against sibling models and
  SKUs to check whether the issue is already public across the family.
- Canonicalize vendor spelling (for example D-Link vs D-Link) and try both product
  forms with and without spaces or dashes when constructing follow-up queries.
- Deduplicate references by source and identifier; repeated search terms should not
  inflate match counts or scores.

## Final Report

Include, when available:

- finding summary and CWE bucket
- affected binary, function/address, route, source, sink, and argument
- static and dynamic evidence with the validation tier (CONFIRMED, DISPROVED,
  WEAKENED, NEEDS_QEMU, NEEDS_DEVICE)
- intelligence outcome: matched CVE/PoC references with URLs, score, confidence,
  and matched terms, or the explicit no-strong-match conclusion
- sibling-model/SKU impact assessment
- missing evidence and the next safest step

Never present lookup failures or keyword-only overlap as confirmed CVE matches.
