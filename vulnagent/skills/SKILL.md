---
name: vuln-discovery
description: CWE-bucket-driven IoT firmware vulnerability discovery router. Use for broad vulnerability hunting, 0-day discovery, firmware/rootfs triage, Web/CGI binary selection, source-to-sink analysis, validation planning, CVE deduplication, and final evidence reporting across buckets A memory corruption, B command/config injection, C auth/access control, F crypto, G information leak, and H deployment/configuration.
---

# Vulnerability Discovery Skill Index

Use this skill as the short router for independent firmware vulnerability
discovery. Load exactly one focused sub-skill unless the user asks for an
end-to-end report.

## Core Principles

- Treat IDA output, deterministic scanners, runtime traces, and device evidence
  as the source of truth.
- A sink, string, route name, xref, or suspicious filename is only a candidate.
  Require source-to-sink evidence before claiming a vulnerability.
- Classify each candidate as `CONFIRMED`, `DISPROVED`, `WEAKENED`,
  `NEEDS_QEMU`, or `NEEDS_DEVICE`.
- Record the missing proof when evidence is incomplete. Do not invent reachability,
  exploitability, authentication state, or sanitizer behavior.
- Prefer one target binary, one function, one sink, and one argument at a time.
  Avoid broad repeated decompilation when a focused tool can answer the question.

## Focus Skills

- `/skill discovery`: firmware/rootfs attack-surface triage, Web/CGI binary
  ranking, route/source/sink discovery, and CWE bucket candidate generation.
- `/skill validation`: IDA validation, candidate classification, QEMU/device
  decision, gdbserver/syscall-trace planning, and dynamic evidence standards.
- `/skill intel_report`: CVE intelligence, public PoC matching, cross-model/SKU
  deduplication, and final report structure.
- `/skill firmware_web_audit`: active-binary Web/CGI audit when an IDA backend is
  already connected and the user wants command-injection or unsafe-memory focus.

## Bucket Router

| User intent | Bucket | Focus |
|---|---|---|
| memory corruption, overflow, heap, stack, format string, UAF | A | unsafe copy/format/recv/parse paths and bounds evidence |
| command injection, RCE, config injection, shell, `system` | B | direct command sinks and second-stage config consumers |
| auth bypass, unauthorized, IDOR, privilege, TOCTOU | C | handler auth gates, role checks, ownership checks |
| crypto, key, RNG, DES, MD5, certificate, private key | F | static keys, weak algorithms, predictable randomness |
| information leak, dump, debug, log, config export | G | sensitive endpoints, debug artifacts, response contents |
| SUID, world-writable, init scripts, unsafe deployment | H | filesystem permissions, startup behavior, unsafe paths |
| broad vuln hunting, 0-day discovery, find bugs | all | start with `discovery`, then validate high-signal candidates |

Explicit `cwe_focus` or user redirection overrides keyword routing.

## Default Flow

1. If the user gives a firmware image, extracted firmware directory, `rootfs`, or
   `squashfs-root`, load `discovery`.
2. If the user already selected a binary or IDA database and asks to find bugs,
   load `firmware_web_audit` for Web/CGI command/memory audit, otherwise load
   `discovery`.
3. If there is a concrete route, function, source, sink, candidate, PoC, or
   exploitability question, load `validation`.
4. If the user asks whether the issue is known, whether it has a CVE, whether it
   affects sibling models, or wants a final report, load `intel_report`.
