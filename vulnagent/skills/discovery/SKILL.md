---
name: discovery
description: Firmware attack-surface triage and CWE-bucket static vulnerability candidate discovery for IoT Web/CGI firmware. Use when the user provides firmware/rootfs paths, asks which binary to analyze, asks for broad 0-day/vulnerability hunting, or wants route/source/sink discovery across memory, command injection, auth, crypto, info leak, and deployment buckets.
---

# Discovery Skill

Use this skill to turn firmware or an active binary into a prioritized candidate
list. Discovery produces candidates, not final vulnerability claims.

## Required Inputs

- Need at least one of: firmware image path, extracted rootfs path, selected
  binary path, or active IDA backend.
- Ask for vendor/model/version when the user wants CVE matching or final reports.
- If no firmware/rootfs/binary is available, ask for the target artifact before
  scanning.

## Firmware And Binary Triage

- If the user provides `squashfs-root`, `rootfs`, or an unpacked firmware path,
  call `scan_firmware_filesystem` first.
- If the user provides a firmware image that is not extracted, explain that the
  image must be unpacked first and ask for the extracted rootfs path unless the
  environment already provides an unpacking workflow.
- Rank likely Web/CGI targets: `httpd`, `lighttpd`, `boa`, `goahead`, `uhttpd`,
  `webs`, `*.cgi`, vendor dispatchers, config daemons, and key shared libraries.
- Treat filesystem strings, filenames, routes, imports, permissions, and xrefs as
  attack-surface evidence only.
- After triage, ask the user to choose one recommended binary or provide the IDA
  backend command before using IDA-only tools.
- For SUID/SGID checks, remember that non-root extraction can strip permission
  bits. Prefer original squashfs metadata when available.

## CWE Buckets

| Bucket | Intent | Inspect |
|---|---|---|
| A | memory corruption, overflow, heap/stack, format string | `strcpy`, `strcat`, `sprintf`, `sscanf`, `memcpy`, `memmove`, `recv`, `read`, `printf`, user-controlled length arithmetic |
| B | command injection, RCE, config injection | `system`, `popen`, `exec*`, vendor wrappers, `nvram_set`, config file writes, second-stage config consumers |
| C | auth bypass, unauthorized, IDOR, TOCTOU | missing `check_auth`/session/role/owner checks, hardcoded credentials, check-then-use file paths |
| F | crypto weakness, keys, RNG | static keys/IVs, PEM blobs, `DES`, `RC4`, `MD5`, ECB mode, `srand(time/getpid)` token paths |
| G | information leak, debug, dump | `getcfg`, `export`, `dump`, `log`, `debug`, backups, core files, sensitive error responses |
| H | deployment/configuration | SUID/SGID, world-writable files, init scripts, unsafe `PATH`/`LD_LIBRARY_PATH`, writable config consumed as code |

Explicit `cwe_focus` from the user overrides keyword routing.

## Static Workflow

1. Identify route handlers, dispatchers, indirect callback tables, source getters,
   request objects, and configuration readers/writers.
2. Enumerate dangerous sinks and suspicious wrappers by bucket.
3. Connect candidate sources to candidate sinks with lightweight evidence first:
   function signals, imports, strings, xrefs, known wrappers, and bounded scans.
4. Inspect only the functions needed for the current candidate.
5. For bucket B, always check second-stage chains: user input stored through
   `nvram_set`, `apmib_set`, database setters, or config file writes, then later
   consumed by `system`, `exec*`, shell scripts, service restart logic, or file
   generation.
6. For bucket A, record whether destination size, source control, length control,
   integer conversion, and bounds checks are known. Mark heap exploitation details
   as validation work unless allocator metadata is visible.
7. Output candidates with `bucket`, `function`, `binary`, `source`, `sink`,
   `evidence`, `uncertainty`, `suggested_status`, and `next_validation_step`.

## Evidence Rules

- A dangerous sink alone is not a vulnerability.
- String routes and xrefs are hints, not complete reachability proof.
- Static candidates remain unverified until validation proves input reachability,
  argument control, and absence of effective filtering or authorization.
- Do not skip a candidate solely because a function name appears in known CVEs;
  same function names can contain different routes, parameters, or bug classes.
- When static evidence hits a runtime boundary, mark the reason:
  `NEEDS_QEMU` for reproducible HTTP parsing, command construction, or sink
  trigger; `NEEDS_DEVICE` for allocator state, real NVRAM, ASIC, daemon order,
  boot timing, or per-device data.
