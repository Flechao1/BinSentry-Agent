---
name: validation
description: IDA, QEMU, gdbserver, syscall trace, and real-device validation for concrete firmware vulnerability candidates. Use when there is a route, function, source, sink, PoC, candidate finding, exploitability question, or need to classify evidence as confirmed, disproved, weakened, needs emulation, or needs device.
---

# Validation Skill

Use this skill when a candidate exists and the question is whether it is real,
reachable, exploitable, already mitigated, or needs runtime proof.

## IDA Validation

- `xrefs_to` only proves who references a sink, not whether user input reaches it.
- Validate the known callsite before broad scanning.
- Decompile only the functions needed to answer the current question.
- Trace the relevant sink argument, not the whole function, when the callsite is
  known.
- Inspect filtering, parsing, type conversion, bounds checks, auth gates,
  sanitizer calls, and constant substitutions.
- For `execve`/`execl`/`execvp`, distinguish raw argv execution from shell
  interpretation. Do not claim shell injection when no shell parses attacker data.
- For config injection, validate both stages: write-side input control and
  read-side consumption by command execution, script generation, service restart,
  or privileged file use.

## Classification

- `CONFIRMED`: complete source-to-sink evidence with reachable input, controlled
  argument, no blocking sanitizer/auth check, and enough impact evidence for the
  claim being made.
- `DISPROVED`: evidence shows unreachable path, constant argument, safe conversion,
  effective filtering, failed auth reachability, or non-sensitive output.
- `WEAKENED`: risky but constrained, partially controlled, limited by format,
  length, type conversion, required privilege, or environmental assumptions.
- `NEEDS_QEMU`: HTTP reachability, parsing, command construction, sink trigger,
  syscall behavior, or response leakage can be reproduced in emulation.
- `NEEDS_DEVICE`: validation depends on real NVRAM, ASIC/co-processor behavior,
  daemon startup order, allocator/freelist state, boot timing, watchdog behavior,
  per-unit data, or hardware-only reset paths.

## Dynamic Evidence Bar

For code-execution or command-execution claims, require strong independent
evidence:

- new listener on an attacker-selected port
- outbound connection to an attacker-controlled listener
- attacker-selected file path or content created/modified
- expected syscall, command argument, register state, or breakpoint hit
- serial console, kernel ring buffer, or daemon log showing the expected action

Weak signals are not enough: transient HTTP failure, keepalive close timing,
occasional ping loss, service flap, watchdog restart, small RTT changes, or one
uncontrolled crash.

For every runtime proof, include a control run: no payload, empty payload, inert
payload, or a baseline request. The proof signal must differ from control by kind
or clear magnitude, not by a tiny timing change.

## Runtime Path Selection

- Use QEMU when the target daemon can run, HTTP can reach the handler, and the
  question is input parsing, command construction, sink trigger, response content,
  or simple syscall behavior.
- Use the real device when the candidate depends on allocator layout, real NVRAM
  values, sibling daemons over Unix sockets, ASIC/co-processor interaction,
  per-device calibration data, watchdog behavior, or boot-time windows.
- If a daemon logs initialization then fails on missing Unix sockets or sibling
  daemons, record the blocker and move to device validation or explicit stubbing.
- Do not let a failed emulation run disprove a candidate unless the emulation
  faithfully reached the relevant handler and state.

## gdbserver And Syscall Trace

- Use syscall trace for second-stage command/config injection, file writes,
  process execution, or ambiguous runtime side effects.
- Use gdbserver to validate a specific state: sink argument, register value,
  calculated length, auth result, key bytes, or crash register control.
- For timing-sensitive PoCs, separate debugger-assisted state inspection from
  non-debugger reproduction. Attaching can change thread timing and allocator state.
- Prefer conditional/address breakpoints for known addresses. Avoid broad symbol
  loading when it delays or perturbs the target.
- Record architecture, binary, PID, breakpoint address, command/request, observed
  registers/arguments, and whether the same request works without the debugger.

## Device Hygiene

- Before destructive flash, patch, erase, or persistent config tests, require an
  external backup and hash verification.
- Never assume `/tmp` or device-local temporary storage survives reboot.
- Treat per-unit partitions such as factory, calibration, NVRAM, MAC/SN, or
  anti-rollback data as non-regenerable.
- Verify the real reboot path. Vendor CLI/API reboot may differ from Linux
  `/sbin/reboot`; some devices need physical power cycling after service failure.
- Use slow, single-port probing on devices that may have anti-scan rules.

## Output

Include function names, addresses, binary, route, source, sink, argument,
transformation path, filtering/auth evidence, classification, validation tier,
runtime proof or missing evidence, and the next safest validation step.
