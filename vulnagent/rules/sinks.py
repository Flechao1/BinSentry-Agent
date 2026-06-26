"""Default sink rules for Web/CGI firmware analysis."""

from __future__ import annotations

from copy import deepcopy


DEFAULT_SINK_SPECS: dict[str, list[tuple]] = {
    "system": [("index", 1)],
    "popen": [("index", 1)],
    "exec": [("range", 1, 8)],
    "execl": [("range", 1, 8)],
    "execlp": [("range", 1, 8)],
    "execle": [("range", 1, 8)],
    "execv": [("range", 1, 2)],
    "execvp": [("range", 1, 2)],
    "execve": [("range", 1, 3)],
    "doSystem": [("range", 1, 8)],
    "strcpy": [("index", 2)],
    "strcat": [("index", 2)],
    "sprintf": [("range", 2, 32)],
    "vsprintf": [("range", 2, 32)],
    "memcpy": [("range", 2, 3)],
    "memmove": [("range", 2, 3)],
}


def get_default_sink_specs() -> dict[str, list[tuple]]:
    """Return a caller-owned copy of the default sink rules."""
    return deepcopy(DEFAULT_SINK_SPECS)
