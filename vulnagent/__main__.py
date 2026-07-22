import sys

from vulnagent.cli import main as cli_main
from vulnagent.ida.backend import main as backend_main


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in {
        "serve",
        "ask",
        "scan",
        "runs",
        "show-run",
        "api",
        "scan-firmware",
        "triage-firmware",
        "intel",
    }:
        cli_main()
    else:
        backend_main()
