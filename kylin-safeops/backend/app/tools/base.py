import os
import subprocess
import time
from shutil import which


def run_command(args: list[str], timeout: int = 5) -> dict:
    if not args or which(args[0]) is None:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"command not found: {args[0] if args else ''}",
            "command": " ".join(args),
            "duration_ms": 0,
        }

    start = time.perf_counter()
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={
                **os.environ,
                "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
                "LANG": os.environ.get("LANG", "C.UTF-8"),
            },
        )
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": " ".join(args),
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "command": " ".join(args),
            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        }
