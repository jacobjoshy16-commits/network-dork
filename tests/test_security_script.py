import subprocess
import sys


def test_bootstrap_opensearch_security_script_help_runs():
    result = subprocess.run(
        [sys.executable, "scripts/bootstrap_opensearch_security.py", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "--telemetry-user" in result.stdout
    assert "--report-index" in result.stdout
