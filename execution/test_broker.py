import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BROKER = ROOT / "execution" / "broker.py"


class BrokerIntegrationTests(unittest.TestCase):
    def start_broker(self) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [sys.executable, "-u", str(BROKER)],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def read_json(self, process: subprocess.Popen[str]) -> dict:
        assert process.stdout is not None
        line = process.stdout.readline()
        self.assertTrue(line, "broker exited without a protocol response")
        return json.loads(line)

    def send_json(self, process: subprocess.Popen[str], payload: dict) -> dict:
        assert process.stdin is not None
        process.stdin.write(json.dumps(payload) + "\n")
        process.stdin.flush()
        return self.read_json(process)

    def test_ready_health_and_harmless_git_execution(self) -> None:
        process = self.start_broker()
        try:
            ready = self.read_json(process)
            self.assertEqual(ready["type"], "ready")
            self.assertEqual(ready["coreVersion"], "1.1.12")
            self.assertEqual(ready["allowedCommands"], ["git"])

            health = self.send_json(process, {"id": "health-1", "type": "health"})
            self.assertTrue(health["ok"])
            self.assertEqual(health["coreVersion"], "1.1.12")

            result = self.send_json(
                process,
                {
                    "id": "exec-1",
                    "type": "execute",
                    "command": ["git", "--version"],
                    "directory": str(ROOT),
                    "timeout": 15,
                },
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["result"]["status"], 0)
            self.assertIn("git version", result["result"]["stdout"].lower())

            denied = self.send_json(
                process,
                {
                    "id": "exec-2",
                    "type": "execute",
                    "command": ["python", "-c", "print('should not run')"],
                    "directory": str(ROOT),
                },
            )
            self.assertFalse(denied["ok"])
            self.assertIn("bootstrap policy", denied["error"])
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
