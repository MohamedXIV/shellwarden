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

    def send_json(
        self, process: subprocess.Popen[str], payload: dict
    ) -> tuple[list[dict], dict]:
        assert process.stdin is not None
        process.stdin.write(json.dumps(payload) + "\n")
        process.stdin.flush()

        events: list[dict] = []
        while True:
            message = self.read_json(process)
            if message.get("type") == "response":
                return events, message
            events.append(message)

    def test_ready_health_and_streamed_harmless_git_execution(self) -> None:
        process = self.start_broker()
        try:
            ready = self.read_json(process)
            self.assertEqual(ready["type"], "ready")
            self.assertEqual(ready["coreVersion"], "1.1.12")
            self.assertEqual(ready["allowedCommands"], ["git"])

            events, health = self.send_json(
                process, {"id": "health-1", "type": "health"}
            )
            self.assertEqual(events, [])
            self.assertTrue(health["ok"])
            self.assertEqual(health["coreVersion"], "1.1.12")

            events, result = self.send_json(
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

            lifecycle = [event.get("event") for event in events]
            self.assertEqual(lifecycle[0], "requested")
            self.assertIn("running", lifecycle)
            self.assertIn("output", lifecycle)
            self.assertEqual(lifecycle[-1], "succeeded")

            output = "".join(
                event.get("chunk", "")
                for event in events
                if event.get("event") == "output"
                and event.get("stream") == "stdout"
            )
            self.assertIn("git version", output.lower())

            events, denied = self.send_json(
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
            self.assertEqual(
                [event.get("event") for event in events],
                ["requested", "denied"],
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
