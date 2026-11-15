"""Validate the debugger against a bounded, cooperative direct/vtable-call fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import threading
import time


def capture_available(status):
    return status.get("matrixhv_protocol") == 10 and status.get("memory_event_v3") is True


def fetch_records(neo, token, cpu_count):
    records = []
    for cpu in range(cpu_count):
        cursor = 0
        while True:
            batch = neo("session", "fetch", token, cpu, cursor, 1)
            assert int(batch["dropped"], 16) == 0
            if not batch["records"]:
                break
            next_cursor = int(batch["next"], 16)
            if next_cursor <= cursor:
                raise RuntimeError("Event fetch did not advance its cursor")
            records.extend(batch["records"])
            cursor = next_cursor
            if cursor >= int(batch["head"], 16):
                break
    return records


class FixtureProcess:
    def __init__(self, binary):
        self.process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
        self.pending = queue.Queue()
        threading.Thread(target=self.read, daemon=True).start()
        try:
            self.ready = self.row()
        except BaseException:
            self.close()
            raise

    def read(self):
        for line in self.process.stdout:
            self.pending.put(line)

    def row(self):
        try:
            return json.loads(self.pending.get(timeout=15))
        except queue.Empty as error:
            raise RuntimeError("Fixture did not respond within 15 seconds") from error

    def call(self, operation):
        self.process.stdin.write(operation + "\n")
        self.process.stdin.flush()
        result = self.row()
        assert result["type"] == "done" and result["scalar"] == 0x11223344 and result["stack"] == 85
        assert result["result"] == 0x11223344 ^ 85
        return result

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write("exit\n")
                self.process.stdin.flush()
                self.process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--neo", type=Path)
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--resolve", action="store_true")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = project / "builds/debugger-fixture"
    output.mkdir(parents=True, exist_ok=True)
    binary = output / "debugger-fixture.exe"
    subprocess.run(["rustc", "--edition=2024", "-Dwarnings", "-C", "opt-level=1",
                    str(project / "tests/debugger_fixture.rs"), "-o", str(binary)], cwd=project, check=True)
    if (args.capture or args.resolve) and args.neo is None:
        parser.error("--capture and --resolve require --neo")

    def neo(*operands):
        result = subprocess.run([str(args.neo.resolve()), "--json", *map(str, operands)],
                                capture_output=True, timeout=60)
        rows = [json.loads(line) for line in result.stdout.decode().splitlines() if line.strip()]
        if result.returncode or not rows or not rows[-1].get("ok"):
            raise RuntimeError(f"Neo command failed: {operands}: {result.stdout!r} {result.stderr!r}")
        return rows[-1]["data"]

    if args.capture:
        status = neo("status")
        available = capture_available(status)
        (output / "capture-preflight.json").write_text(json.dumps({
            "status": "PASS" if available else "UNAVAILABLE",
            "required_protocol": 10, "observed": status}, indent=2))
        if not available:
            raise RuntimeError("This test requires a booted MatrixHV protocol 10 core with event-v3 capture")

    fixture = FixtureProcess(binary)
    evidence = {"status": "RUNNING", "capture": args.capture, "checks": []}
    token = None
    recording = None
    try:
        ready = fixture.ready
        evidence["fixture"] = ready
        if args.resolve:
            modules = neo("modules", ready["pid"], "auto", "--sections")
            fixture_module = next(module for module in modules["modules"] if module["name"].lower() == binary.name.lower())
            base = int(fixture_module["base"], 16)
            direct_rva = int(ready["direct_probe"], 16) - base
            decoded = neo("disasm", ready["pid"], "auto", f"{binary.name}+{direct_rva:#x}", 5)
            instruction = decoded["instructions"][0]
            assert instruction["bytes"].startswith("e8")
            assert int(instruction["targets"][0]["address"], 16) == int(ready["target"], 16)
            evidence["resolution"] = {"status": "PASS", "module": fixture_module, "instruction": instruction}
        for operation in ("direct", "virtual"):
            if args.capture:
                setup = neo("session", "set", "auto", 0, "--process", ready["pid"],
                            "--instruction", ready[operation + "_probe"], "--arg-reg", "r8", 16, 1,
                            "--arg-stack", 32, 0, 0, "--region", ready["state"], 64,
                            "--code-pages", "--snapshot-arm", "--snapshot-after", "--lease-ms", 10000)
                token = setup["token"]
                path = output / f"{operation}-{time.time_ns()}.jsonl"
                recording = subprocess.Popen([str(args.neo.resolve()), "--json", "session", "record", str(token),
                                               "--process", str(ready["pid"]), "--seconds", "2", "--output", str(path)],
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                deadline = time.monotonic() + 10
                while not path.exists() or path.stat().st_size == 0:
                    if recording.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("Recorder did not initialize")
                    time.sleep(0.025)
            result = fixture.call(operation)
            if args.capture:
                stdout, stderr = recording.communicate(timeout=15)
                if recording.returncode:
                    raise RuntimeError(f"Recorder failed: {stdout} {stderr}")
                events = [json.loads(line) for line in path.read_text().splitlines()]
                hits = [event for event in events if event.get("kind") == "instruction"]
                assert len(hits) == 1
                hit = hits[0]
                assert int(hit["context"]["rip"], 16) == int(ready[operation + "_probe"], 16)
                assert hit["instruction"]["call_kind"] == ("direct" if operation == "direct" else "memory")
                assert int(hit["instruction"]["effective_target"], 16) == int(ready["target"], 16)
                assert hit["instruction"]["status"] == 0
                assert int(hit["context"]["rdx"], 16) == 0x11223344
                assert int(hit["context"]["rcx"], 16) == int(ready["state"], 16)
                assert int(hit["context"]["r8"], 16) == int(ready["data"], 16)
                assert int(hit["context"]["r9"], 16) == 7
                assert int(hit["target_identity"]["pid"], 16) == ready["pid"]
                assert hit["thread_id_status"] == 0 and int(hit["thread_id"], 16) != 0
                assert hit["process_atomic"] is False and hit["target_identity"]["validated"] is True
                arguments = [segment for segment in hit["segments"] if segment.get("argument")]
                register = next(segment for segment in arguments if segment["argument"]["source_kind"] == "register")
                stack = next(segment for segment in arguments if segment["argument"]["source_kind"] == "stack")
                assert register["copied"] == 16 and register["bytes"] == "5a" * 16
                assert int(stack["argument"]["value"], 16) == 85 and stack["requested"] == 0
                assert hit["segments"][3]["copied"] == 4096 and hit["segments"][3]["status"] == 0
                frozen_state = bytes.fromhex(hit["segments"][2]["bytes"])
                assert int.from_bytes(frozen_state[8:16], "little") == (0 if operation == "direct" else 1)
                phases = {event.get("snapshot_phase") for event in events if event.get("type") == "event"}
                assert {"arm", "hit", "after_instruction"} <= phases
                after = next(event for event in events if event.get("snapshot_phase") == "after_instruction")
                assert after["instruction_retired"] is True
                assert after["correlation"]["hit_sequence"] == hit["context"]["sequence"]
                assert after["context"]["cpu"] == hit["context"]["cpu"]
                assert int(after["context"]["rip"], 16) == int(ready["target"], 16)
                assert int(after["context"]["rsp"], 16) == int(hit["context"]["rsp"], 16) - 8
                assert int.from_bytes(bytes.fromhex(after["segments"][1]["bytes"][:16]), "little") == int(hit["context"]["rip"], 16) + hit["instruction"]["length"]
                assert events[-1]["type"] == "end" and events[-1]["complete"] is True
                before_key = f'{hit["context"]["cpu"]}:{hit["context"]["sequence"]}'
                after_key = f'{after["context"]["cpu"]}:{after["context"]["sequence"]}'
                comparison = neo("session", "compare", path, before_key, after_key)
                assert comparison["process_atomic"] is False
                assert any(page["segment"] == 2 and page["state"] == "unchanged" for page in comparison["pages"])
                destination = output / f"{operation}-export-{time.time_ns()}"
                neo("session", "export", path, "--output", destination)
                manifest = json.loads((destination / "metadata.json").read_text())
                assert manifest["process_atomic"] is False and len(manifest["events"]) == 3
                for event in manifest["events"]:
                    assert event["process_atomic"] is False and event["consistency_note"]
                    for segment in event["segments"]:
                        for page in segment["pages"]:
                            data = (destination / page["buffer"]).read_bytes()
                            assert len(data) == page["copied"]
                            assert hashlib.sha256(data).hexdigest() == page["sha256"]
                evidence["checks"].append({"operation": operation, "capture": str(path),
                    "phases": sorted(phases), "export": str(destination), "status": "PASS"})
                neo("hook", "release", token)
                token = None
            evidence["checks"].append({"operation": operation, "result": result, "status": "PASS"})
        if args.capture:
            def arm(*options):
                return neo("session", "set", "auto", 0, "--process", ready["pid"],
                           "--instruction", ready["direct_probe"], *options)["token"]

            def fetch(label):
                records = fetch_records(neo, token, status["logical_processor_count"])
                path = output / f"{label}-{time.time_ns()}.json"
                path.write_text(json.dumps(records, indent=2))
                return records

            other = FixtureProcess(binary)
            try:
                assert other.ready["direct_probe"] == ready["direct_probe"]
                token = arm("--lease-ms", 10000)
                other.call("direct")
                assert fetch("other-process") == []
                fixture.call("direct")
                hits = fetch("target-process")
                assert len(hits) == 1 and int(hits[0]["target_identity"]["pid"], 16) == ready["pid"]
                evidence["checks"].append({"check": "same-address-process-isolation", "status": "PASS"})
                neo("hook", "release", token)
                fixture.call("direct")
                assert len(fetch("disarmed")) == 1 and neo("hook", "status")["state"] == 0
                token = None
                evidence["checks"].append({"check": "disarm-restores-execution", "status": "PASS"})
            finally:
                other.close()

            token = arm("--lease-ms", 100)
            time.sleep(0.3)
            fixture.call("direct")
            assert fetch("expired") == []
            expired = neo("hook", "status")
            assert expired["state"] == 2 and expired["revocation_cause"] == 4
            neo("hook", "release", token)
            token = None
            evidence["checks"].append({"check": "expiration-restores-execution", "status": "PASS"})

            token = arm("--region", "0x10000", 64, "--region", ready["state"], 64,
                        "--arg-reg", "r8", 16, 2, "--lease-ms", 10000)
            fixture.call("direct")
            hits = fetch("invalid-pointer")
            assert len(hits) == 1 and hits[0]["capture_status"] == "partial"
            segments = hits[0]["segments"]
            assert segments[2]["copied"] == 0 and segments[2]["status"] != 0
            assert segments[3]["copied"] == 64 and segments[3]["status"] == 0
            assert segments[4]["status"] != 0
            neo("hook", "release", token)
            token = None
            evidence["checks"].append({"check": "invalid-pointers-preserve-other-regions", "status": "PASS"})

            token = arm("--region", ready["partial_region"], 16,
                        "--region", ready["sparse_region"], 16, "--lease-ms", 10000)
            fixture.call("direct")
            hits = fetch("partial-pages")
            assert len(hits) == 1 and hits[0]["capture_status"] == "partial"
            for segment, readable_index in zip(hits[0]["segments"][2:4], (0, 1)):
                assert segment["requested"] == 16 and segment["copied"] == 8 and segment["status"] != 0
                assert len(segment["pages"]) == 2
                assert segment["pages"][readable_index]["copied"] == 8
                assert segment["pages"][1 - readable_index]["copied"] == 0
                start = readable_index * 8
                assert bytes.fromhex(segment["bytes"])[start:start + 8] == b"\xa5" * 8
            neo("hook", "release", token)
            token = None
            evidence["checks"].append({"check": "partial-and-sparse-page-reads", "status": "PASS"})

            token = arm("--max-events", 4, "--lease-ms", 10000)
            fixture.call("concurrent")
            hits = fetch("concurrent-threads")
            assert len(hits) == 4 and len({hit["thread_id"] for hit in hits}) == 4
            assert len({(hit["context"]["cpu"], hit["context"]["sequence"]) for hit in hits}) == 4
            assert all(int(hit["context"]["rdx"], 16) == 0x11223344 for hit in hits)
            fixture.call("direct")
            assert len(fetch("event-limit")) == 4
            neo("hook", "release", token)
            token = None
            evidence["checks"].append({"check": "concurrent-threads-and-global-event-limit", "status": "PASS"})
        evidence["status"] = "PASS"
    except BaseException as error:
        evidence["status"] = "FAIL"
        evidence["error"] = repr(error)
        raise
    finally:
        try:
            if token is not None:
                neo("hook", "release", token)
        finally:
            if recording is not None and recording.poll() is None:
                recording.kill()
                recording.wait(timeout=10)
            fixture.close()
            (output / "results.json").write_text(json.dumps(evidence, indent=2))
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
