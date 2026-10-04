"""Validate interception against private executable pages in a Windows guest."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote", required=True)
    parser.add_argument("--neo", type=Path, required=True)
    parser.add_argument("--guest-neo", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-no-watchdog", action="store_true",
                        help="Check safe rejection on a target known to lack the required VMX timer")
    parser.add_argument("--no-lease", action="store_true",
                        help="Use explicit-release sessions and skip watchdog expiry tests")
    arguments = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = arguments.output.resolve()
    output.relative_to(project / "builds")
    output.mkdir(parents=True, exist_ok=True)
    guest = r"C:\MatrixHVInterceptionValidation-" + uuid.uuid4().hex[:12]
    peer_directory = guest + r"\peer"
    peer_started = False
    token = None
    sequence = 0
    results = []
    log = (output / "commands.log").open("w", encoding="utf-8", buffering=1)

    def remote(*operands, expected=0):
        command = [str(arguments.neo.resolve()), "--remote", arguments.remote,
                   "--timeout", "30", "exec", *map(str, operands)]
        log.write(f"BEGIN {time.time():.6f} " + " ".join(map(str, operands)) + "\n")
        log.flush()
        os.fsync(log.fileno())
        completed = subprocess.run(command, capture_output=True, timeout=40)
        text = completed.stdout.decode("utf-8", errors="replace") + completed.stderr.decode("utf-8", errors="replace")
        log.write(f"END {time.time():.6f} exit={completed.returncode}\n" + text + "\n")
        log.flush()
        os.fsync(log.fileno())
        if expected is not None and completed.returncode != expected:
            raise AssertionError(f"Exit {completed.returncode}, expected {expected}: {text}")
        return text

    def script(source):
        source = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; " + source
        encoded = base64.b64encode(source.encode("utf-16le")).decode()
        return remote("powershell.exe", "-NoProfile", "-EncodedCommand", encoded)

    def neo(*operands, expected=0):
        return remote(arguments.guest_neo, *operands, expected=expected)

    def detached(source):
        # Launch through the Windows broker so descendants cannot retain RPC pipes.
        encoded = base64.b64encode(source.encode('utf-16le')).decode()
        return script(f"$startup=([wmiclass]'Win32_ProcessStartup').CreateInstance();$startup.ShowWindow=0;"
                      f"$result=([wmiclass]'Win32_Process').Create('powershell.exe -NoProfile -EncodedCommand {encoded}',$null,$startup);"
                      "if($result.ReturnValue -ne 0){throw ('Detached launch failed: '+$result.ReturnValue)}")

    def field(text, name):
        match = re.search(r"\b" + re.escape(name) + r"=([^\s]+)", text)
        if not match:
            raise AssertionError(f"Missing {name}: {text}")
        return match[1]

    def install(*extra, patch="b833000000", address=None):
        nonlocal token
        text = neo("hook", "install", root, address or fixture["first"], patch,
                   *(["--no-lease"] if arguments.no_lease else ["--lease-ms", "600000"]), *extra)
        token = field(text, "token")
        assert field(text, "state") == "active", text
        return text

    def release():
        nonlocal token
        if token is not None:
            text = neo("hook", "release", token)
            assert field(text, "state") == "disabled", text
            token = None

    def fixture_command(operation, directory=guest, **values):
        nonlocal sequence
        sequence += 1
        payload = json.dumps(dict(id=sequence, operation=operation, **values))
        text = script(f"Remove-Item -LiteralPath '{directory}\\result.json' -ErrorAction SilentlyContinue; "
                      f"Set-Content -LiteralPath '{directory}\\command.tmp' -Value '{payload}'; "
                      f"Move-Item -LiteralPath '{directory}\\command.tmp' -Destination '{directory}\\command.json' -Force; "
                      f"for ($attempt=0; $attempt -lt 800; ++$attempt) {{ "
                      f"if (Test-Path '{directory}\\result.json') {{ Get-Content -Raw '{directory}\\result.json'; exit 0 }}; "
                      "Start-Sleep -Milliseconds 25 }; throw 'Fixture command timed out'")
        result = json.loads(text)
        assert result["id"] == sequence and "error" not in result, result
        return result["value"]

    def expect_execution(value, function=0, directory=guest):
        actual = fixture_command("execute-all", directory=directory, function=function, iterations=100)
        assert actual == [value] * fixture["processors"], (actual, value)

    def passed(name):
        results.append(name)
        print("PASS", name, flush=True)
        (output / "results.json").write_text(json.dumps(results, indent=2))

    guest_hash = script("(Get-FileHash -LiteralPath '" + arguments.guest_neo.replace("'", "''") + "' -Algorithm SHA256).Hash").strip()
    host_hash = hashlib.sha256(arguments.neo.read_bytes()).hexdigest()
    assert guest_hash.lower() == host_hash, "Guest Neo must match the supplied host binary"
    fixture_bytes = (project / "tests/interception_vm_fixture.ps1").read_bytes()
    script(f"New-Item -ItemType Directory -Path '{guest}' -Force | Out-Null; "
           f"Remove-Item -LiteralPath '{guest}\\fixture.json','{guest}\\command.json','{guest}\\result.json' -ErrorAction SilentlyContinue; "
           f"[IO.File]::WriteAllBytes('{guest}\\fixture.ps1', [byte[]]@())")
    # Keep both the host and guest Windows command lines below their size limit.
    for offset in range(0, len(fixture_bytes), 4096):
        chunk = base64.b64encode(fixture_bytes[offset:offset + 4096]).decode()
        script(f"$bytes=[Convert]::FromBase64String('{chunk}'); "
               f"$stream=[IO.File]::Open('{guest}\\fixture.ps1', [IO.FileMode]::Append); "
               "try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }")
    detached(f"Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command \"& ''{guest}\\fixture.ps1'' -OutputDirectory ''{guest}'' *> ''{guest}\\fixture-out.log''\"'; exit 0")
    try:
        fixture = json.loads(script(f"for ($attempt=0; $attempt -lt 200; ++$attempt) {{ "
                                    f"if (Test-Path '{guest}\\fixture.json') {{ Get-Content -Raw '{guest}\\fixture.json'; exit 0 }}; "
                                    "Start-Sleep -Milliseconds 25 }; throw 'Fixture initialization timed out'"))
        (output / "fixture.json").write_text(json.dumps(fixture, indent=2))
        root = field(neo("read", fixture["pid"], "auto"), "cr3")
        assert int(root, 0) != 0
        expect_execution(17)
        expect_execution(34, 1)
        passed("Original execution on every CPU")

        if arguments.expect_no_watchdog:
            before = neo("hook", "status")
            assert field(before, "state") == "disabled", before
            for command in (
                ("hook", "install", root, fixture["first"], "b833000000"),
                ("hook", "install", root, fixture["first"], "b833000000", "--vmfunc"),
                ("hook", "install", root, fixture["first"], "b833000000", "--concurrent-writes"),
                ("hook", "install", root, fixture["first"], "b833000000", "--persistent-data"),
                ("hook", "install", root, fixture["first"], "b833000000", "--tsc-offset"),
                ("debug-registers", "set", root, fixture["first"], fixture["second"]),
            ):
                text = neo(*command, expected=1)
                assert "unsupported paging mode" in text, text
                status = neo("hook", "status")
                for name in ("token", "state", "hooks", "debug_targets", "generation", "contexts"):
                    assert field(status, name) == field(before, name), status
            expect_execution(17)
            expect_execution(34, 1)
            assert fixture_command("read").startswith("b811000000c3")
            passed("Unsupported watchdog rejects hook/DR modes without publishing a profile or changing code")
            (output / "skipped.json").write_text(json.dumps({
                "reason": "Target lacks the required VMX preemption timer; runtime interception was explicitly skipped",
                "scenarios": ["EPT hooks", "dynamic patches", "context aliases", "merge", "DR redirects", "VMFUNC", "lease expiry", "TSC offset"],
            }, indent=2))
            return

        install()
        expect_execution(51)
        assert fixture_command("read").startswith("b811000000c3")
        read = neo("read", fixture["pid"], "auto", fixture["first"], "6")
        assert "data=b811000000c3" in read, read
        passed("Patched execution and original reads on every CPU")

        detached(f"New-Item -ItemType Directory -Path '{peer_directory}' -Force | Out-Null; "
               f"Remove-Item -LiteralPath '{peer_directory}\\fixture.json','{peer_directory}\\command.json' -ErrorAction SilentlyContinue; "
               f"Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command \"& ''{guest}\\fixture.ps1'' "
               f"-OutputDirectory ''{peer_directory}'' -SharedName ''{fixture['sharedName']}'' -ViewAddress ''{fixture['first']}'' "
               f"*> ''{peer_directory}\\fixture-out.log''\"'; exit 0")
        peer_started = True
        peer = json.loads(script(f"for ($attempt=0; $attempt -lt 200; ++$attempt) {{ "
                                 f"if (Test-Path '{peer_directory}\\fixture.json') {{ Get-Content -Raw '{peer_directory}\\fixture.json'; exit 0 }}; "
                                 "Start-Sleep -Milliseconds 25 }; throw 'Peer initialization timed out'"))
        peer_root = field(neo("read", peer["pid"], "auto"), "cr3")
        assert peer_root != root and peer["first"] == fixture["first"], peer
        expect_execution(17, directory=peer_directory)
        text = neo("hook", "context-add", token, peer_root)
        assert field(text, "contexts") == "2", text
        expect_execution(51, directory=peer_directory)
        text = neo("hook", "context-remove", token, peer_root)
        assert field(text, "contexts") == "1", text
        expect_execution(17, directory=peer_directory)
        expect_execution(51)
        passed("Distinct process CR3 scope and validated shared-page context add/remove")

        text = neo("hook", "add", token, fixture["second"], "b844000000")
        second_id = field(text, "id")
        expect_execution(68, 1)
        listing = neo("hook", "list", token)
        assert len(re.findall(r"\bid=", listing)) == 2, listing
        generation = field(listing, "generation")
        if arguments.no_lease:
            neo("hook", "renew", token, expected=1)
        else:
            renewed = neo("hook", "renew", token, "--lease-ms", "600000")
            assert field(renewed, "generation") == generation
        neo("hook", "remove", token, second_id)
        expect_execution(34, 1)
        expect_execution(51)
        passed("Dynamic add/list/drop preserve neighboring patches")

        fixture_command("write", offset=128, value=165)
        expect_execution(51)
        neo("write", fixture["pid"], "auto", hex(int(fixture["first"], 0) + 129), "a6")
        expect_execution(51)
        assert field(neo("hook", "status"), "state") == "active"
        passed("Guest and Neo writes to unpatched bytes preserve the shadow")
        fixture_command("write", offset=1, value=18)
        status = neo("hook", "status")
        assert field(status, "state") == "revoked", status
        assert field(status, "revocation_cause") == "page-merge-conflict", status
        expect_execution(18)
        release()
        fixture_command("write", offset=1, value=17)
        passed("Conflicting guest write revokes interception and preserves the committed byte")

        for mode in ("--concurrent-writes", "--persistent-data"):
            install(mode)
            expect_execution(51)
            assert fixture_command("read").startswith("b811000000c3")
            fixture_command("write", offset=130, value=167)
            expect_execution(51)
            if mode == "--concurrent-writes":
                actual = fixture_command("concurrent", function=0, iterations=32, writing=True)
                assert actual == [51] * fixture["processors"], actual
                assert field(neo("hook", "status"), "state") == "active"
            release()
            expect_execution(17)
            passed(mode + " reads, writes and release on every CPU")

        install(patch="0fb605f9000000", address=fixture["mixed"])
        expect_execution(91, 2)
        release()
        passed("Instruction fetch and data access on the same hooked page")

        text = neo("debug-registers", "set", root, fixture["first"], fixture["second"],
                   *(["--no-lease"] if arguments.no_lease else ["--lease-ms", "600000"]))
        token = field(text, "token")
        expect_execution(34)
        assert int(field(neo("debug-registers", "status"), "hits")) >= fixture["processors"]
        neo("debug-registers", "clear", token)
        token = None
        expect_execution(17)
        passed("DR execution redirection and restoration on every CPU")

        pairs = []
        for index in range(4):
            pairs += [hex(int(fixture["first"], 0) + index * 16),
                      hex(int(fixture["second"], 0) + index * 16)]
        text = neo("debug-registers", "set", root, *pairs,
                   *(["--no-lease"] if arguments.no_lease else ["--lease-ms", "600000"]))
        token = field(text, "token")
        assert field(text, "debug_targets") == "4", text
        assert fixture_command("debug-all") == [34, 35, 36, 37] * fixture["processors"]
        release()
        assert fixture_command("debug-all") == [17, 18, 19, 20] * fixture["processors"]
        passed("All four DR slots redirect independently and restore on every CPU")

        install("--vmfunc")
        expect_execution(51)
        expect_execution(0xb8, 3)
        expect_execution(51)
        assert field(neo("hook", "status"), "state") == "active"
        text = neo("debug-registers", "set", root, fixture["first"], fixture["second"],
                   *(["--no-lease"] if arguments.no_lease else ["--lease-ms", "600000"]))
        token = field(text, "token")
        expect_execution(34)
        expect_execution(0xb8, 3)
        neo("debug-registers", "clear", token)
        expect_execution(51)
        release()
        passed("Cooperative VMFUNC switching with EPT hooks and DR redirects on every CPU")

        install("--alternate-cr3", hex(int(root, 0) | 1))
        listing = neo("hook", "context-list", token)
        assert listing.count("context_cr3=") == 1, listing
        neo("hook", "context-add", token, hex(int(root, 0) | 2), expected=1)
        expect_execution(51)
        assert neo("hook", "context-list", token).count("context_cr3=") == 1
        release()
        passed("CR3 PCID aliases retain scope and are enumerated once")

        text = neo("hook", "install", root, fixture["first"], "b833000000", "--tsc-offset",
                   *(["--no-lease"] if arguments.no_lease else ["--lease-ms", "600000"]), expected=None)
        if "state=active" in text:
            token = field(text, "token")
            expect_execution(51)
            status = neo("hook", "status")
            assert int(field(status, "compensated_ticks")) > 0, status
            release()
            expect_execution(17)
            passed("TSC compensation accumulates root time and restores execution on release")
        else:
            assert "unsupported paging mode" in text, text
            status = neo("hook", "status")
            assert field(status, "state") == "disabled", status
            expect_execution(17)
            passed("Unsupported TSC compensation is rejected without publishing a profile")

        if arguments.no_lease:
            (output / "skipped.json").write_text(json.dumps({
                "reason": "Watchdog tests explicitly skipped; the target lacks the required VMX timer",
                "scenarios": ["lease renewal", "idle lease expiry"],
            }, indent=2))
            return

        text = neo("hook", "install", root, fixture["first"], "b833000000", "--lease-ms", "1000")
        token = field(text, "token")
        time.sleep(2)
        status = neo("hook", "status")
        assert field(status, "state") == "revoked" and field(status, "revocation_cause") == "lease-expired", status
        expect_execution(17)
        neo("hook", "renew", token, expected=1)
        release()
        passed("Idle lease expiry restores execution and rejects stale renewal")
    finally:
        original_error = sys.exc_info()[1]
        cleanup_errors = []
        try:
            release()
        except Exception as error:
            cleanup_errors.append('Hook release: ' + repr(error))
        for directory in ([peer_directory] if peer_started else []) + [guest]:
            try:
                script(f"Set-Content -LiteralPath '{directory}\\command.json' -Value '{{\"operation\":\"stop\"}}'")
            except Exception as error:
                cleanup_errors.append(directory + ': ' + repr(error))
        (output / 'run-status.json').write_text(json.dumps({
            'status': 'FAIL' if original_error or cleanup_errors else 'PASS',
            'error': repr(original_error) if original_error else None,
            'cleanup_errors': cleanup_errors, 'guest_directory': guest,
            'passed_scenarios': len(results),
        }, indent=2), encoding='utf-8')
        log.close()
        if cleanup_errors and original_error is None:
            raise AssertionError(cleanup_errors)


if __name__ == "__main__":
    main()
