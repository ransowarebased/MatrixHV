"""Exercise stack-budget rejection using compiler-shaped assembly fixtures."""

from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
from check_resident_stack import check, compiled_functions, longest_path

PROJECT = Path(__file__).resolve().parents[1]
MEMORY = "_RNv_access8resident12memory_entry"
RUNTIME = "_RNv_runtime18interception_entry"
VIEWS = "_RNv_interception9cpu_views"
REFRESH = "_RNv_interception12refresh_page"


def function(name, size, calls=()):
    return f"{name}:\n\tsubq ${size}, %rsp\n" + "".join(
        f"\tcallq {callee}\n" for callee in calls
    ) + f"\taddq ${size}, %rsp\n\tretq\n"


class StackBudgetTests(unittest.TestCase):
    def report(self, assembly, pages):
        output = PROJECT / "builds/tests"
        output.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=output) as directory:
            root = Path(directory)
            (root / "core.s").write_text(assembly, encoding="utf-8")
            (root / "vcpu.rs").write_text(
                f"const HOST_STACK_PAGES: usize = {pages};\n"
                "const HOST_EXIT_STACK_PAGES: usize = HOST_STACK_PAGES;\n",
                encoding="utf-8",
            )
            return check(root / "core.s", root / "vcpu.rs")

    def fixture(self, installation=11072, refresh=8304):
        return (function(MEMORY, 0, ("transaction",))
                + function("transaction", installation, (VIEWS, REFRESH))
                + function(VIEWS, 8)
                + function(RUNTIME, 1424, (REFRESH,))
                + function(REFRESH, refresh))

    def test_previous_installation_overflow_is_rejected(self):
        result = self.report(self.fixture(installation=19488), 4)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["paths"]["hook_installation"]["bytes"], 19520)

    def test_refresh_below_transaction_is_checked_beyond_installation(self):
        result = self.report(self.fixture(), 8)
        self.assertGreater(result["paths"]["memory_service"]["bytes"],
                           result["paths"]["hook_installation"]["bytes"])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(self.report(self.fixture(refresh=30000), 8)["status"], "FAIL")

    def test_runtime_entry_can_exceed_the_memory_service_budget(self):
        assembly = self.fixture(installation=0, refresh=0)
        assembly = assembly.replace(function(RUNTIME, 1424, (REFRESH,)),
                                    function(RUNTIME, 25000, (REFRESH,)))
        self.assertEqual(self.report(assembly, 8)["status"], "FAIL")

    def test_probed_frames_include_pushes_and_return_address(self):
        frames, _ = compiled_functions("probed:\n\tpushq %rbp\n\tpushq %rsi\n"
                                       "\tmovl $8248, %eax\n\tcallq __rust_probestack\n"
                                       "\tsubq %rax, %rsp\n\tretq\n")
        self.assertEqual(frames["probed"], 8272)

    def test_direct_tail_calls_keep_the_callee_budget(self):
        frames, edges = compiled_functions("root:\n\tjmp leaf\n" + function("leaf", 4096))
        self.assertEqual(longest_path("root", frames, edges), ["root", "leaf"])

    def test_missing_or_disconnected_compiled_symbols_fail_closed(self):
        with self.assertRaises(ValueError):
            self.report(function(MEMORY, 0), 8)
        with self.assertRaises(ValueError):
            self.report(self.fixture().replace("\tcallq " + VIEWS, "\tnop"), 8)

    def test_unmodeled_dynamic_allocations_are_rejected(self):
        with self.assertRaises(ValueError):
            compiled_functions("dynamic:\n\tsubq %rcx, %rsp\n\tretq\n")


if __name__ == "__main__":
    unittest.main()
