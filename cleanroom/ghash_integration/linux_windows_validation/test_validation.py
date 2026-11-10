"""Only synthetic metadata, mocked process results, and temporary text files."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("fixed_validation", Path(__file__).with_name("run_validation.py"))
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


def output(selector=V.HRR, failed=False, ignored=False):
    return ("running 1 test\ntest " + selector + " ... " + ("ignored" if ignored else "FAILED" if failed else "ok") +
            "\ntest result: " + ("FAILED" if failed else "ok") + ". " +
            ("0 passed; 0 failed; 1 ignored" if ignored else "0 passed; 1 failed; 0 ignored" if failed else "1 passed; 0 failed; 0 ignored") +
            "; 0 measured; 51 filtered out; finished in 0.01s\n")


class ValidationContracts(unittest.TestCase):
    def test_fixed_commands_and_caps(self):
        msrv = dict((n, a) for n, _, a in V.fixed_plan("linux-msrv"))
        self.assertEqual(msrv["full-release"], ["cargo", "test", "--release", "--all-features"])
        self.assertEqual(msrv["source-package"], ["cargo", "package", "--frozen", "--all-features"])
        for name, selector in V.TIMING_SELECTORS.items():
            self.assertEqual(msrv[name][5], selector)
            self.assertEqual(msrv[name][6:], ["--", "--ignored", "--nocapture", "--test-threads=1"])
        for lane in ("windows-arm64", "windows-x64"):
            plan = V.fixed_plan(lane)
            self.assertEqual([n for n, _, _ in plan], ["baseline-hrr-build", "baseline-hrr", "candidate-hrr-build", "candidate-hrr", "full-release"])
            self.assertEqual([cap for n, cap, _ in plan if n.endswith("-hrr")], [45, 45])
            self.assertEqual(plan[0][2], plan[2][2])
            self.assertEqual(plan[-1][2], ["cargo", "test", "--release", "--target", V.TARGETS[lane]])
            self.assertNotIn("--all-features", plan[-1][2])

    def test_no_timing_override(self):
        env = {"PRATIQUE_TIMING_SECS": "3", "RUSTFLAGS": V.PORTABLE}
        V.validate_environment("linux-msrv", env)
        for key, value in [("PRATIQUE_TIMING_SECS", "30"), ("PRATIQUE_TIMING_REPS", "1"),
                           ("PRATIQUE_TIMING_TICKS", "0"), ("PRATIQUE_TIMING_TICK_NS", "0"),
                           ("PRATIQUE_NULL_PAIRS", ""), ("CARGO_ENCODED_RUSTFLAGS", "x"),
                           ("CARGO_BUILD_TARGET", "aarch64"), ("CARGO_TARGET_DIR", "/other"),
                           ("RUSTFLAGS", "")]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                V.validate_environment("linux-msrv", dict(env, **{key: value}))

    def test_exact_footer_and_zero_test_rejection(self):
        for failed in (False, True):
            r = V.footer_summary(output(failed=failed), "", exact_hrr=True)
            self.assertTrue(r["exact_hrr_completion"])
        for txt in (output(ignored=True), output().replace("running 1 test", "running 0 tests"), output(selector="another_test"), "", output() + output()):
            with self.subTest(txt=txt):
                self.assertFalse(V.footer_summary(txt, "", exact_hrr=True)["exact_hrr_completion"])
        for name, selector in V.TIMING_SELECTORS.items():
            txt = output(selector=selector)
            self.assertTrue(V.single_test_completed(V.footer_summary(txt, ""), txt, selector))
            self.assertFalse(V.single_test_completed(V.footer_summary(txt, ""), txt.replace(selector, "another_test"), selector))
        self.assertTrue(V.footer_summary(output(), "skipping: openssl not installed")["openssl_skip_observed"])

    def test_actual_pe_machine(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test.exe"
            for machine, expected in V.PE_MACHINES.items():
                data = bytearray(256)
                data[:2] = b"MZ"
                struct.pack_into("<I", data, 60, 128)
                data[128:134] = b"PE\0\0" + struct.pack("<H", machine)
                p.write_bytes(data)
                self.assertEqual(V.binary_info(p)["target"], expected)
            p.write_bytes(b"MZ")
            with self.assertRaises(ValueError):
                V.binary_info(p)

    def test_source_bytes_and_missing_config_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / "src").mkdir()
            data = b"synthetic source fixture\n"
            (p / "src/input.txt").write_bytes(data)
            blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            rows = ("100644 blob " + blob + "\tsrc/input.txt\0" + "100644 blob " + "a" * 40 + "\tfuzz/corpus/not-copied\0").encode()
            def command(argv, **kwargs):
                return V.CANDIDATE + "\n" if "rev-parse" in argv else rows
            with mock.patch.object(V.subprocess, "check_output", side_effect=command):
                r = V.source_binding(p, V.CANDIDATE, {"src/input.txt": hashlib.sha256(data).hexdigest()})
                self.assertEqual(r["omitted_fuzz_corpus"], 1)
                with self.assertRaises(ValueError):
                    V.source_binding(p, V.BASELINE)
                (p / "src/input.txt").write_bytes(data + b"changed")
                with self.assertRaises(ValueError):
                    V.source_binding(p, V.CANDIDATE)
                (p / "src/input.txt").write_bytes(data)
                (p / ".cargo").mkdir()
                (p / ".cargo/config.toml").write_text("synthetic override")
                with self.assertRaises(ValueError):
                    V.source_binding(p, V.CANDIDATE)

    def test_failed_hrr_continues_and_hash_mutation_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = str((root / "interop_openssl-fixture.exe").resolve())
            info = {binary: {"path": binary, "sha256": "a" * 64, "target": V.TARGETS["windows-arm64"]}}
            modes = [101, 0, 0]
            class Process:
                pid = 123456
                def __init__(self, argv, stdout, stderr, **kwargs):
                    self.code = modes.pop(0)
                    stdout.write(output(failed=self.code == 101).encode())
                def wait(self, timeout):
                    return self.code
            d = V.Driver("windows-arm64", root, root / "out")
            with mock.patch.object(d, "catalog", return_value=info), mock.patch.object(V.subprocess, "Popen", Process):
                first = d.command("baseline-hrr", [binary, V.HRR], root, 45, exact=True, test=True)
                second = d.command("candidate-hrr", [binary, V.HRR], root, 45, exact=True, test=True)
            self.assertTrue(first["test_footer_completed"])
            self.assertFalse(first["check_passed"])
            self.assertTrue(second["check_passed"])
            changed = {binary: dict(info[binary], sha256="b" * 64)}
            with mock.patch.object(d, "catalog", side_effect=[info, changed]), mock.patch.object(V.subprocess, "Popen", Process):
                mutation = d.command("candidate-hrr", [binary, V.HRR], root, 45, exact=True, test=True)
            self.assertFalse(mutation["selected_binary_identity_verified"])
            self.assertFalse(mutation["test_footer_completed"])
            self.assertFalse(mutation["check_passed"])

    def test_missing_binary_prevents_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = V.Driver("windows-arm64", tmp, Path(tmp) / "out")
            with mock.patch.object(d, "catalog", return_value={}), mock.patch.object(V.subprocess, "Popen") as create:
                r = d.command("candidate-hrr", [str(Path(tmp) / "missing.exe"), V.HRR], tmp, 45, exact=True, test=True)
            create.assert_not_called()
            self.assertIn("identity_error", r)

    def test_windows_timeout_and_cancel_cleanup(self):
        for cancel, cleanup_exit in [(False, 5), (True, 0)]:
            with self.subTest(cancel=cancel), tempfile.TemporaryDirectory() as tmp:
                d = V.Driver("windows-arm64", tmp, Path(tmp) / "out")
                class Process:
                    pid = 123456
                    calls = 0
                    def wait(self, timeout):
                        self.calls += 1
                        if self.calls == 1:
                            if cancel:
                                raise KeyboardInterrupt()
                            raise subprocess.TimeoutExpired("synthetic", timeout)
                        return -9
                def create(argv, stdout, stderr, **kwargs):
                    stdout.write(b"partial synthetic output\n")
                    return Process()
                with mock.patch.object(d, "catalog", return_value={}), \
                     mock.patch.object(V, "os", SimpleNamespace(name="nt")), \
                     mock.patch.object(V.subprocess, "CREATE_NEW_PROCESS_GROUP", 512, create=True), \
                     mock.patch.object(V.subprocess, "Popen", side_effect=create) as popen, \
                     mock.patch.object(V.subprocess, "run", return_value=SimpleNamespace(returncode=cleanup_exit)) as kill:
                    first = d.command("synthetic-full", ["synthetic"], tmp, 45, test=True)
                    later = d.command("synthetic-next", ["synthetic"], tmp, 45, test=True)
                self.assertEqual(popen.call_count, 1)
                self.assertEqual(kill.call_args[0][0], ["taskkill", "/PID", "123456", "/T", "/F"])
                self.assertFalse(first["invocation_completed"])
                self.assertFalse(d.safe)
                self.assertEqual(later["execution"], "not_started")
                self.assertTrue((Path(tmp) / "out/synthetic-full/case.json").exists())
                self.assertIn("partial", (Path(tmp) / "out/synthetic-full/stdout.log").read_text())

    def test_source_package_identity_and_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, helper = root / "source", root / "helper"
            helper.mkdir()
            original = V.PACKAGE_PROVENANCE | {"Cargo.toml", "Cargo.lock",
                         "src/crypto/clmul_batch_clean/guarded.rs", "src/crypto/clmul_batch_clean/guard_constants.rs"}
            for name in original:
                p = source / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(("synthetic:" + name).encode())
            (helper / "production-sha256.json").write_text(json.dumps({"Cargo.toml": "unused", "Cargo.lock": "unused"}))
            archive = source / "target/package/pratique-0.1.0.crate"
            archive.parent.mkdir(parents=True)
            def make(changed=None, omit=None, dirty=False, wrong_sha=False):
                files = {name: (source / name).read_bytes() for name in original if name != "Cargo.toml"}
                files["Cargo.toml"] = b"Cargo-normalized synthetic manifest"
                files["Cargo.toml.orig"] = (source / "Cargo.toml").read_bytes()
                files[".cargo_vcs_info.json"] = json.dumps({"git": {"sha1": V.BASELINE if wrong_sha else V.CANDIDATE, "dirty": dirty}}).encode()
                if changed:
                    files[changed] += b"changed"
                if omit:
                    del files[omit]
                with tarfile.open(archive, "w:gz") as tar:
                    for name, data in files.items():
                        info = tarfile.TarInfo("pratique-0.1.0/" + name)
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
            d = V.Driver("linux-stable", root, root / "out")
            with mock.patch.object(V, "HERE", helper), mock.patch.object(V.subprocess, "check_output", return_value=b""):
                make()
                self.assertTrue(d.package_binding(source)["vcs_metadata_present"])
                for kwargs in ({"changed": "NOTICE"}, {"omit": "cleanroom/ghash_integration/GUARDED_NATIVE_8370C_RESULT.md"}, {"dirty": True}, {"wrong_sha": True}):
                    with self.subTest(kwargs=kwargs):
                        make(**kwargs)
                        with self.assertRaises(ValueError):
                            d.package_binding(source)

    def test_post_spawn_recording_error_cleans_and_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = V.Driver("windows-arm64", tmp, Path(tmp) / "out")
            process = SimpleNamespace(pid=123456, wait=mock.Mock(return_value=0))
            original = V.write
            failed = [False]
            def write(path, value):
                if value.get("execution") == "started" and not failed[0]:
                    failed[0] = True
                    raise OSError("synthetic post-spawn metadata write failure")
                original(path, value)
            with mock.patch.object(d, "catalog", return_value={}), \
                 mock.patch.object(V, "write", side_effect=write), \
                 mock.patch.object(V, "os", SimpleNamespace(name="nt")), \
                 mock.patch.object(V.subprocess, "CREATE_NEW_PROCESS_GROUP", 512, create=True), \
                 mock.patch.object(V.subprocess, "Popen", return_value=process) as popen, \
                 mock.patch.object(V.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as kill:
                first = d.command("synthetic-error", ["synthetic"], tmp, 45)
                later = d.command("synthetic-next", ["synthetic"], tmp, 45)
            self.assertEqual(popen.call_count, 1)
            self.assertTrue(kill.called)
            process.wait.assert_called_once_with(timeout=10)
            self.assertIn("collector_error", first)
            self.assertFalse(d.safe)
            self.assertEqual(later["execution"], "not_started")


if __name__ == "__main__":
    unittest.main()
