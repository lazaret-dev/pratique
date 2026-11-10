#!/usr/bin/env python3
"""Fixed, manual hosted validation. No source/test/threshold modifications."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import time

BRANCH = "refs/heads/codex/pr10-linux-windows-validation"
CANDIDATE = "c6377a42e8e30131692e305ca8e016d78def19f0"
BASELINE = "a29c72ffbf7bfcade5b99f04f1414f77ac31a8cf"
HRR = "a_server_that_accepts_only_nist_groups_makes_the_client_retry"
PORTABLE = "--cfg pratique_portable -C target-feature=-aes,-pclmulqdq"
TIMING_SELECTORS = {"aes-timing": "crypto::timing::aes_is_constant_time",
                    "ghash-timing": "crypto::timing::ghash_multiplication_is_constant_time"}
TARGETS = {"windows-arm64": "aarch64-pc-windows-msvc",
           "windows-x64": "x86_64-pc-windows-msvc",
           "linux-msrv": "x86_64-unknown-linux-gnu",
           "linux-stable": "x86_64-unknown-linux-gnu"}
PE_MACHINES = {0xAA64: "aarch64-pc-windows-msvc", 0x8664: "x86_64-pc-windows-msvc"}
PACKAGE_PROVENANCE = {"LICENSE", "NOTICE", "roots/mozilla.pem", "CLEAN_ROOM_AES_GHASH.md",
                      "cleanroom/ghash_integration/PROVENANCE.md",
                      "cleanroom/ghash_integration/ATTRIBUTION_AUDIT.md",
                      "cleanroom/ghash_integration/GUARDED_COMPARISON.md",
                      "cleanroom/ghash_integration/GUARDED_NATIVE_8370C_RESULT.md"}
HERE = Path(__file__).resolve().parent


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".pending")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    temp.replace(path)


def binary_info(path):
    p = Path(path).resolve()
    with p.open("rb") as f:
        header = f.read(64)
        if header[:2] == b"MZ":
            if len(header) < 64:
                raise ValueError("short DOS header")
            offset = struct.unpack_from("<I", header, 60)[0]
            if offset > p.stat().st_size - 6:
                raise ValueError("PE header outside file")
            f.seek(offset)
            pe = f.read(6)
            if pe[:4] != b"PE\0\0":
                raise ValueError("missing PE signature")
            machine = struct.unpack_from("<H", pe, 4)[0]
            kind, target = "PE", PE_MACHINES.get(machine, "unknown")
        elif header[:4] == b"\x7fELF" and len(header) >= 20:
            endian = "<" if header[5] == 1 else ">" if header[5] == 2 else None
            if not endian:
                raise ValueError("unknown ELF byte order")
            machine = struct.unpack_from(endian + "H", header, 18)[0]
            kind = "ELF"
            target = {62: "x86_64-unknown-linux-gnu", 183: "aarch64-unknown-linux-gnu"}.get(machine, "unknown")
        else:
            raise ValueError("not a PE/ELF executable")
    return {"path": str(p), "bytes": p.stat().st_size, "sha256": sha(p),
            "format": kind, "machine": machine, "target": target}


def footer_summary(stdout, stderr, exact_hrr=False):
    combined = stdout + "\n" + stderr
    matches = re.findall(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", combined)
    footers = [{"result": m[0], "passed": int(m[1]), "failed": int(m[2]),
                "ignored": int(m[3]), "measured": int(m[4]), "filtered_out": int(m[5])}
               for m in matches]
    skipped_openssl = "skipping: openssl not installed" in combined
    exact_completed = (not exact_hrr or (len(footers) == 1 and
                       footers[0]["passed"] + footers[0]["failed"] == 1 and
                       footers[0]["ignored"] == 0 and "running 1 test" in combined and HRR in combined))
    return {"footers": footers, "footer_present": bool(footers),
            "exact_hrr_completion": exact_completed,
            "openssl_skip_observed": skipped_openssl}


def validate_environment(lane, env):
    if env.get("CARGO_ENCODED_RUSTFLAGS") or env.get("CARGO_BUILD_TARGET") or env.get("CARGO_TARGET_DIR"):
        raise ValueError("unexpected inherited target/flags override")
    if env.get("RUSTFLAGS", "") != (PORTABLE if lane == "linux-msrv" else ""):
        raise ValueError("wrong fixed Rust flags")
    if env.get("PRATIQUE_TIMING_SECS") != "3":
        raise ValueError("wrong original timing seconds budget")
    for name in ("PRATIQUE_TIMING_REPS", "PRATIQUE_TIMING_TICK_NS", "PRATIQUE_TIMING_TICKS", "PRATIQUE_NULL_PAIRS"):
        if name in env:
            raise ValueError("unexpected timing override: " + name)


def single_test_completed(summary, stdout, selector):
    fs = summary["footers"]
    return (len(fs) == 1 and fs[0]["passed"] + fs[0]["failed"] == 1 and
            fs[0]["ignored"] == 0 and "running 1 test" in stdout and selector in stdout)


def source_binding(source, expected, production_expected=None):
    source = Path(source).resolve()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if head != expected:
        raise ValueError("wrong immutable source commit")
    if any((source / ".cargo" / name).exists() for name in ("config", "config.toml")):
        raise ValueError("unexpected Cargo config override")
    rows = subprocess.check_output(["git", "ls-tree", "-rz", "HEAD"], cwd=source).split(b"\0")
    inventory, omitted = {}, 0
    for row in rows:
        if not row:
            continue
        meta, raw_path = row.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split()
        name = raw_path.decode("utf-8")
        if name.startswith("fuzz/corpus/"):
            omitted += 1
            continue
        p = source / name
        if kind != "blob" or mode not in ("100644", "100755") or p.is_symlink() or not p.is_file():
            raise ValueError("missing/nonregular source input: " + name)
        data = p.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        if blob != oid:
            raise ValueError("source bytes differ from immutable Git object: " + name)
        if os.name != "nt" and bool(p.stat().st_mode & stat.S_IXUSR) != (mode == "100755"):
            raise ValueError("source executable mode differs: " + name)
        inventory[name] = {"mode": mode, "sha256": hashlib.sha256(data).hexdigest()}
    production = {k: v["sha256"] for k, v in inventory.items()
                  if k.startswith("src/") or k in ("Cargo.toml", "Cargo.lock")}
    if production_expected is not None and production != production_expected:
        raise ValueError("candidate production/Cargo inventory differs from reviewed197")
    return {"commit": head, "root": str(source), "inventory": inventory,
            "production_Cargo_sha256": production, "included_files": len(inventory),
            "omitted_fuzz_corpus": omitted, "all_included_bytes_modes_verified": True,
            "synthetic_worker_git_identity": False}


def fixed_plan(lane):
    if lane == "linux-msrv":
        return [("debug-crypto", 300, ["cargo", "test", "--lib", "crypto::", "--", "--skip", "crypto::timing", "--skip", "release_profile"]),
                ("full-release", 480, ["cargo", "test", "--release", "--all-features"]),
                ("aes-timing", 55, ["cargo", "test", "--release", "--all-features", "--lib", TIMING_SELECTORS["aes-timing"], "--", "--ignored", "--nocapture", "--test-threads=1"]),
                ("ghash-timing", 55, ["cargo", "test", "--release", "--all-features", "--lib", TIMING_SELECTORS["ghash-timing"], "--", "--ignored", "--nocapture", "--test-threads=1"]),
                ("production-audit", 180, ["python3", "cleanroom/ghash_integration/audit_primitives.py", "--toolchain", "1.87.0"]),
                ("source-package", 360, ["cargo", "package", "--frozen", "--all-features"])]
    if lane == "linux-stable":
        return [("full-release", 720, ["cargo", "test", "--release", "--all-features"]),
                ("source-package", 360, ["cargo", "package", "--frozen", "--all-features"])]
    target = TARGETS[lane]
    build = ["cargo", "test", "--target", target, "--test", "interop_openssl", "--no-run", "--message-format=json"]
    return [("baseline-hrr-build", 360, build), ("baseline-hrr", 45, None),
            ("candidate-hrr-build", 360, build), ("candidate-hrr", 45, None),
            ("full-release", 720, ["cargo", "test", "--release", "--target", target])]


class Driver:
    def __init__(self, lane, workspace, output):
        self.lane, self.workspace, self.output = lane, Path(workspace).resolve(), Path(output).resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.env = os.environ.copy()
        self.records = []
        self.safe = True
        self.binaries = {}
        self.start = time.monotonic()
        self.deadline = self.start + {"linux-msrv": 1680, "linux-stable": 1200,
                                     "windows-arm64": 1620, "windows-x64": 1620}[lane]

    def command(self, name, argv, cwd, cap, exact=False, test=False):
        directory = self.output / name
        directory.mkdir(parents=True, exist_ok=True)
        rec = {"name": name, "argv": argv, "cwd": str(cwd), "timeout_seconds": cap,
               "started_at": now(), "execution": "not_started", "exit_code": None,
               "timed_out": False, "cleanup_incomplete": False, "is_test": test}
        self.records.append(rec)
        write(directory / "case.json", rec)
        if not self.safe or self.deadline - time.monotonic() < cap + 20:
            rec["skip_reason"] = "unsafe prior cleanup or insufficient declared budget; no retry"
            write(directory / "case.json", rec)
            return rec
        before = self.catalog(cwd)
        rec["binaries_before"] = before
        identity_enforced = exact or name in ("aes-timing", "ghash-timing")
        rec["binary_identity_required"] = identity_enforced
        selected_binary = None
        if exact:
            selected_binary = str(Path(argv[0]).resolve())
        elif identity_enforced:
            candidates = [p for p in before if Path(p).name.startswith("pratique-") and
                          "release" in Path(p).parts]
            if len(candidates) == 1:
                selected_binary = candidates[0]
        if identity_enforced and (selected_binary is None or selected_binary not in before):
            rec["identity_error"] = "selected test executable unavailable or ambiguous before invocation"
            write(directory / "case.json", rec)
            return rec
        rec["selected_binary_before"] = before.get(selected_binary) if selected_binary else None
        start = time.monotonic()
        process = None
        try:
            with (directory / "stdout.log").open("wb") as out, (directory / "stderr.log").open("wb") as err:
                kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
                process = subprocess.Popen(argv, cwd=str(cwd), env=self.env, stdout=out, stderr=err, **kwargs)
                rec["execution"] = "started"
                rec["pid"] = process.pid
                write(directory / "case.json", rec)
                try:
                    rec["exit_code"] = process.wait(timeout=cap)
                except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                    rec["timed_out"] = isinstance(exc, subprocess.TimeoutExpired)
                    rec["interrupted"] = isinstance(exc, KeyboardInterrupt)
                    self.stop_child(process, err, rec)
                    if rec.get("interrupted"):
                        self.safe = False
        except Exception as exc:
            rec["collector_error"] = str(exc)
            if process is not None:
                self.safe = False
                self.stop_child(process, subprocess.DEVNULL, rec)
        rec["finished_at"] = now()
        rec["elapsed_seconds"] = round(time.monotonic() - start, 6)
        rec["binaries_after"] = self.catalog(cwd)
        if before:
            rec["previous_binary_hashes_unchanged"] = all(rec["binaries_after"].get(k, {}).get("sha256") == v["sha256"] for k, v in before.items())
        rec["selected_binary_after"] = rec["binaries_after"].get(selected_binary) if selected_binary else None
        rec["selected_binary_identity_verified"] = (not identity_enforced or
                rec["selected_binary_before"] == rec["selected_binary_after"])
        self.safe = self.safe and not rec["cleanup_incomplete"]
        stdout = (directory / "stdout.log").read_text(encoding="utf-8", errors="replace") if (directory / "stdout.log").exists() else ""
        stderr = (directory / "stderr.log").read_text(encoding="utf-8", errors="replace") if (directory / "stderr.log").exists() else ""
        rec.update(footer_summary(stdout, stderr, exact_hrr=exact))
        rec["executed_tests_from_footers"] = sum(f["passed"] + f["failed"] for f in rec["footers"])
        if name in ("aes-timing", "ghash-timing"):
            rec["selected_exact_timing_test_completed"] = single_test_completed(rec, stdout, TIMING_SELECTORS[name])
        rec["invocation_completed"] = rec["execution"] == "started" and not any(rec.get(k) for k in ("timed_out", "interrupted", "cleanup_incomplete", "collector_error"))
        rec["test_footer_completed"] = rec["invocation_completed"] and rec["selected_binary_identity_verified"] and (
             not test or (rec["footer_present"] and rec["exact_hrr_completion"] and
             rec["executed_tests_from_footers"] > 0 and rec.get("selected_exact_timing_test_completed", True)
             and not rec["openssl_skip_observed"]))
        rec["check_passed"] = rec["test_footer_completed"] and rec["exit_code"] == 0
        rec["logs"] = {name: {"bytes": (directory / name).stat().st_size, "sha256": sha(directory / name)}
                       for name in ("stdout.log", "stderr.log") if (directory / name).exists()}
        write(directory / "case.json", rec)
        return rec

    def stop_child(self, process, errors, rec):
        rec["cleanup_attempted"] = True
        try:
            if os.name == "nt":
                cleanup = subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                         stdout=errors, stderr=errors, timeout=15)
                rec["cleanup_exit"] = cleanup.returncode
                rec["cleanup_incomplete"] = cleanup.returncode != 0
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        except (OSError, subprocess.TimeoutExpired) as exc:
            rec["cleanup_incomplete"] = True
            rec["cleanup_error"] = str(exc)
        try:
            rec["exit_code"] = process.wait(timeout=10)
            rec["child_reaped"] = True
        except (OSError, subprocess.TimeoutExpired) as exc:
            rec["cleanup_incomplete"] = True
            rec["reap_error"] = str(exc)

    def catalog(self, source):
        result = {}
        target = Path(source) / "target"
        folders = [target / p / "deps" for p in ("debug", "release")]
        folders += [target / TARGETS[self.lane] / p / "deps" for p in ("debug", "release")]
        for folder in folders:
            if not folder.exists():
                continue
            for p in folder.iterdir():
                if not p.is_file() or p.suffix not in ("", ".exe"):
                    continue
                try:
                    info = binary_info(p)
                except ValueError:
                    continue
                if info["target"] != TARGETS[self.lane]:
                    raise ValueError("produced test executable has wrong target: " + p.name)
                result[str(p.resolve())] = info
        return result

    def prerequisites(self):
        rust = self.command("rustc-version", ["rustc", "-vV"], self.workspace, 15)
        cargo = self.command("cargo-version", ["cargo", "--version"], self.workspace, 15)
        version = (self.output / "rustc-version/stdout.log").read_text(encoding="utf-8")
        host = re.search(r"^host: (\S+)$", version, re.M)
        release = re.search(r"^release: (\S+)$", version, re.M)
        if not host or host.group(1) != TARGETS[self.lane]:
            raise ValueError("actual Rust compiler host architecture differs from declared native lane")
        expected_release = "1.87.0" if self.lane == "linux-msrv" else "1.97.0" if self.lane.startswith("windows-") else None
        if expected_release and (not release or release.group(1) != expected_release):
            raise ValueError("actual Rust compiler version differs from pinned release")
        if not rust["check_passed"] or not cargo["check_passed"]:
            raise ValueError("compiler prerequisite failed")
        which = self.command("rustup-which-rustc", ["rustup", "which", "rustc"], self.workspace, 15)
        if not which["check_passed"]:
            raise ValueError("actual compiler path unavailable")
        compiler = binary_info((self.output / "rustup-which-rustc/stdout.log").read_text(encoding="utf-8").strip())
        if compiler["target"] != TARGETS[self.lane]:
            raise ValueError("actual Rust compiler executable machine differs from native lane")
        executable = shutil.which("openssl")
        if not executable:
            raise ValueError("OpenSSL unavailable; tests must not silently skip")
        path = Path(executable).resolve()
        openssl_info = binary_info(path)
        self.env["PATH"] = str(path.parent) + os.pathsep + self.env.get("PATH", "")
        rec = self.command("openssl-version", [str(path), "version", "-a"], self.workspace, 15)
        rec["executable"] = openssl_info
        write(self.output / "openssl-version/case.json", rec)
        if not rec["check_passed"]:
            raise ValueError("OpenSSL prerequisite invocation failed")
        go = shutil.which("go")
        go_result = None
        if go:
            go_result = self.command("go-version", [go, "version"], self.workspace, 15)
            if self.lane.startswith("linux-") and not go_result["check_passed"]:
                raise ValueError("Go version prerequisite failed")
        elif self.lane.startswith("linux-"):
            raise ValueError("Go prerequisite unavailable for existing Linux CI contract")
        return {"actual_rust_host": host.group(1), "actual_rust_release": release.group(1) if release else None,
                "actual_rust_compiler": compiler,
                "openssl": openssl_info, "openssl_native_to_rust_host": openssl_info["target"] == TARGETS[self.lane],
                "go_available": bool(go), "python": sys.version, "python_machine": platform.machine(),
                "go_version_check_passed": go_result.get("check_passed") if go_result else None,
                "runner_arch": os.environ.get("RUNNER_ARCH"), "os": platform.platform(),
                "PROCESSOR_ARCHITECTURE": os.environ.get("PROCESSOR_ARCHITECTURE"),
                "PROCESSOR_ARCHITEW6432": os.environ.get("PROCESSOR_ARCHITEW6432")}

    def hrr_binary(self, name, source):
        path = self.output / name / "stdout.log"
        candidates = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("reason") == "compiler-artifact" and event.get("target", {}).get("name") == "interop_openssl" and event.get("executable"):
                p = Path(event["executable"]).resolve()
                if Path(source).resolve() not in p.parents:
                    raise ValueError("HRR test executable escaped its source/target directory")
                candidates.append(p)
        if len(set(candidates)) != 1:
            raise ValueError("expected exactly one built OpenSSL integration test executable")
        p = candidates[0]
        info = binary_info(p)
        if info["target"] != TARGETS[self.lane]:
            raise ValueError("HRR test PE machine does not match native Rust target")
        return p

    def retain_binaries(self):
        retained, unavailable = [], []
        for rec in self.records:
            for info in rec.get("binaries_after", {}).values():
                p = Path(info["path"])
                if not p.name.startswith(("pratique-", "interop_openssl-")) or info["sha256"] in {v["sha256"] for v in retained}:
                    continue
                if p.stat().st_size > 80000000 or sum(v["bytes"] for v in retained) + p.stat().st_size > 240000000:
                    unavailable.append({"path": str(p), "sha256": info["sha256"], "reason": "declared retained-binary size bound"})
                    continue
                dest = self.output / "binaries" / (info["sha256"][:16] + "-" + p.name)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, dest)
                if sha(dest) != info["sha256"]:
                    raise ValueError("retained executable differs from measured/built hash")
                retained.append({"artifact_path": str(dest.relative_to(self.output)), "sha256": info["sha256"], "bytes": info["bytes"]})
        return {"retained": retained, "not_retained": unavailable,
                "bounds": {"one_file_bytes": 80000000, "total_bytes": 240000000}}

    def package_binding(self, source):
        source = Path(source)
        if subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=no"], cwd=source):
            raise ValueError("source-crate checkout has tracked modifications")
        archive = source / "target/package/pratique-0.1.0.crate"
        members = {}
        with tarfile.open(archive, "r:gz") as package:
            for entry in package.getmembers():
                prefix = "pratique-0.1.0/"
                if not entry.isfile() or not entry.name.startswith(prefix):
                    raise ValueError("nonregular or unexpected source-crate member")
                name = entry.name[len(prefix):]
                if name in members or not name or ".." in Path(name).parts:
                    raise ValueError("duplicate/unsafe source-crate member")
                data = package.extractfile(entry).read()
                digest = hashlib.sha256(data).hexdigest()
                if name == "Cargo.toml":
                    classification = "Cargo-generated normalized manifest"
                elif name == ".cargo_vcs_info.json":
                    vcs = json.loads(data.decode("utf-8"))
                    if vcs.get("git", {}).get("sha1") != CANDIDATE:
                        raise ValueError("source-crate VCS metadata has wrong commit")
                    if vcs.get("git", {}).get("dirty", False) is not False:
                        raise ValueError("source-crate VCS metadata is dirty or malformed")
                    classification = "Cargo-generated VCS metadata"
                else:
                    original = source / ("Cargo.toml" if name == "Cargo.toml.orig" else name)
                    if not original.is_file() or sha(original) != digest:
                        raise ValueError("source-crate content differs from immutable candidate: " + name)
                    classification = "byte-identical to candidate"
                members[name] = {"bytes": len(data), "sha256": digest, "classification": classification}
        required = json.loads((HERE / "production-sha256.json").read_text())
        required = set(required) | PACKAGE_PROVENANCE | {"Cargo.toml.orig",
                                    "src/crypto/clmul_batch_clean/guarded.rs", "src/crypto/clmul_batch_clean/guard_constants.rs"}
        if not required <= set(members):
            raise ValueError("source-crate missing reviewed production/provenance prerequisite")
        dest = self.output / "package" / archive.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(archive, dest)
        result = {"path": str(dest.relative_to(self.output)), "sha256": sha(dest),
                  "bytes": dest.stat().st_size, "source_commit": CANDIDATE,
                  "external_source_binding_authoritative": True, "members": members,
                  "vcs_metadata_present": ".cargo_vcs_info.json" in members}
        write(self.output / "package/package-file-list.json", result)
        return {k: v for k, v in result.items() if k != "members"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("lane", choices=sorted(TARGETS))
    args = parser.parse_args()
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    output = Path(os.environ["RUNNER_TEMP"]) / "pratique-release-validation"
    d = Driver(args.lane, workspace, output)
    report = {"started_at": now(), "lane": args.lane, "workflow_head": os.environ.get("GITHUB_SHA"),
              "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"), "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA"),
              "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "candidate_commit": CANDIDATE, "baseline_commit": BASELINE,
              "planned_checks": [{"name": n, "timeout_seconds": t, "argv": a} for n, t, a in fixed_plan(args.lane)],
              "records": d.records, "collection_complete": False, "all_requested_checks_passed": False}
    sources = {}
    try:
        if os.environ.get("GITHUB_REF") != BRANCH or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=HERE.parents[2], text=True).strip() != os.environ["GITHUB_SHA"]:
            raise ValueError("wrong fixed workflow branch/admin commit")
        validate_environment(args.lane, os.environ)
        expected = json.loads((HERE / "production-sha256.json").read_text(encoding="utf-8"))
        sources["candidate"] = source_binding(workspace / "candidate", CANDIDATE, expected)
        if args.lane.startswith("windows-"):
            try:
                sources["baseline"] = source_binding(workspace / "baseline", BASELINE)
            except Exception as exc:
                report["baseline_source_error"] = str(exc)
        write(output / "source-binding-before.json", sources)
        report["host"] = d.prerequisites()
        if args.lane.startswith("linux-"):
            d.command("lscpu", ["lscpu"], workspace, 15)
        for name, cap, argv in fixed_plan(args.lane):
            who = "baseline" if name.startswith("baseline-") else "candidate"
            source = workspace / who
            if who not in sources:
                d.records.append({"name": name, "execution": "not_started", "skip_reason": "immutable source binding unavailable"})
                continue
            if argv is None:
                build = next(r for r in d.records if r["name"] == name + "-build")
                if not build.get("check_passed"):
                    d.records.append({"name": name, "execution": "not_started", "skip_reason": "HRR build not successful"})
                    continue
                try:
                    binary = d.hrr_binary(name + "-build", source)
                except Exception as exc:
                    d.records.append({"name": name, "execution": "not_started", "identity_error": str(exc)})
                    continue
                argv = [str(binary), HRR, "--exact", "--nocapture", "--test-threads=1"]
            rec = d.command(name, argv, source, cap, exact=name.endswith("-hrr"),
                            test=name in ("debug-crypto", "full-release", "aes-timing", "ghash-timing", "baseline-hrr", "candidate-hrr"))
            if name == "source-package" and rec.get("check_passed"):
                try:
                    rec["package"] = d.package_binding(source)
                except Exception as exc:
                    rec["package_identity_error"] = str(exc)
                    rec["check_passed"] = False
                write(output / name / "case.json", rec)
        after = {name: source_binding(workspace / name, value["commit"], expected if name == "candidate" else None)
                 for name, value in sources.items()}
        write(output / "source-binding-after.json", after)
        report["source_inputs_unchanged"] = sources == after
        report["retained_binaries"] = d.retain_binaries()
        wanted = [n for n, _, _ in fixed_plan(args.lane)]
        checks = [r for r in d.records if r["name"] in wanted]
        report["collection_complete"] = (len(checks) == len(wanted) and
              [r["name"] for r in checks] == wanted and all(r.get("invocation_completed") and
                   (not r.get("is_test") or r.get("test_footer_completed")) for r in checks)
              and report["source_inputs_unchanged"] and d.safe)
        report["all_requested_checks_passed"] = report["collection_complete"] and all(r.get("check_passed") for r in checks)
    except BaseException as exc:
        report["controller_error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        report["finished_at"] = now()
        report["elapsed_seconds"] = round(time.monotonic() - d.start, 6)
        names = {r["name"] for r in d.records}
        for name, cap, argv in fixed_plan(args.lane):
            if name not in names:
                d.records.append({"name": name, "execution": "not_started", "skip_reason": "prerequisite/controller failure; no retry"})
        report["limits"] = ["CI job success requires requested checks; artifact upload alone is collection only.",
                            "No test/threshold/timeout assertion changes; HRR direct invocations use45s external cap.",
                            "The full release suite contains its normal HRR test in addition to the predeclared exact diagnostics; no outcome-based repetition.",
                            "No CPU selection, test retry, new sampler, privileged mode changes or release action.",
                            "OpenSSL executable architecture is recorded separately and may be emulated on ARM."]
        write(output / "summary.json", report)
        files = {str(p.relative_to(output)): {"bytes": p.stat().st_size, "sha256": sha(p)}
                 for p in output.rglob("*") if p.is_file() and p.name != "manifest.json"}
        write(output / "manifest.json", files)
        print(json.dumps({k: report.get(k) for k in ("lane", "collection_complete", "all_requested_checks_passed", "controller_error")}))
    return 0 if report["all_requested_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
