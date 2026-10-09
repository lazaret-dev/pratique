#!/usr/bin/env python3
"""Mutation check of the fuzz targets: does each target notice when the code it watches is deliberately broken?

    python3 fuzz/mutate.py [--list] [--seconds N] [NAME-PREFIX ...]

`mutants.py` holds the mutants: a file, the exact text to change, what to change it to, and the target that has to notice (and,
optionally, how long to give it). For each one this makes a copy of the repository (in $MUTATE_TREE, by default a directory under
the system's temporary directory, so the working tree is not touched), applies the change, builds the fuzzer there and runs the
target on the corpus in `fuzz/corpus/TARGET` (if there is one; otherwise on its seeds) for a while. A mutant is KILLED if a seed,
a corpus input or a made-up input makes the target fail, SURVIVED if not. A survivor is either a hole in the target (strengthen it:
a seed at the edge of a limit, a model check, an extra step in the script) or a change that does nothing anybody can see, and then
it goes in `EQUIVALENT` in `mutants.py` with the reason.

A target written `test:FILTER` is not a fuzz target but the unit tests `cargo test --lib FILTER` runs, which must fail; one written
`itest:NAME:FILTER` is the integration test file `tests/NAME.rs` (`cargo test --test NAME FILTER`), for what only a server that is not
ours can show (it needs what the tests need: AIOQUIC_PATH for `h3_client_interop`).

It takes a few minutes per mutant, most of it building. Exits 1 if a mutant that is not listed as equivalent survived, or if one
that is listed as equivalent was killed (then the list is out of date).
"""
import os
import re
import runpy
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FLAGS = ("--cfg pratique_fuzzing -C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3 "
         "-C llvm-args=-sanitizer-coverage-inline-8bit-counters")


def run_unit_tests(tree, target_dir, filt, integration=False):
    """The unit tests that match `filt` must fail (`integration`: `filt` is `NAME:FILTER`, the tests of `tests/NAME.rs` that match FILTER).
    Returns (killed, the line that says which) or the end of the compiler's complaint."""
    env = dict(os.environ, CARGO_TARGET_DIR=target_dir + "-test")
    which = ["--test", *filt.split(":", 1)] if integration else ["--lib", filt]
    run = subprocess.run(["cargo", "test", *which], cwd=tree, env=env, capture_output=True, text=True, timeout=1800)
    out = run.stdout + run.stderr
    if "could not compile" in out:
        return "\n".join(out.splitlines()[-12:])
    return run.returncode != 0, [l for l in out.splitlines() if "FAILED" in l or "panicked" in l][:1]


def run_fuzz_target(tree, target_dir, target, secs):
    """Builds the fuzzer in the mutated tree and runs `target` for `secs` seconds on its corpus. Returns (killed, the lines that say so)
    or the end of the compiler's complaint."""
    env = dict(os.environ, RUSTFLAGS=FLAGS, CARGO_TARGET_DIR=target_dir)
    build = subprocess.run(["cargo", "build", "--release"], cwd=os.path.join(tree, "fuzz"), env=env, capture_output=True, text=True)
    if build.returncode != 0:
        return "\n".join(build.stderr.splitlines()[-12:])
    corpus = os.path.join(tempfile.gettempdir(), "pratique_mutants-corpus", target)
    shutil.rmtree(corpus, ignore_errors=True)
    seeds = os.path.join(HERE, "corpus", target)
    if os.path.isdir(seeds):
        shutil.copytree(seeds, corpus)
    else:
        os.makedirs(corpus)
    artifacts = os.path.join(tempfile.gettempdir(), "pratique_mutants-artifacts", target)
    shutil.rmtree(artifacts, ignore_errors=True)
    run = subprocess.run(
        [os.path.join(target_dir, "release", "pratique_fuzz"), "run", target, "--corpus", corpus, "--artifacts", artifacts,
         "--seconds", str(secs), "--max-crashes", "1"],
        cwd=os.path.join(tree, "fuzz"), capture_output=True, text=True, timeout=secs + 60)
    out = run.stdout + run.stderr
    # what the engine prints when it finds something: a panic (with the input saved), memory bloat, a hang or a crash that ends it; and
    # in its last line the counts, which are 0 when it found nothing (its exit status is then 0 too)
    found = r"\]: PANIC |bytes allocated for a |timeout: one input|[1-9]\d* distinct panics|[1-9]\d* bloat inputs"
    lines = [l for l in out.splitlines() if re.search(found, l)]
    if run.returncode not in (0, 3):  # (3 is "found something")
        return f"the fuzzer exited with status {run.returncode}:\n" + "\n".join(out.splitlines()[-8:])
    return run.returncode == 3 or bool(lines), lines


def main():
    args = sys.argv[1:]
    seconds = None
    if "--seconds" in args:
        i = args.index("--seconds")
        seconds = int(args[i + 1])
        del args[i:i + 2]
    spec = runpy.run_path(os.path.join(HERE, "mutants.py"))
    mutants, equivalent = spec["MUTANTS"], spec["EQUIVALENT"]
    if "--list" in args:
        for name, m in mutants.items():
            print(f"{name:34} {m[3]:16} {m[0]}" + ("   (equivalent: " + equivalent[name] + ")" if name in equivalent else ""))
        return 0
    chosen = [n for n in mutants if not args or any(n.startswith(a) for a in args)]
    if not chosen:
        print("no mutant has a name that starts with", args)
        return 2

    tree = os.environ.get("MUTATE_TREE") or os.path.join(tempfile.gettempdir(), "pratique_mutants")
    target_dir = tree + "-target"
    shutil.rmtree(tree, ignore_errors=True)

    def skip(directory, names):
        out = {"target", ".git", "native_report.txt", "fuzz-results.tgz"}.intersection(names)
        # (and the other build directories: target-portable, target-native and the like)
        out |= {n for n in names if n.startswith("target-")}
        if os.path.abspath(directory) == HERE:
            out |= {"artifacts", "artifacts.prev", "logs", "work"}.intersection(names)
        return out

    shutil.copytree(ROOT, tree, ignore=skip)
    bad = []
    for name in chosen:
        file, old, new, target = mutants[name][:4]
        secs = seconds or (mutants[name][4] if len(mutants[name]) > 4 else 25)
        path = os.path.join(tree, file)
        good = open(path).read()
        if good.count(old) != 1:
            print(f"{name}: the text to change is there {good.count(old)} times, not once; the code has moved on, update mutants.py")
            bad.append(name)
            continue
        open(path, "w").write(good.replace(old, new))
        try:
            if target.startswith("itest:"):
                result = run_unit_tests(tree, target_dir, target[6:], integration=True)
            elif target.startswith("test:"):
                result = run_unit_tests(tree, target_dir, target[5:])
            else:
                result = run_fuzz_target(tree, target_dir, target, secs)
        finally:
            open(path, "w").write(good)
        if isinstance(result, str):
            print(f"{name}: BUILD ERROR\n" + result)
            bad.append(name)
            continue
        killed, lines = result
        verdict = "KILLED  " if killed else "SURVIVED"
        note = ""
        if name in equivalent:
            note = ("   (listed as equivalent: " + equivalent[name] + ")") if not killed else "   (listed as equivalent, but killed: update EQUIVALENT)"
            if killed:
                bad.append(name)
        elif not killed:
            bad.append(name)
        print(f"{verdict} {name}{note}", flush=True)
        if killed and lines:
            print("         " + lines[0].strip()[:200], flush=True)
    print(f"{len(chosen) - len(bad)} of {len(chosen)} as expected" + (f"; not: {', '.join(bad)}" if bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
