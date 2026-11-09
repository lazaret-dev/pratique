#!/usr/bin/env python3
"""Build only the permitted primitive and this experiment, never production GHASH."""

import argparse
import hashlib
import json
import platform
import re
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def assembly_summary(path):
    text = path.read_text()
    instructions = 0
    rejected = []
    branches = []
    calls = []
    for line in text.splitlines():
        match = re.match(r"\s+([a-z][a-z0-9_.]*)\s*(.*)", line)
        if not match:
            continue
        op, args = match.groups()
        instructions += 1
        if re.match(r"(?:v?(?:p?clmul|pmull|mul)|[su](?:mul|madd|msub|mlal)|madd|msub|mla|mls|imul|[isu]?div|i(?:32|64)\.(?:mul|div))", op):
            rejected.append(line.strip())
        if re.match(r"(?:j\w*|b\.\w+|b(?:eq|ne|lt|ge|gt|le)(?:z|u)?(?:\.[wn])?|cbn?z|tbn?z|br_if|if)$", op):
            branches.append(line.strip())
        if op in ("bl", "blx", "blr", "call", "callq", "calll", "jal", "jalr"):
            calls.append(line.strip())
    if rejected:
        raise RuntimeError(f"Prohibited multiplication/division instructions in {path}: {rejected}")
    return {
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "instruction_lines": instructions,
        "multiplication_or_division": rejected,
        "branches_for_manual_review": branches,
        "calls_for_manual_review": sorted(set(calls)),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--toolchain", default="1.87.0")
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--timing", action="store_true")
    parser.add_argument("--iterations", type=int, default=100_000)
    args = parser.parse_args()
    out = Path(tempfile.mkdtemp(prefix=f"pratique-clmul-{args.toolchain}-"))
    record = {"platform": platform.platform(), "machine": platform.machine(),
              "artifacts": str(out), "commands": [], "assembly": {}}

    def run(command):
        result = subprocess.run([str(x) for x in command], cwd=HERE, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        record["commands"].append({"argv": [str(x) for x in command],
                                   "exit": result.returncode, "output": result.stdout})
        print(result.stdout, end="", flush=True)
        if result.returncode:
            raise RuntimeError(f"Command failed: {command}")
        return result.stdout

    compiler = ["rustc", f"+{args.toolchain}"]
    version = run(compiler + ["--version", "--verbose"])
    host = re.search(r"^host: (.+)$", version, re.MULTILINE).group(1)
    flags = ["--edition=2024", "-O"]

    def feature(target):
        if target.startswith("aarch64"):
            return ["-C", "target-feature=-aes"]
        if target.startswith("x86") or target.startswith("i686"):
            return ["-C", "target-feature=-pclmulqdq"]
        return []

    run(["python3", HERE / "generate.py"])
    run(compiler + flags + feature(host) + ["--test", HERE / "lib.rs", "-o", out / "tests"])
    run([out / "tests"])
    library = out / "libclmul_feasibility.rlib"
    run(compiler + flags + feature(host) + ["--crate-type=rlib", "--crate-name=clmul_feasibility",
                                           HERE / "lib.rs", "-o", library])
    for program in ["bench"] + (["timing"] if args.timing else []):
        run(compiler + flags + feature(host) + ["--extern", f"clmul_feasibility={library}",
                                               HERE / f"{program}.rs", "-o", out / program])

    for target in [host] + [x for x in args.target if x != host]:
        asm = out / f"{target}.s"
        run(compiler + flags + feature(target) + ["--crate-type=lib", "--emit=asm", "--target", target,
                                                HERE / "lib.rs", "-o", asm])
        record["assembly"][target] = assembly_summary(asm)

    # Benchmarks and statistical screens run sequentially, after all compilation.
    run([out / "bench", str(args.iterations)])
    if args.timing:
        run([out / "timing"])
    record["sources"] = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
                         for name in ["lib.rs", "circuit.rs", "generate.py", "bench.rs", "timing.rs", "check.py"]}
    results = HERE / "results"
    results.mkdir(exist_ok=True)
    report = results / f"{args.toolchain}.json"
    report.write_text(json.dumps(record, indent=2) + "\n")
    print(f"Saved {report}; binaries and assembly: {out}")


if __name__ == "__main__":
    main()
