#!/usr/bin/env python3
"""Pilotaż D1: budowa projektów testowych scenariusza S1 z przypadków zweryfikowanych w W1.

Dla każdego wybranego przypadku powstają dwa projekty (pos: wersja podatna, neg: wersja
naprawiona), każdy w dwóch formach wejścia:
  F1: manifest i plik blokady (npm: package.json + package-lock.json; PyPI: requirements.in
      + pełne przypięte drzewo w requirements.txt; Maven: pom.xml),
  F2: rozwiązane artefakty (npm: node_modules; PyPI: zainstalowane pakiety z metadanymi
      dist-info; Maven: pliki JAR z dependency:copy-dependencies).

Żaden kod z pakietów nie jest wykonywany: npm z --ignore-scripts, pip wyłącznie z pakietami
binarnymi (wheel), Maven bez uruchamiania wtyczek projektu poza rozwiązywaniem zależności.

Użycie:
    python d1/build_s1.py --per-ecosystem 10
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
PY_IMAGES = ["python312", "python310", "python38"]
# artefakt bez pliku JAR w Maven Central (np. dystrybucja, POM, BOM)
NOT_JAR_RE = re.compile(r"Could not find artifact \S+:jar:|\S+:jar:\S+ was not found in|"
                        r"\S+:jar:\S+ \(absent\)")


def image(name: str) -> str:
    for line in (TOOLS / "images.lock").read_text().splitlines():
        if line.startswith(f"{name}="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(f"Brak obrazu {name} w tools/images.lock (uruchom tools/freeze_images.sh)")


def cache_dir(sub: str) -> Path:
    base = Path(os.environ.get("SCA_CACHE", Path.home() / ".cache" / "sca-thesis"))
    p = base / sub
    p.mkdir(parents=True, exist_ok=True)
    return p


def docker(img: str, args: list[str], mounts: dict[Path, str], workdir: str | None = None,
           env: dict[str, str] | None = None, timeout: int = 900,
           entrypoint: str | None = None) -> subprocess.CompletedProcess:
    cmd = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp"]
    if entrypoint:
        cmd += ["--entrypoint", entrypoint]
    for host, cont in mounts.items():
        cmd += ["-v", f"{host}:{cont}"]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    if workdir:
        cmd += ["-w", workdir]
    cmd += [img, *args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(cmd, 124, exc.stdout or "", "timeout")


# --------------------------------------------------------------------------- wybór przypadków

def select_cases(pilot_jsonl: Path, per_eco: int, seed: int) -> list[dict]:
    rows = [json.loads(l) for l in pilot_jsonl.read_text(encoding="utf-8").splitlines() if l.strip()]
    ok = [r for r in rows if r.get("pos_status") == "consistent"
          and r.get("neg_status") in ("consistent", "consistent_backport")]
    by_eco: dict[str, list[dict]] = defaultdict(list)
    for r in sorted(ok, key=lambda r: r["case_id"]):
        by_eco[r["ecosystem"]].append(r)
    rng = random.Random(seed)
    chosen = []
    for eco, items in sorted(by_eco.items()):
        chosen += rng.sample(items, min(per_eco, len(items)))
    return chosen


def slug(case: dict) -> str:
    s = f"{case['advisory']}__{case['package']}"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


# --------------------------------------------------------------------------- npm

def build_npm(pkg: str, version: str, f1: Path, f2: Path) -> dict:
    manifest = {"name": "d1-case", "version": "1.0.0", "private": True,
                "description": "Projekt testowy D1 (praca magisterska, badanie narzędzi SCA)",
                "dependencies": {pkg: version}}
    (f1 / "package.json").write_text(json.dumps(manifest, indent=2) + "\n")
    npm_cache = cache_dir("npm")
    common = dict(mounts={f1: "/p", npm_cache: "/tmp/.npm"}, workdir="/p")
    r = docker(image("node"), ["npm", "install", "--package-lock-only", "--ignore-scripts",
                               "--no-audit", "--no-fund", "--loglevel=error"], **common)
    if r.returncode != 0 or not (f1 / "package-lock.json").exists():
        return {"ok": False, "stage": "lock", "stderr": r.stderr[-2000:]}
    work = f2.parent / (f2.name + "_work")
    shutil.copytree(f1, work, dirs_exist_ok=True)
    r = docker(image("node"), ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund",
                               "--loglevel=error"],
               mounts={work: "/p", npm_cache: "/tmp/.npm"}, workdir="/p")
    if r.returncode != 0:
        shutil.rmtree(work, ignore_errors=True)
        return {"ok": False, "stage": "install", "stderr": r.stderr[-2000:]}
    f2.mkdir(parents=True, exist_ok=True)
    shutil.move(str(work / "node_modules"), str(f2 / "node_modules"))
    shutil.rmtree(work, ignore_errors=True)
    lock = json.loads((f1 / "package-lock.json").read_text())
    tree = {k.split("node_modules/")[-1]: v.get("version")
            for k, v in (lock.get("packages") or {}).items() if k}
    return {"ok": True, "packages": len(tree), "tree": tree}


# --------------------------------------------------------------------------- PyPI

def build_pypi(pkg: str, version: str, f1: Path, f2: Path) -> dict:
    (f1 / "requirements.in").write_text(f"{pkg}=={version}\n")
    pip_cache = cache_dir("pip")
    last_err = ""
    for py in PY_IMAGES:
        r = docker(image(py), ["pip", "install", "--quiet", "--dry-run", "--ignore-installed",
                               "--only-binary=:all:", "--report", "/p/resolve.json",
                               "-r", "/p/requirements.in"],
                   mounts={f1: "/p", pip_cache: "/tmp/.cache/pip"})
        if r.returncode == 0 and (f1 / "resolve.json").exists():
            break
        last_err = r.stderr[-2000:]
    else:
        if "No matching distribution found" in last_err:
            # Brak pakietu binarnego (wheel): F1 z samą przypiętą zależnością docelową,
            # bez rozwiązywania drzewa (rozwiązanie wymagałoby budowy pakietu źródłowego,
            # czyli wykonania jego kodu). F2 nie jest budowane.
            (f1 / "requirements.txt").write_text(f"{pkg}=={version}\n")
            return {"ok": True, "python": None, "resolution": "direct_only",
                    "f2": False, "packages": 1, "tree": {pkg: version}}
        return {"ok": False, "stage": "resolve", "stderr": last_err}
    report = json.loads((f1 / "resolve.json").read_text())
    pins = sorted({(i["metadata"]["name"], i["metadata"]["version"]) for i in report["install"]})
    (f1 / "requirements.txt").write_text("".join(f"{n}=={v}\n" for n, v in pins))
    (f1 / "resolve.json").rename(f1.parent / f"{f1.name}_resolve.json")
    f2.mkdir(parents=True, exist_ok=True)
    r = docker(image(py), ["pip", "install", "--quiet", "--no-deps", "--only-binary=:all:",
                           "--no-compile", "--target", "/out/site-packages",
                           "-r", "/p/requirements.txt"],
               mounts={f1: "/p", f2: "/out", pip_cache: "/tmp/.cache/pip"})
    if r.returncode != 0:
        return {"ok": False, "stage": "install", "stderr": r.stderr[-2000:], "python": py}
    return {"ok": True, "python": py, "resolution": "full", "f2": True,
            "packages": len(pins), "tree": dict(pins)}


# --------------------------------------------------------------------------- Maven

POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>pl.thesis.d1</groupId>
  <artifactId>d1-case</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>
  <description>Projekt testowy D1 (praca magisterska, badanie narzędzi SCA)</description>
  <dependencies>
    <dependency>
      <groupId>{g}</groupId>
      <artifactId>{a}</artifactId>
      <version>{v}</version>
    </dependency>
  </dependencies>
</project>
"""


def build_maven(pkg: str, version: str, f1: Path, f2: Path) -> dict:
    g, a = pkg.split(":", 1)
    (f1 / "pom.xml").write_text(POM.format(g=g, a=a, v=version))
    m2 = cache_dir("m2")
    mounts = {f1: "/p", m2: "/m2"}
    opts = ["-B", "-q", "-Dmaven.repo.local=/m2/repository"]
    r = docker(image("maven"), [*opts, "dependency:tree", "-DoutputFile=tree.txt"],
               mounts=mounts, workdir="/p", entrypoint="mvn")
    if r.returncode != 0 or not (f1 / "tree.txt").exists():
        out = r.stdout + r.stderr
        reason = "artifact_not_jar" if NOT_JAR_RE.search(out) else None
        return {"ok": False, "stage": "tree", "reason": reason, "stderr": out[-2000:]}
    tree_txt = (f1 / "tree.txt").read_text()
    (f1 / "tree.txt").rename(f1.parent / f"{f1.name}_tree.txt")
    f2.mkdir(parents=True, exist_ok=True)
    r = docker(image("maven"), [*opts, "dependency:copy-dependencies",
                                "-DoutputDirectory=/out", "-DincludeScope=runtime"],
               mounts={**mounts, f2: "/out"}, workdir="/p", entrypoint="mvn")
    shutil.rmtree(f1 / "target", ignore_errors=True)
    if r.returncode != 0:
        out = r.stdout + r.stderr
        reason = "artifact_not_jar" if NOT_JAR_RE.search(out) else None
        return {"ok": False, "stage": "copy", "reason": reason, "stderr": out[-2000:]}
    tree = {}
    for line in tree_txt.splitlines()[1:]:
        m = re.search(r"([\w.\-]+):([\w.\-]+):[\w-]+:([^:\s]+)(?::(\w+))?", line)
        if m:
            tree[f"{m.group(1)}:{m.group(2)}"] = m.group(3)
    return {"ok": True, "packages": len(tree), "tree": tree,
            "jars": sorted(p.name for p in f2.glob("*.jar"))}


BUILDERS = {"npm": build_npm, "PyPI": build_pypi, "Maven": build_maven}


# --------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pilot", type=Path, default=ROOT / "pilot" / "results" / "pilot_w1.jsonl")
    ap.add_argument("--per-ecosystem", type=int, default=10)
    ap.add_argument("--seed", type=int, default=20261021)
    ap.add_argument("--out", type=Path, default=ROOT / "d1" / "projects_s1")
    args = ap.parse_args()

    cases = select_cases(args.pilot, args.per_ecosystem, args.seed)
    args.out.mkdir(parents=True, exist_ok=True)
    stats = Counter()
    index = []
    for i, case in enumerate(cases, 1):
        eco = case["ecosystem"]
        base = args.out / eco / slug(case)
        record = {"case": case, "builds": {}}
        for label, version in (("pos", case["vulnerable"]), ("neg", case["fixed"])):
            f1, f2 = base / label / "F1", base / label / "F2"
            if (base / label / "build.json").exists():
                record["builds"][label] = json.loads((base / label / "build.json").read_text())
                continue
            shutil.rmtree(base / label, ignore_errors=True)
            f1.mkdir(parents=True)
            res = BUILDERS[eco](case["package"], version, f1, f2)
            res.update({"label": label, "version": version})
            (base / label / "build.json").write_text(json.dumps(res, indent=2))
            record["builds"][label] = res
        ok = all(b.get("ok") for b in record["builds"].values())
        stats[(eco, "ok" if ok else "failed")] += 1
        (base / "case.json").write_text(json.dumps(record["case"], indent=2, ensure_ascii=False))
        index.append({"ecosystem": eco, "dir": str(base.relative_to(args.out)),
                      "advisory": case["advisory"], "package": case["package"],
                      "vulnerable": case["vulnerable"], "fixed": case["fixed"], "ok": ok,
                      "fail_stage": next((b.get("stage") for b in record["builds"].values()
                                          if not b.get("ok")), None)})
        print(f"[{i}/{len(cases)}] {eco} {case['package']}: {'OK' if ok else 'BŁĄD'}",
              file=sys.stderr)
    (args.out / "index.json").write_text(json.dumps(index, indent=2, ensure_ascii=False))
    print("\nBUDOWA S1:")
    for (eco, status), n in sorted(stats.items()):
        print(f"  {eco:6} {status:7} {n}")


if __name__ == "__main__":
    main()
