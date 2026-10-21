#!/usr/bin/env python3
"""D3: codzienny pomiar opóźnienia wykrywania nowo opublikowanych porad przez narzędzia SCA.

Każde uruchomienie (raz na dobę):
  1. pobiera aktualne zrzuty OSV (npm, PyPI, Maven),
  2. tworzy kohortę dnia: do K porad na ekosystem opublikowanych w ostatnich WINDOW dniach,
     jeszcze nieśledzonych (także jako alias); dla każdej buduje projekt z podatną wersją,
  3. skanuje wszystkie śledzone projekty (wiek do TRACK dni) narzędziami, które jeszcze nie
     wykryły porady, z bazami zaktualizowanymi tego dnia,
  4. dopisuje wyniki do d3/data/detections.jsonl i aktualizuje d3/data/state.json.

Opóźnienie = data pierwszego wykrycia − data publikacji porady (rozdzielczość: 1 doba).
Porada niewykryta przez TRACK dni jest obserwacją uciętą (prawostronnie).

Użycie (lokalnie lub w GitHub Actions):
    NVD_API_KEY=... python3 d3/d3_daily.py
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "pilot"), str(ROOT / "d1")]
import pilot_w1 as pw  # noqa: E402
import build_s1 as bs  # noqa: E402
import evaluate_s1 as ev  # noqa: E402

D3 = ROOT / "d3"
DATA = D3 / "data"
PROJ = D3 / "projects"
ECOS = ["npm", "PyPI", "Maven"]
# narzędzie -> forma wejścia, w której działa w konfiguracji domyślnej (wyniki pilotażu S1)
TOOL_FORMS = {
    "npm": {"trivy": "F1", "grype": "F1", "osv-scanner": "F1", "dependency-check": "F1",
            "npm-audit": "F1"},
    "PyPI": {"trivy": "F1", "grype": "F1", "osv-scanner": "F1", "dependency-check": "F2",
             "pip-audit": "F1"},
    "Maven": {"trivy": "F1", "grype": "F1", "osv-scanner": "F1", "dependency-check": "F2"},
}


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_ts(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def append_jsonl(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------- kohorta dnia

MAX_PER_CLUSTER_TOTAL = 3


def cluster_of(eco: str, pkg: str) -> str:
    """Projekt, z którego pochodzi pakiet: Maven groupId, npm zakres lub nazwa, PyPI nazwa."""
    if eco == "Maven":
        return f"Maven:{pkg.split(':', 1)[0].lower()}"
    if eco == "npm":
        return f"npm:{pkg.split('/', 1)[0].lower() if pkg.startswith('@') else pkg.lower()}"
    return f"PyPI:{ev.norm_pkg('PyPI', pkg)}"


def pick_version(eco: str, aff: dict, session: requests.Session) -> str | None:
    """Najwyższa stabilna wersja z rejestru objęta zakresem porady."""
    pairs = [p for rng in aff.get("ranges") or [] if rng.get("type") in ("ECOSYSTEM", "SEMVER")
             for p in pw.range_pairs(rng.get("events", []))]
    try:
        available = pw.registry_versions(eco, aff["package"]["name"], session)
    except Exception:  # noqa: BLE001
        return None
    listed = set(aff.get("versions") or [])
    cands = []
    for v in available:
        pv = pw.parse_version(eco, v)
        if pv is None:
            continue
        if v in listed or (pairs and pw.affected_by_any(eco, pv, pairs)):
            cands.append((pv, v))
    stable = [c for c in cands if not pw.is_prerelease(eco, c[1])]
    pool = stable or cands
    return max(pool)[1] if pool else None


def new_cohort(run_date: str, per_eco: int, window_days: int, dumps: Path,
               tracked_ids: set[str], session: requests.Session,
               cluster_counts: dict[str, int]) -> list[dict]:
    cutoff = now_utc() - dt.timedelta(days=window_days)
    rng = random.Random(f"d3-{run_date}")
    cohort = []
    used_today: set[str] = set()
    for eco in ECOS:
        recs = pw.load_records(pw.download_dump(eco, dumps, refresh=True))
        cands = []
        for r in recs:
            ids = {r["id"].upper(), *[a.upper() for a in r.get("aliases") or []]}
            if r["id"].startswith("MAL-") or r.get("withdrawn") or ids & tracked_ids:
                continue
            if not r.get("published") or parse_ts(r["published"]) < cutoff:
                continue
            affs = [a for a in r.get("affected") or [] if (a.get("package") or {}).get("ecosystem") == eco]
            if affs:
                cands.append((r, affs))
        rng.shuffle(cands)
        added = 0
        for r, affs in cands:
            if added >= per_eco:
                break
            aff = rng.choice(affs)
            cl = cluster_of(eco, aff["package"]["name"])
            if cl in used_today or cluster_counts.get(cl, 0) >= MAX_PER_CLUSTER_TOTAL:
                continue
            version = pick_version(eco, aff, session)
            if not version:
                continue
            pkg = aff["package"]["name"]
            key = bs.slug({"advisory": r["id"], "package": pkg})
            base = PROJ / eco / key / "pos"
            shutil.rmtree(base, ignore_errors=True)
            (base / "F1").mkdir(parents=True)
            res = bs.BUILDERS[eco](pkg, version, base / "F1", base / "F2")
            (base / "build.json").write_text(json.dumps(res, indent=2))
            if not res.get("ok"):
                continue
            tracked_ids |= {r["id"].upper(), *[a.upper() for a in r.get("aliases") or []]}
            used_today.add(cl)
            cluster_counts[cl] = cluster_counts.get(cl, 0) + 1
            cohort.append({"advisory": r["id"], "aliases": r.get("aliases") or [],
                           "ecosystem": eco, "package": pkg, "version": version,
                           "published": r["published"], "added_run": run_date,
                           "project": f"{eco}/{key}", "f2": base.joinpath("F2").exists(),
                           "cluster": cl})
            added += 1
    return cohort


# --------------------------------------------------------------------------- skanowanie

def ensure_f2(c: dict) -> None:
    """Artefakty F2 nie są przechowywane w repozytorium; odtwarzane z tej samej wersji."""
    base = PROJ / c["project"] / "pos"
    if not c.get("f2") or (base / "F2").exists():
        return
    with tempfile.TemporaryDirectory() as tmp:
        t1, t2 = Path(tmp) / "F1", Path(tmp) / "F2"
        t1.mkdir()
        res = bs.BUILDERS[c["ecosystem"]](c["package"], c["version"], t1, t2)
        if res.get("ok") and t2.exists():
            shutil.move(str(t2), str(base / "F2"))


def scan_one(tool: str, src: Path) -> tuple[dict, dict | None, str]:
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([str(ROOT / "tools" / "scan.sh"), tool, str(src), tmp],
                       capture_output=True, text=True, timeout=1800)
        meta = json.loads((Path(tmp) / f"{tool}.meta.json").read_text())
        try:
            data = json.loads((Path(tmp) / f"{tool}.json").read_text())
        except Exception:  # noqa: BLE001
            data = None
        log_path = Path(tmp) / f"{tool}.log"
        log_tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-20:]) \
            if log_path.exists() else ""
    return meta, data, log_tail


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--per-ecosystem", type=int, default=5)
    ap.add_argument("--window-days", type=int, default=3)
    ap.add_argument("--track-days", type=int, default=30)
    ap.add_argument("--no-new", action="store_true", help="bez nowej kohorty, tylko skany")
    args = ap.parse_args()

    run_date = now_utc().date().isoformat()
    dumps = D3 / "cache" / "osv"
    dumps.mkdir(parents=True, exist_ok=True)
    cohort_path, det_path = DATA / "cohort.jsonl", DATA / "detections.jsonl"
    state_path = DATA / "state.json"
    cohort = load_jsonl(cohort_path)
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    if state.get("_last_run") == run_date:
        sys.exit(f"Seria z dnia {run_date} została już wykonana.")

    session = requests.Session()
    session.headers["User-Agent"] = pw.USER_AGENT
    if not args.no_new:
        tracked = {i.upper() for c in cohort for i in [c["advisory"], *c["aliases"]]}
        counts: dict[str, int] = {}
        for c in cohort:
            cl = c.get("cluster") or cluster_of(c["ecosystem"], c["package"])
            counts[cl] = counts.get(cl, 0) + 1
        new = new_cohort(run_date, args.per_ecosystem, args.window_days, dumps, tracked,
                         session, counts)
        append_jsonl(cohort_path, new)
        cohort += new
        print(f"[d3] nowa kohorta: {len(new)} porad", file=sys.stderr)
    else:
        for eco in ECOS:
            pw.download_dump(eco, dumps, refresh=True)

    osv = ev.OSVIndex(dumps)
    rows = []
    today = dt.date.fromisoformat(run_date)
    for c in cohort:
        age = (today - dt.date.fromisoformat(c["added_run"])).days
        if age > args.track_days:
            continue
        st = state.setdefault(c["advisory"], {})
        eco = c["ecosystem"]
        group = osv.group(c["advisory"]) | {a.upper() for a in c["aliases"]} | {c["advisory"].upper()}
        for tool, form in TOOL_FORMS[eco].items():
            if st.get(tool):
                continue  # już wykryte
            if form == "F2":
                ensure_f2(c)
            src = PROJ / c["project"] / "pos" / form
            if not src.exists():
                continue
            meta, data, log_tail = scan_one(tool, src)
            ok = data is not None and meta["exit_code"] in ev.OK_CODES[tool]
            if tool == "osv-scanner" and meta["exit_code"] == 128:
                data, ok = {"results": []}, True
            detected = False
            if ok and not (isinstance(data, dict) and data.get("skipped")):
                findings, _ = ev.PARSERS[tool](data, eco)
                target = ev.norm_pkg(eco, c["package"])
                detected = any(f["package"] and ev.norm_pkg(eco, f["package"]) == target
                               and f["ids"] & group for f in findings)
            rows.append({"run_date": run_date, "advisory": c["advisory"], "ecosystem": eco,
                         "tool": tool, "form": form, "status": "ok" if ok else "error",
                         "detected": detected, "exit_code": meta["exit_code"],
                         "wall_seconds": meta["wall_seconds"], "age_days": age,
                         **({"log_tail": log_tail} if not ok else {})})
            if detected:
                st[tool] = run_date
    append_jsonl(det_path, rows)
    state["_last_run"] = run_date
    state_path.write_text(json.dumps(state, indent=1, sort_keys=True))
    subprocess.run([str(ROOT / "tools" / "db_status.sh"), str(DATA / "db_status" / run_date)],
                   capture_output=True)
    print(f"[d3] {run_date}: skany {len(rows)}, wykrycia {sum(r['detected'] for r in rows)}, "
          f"błędy {sum(r['status'] == 'error' for r in rows)}", file=sys.stderr)


if __name__ == "__main__":
    main()
