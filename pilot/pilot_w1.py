#!/usr/bin/env python3
"""Pilotaż warstwy W1 wzorca (weryfikacja zakresów podatności dowodem pierwotnym).

Dla losowej próby porad z bazy OSV (npm, PyPI, Maven) skrypt sprawdza, czy granicę
zakresu podatnych wersji da się potwierdzić automatycznie w historii repozytorium:

  * przypadek negatywny: tag wersji naprawionej ZAWIERA co najmniej jeden commit z poprawką,
  * przypadek pozytywny: tag najwyższej wersji podatnej NIE ZAWIERA żadnego commitu z poprawką.

Wynik pilotażu to odsetek przypadków, które da się zweryfikować automatycznie (W1),
oraz rozkład przyczyn niepowodzeń. Skrypt nie instaluje żadnych pakietów.

Użycie (szczegóły w README.md):
    python pilot_w1.py --population-only
    python pilot_w1.py --per-ecosystem 5
    python pilot_w1.py --per-ecosystem 100
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import os
import random
import re
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote

import requests
from univers.versions import MavenVersion, PypiVersion, SemverVersion

ECOSYSTEMS = ["npm", "PyPI", "Maven"]
OSV_DUMP_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
VERSION_CLS = {"npm": SemverVersion, "PyPI": PypiVersion, "Maven": MavenVersion}
HTTP_TIMEOUT = 60
USER_AGENT = "sca-thesis-w1-pilot/1.0 (academic research)"

COMMIT_RE = re.compile(
    r"https?://github\.com/([^/\s]+)/([^/\s#?]+)/(?:pull/\d+/)?commits?/([0-9a-fA-F]{7,40})"
)
GITHUB_REPO_RE = re.compile(r"https?://github\.com/([^/\s]+)/([^/\s#?]+)")
PRERELEASE_RE = re.compile(
    r"(alpha|beta|rc|pre|preview|snapshot|dev|canary|next|nightly|[.-]m\d+$|[.-]cr\d*$|a\d+$|b\d+$)",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- wersje

def parse_version(eco: str, v: str):
    try:
        return VERSION_CLS[eco](v)
    except Exception:
        return None


def is_prerelease(eco: str, v: str) -> bool:
    if eco == "npm":
        return "-" in v
    return bool(PRERELEASE_RE.search(v))


def range_pairs(events: list[dict]) -> list[tuple[str, str | None, str | None]]:
    """Zamienia listę zdarzeń OSV na pary (introduced, fixed, last_affected)."""
    pairs, intro = [], None
    for ev in events:
        if "introduced" in ev:
            if intro is not None:
                pairs.append((intro, None, None))
            intro = ev["introduced"]
        elif "fixed" in ev:
            pairs.append((intro if intro is not None else "0", ev["fixed"], None))
            intro = None
        elif "last_affected" in ev:
            pairs.append((intro if intro is not None else "0", None, ev["last_affected"]))
            intro = None
    if intro is not None:
        pairs.append((intro, None, None))
    return pairs


def in_pair(eco: str, v, pair) -> bool:
    intro, fixed, last = pair
    if intro not in (None, "0"):
        pi = parse_version(eco, intro)
        if pi is None or v < pi:
            return False
    if fixed is not None:
        pf = parse_version(eco, fixed)
        return pf is not None and v < pf
    if last is not None:
        pl = parse_version(eco, last)
        return pl is not None and v <= pl
    return True  # brak górnej granicy


def affected_by_any(eco: str, v, all_pairs) -> bool:
    return any(in_pair(eco, v, p) for p in all_pairs)


# --------------------------------------------------------------------------- dane OSV

def download_dump(eco: str, data_dir: Path, refresh: bool) -> Path:
    path = data_dir / f"osv-{eco}.zip"
    if path.exists() and not refresh:
        return path
    url = OSV_DUMP_URL.format(eco=eco)
    print(f"[osv] pobieranie {url}", file=sys.stderr)
    with requests.get(url, stream=True, timeout=HTTP_TIMEOUT,
                      headers={"User-Agent": USER_AGENT}) as r:
        r.raise_for_status()
        tmp = path.with_suffix(".part")
        with open(tmp, "wb") as fh:
            for chunk in r.iter_content(1 << 20):
                fh.write(chunk)
        tmp.replace(path)
    meta = {"url": url, "downloaded_utc": dt.datetime.now(dt.timezone.utc).isoformat()}
    path.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2))
    return path


def load_records(zip_path: Path) -> list[dict]:
    records = []
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if name.endswith(".json"):
                with zf.open(name) as fh:
                    records.append(json.load(io.TextIOWrapper(fh, encoding="utf-8")))
    return records


class UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def representative(ids: list[str]) -> str:
    ghsa = sorted(i for i in ids if i.startswith("GHSA-"))
    return ghsa[0] if ghsa else sorted(ids)[0]


def extract_commits(refs: list[dict], ranges: list[dict]) -> dict[str, set[str]]:
    """Zwraca {'owner/repo': {sha, ...}} z referencji i zakresów typu GIT."""
    out: dict[str, set[str]] = defaultdict(set)
    for ref in refs:
        m = COMMIT_RE.match(ref.get("url", ""))
        if m:
            owner, repo, sha = m.groups()
            out[f"{owner}/{repo.removesuffix('.git')}".lower()].add(sha.lower())
    for rng in ranges:
        if rng.get("type") != "GIT":
            continue
        m = GITHUB_REPO_RE.match(rng.get("repo", ""))
        if not m:
            continue
        key = f"{m.group(1)}/{m.group(2).removesuffix('.git')}".lower()
        for ev in rng.get("events", []):
            if "fixed" in ev and re.fullmatch(r"[0-9a-fA-F]{7,40}", ev["fixed"]):
                out[key].add(ev["fixed"].lower())
    return dict(out)


def has_non_github_commit(refs: list[dict]) -> bool:
    return any(re.search(r"/-/commit/|bitbucket\.org/.+/commits?/|/commit/[0-9a-f]{7,40}", r.get("url", ""))
               and "github.com" not in r.get("url", "") for r in refs)


def build_cases(eco: str, records: list[dict]) -> tuple[list[dict], Counter]:
    """Grupuje rekordy będące wzajemnymi aliasami i tworzy przypadki (grupa, pakiet)."""
    stats = Counter()
    by_id = {r["id"]: r for r in records}
    uf = UnionFind()
    for r in records:
        uf.find(r["id"])
        for a in r.get("aliases", []) or []:
            if a in by_id:  # łączymy tylko rekordy obecne w zrzucie (np. PYSEC <-> GHSA)
                uf.union(r["id"], a)
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        groups[uf.find(r["id"])].append(r)

    cases = []
    for members in groups.values():
        stats["groups"] += 1
        ids = [m["id"] for m in members]
        if any(i.startswith("MAL-") for i in ids):
            stats["excluded_malicious"] += 1
            continue
        active = [m for m in members if not m.get("withdrawn")]
        if not active:
            stats["excluded_withdrawn"] += 1
            continue
        rep_id = representative([m["id"] for m in active])
        rep = next(m for m in active if m["id"] == rep_id)
        refs = [ref for m in active for ref in (m.get("references") or [])]
        aliases = sorted({a for m in active for a in (m.get("aliases") or [])} | set(ids))
        for aff in rep.get("affected", []) or []:
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") != eco:
                continue
            ranges = aff.get("ranges", []) or []
            pairs = [p for rng in ranges if rng.get("type") in ("ECOSYSTEM", "SEMVER")
                     for p in range_pairs(rng.get("events", []))]
            stats["cases_total"] += 1
            if not any(p[1] for p in pairs):
                stats["cases_without_fixed"] += 1
                continue
            commits = extract_commits(refs, ranges)
            cases.append({
                "case_id": f"{eco}|{rep_id}|{pkg.get('name')}",
                "ecosystem": eco,
                "advisory": rep_id,
                "aliases": aliases,
                "package": pkg.get("name"),
                "published": rep.get("published"),
                "severity_db": (rep.get("database_specific") or {}).get("severity"),
                "pairs": pairs,
                "osv_versions": aff.get("versions") or [],
                "commits": {k: sorted(v) for k, v in commits.items()},
                "non_github_commit": has_non_github_commit(refs),
            })
            stats["cases_eligible"] += 1
            if commits:
                stats["eligible_with_github_fix_commit"] += 1
    return cases, stats


# --------------------------------------------------------------------------- rejestry

def registry_versions(eco: str, name: str, session: requests.Session) -> list[str]:
    if eco == "npm":
        url = f"https://registry.npmjs.org/{quote(name, safe='@')}"
        r = session.get(url, timeout=HTTP_TIMEOUT,
                        headers={"Accept": "application/vnd.npm.install-v1+json"})
        r.raise_for_status()
        return list((r.json().get("versions") or {}).keys())
    if eco == "PyPI":
        r = session.get(f"https://pypi.org/pypi/{quote(name)}/json", timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return list((r.json().get("releases") or {}).keys())
    if eco == "Maven":
        group, artifact = name.split(":", 1)
        url = (f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/"
               f"{artifact}/maven-metadata.xml")
        r = session.get(url, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        root = ET.fromstring(r.content)
        return [v.text for v in root.iter("version") if v.text]
    raise ValueError(eco)


def choose_versions(eco: str, case: dict, available: list[str]) -> dict:
    """Wybiera wersję podatną (najwyższą poniżej 'fixed') i naprawioną."""
    parsed = [(v, parse_version(eco, v)) for v in available]
    parsed = [(s, p) for s, p in parsed if p is not None]
    fixed_pairs = [p for p in case["pairs"] if p[1]]
    pair = fixed_pairs[0]
    fixed_str = pair[1]
    fixed_v = parse_version(eco, fixed_str)
    if fixed_v is None:
        return {"error": "fixed_version_unparsable"}

    candidates = [(s, p) for s, p in parsed if in_pair(eco, p, pair)]
    stable = [(s, p) for s, p in candidates if not is_prerelease(eco, s)]
    pool = stable or candidates
    if not pool:
        return {"error": "no_vulnerable_version_in_registry"}
    vuln_str = max(pool, key=lambda sp: sp[1])[0]

    neg = [(s, p) for s, p in parsed if s == fixed_str]
    if not neg:
        later = [(s, p) for s, p in parsed if p >= fixed_v and not is_prerelease(eco, s)]
        if not later:
            return {"error": "fixed_version_not_in_registry", "vulnerable": vuln_str}
        neg = [min(later, key=lambda sp: sp[1])]
    neg_str, neg_v = neg[0]
    result = {"vulnerable": vuln_str, "fixed": neg_str, "fixed_declared": fixed_str}
    if affected_by_any(eco, neg_v, case["pairs"]):
        result["warning"] = "fixed_version_affected_by_other_range"
    if case["osv_versions"] and vuln_str not in case["osv_versions"]:
        result["warning_osv_versions"] = "vulnerable_version_missing_from_osv_versions"
    return result


# --------------------------------------------------------------------------- git

GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1"}


def git(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, text=True,
                          timeout=timeout, env=GIT_ENV)


class RepoCache:
    def __init__(self, root: Path, clone_timeout: int, url_template: str):
        self.root = root
        self.clone_timeout = clone_timeout
        self.url_template = url_template  # w testach można podać lokalną ścieżkę
        self.locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
        self.global_lock = threading.Lock()
        self.tags: dict[str, list[str]] = {}
        self.failed: dict[str, str] = {}

    def lock_for(self, key: str) -> threading.Lock:
        with self.global_lock:
            return self.locks[key]

    def ensure(self, key: str) -> tuple[Path | None, str | None]:
        path = self.root / (key.replace("/", "__") + ".git")
        with self.lock_for(key):
            if key in self.failed:
                return None, self.failed[key]
            if not path.exists():
                url = self.url_template.format(repo=key)
                try:
                    res = git(["clone", "--bare", "--filter=tree:0", "--quiet", url, str(path)],
                              timeout=self.clone_timeout)
                except subprocess.TimeoutExpired:
                    self.failed[key] = "clone_timeout"
                    return None, "clone_timeout"
                if res.returncode != 0:
                    self.failed[key] = "clone_failed"
                    return None, "clone_failed"
            if key not in self.tags:
                res = git(["-C", str(path), "for-each-ref", "--format=%(refname:short)",
                           "refs/tags"])
                self.tags[key] = res.stdout.split()
        return path, None


def short_name(eco: str, package: str) -> str:
    if eco == "npm":
        name = package.split("/")[-1]
    elif eco == "Maven":
        name = package.split(":")[-1]
    else:
        name = package
    return re.sub(r"[-_.]+", "-", name.lower())


def match_tag(tags: list[str], version: str, pkg_short: str) -> tuple[str | None, str | None]:
    """Zwraca (tag, None) albo (None, przyczyna)."""
    variants = [version]
    if re.fullmatch(r"\d+(\.\d+)*\.0", version):
        variants.append(version[:-2])
    for ver in variants:
        pat = re.compile(r"(?:^|[^0-9A-Za-z.])v?" + re.escape(ver) + r"$")
        cands = [t for t in tags if pat.search(t)]
        if not cands:
            continue
        exact = [t for t in cands if t in (ver, f"v{ver}")]
        if exact:
            return exact[0], None
        named = [t for t in cands if pkg_short in re.sub(r"[-_.]+", "-", t.lower())]
        if len(named) == 1:
            return named[0], None
        if len(cands) == 1:
            return cands[0], None
        return None, "tag_ambiguous"
    return None, "tag_not_found"


def resolve_commit(path: Path, sha: str) -> str | None:
    res = git(["-C", str(path), "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}"])
    return res.stdout.strip() if res.returncode == 0 else None


def is_ancestor(path: Path, commit: str, tag: str) -> bool | None:
    res = git(["-C", str(path), "merge-base", "--is-ancestor", commit, f"refs/tags/{tag}"])
    if res.returncode in (0, 1):
        return res.returncode == 0
    return None


def _norm_subject(subject: str) -> str:
    subject = re.sub(r"\s*\(#\d+\)\s*$", "", subject.strip())
    subject = re.sub(r"^(\[[^\]]*\]\s*|(cherry[- ]?pick|backport)\w*:?\s*)+", "", subject,
                     flags=re.IGNORECASE)
    return subject.strip().lower()


def cherry_pick_refs(path: Path, commits: list[str], tag: str) -> list[str]:
    """Commity osiągalne z tagu, które w opisie odwołują się do commitu z poprawką."""
    found = []
    for c in commits:
        res = git(["-C", str(path), "log", "--format=%H", "-F", f"--grep={c[:12]}",
                   f"refs/tags/{tag}"], timeout=300)
        found += [h for h in res.stdout.split() if h != c]
    return found


def subject_matches(path: Path, commits: list[str], tag_from: str, tag_to: str) -> list[str]:
    """Commity z zakresu tag_from..tag_to o tym samym tytule co commit z poprawką."""
    subjects = set()
    for c in commits:
        res = git(["-C", str(path), "log", "-1", "--format=%s", c])
        norm = _norm_subject(res.stdout)
        if len(norm) >= 20:
            subjects.add(norm)
    if not subjects:
        return []
    res = git(["-C", str(path), "log", "--format=%H%x09%s",
               f"refs/tags/{tag_from}..refs/tags/{tag_to}"], timeout=300)
    out = []
    for line in res.stdout.splitlines():
        sha, _, subj = line.partition("\t")
        if _norm_subject(subj) in subjects:
            out.append(sha)
    return out


# --------------------------------------------------------------------------- ocena przypadku

def evaluate(case: dict, session: requests.Session, repos: RepoCache) -> dict:
    eco = case["ecosystem"]
    out = {k: case[k] for k in ("case_id", "ecosystem", "advisory", "package", "published",
                                "severity_db", "commits", "non_github_commit")}
    out["pos_status"] = out["neg_status"] = "unresolved"

    if not case["commits"]:
        out["reason"] = "no_fix_commit_non_github" if case["non_github_commit"] else "no_fix_commit_ref"
        return out
    try:
        available = registry_versions(eco, case["package"], session)
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "?"
        out["reason"] = f"registry_error:HTTP{code}"
        return out
    except Exception as exc:  # noqa: BLE001
        out["reason"] = f"registry_error:{type(exc).__name__}"
        return out
    versions = choose_versions(eco, case, available)
    out.update({k: v for k, v in versions.items() if k != "error"})
    if "error" in versions:
        out["reason"] = versions["error"]
        return out

    pkg_short = short_name(eco, case["package"])
    reasons = []
    # repozytoria w kolejności liczby commitów z poprawką
    for repo_key, shas in sorted(case["commits"].items(), key=lambda kv: -len(kv[1])):
        path, err = repos.ensure(repo_key)
        if err:
            reasons.append(err)
            continue
        resolved = [c for c in (resolve_commit(path, s) for s in shas) if c]
        if not resolved:
            reasons.append("commit_not_in_history")
            continue
        tags = repos.tags.get(repo_key, [])
        tag_fixed, e1 = match_tag(tags, versions["fixed"], pkg_short)
        tag_vuln, e2 = match_tag(tags, versions["vulnerable"], pkg_short)
        if not (tag_fixed and tag_vuln):
            reasons.append(f"fixed_{e1}" if e1 else f"vulnerable_{e2}")
            continue
        in_fixed = [is_ancestor(path, c, tag_fixed) for c in resolved]
        in_vuln = [is_ancestor(path, c, tag_vuln) for c in resolved]
        if None in in_fixed or None in in_vuln:
            reasons.append("git_error")
            continue
        out.update({"repo": repo_key, "tag_fixed": tag_fixed, "tag_vulnerable": tag_vuln,
                    "fix_commits_resolved": resolved})
        # przypadek negatywny: wersja naprawiona zawiera poprawkę
        if any(in_fixed):
            out["neg_status"], out["neg_method"] = "consistent", "ancestry"
        elif (cp := cherry_pick_refs(path, resolved, tag_fixed)):
            out["neg_status"], out["neg_method"] = "consistent_backport", "cherry_pick_ref"
            out["neg_evidence"] = cp[:5]
        elif (sm := subject_matches(path, resolved, tag_vuln, tag_fixed)):
            out["neg_status"], out["neg_method"] = "consistent_backport", "subject_match"
            out["neg_evidence"] = sm[:5]
        else:
            out["neg_status"], out["neg_method"] = "inconsistent", None
        # przypadek pozytywny: wersja podatna nie zawiera poprawki (także w postaci backportu)
        if any(in_vuln):
            out["pos_status"], out["pos_method"] = "inconsistent", "ancestry"
        elif (cp := cherry_pick_refs(path, resolved, tag_vuln)):
            out["pos_status"], out["pos_method"] = "inconsistent", "cherry_pick_ref"
            out["pos_evidence"] = cp[:5]
        else:
            out["pos_status"], out["pos_method"] = "consistent", "ancestry"
        out["reason"] = None
        return out
    out["reason"] = reasons[0] if reasons else "unknown"
    out["reasons_all"] = reasons
    return out


# --------------------------------------------------------------------------- raport

def summarize(results: list[dict], population: dict[str, Counter], out_dir: Path):
    rows = []
    for eco in [e for e in ECOSYSTEMS if e in population]:
        res = [r for r in results if r["ecosystem"] == eco]
        pop = population.get(eco, Counter())
        n = len(res)
        both = sum(r["pos_status"] == "consistent" and r["neg_status"] == "consistent" for r in res)
        ext = sum(r["pos_status"] == "consistent"
                  and r["neg_status"] in ("consistent", "consistent_backport") for r in res)
        incons = sum("inconsistent" in (r["pos_status"], r["neg_status"]) for r in res)
        unres = sum(r["pos_status"] == "unresolved" for r in res)
        rows.append({
            "ecosystem": eco,
            "population_eligible_cases": pop.get("cases_eligible", 0),
            "population_eligible_advisories": pop.get("advisories_eligible", 0),
            "population_share_github_fix_commit": round(
                pop.get("eligible_with_github_fix_commit", 0) / pop["cases_eligible"], 3)
            if pop.get("cases_eligible") else "",
            "sample_n": n,
            "w1_both_consistent": both,
            "w1_share": round(both / n, 3) if n else "",
            "w1_with_backport": ext,
            "w1_with_backport_share": round(ext / n, 3) if n else "",
            "any_inconsistent": incons,
            "unresolved": unres,
        })
    with open(out_dir / "pilot_w1_summary.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    reasons = Counter((r["ecosystem"], r.get("reason")) for r in results if r.get("reason"))
    with open(out_dir / "pilot_w1_reasons.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ecosystem", "reason", "count"])
        for (eco, reason), c in sorted(reasons.items()):
            w.writerow([eco, reason, c])

    incons = [r for r in results if "inconsistent" in (r["pos_status"], r["neg_status"])]
    with open(out_dir / "pilot_w1_inconsistent.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ecosystem", "advisory", "package", "vulnerable", "fixed", "repo",
                    "tag_vulnerable", "tag_fixed", "pos_status", "pos_method", "neg_status",
                    "neg_method", "osv_url"])
        for r in incons:
            w.writerow([r["ecosystem"], r["advisory"], r["package"], r.get("vulnerable"),
                        r.get("fixed"), r.get("repo"), r.get("tag_vulnerable"),
                        r.get("tag_fixed"), r["pos_status"], r.get("pos_method"),
                        r["neg_status"], r.get("neg_method"),
                        f"https://osv.dev/vulnerability/{r['advisory']}"])

    print("\nPODSUMOWANIE (pilot_w1_summary.csv)")
    for row in rows:
        print("  " + ", ".join(f"{k}={v}" for k, v in row.items()))
    print("\nPRZYCZYNY NIEROZSTRZYGNIĘĆ (pilot_w1_reasons.csv)")
    for (eco, reason), c in sorted(reasons.items(), key=lambda kv: (kv[0][0], -kv[1])):
        print(f"  {eco:6} {reason:45} {c}")


def cluster_key(case: dict) -> str:
    """Repozytorium z commitów z poprawką; bez commitów nazwa pakietu."""
    if case["commits"]:
        return "repo:" + sorted(case["commits"], key=lambda k: -len(case["commits"][k]))[0]
    return "pkg:" + case["package"].lower()


def sample_cases(cases: list[dict], n: int, seed: str, max_per_cluster: int) -> list[dict]:
    """Losowanie po poradach z limitem przypadków na repozytorium (lub pakiet)."""
    rng = random.Random(seed)
    by_adv: dict[str, list[dict]] = defaultdict(list)
    for c in sorted(cases, key=lambda c: c["case_id"]):
        by_adv[c["advisory"]].append(c)
    advisories = sorted(by_adv)
    rng.shuffle(advisories)
    used: Counter = Counter()
    chosen = []
    for adv in advisories:
        if len(chosen) >= n:
            break
        options = by_adv[adv][:]
        rng.shuffle(options)
        pick = next((c for c in options if used[cluster_key(c)] < max_per_cluster), None)
        if pick is None:
            continue
        used[cluster_key(pick)] += 1
        chosen.append(pick)
    return chosen


# --------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--per-ecosystem", type=int, default=100,
                    help="liczność próby na ekosystem (domyślnie 100)")
    ap.add_argument("--ecosystems", nargs="+", default=ECOSYSTEMS, choices=ECOSYSTEMS)
    ap.add_argument("--seed", type=int, default=20261020)
    ap.add_argument("--max-per-repo", type=int, default=1,
                    help="maks. liczba przypadków z jednego repozytorium/pakietu (domyślnie 1)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--clone-timeout", type=int, default=900, help="sekundy na klon repozytorium")
    ap.add_argument("--data-dir", type=Path, default=Path("data"))
    ap.add_argument("--cache-dir", type=Path, default=Path("cache/repos"))
    ap.add_argument("--out-dir", type=Path, default=Path("results"))
    ap.add_argument("--refresh-osv", action="store_true", help="pobierz zrzuty OSV ponownie")
    ap.add_argument("--population-only", action="store_true",
                    help="tylko statystyki całej populacji porad (bez sieci poza OSV)")
    ap.add_argument("--repo-url-template", default="https://github.com/{repo}.git",
                    help=argparse.SUPPRESS)
    args = ap.parse_args()

    for d in (args.data_dir, args.cache_dir, args.out_dir):
        d.mkdir(parents=True, exist_ok=True)

    population, sample = {}, []
    for eco in args.ecosystems:
        zip_path = download_dump(eco, args.data_dir, args.refresh_osv)
        cases, stats = build_cases(eco, load_records(zip_path))
        population[eco] = stats
        print(f"[{eco}] {dict(stats)}", file=sys.stderr)
        stats["advisories_eligible"] = len({c["advisory"] for c in cases})
        stats["clusters_eligible"] = len({cluster_key(c) for c in cases})
        sample.extend(sample_cases(cases, args.per_ecosystem, f"{args.seed}-{eco}",
                                   args.max_per_repo))
        print(f"[{eco}] {dict(stats)}", file=sys.stderr)

    (args.out_dir / "population_stats.json").write_text(
        json.dumps({k: dict(v) for k, v in population.items()}, indent=2))
    if args.population_only:
        print(json.dumps({k: dict(v) for k, v in population.items()}, indent=2))
        return

    jsonl = args.out_dir / "pilot_w1.jsonl"
    done = {}
    if jsonl.exists():
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                done[r["case_id"]] = r
    todo = [c for c in sample if c["case_id"] not in done]
    print(f"[pilot] próba: {len(sample)}, już ocenione: {len(sample) - len(todo)}, "
          f"do oceny: {len(todo)}", file=sys.stderr)

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    repos = RepoCache(args.cache_dir, args.clone_timeout, args.repo_url_template)
    write_lock = threading.Lock()
    with open(jsonl, "a", encoding="utf-8") as fh, ThreadPoolExecutor(args.workers) as pool:
        futures = {pool.submit(evaluate, c, session, repos): c for c in todo}
        for i, fut in enumerate(as_completed(futures), 1):
            case = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:  # noqa: BLE001
                res = {"case_id": case["case_id"], "ecosystem": case["ecosystem"],
                       "advisory": case["advisory"], "package": case["package"],
                       "pos_status": "unresolved", "neg_status": "unresolved",
                       "reason": f"exception:{type(exc).__name__}:{exc}"[:200]}
            with write_lock:
                fh.write(json.dumps(res, ensure_ascii=False) + "\n")
                fh.flush()
                done[res["case_id"]] = res
            print(f"[{i}/{len(todo)}] {res['case_id']}: pos={res['pos_status']} "
                  f"neg={res['neg_status']} {res.get('reason') or ''}", file=sys.stderr)

    sample_ids = {c["case_id"] for c in sample}
    summarize([r for cid, r in done.items() if cid in sample_ids], population, args.out_dir)


if __name__ == "__main__":
    main()
