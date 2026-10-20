#!/usr/bin/env python3
"""Normalizacja wyników narzędzi SCA i klasyfikacja względem wzorca D1 (scenariusz S1).

Dla każdego skanu (przypadek, etykieta pos/neg, forma F1/F2, narzędzie) skrypt:
  1. sprowadza zgłoszenia narzędzia do wspólnego schematu (pakiet, wersja, identyfikatory
     podatności ze wszystkimi aliasami podanymi przez narzędzie, źródło danych),
  2. sprawdza, czy zgłoszono poradę docelową (dowolny alias z grupy aliasów OSV) dla pakietu
     docelowego,
  3. klasyfikuje wynik: pos + wykrycie = TP, pos + brak = FN, neg + wykrycie = FP,
     neg + brak = TN; nieudany skan = ERR (wyłączany z miar i do powtórzenia).

Zgłoszenia innych porad lub innych pakietów nie wchodzą do miar (specyfikacja D1, p. 7.2).

Wyniki: d1/results_s1/findings.csv (wszystkie znormalizowane zgłoszenia),
        d1/results_s1/outcomes.csv (jeden wiersz na skan), podsumowanie na ekranie.

Użycie:
    python3 d1/evaluate_s1.py
"""
from __future__ import annotations

import csv
import io
import json
import re
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
PROJ = ROOT / "d1" / "projects_s1"
RAW = ROOT / "d1" / "raw_s1"
OUT = ROOT / "d1" / "results_s1"
DUMPS = ROOT / "pilot" / "data"

# kody wyjścia oznaczające poprawne zakończenie (1 = znaleziono podatności)
OK_CODES = {
    "trivy": {0}, "grype": {0, 1}, "osv-scanner": {0, 1, 128}, "osv-scanner-ext": {0, 1, 128},
    "dependency-check": {0}, "npm-audit": {0, 1}, "pip-audit": {0, 1},
}
OSV_CHECKS = ["confirmed", "version_not_affected", "package_mismatch", "not_in_osv",
              "unknown_version"]
VULN_ID_RE = re.compile(r"(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|CVE-\d{4}-\d{4,}|PYSEC-\d{4}-\d+)",
                        re.IGNORECASE)


# --------------------------------------------------------------------------- tożsamość pakietu

def norm_pkg(eco: str, name: str) -> str:
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco == "npm":
        return name.lower()
    return name.lower()  # Maven: groupId:artifactId


def from_purl(purl: str | None) -> tuple[str | None, str | None, str | None]:
    """Zwraca (ekosystem, nazwa, wersja) z identyfikatora PURL."""
    if not purl or not purl.startswith("pkg:"):
        return None, None, None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    typ, _, rest = body.partition("/")
    rest = unquote(rest)
    version = None
    at = rest.rfind("@")
    if at > 0:  # '@' na pozycji 0 to zakres pakietu npm, nie wersja
        rest, version = rest[:at], rest[at + 1:]
    eco = {"npm": "npm", "pypi": "PyPI", "maven": "Maven"}.get(typ.lower())
    if eco == "Maven":
        ns, _, nm = rest.rpartition("/")
        return eco, f"{ns.replace('/', '.')}:{nm}", version
    return eco, rest, version


def vuln_ids(*values) -> set[str]:
    out = set()
    for v in values:
        if not v:
            continue
        if isinstance(v, (list, tuple, set)):
            out |= vuln_ids(*v)
        else:
            out |= {m.upper() for m in VULN_ID_RE.findall(str(v))}
    return out


# --------------------------------------------------------------------------- parsery narzędzi
# Każdy parser zwraca (lista zgłoszeń, zbiór nazw pakietów w inwentarzu lub None).

def parse_trivy(data, eco):
    findings, inventory = [], set()
    for res in data.get("Results") or []:
        for p in res.get("Packages") or []:
            _, n, _ = from_purl((p.get("Identifier") or {}).get("PURL"))
            inventory.add(norm_pkg(eco, n or p.get("Name", "")))
        for v in res.get("Vulnerabilities") or []:
            _, n, ver = from_purl((v.get("PkgIdentifier") or {}).get("PURL"))
            findings.append({"package": n or v.get("PkgName"), "version": ver or v.get("InstalledVersion"),
                             "ids": vuln_ids(v.get("VulnerabilityID"), v.get("VendorIDs")),
                             "source": (v.get("DataSource") or {}).get("ID")})
    return findings, inventory


def parse_grype(data, eco):
    findings = []
    for m in data.get("matches") or []:
        art, vul = m.get("artifact") or {}, m.get("vulnerability") or {}
        _, n, ver = from_purl(art.get("purl"))
        related = [r.get("id") for r in m.get("relatedVulnerabilities") or []]
        findings.append({"package": n or art.get("name"), "version": ver or art.get("version"),
                         "ids": vuln_ids(vul.get("id"), related),
                         "source": vul.get("namespace")})
    return findings, None  # Grype nie zwraca pełnego inwentarza w raporcie JSON


def parse_osv(data, eco):
    findings, inventory = [], set()
    for res in data.get("results") or []:
        for p in res.get("packages") or []:
            pkg = p.get("package") or {}
            inventory.add(norm_pkg(eco, pkg.get("name", "")))
            group_aliases = [g.get("aliases") for g in p.get("groups") or []]
            for v in p.get("vulnerabilities") or []:
                findings.append({"package": pkg.get("name"), "version": pkg.get("version"),
                                 "ids": vuln_ids(v.get("id"), v.get("aliases")),
                                 "source": "osv"})
            if not p.get("vulnerabilities") and group_aliases:
                findings.append({"package": pkg.get("name"), "version": pkg.get("version"),
                                 "ids": vuln_ids(group_aliases), "source": "osv"})
    return findings, None  # raport OSV-Scanner zawiera tylko pakiety z podatnościami


def parse_dc(data, eco):
    findings, inventory = [], set()
    for dep in data.get("dependencies") or []:
        names = []
        for p in dep.get("packages") or []:
            e, n, ver = from_purl(p.get("id"))
            if n:
                names.append((n, ver))
                inventory.add(norm_pkg(eco, n))
        for v in dep.get("vulnerabilities") or []:
            ids = vuln_ids(v.get("name"))
            for n, ver in names or [(dep.get("fileName"), None)]:
                findings.append({"package": n, "version": ver, "ids": ids,
                                 "source": v.get("source")})
    return findings, inventory


def parse_npm_audit(data, eco):
    findings = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        for via in v.get("via") or []:
            if isinstance(via, dict):
                findings.append({"package": via.get("name") or name, "version": None,
                                 "ids": vuln_ids(via.get("url"), via.get("cve")),
                                 "source": "npm"})
    return findings, None


def parse_pip_audit(data, eco):
    findings, inventory = [], set()
    for dep in data.get("dependencies") or []:
        inventory.add(norm_pkg(eco, dep.get("name", "")))
        for v in dep.get("vulns") or []:
            findings.append({"package": dep.get("name"), "version": dep.get("version"),
                             "ids": vuln_ids(v.get("id"), v.get("aliases")), "source": "pypi"})
    return findings, inventory


PARSERS = {"trivy": parse_trivy, "grype": parse_grype, "osv-scanner": parse_osv,
           "osv-scanner-ext": parse_osv,
           "dependency-check": parse_dc, "npm-audit": parse_npm_audit, "pip-audit": parse_pip_audit}


# --------------------------------------------------------------------------- grupy aliasów

class UnionFind:
    def __init__(self):
        self.p: dict[str, str] = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


class OSVIndex:
    """Grupy aliasów i zakresy podatnych wersji ze zrzutów OSV z dnia zamrożenia."""

    def __init__(self, dumps: Path):
        sys.path.insert(0, str(ROOT / "pilot"))
        import pilot_w1  # funkcje zakresów wersji (te same co w pilotażu W1)
        self.pw = pilot_w1
        self.uf = UnionFind()
        self.affected: dict[tuple[str, str], list[tuple[str, list, set]]] = defaultdict(list)
        for zp in sorted(dumps.glob("osv-*.zip")):
            with zipfile.ZipFile(zp) as zf:
                for name in zf.namelist():
                    rec = json.load(io.TextIOWrapper(zf.open(name), encoding="utf-8"))
                    if rec["id"].startswith("MAL-") or rec.get("withdrawn"):
                        continue
                    ids = [rec["id"].upper(), *[a.upper() for a in rec.get("aliases") or []]]
                    for a in ids[1:]:
                        self.uf.union(ids[0], a)
                    for aff in rec.get("affected") or []:
                        pkg = aff.get("package") or {}
                        eco = pkg.get("ecosystem")
                        if eco not in ("npm", "PyPI", "Maven"):
                            continue
                        pairs = [p for rng in aff.get("ranges") or []
                                 if rng.get("type") in ("ECOSYSTEM", "SEMVER")
                                 for p in pilot_w1.range_pairs(rng.get("events", []))]
                        self.affected[(eco, norm_pkg(eco, pkg.get("name", "")))].append(
                            (ids[0], pairs, set(aff.get("versions") or [])))
        members = defaultdict(set)
        for x in list(self.uf.p):
            members[self.uf.find(x)].add(x)
        self.members = members

    def group(self, vid: str) -> set[str]:
        vid = vid.upper()
        return self.members.get(self.uf.find(vid), {vid}) if vid in self.uf.p else {vid}

    def check(self, eco: str, pkg: str | None, version: str | None, ids: set[str]) -> str:
        """Weryfikacja zgłoszenia w OSV: confirmed, version_not_affected, package_mismatch,
        not_in_osv, unknown_version."""
        known = [i for i in ids if i in self.uf.p]
        if not known:
            return "not_in_osv"
        roots = {self.uf.find(i) for i in known}
        entries = [e for e in self.affected.get((eco, norm_pkg(eco, pkg or "")), [])
                   if self.uf.find(e[0]) in roots]
        if not entries:
            return "package_mismatch"
        if not version:
            return "unknown_version"
        v = self.pw.parse_version(eco, version)
        for _, pairs, versions in entries:
            if version in versions or (v is not None and self.pw.affected_by_any(eco, v, pairs)):
                return "confirmed"
        return "version_not_affected" if v is not None else "unknown_version"


# --------------------------------------------------------------------------- main

def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def main():
    global PROJ, RAW, OUT, DUMPS
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--proj", type=Path, default=PROJ)
    ap.add_argument("--raw", type=Path, default=RAW)
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--dumps", type=Path, default=DUMPS)
    a = ap.parse_args()
    PROJ, RAW, OUT, DUMPS = a.proj, a.raw, a.out, a.dumps
    cases = {}
    for cj in sorted(PROJ.glob("*/*/case.json")):
        cases[cj.parent.relative_to(PROJ).as_posix()] = json.loads(cj.read_text())
    if not cases:
        sys.exit("Brak projektów w d1/projects_s1")
    osv = OSVIndex(DUMPS)

    OUT.mkdir(parents=True, exist_ok=True)
    fin_f = open(OUT / "findings.csv", "w", newline="", encoding="utf-8")
    fin = csv.writer(fin_f)
    fin.writerow(["case", "label", "form", "tool", "package", "version", "ids", "source",
                  "is_target_pkg", "is_target_vuln", "osv_check"])
    outcomes = []
    for meta_path in sorted(RAW.glob("*/*/*/*/*.meta.json")):
        rel = meta_path.parent.relative_to(RAW).parts  # eco, case, label, form
        case_key, label, form = f"{rel[0]}/{rel[1]}", rel[2], rel[3]
        case = cases.get(case_key)
        if not case:
            continue
        eco = case["ecosystem"]
        meta = load_json(meta_path) or {}
        tool = meta.get("tool") or meta_path.name.split(".")[0]
        data = load_json(meta_path.with_name(f"{tool}.json"))
        row = {"ecosystem": eco, "case": case_key, "advisory": case["advisory"],
               "package": case["package"], "label": label, "form": form, "tool": tool,
               "exit_code": meta.get("exit_code"), "wall_seconds": meta.get("wall_seconds")}
        if isinstance(data, dict) and data.get("skipped"):
            row.update(status="skipped", outcome="SKIP")
            outcomes.append(row)
            continue
        if tool.startswith("osv-scanner") and meta.get("exit_code") == 128:
            # zdefiniowana odpowiedź narzędzia: brak obsługiwanych plików wejściowych
            data = {"results": []}
        if data is None or meta.get("exit_code") not in OK_CODES[tool]:
            row.update(status="error", outcome="ERR")
            outcomes.append(row)
            continue
        findings, inventory = PARSERS[tool](data, eco)
        target_pkg = norm_pkg(eco, case["package"])
        group = osv.group(case["advisory"])
        hit, other = False, set()
        checks = defaultdict(int)
        seen = set()
        for f in findings:
            is_pkg = f["package"] is not None and norm_pkg(eco, f["package"]) == target_pkg
            is_vuln = bool(f["ids"] & group)
            hit |= is_pkg and is_vuln
            if is_pkg and not is_vuln:
                other |= f["ids"]
            chk = "" if (is_pkg and is_vuln) else osv.check(eco, f["package"], f["version"], f["ids"])
            key = (norm_pkg(eco, f["package"] or ""),
                   frozenset(osv.uf.find(i) if i in osv.uf.p else i for i in f["ids"]))
            if chk and key not in seen:
                seen.add(key)
                checks[chk] += 1
            fin.writerow([case_key, label, form, tool, f["package"], f["version"],
                          " ".join(sorted(f["ids"])), f["source"], is_pkg, is_vuln, chk])
        status = "no_packages" if tool.startswith("osv-scanner") and meta.get("exit_code") == 128 else "ok"
        outcome = {("pos", True): "TP", ("pos", False): "FN",
                   ("neg", True): "FP", ("neg", False): "TN"}[(label, hit)]
        row.update(status=status, outcome=outcome, detected=hit,
                   target_in_inventory=None if inventory is None else target_pkg in inventory,
                   n_findings=len(findings), other_ids_target_pkg=len(other),
                   **{f"other_{k}": checks.get(k, 0) for k in OSV_CHECKS})
        outcomes.append(row)
    fin_f.close()

    cols = ["ecosystem", "case", "advisory", "package", "label", "form", "tool", "status",
            "outcome", "detected", "target_in_inventory", "n_findings",
            "other_ids_target_pkg", *[f"other_{k}" for k in OSV_CHECKS],
            "exit_code", "wall_seconds"]
    with open(OUT / "outcomes.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(outcomes)

    agg = defaultdict(lambda: defaultdict(int))
    for r in outcomes:
        agg[(r["tool"], r["ecosystem"], r["form"])][r["outcome"]] += 1
    print(f"{'narzędzie':17} {'ekos.':6} {'forma':5}  TP  FN  FP  TN ERR SKIP  czułość swoistość")
    for (tool, eco, form), c in sorted(agg.items()):
        tp, fn, fp, tn = c["TP"], c["FN"], c["FP"], c["TN"]
        rec = f"{tp / (tp + fn):.2f}" if tp + fn else "  - "
        spe = f"{tn / (tn + fp):.2f}" if tn + fp else "  - "
        print(f"{tool:17} {eco:6} {form:5} {tp:3} {fn:3} {fp:3} {tn:3} {c['ERR']:3} "
              f"{c['SKIP']:4}  {rec:>7} {spe:>9}")
    print("\nZGŁOSZENIA SPOZA PORADY DOCELOWEJ (średnio na skan; weryfikacja w OSV)")
    print(f"{'narzędzie':17} {'ekos.':6} " + " ".join(f"{k[:14]:>14}" for k in OSV_CHECKS))
    sums = defaultdict(lambda: defaultdict(float))
    cnt = defaultdict(int)
    for r in outcomes:
        if r.get("status") in ("ok", "no_packages"):
            k = (r["tool"], r["ecosystem"])
            cnt[k] += 1
            for c in OSV_CHECKS:
                sums[k][c] += r.get(f"other_{c}", 0)
    for k in sorted(cnt):
        print(f"{k[0]:17} {k[1]:6} " + " ".join(f"{sums[k][c] / cnt[k]:14.2f}" for c in OSV_CHECKS))
    print(f"\nZapisano: {OUT / 'outcomes.csv'}, {OUT / 'findings.csv'}")


if __name__ == "__main__":
    main()
