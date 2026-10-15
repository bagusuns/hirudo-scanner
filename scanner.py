#!/usr/bin/env python3
"""Read-only Android IOC triage for ThreatFabric Hirudo. Python 3.9+; adb required."""
import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def cmd(args, timeout=30, check=False):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=check)


def adb(serial, *args, timeout=30):
    return cmd(["adb", "-s", serial, *args], timeout=timeout)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def serials():
    result = cmd(["adb", "devices"], timeout=15)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "adb devices failed")
    found = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            found.append(parts[0])
    return found


def certificate_info(apk):
    if not shutil.which("apksigner"):
        return {"status": "not_checked", "reason": "apksigner unavailable"}
    try:
        result = cmd(["apksigner", "verify", "--print-certs", str(apk)], timeout=60)
        fingerprints = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)", result.stdout)
        return {"status": "ok" if result.returncode == 0 else "verification_failed",
                "signer_sha256": fingerprints,
                "detail": (result.stderr or "").strip()[:250]}
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "error", "reason": str(exc)}


def main():
    parser = argparse.ArgumentParser(description="Hirudo IOC check via Android Debug Bridge (read-only)")
    parser.add_argument("--serial", help="adb device serial (required if multiple devices)")
    parser.add_argument("--iocs", type=Path, default=ROOT / "iocs.json")
    parser.add_argument("--output", type=Path, default=Path("reports"))
    parser.add_argument("--hash-all", action="store_true", help="Hash all installed packages; slower, no APKs are retained")
    parser.add_argument("--no-pull", action="store_true", help="Only check package names and Accessibility, do not copy APKs")
    args = parser.parse_args()
    if not shutil.which("adb"):
        parser.error("adb is not installed. Try: sudo apt install adb")
    try:
        iocs = json.loads(args.iocs.read_text(encoding="utf-8"))
        entries = iocs["packages"]
        expected = {p["package"]: p for p in entries}
        hashes = {}
        for e in entries:
            if not re.fullmatch(r"[a-f0-9]{64}", e["sha256"]):
                parser.error("Invalid SHA-256 IOC: " + e["package"])
            hashes.setdefault(e["sha256"], []).append(e)
        available = serials()
        if args.serial:
            if args.serial not in available:
                parser.error(f"Device {args.serial!r} not connected/authorized. Connected: {available}")
            serial = args.serial
        elif len(available) == 1:
            serial = available[0]
        else:
            parser.error(f"Need exactly one authorized device, got: {available}. Use --serial")
        pm = adb(serial, "shell", "pm", "list", "packages", "-3", timeout=45)
        if pm.returncode:
            raise RuntimeError(pm.stderr or pm.stdout or "Unable to list packages")
        installed = sorted(set(re.findall(r"^package:([^\s]+)$", pm.stdout, flags=re.M)))
        accessibility = adb(serial, "shell", "settings", "get", "secure", "enabled_accessibility_services")
        accessibility_services = (accessibility.stdout or "").strip() if accessibility.returncode == 0 else "unavailable"
        if accessibility_services.lower() == "null":
            accessibility_services = None
        inspect = installed if args.hash_all else [p for p in installed if p in expected]
        results = []
        print(f"Device: {serial} | Third-party installed packages: {len(installed)}")
        print(f"Enabled Accessibility Services: {accessibility_services if accessibility_services is not None else 'not configured (null)'}")
        print(f"Packages selected for APK analysis: {len(inspect)}")
        for idx, package in enumerate(inspect, 1):
            entry = expected.get(package)
            record = {"package": package, "role": entry["role"] if entry else "", "package_ioc_match": bool(entry),
                      "apk_sha256": [], "ioc_hash_match": False, "apk_status": "not_checked", "signers": []}
            print(f"[{idx}/{len(inspect)}] {package}", flush=True)
            if args.no_pull:
                record["apk_status"] = "skipped_by_user"
            else:
                paths = adb(serial, "shell", "pm", "path", package, timeout=30)
                apk_paths = [s.removeprefix("package:").strip() for s in paths.stdout.splitlines() if s.startswith("package:")]
                if paths.returncode != 0 or not apk_paths:
                    record["apk_status"] = "path_unavailable"
                else:
                    errors = 0
                    with tempfile.TemporaryDirectory(prefix="hirudo-triage-") as tmp:
                        for apkn, apk_path in enumerate(apk_paths):
                            temp_apk = Path(tmp) / f"{apkn}.apk"
                            try:
                                pulled = adb(serial, "pull", apk_path, str(temp_apk), timeout=120)
                                if pulled.returncode or not temp_apk.is_file():
                                    errors += 1
                                    continue
                                fingerprint = sha256(temp_apk)
                                matched = hashes.get(fingerprint, [])
                                record["apk_sha256"].append({"file": Path(apk_path).name, "sha256": fingerprint,
                                                             "matched_ioc_package": [x["package"] for x in matched]})
                                if matched:
                                    record["ioc_hash_match"] = True
                                record["signers"].append({"file": Path(apk_path).name,
                                                          "certificate": certificate_info(temp_apk)})
                            except (subprocess.TimeoutExpired, OSError) as exc:
                                errors += 1
                                record.setdefault("errors", []).append(str(exc))
                    record["apk_status"] = "partial" if errors and record["apk_sha256"] else "unavailable" if errors else "ok"
            record["assessment"] = "HASH_MATCH" if record["ioc_hash_match"] else "PACKAGE_MATCH_REVIEW" if entry else "NO_KNOWN_IOC_MATCH"
            results.append(record)
        if not args.hash_all:
            # Show all IOC packages, including those absent, in the final report.
            for package, entry in expected.items():
                if package not in installed:
                    results.append({"package": package, "role": entry["role"], "package_ioc_match": False,
                                    "apk_sha256": [], "ioc_hash_match": False, "apk_status": "not_installed",
                                    "signers": [], "assessment": "NOT_INSTALLED"})
        args.output.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_serial = re.sub(r"[^a-zA-Z0-9_-]", "_", serial)
        base = args.output / f"hirudo_{safe_serial}_{stamp}"
        report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "device_serial": serial,
                  "ioc_source": iocs.get("source"), "third_party_package_count": len(installed),
                  "hash_all": args.hash_all, "no_pull": args.no_pull,
                  "accessibility_services": accessibility_services, "results": results,
                  "disclaimer": "No match does not prove clean. Signature certificates not verified against bank's trusted fingerprints."}
        base.with_suffix(".json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        with base.with_suffix(".csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["package", "role", "package_ioc_match", "ioc_hash_match", "apk_status", "assessment", "apk_sha256", "signer_sha256"])
            writer.writeheader()
            for r in results:
                writer.writerow({k: (";".join(item["sha256"] for item in r["apk_sha256"]) if k == "apk_sha256" else
                                     ";".join(fp for s in r["signers"] for fp in s["certificate"].get("signer_sha256", [])) if k == "signer_sha256" else r.get(k, "")) for k in writer.fieldnames})
        print("\nSummary:")
        from collections import Counter
        statuses = Counter(r["assessment"] for r in results)
        for status in ("HASH_MATCH", "PACKAGE_MATCH_REVIEW", "NOT_INSTALLED", "NO_KNOWN_IOC_MATCH"):
            if statuses[status]:
                print(f"  {status}: {statuses[status]}")
        failures = [r for r in results if r["apk_status"] not in ("ok", "not_installed", "skipped_by_user")]
        if failures:
            print(f"  APK read issues: {len(failures)} (see report)")
        for r in results:
            if r["assessment"] in ("HASH_MATCH", "PACKAGE_MATCH_REVIEW"):
                print(f"  REVIEW: {r['assessment']} — {r['package']} (APK: {r['apk_status']})")
        print(f"\nJSON: {base.with_suffix('.json')}\nCSV:  {base.with_suffix('.csv')}")
        print("WARNING: Negative result does not rule out Hirudo or a modified bank app.")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
