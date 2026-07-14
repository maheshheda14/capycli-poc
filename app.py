import json
import os
import re
import select
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from threading import Lock
from typing import Annotated, Any, Dict, List, Optional
from urllib.parse import urlparse
from uuid import uuid4

import requests
from fastapi import BackgroundTasks, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, Response

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

ECOSYSTEM_COMMANDS: Dict[str, str] = {
    "javascript": "javascript",
    "python": "python",
    "mavenpom": "mavenpom",
    "nuget": "nuget",
}

# CycloneDX property keys written by CaPyCli into the SBOM (do not change these,
# they mirror constants defined in capycli/common/capycli_bom_support.py).
CDX_PROP_MAPRESULT = "capycli:mapResult"
CDX_PROP_SW360ID = "siemens:sw360Id"

# Map result codes that mean the component was already present in SW360.
# (Codes 1-4 are "good matches"; 5, 6 are weak candidates; 9 is no match.)
GOOD_MATCH_PREFIXES = ("1", "2", "3", "4")

app = FastAPI(title="CaPyCli Onboarding API")
JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = Lock()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def set_job(job_id: str, **updates: Any) -> None:
    with JOBS_LOCK:
        current = JOBS.get(job_id, {})
        current.update(updates)
        JOBS[job_id] = current


def safe_filename_part(value: str, default: str = "unknown") -> str:
    """Normalize a string so it can be safely used in a download filename."""
    text = (value or "").strip()
    if not text:
        return default
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    return text.strip("._-") or default


def normalize_sw360_url(url: str) -> str:
    clean = url.strip().rstrip("/")
    if not clean:
        return clean

    parsed = urlparse(clean)
    if parsed.scheme and parsed.netloc:
        # Keep only base URL if users paste UI pages such as /group/guest/home.
        return f"{parsed.scheme}://{parsed.netloc}"

    idx = clean.lower().find("/resource/api")
    if idx != -1:
        clean = clean[:idx]
    return clean


def map_failure_hint(output: str) -> Optional[str]:
    """Return an actionable hint for common SW360 map/auth failures.

    ``output`` should contain the failing step's combined stdout + stderr, since
    CaPyCli prints authorization errors to stdout.
    """
    # Token type mismatch: a plain SW360 token was sent with the OAuth2/JWT flag,
    # or a JWT was sent without it. CaPyCli cannot decode it as a JWT.
    if "Not enough segments" in output or "Unable to analyze token" in output:
        return (
            "SW360 token type mismatch. For a plain SW360 API token, disable OAuth2 "
            "(sw360_oauth2=false). Only enable OAuth2 for a JWT/bearer token "
            "(format xxxxx.yyyyy.zzzzz)."
        )

    if "not authorized" in output.lower():
        return (
            "SW360 authorization failed. Check that the token is valid, has the "
            "correct type (OAuth2 vs plain token), and has the required permissions."
        )

    if "JSONDecodeError" in output:
        return (
            "SW360 returned non-JSON content. Use base SW360 URL (without /resource/api), "
            "and ensure token type is correct (check OAuth2 for Bearer/JWT tokens)."
        )

    if "Step timed out" in output and "Refreshing component cache" in output:
        return (
            "SW360 map timed out while building the release cache. This is usually a first-run "
            "or slow-server condition. Retry once, and consider increasing CAPYCLI_MAP_TIMEOUT_SEC "
            "(for example to 600)."
        )

    if "Step timed out" in output:
        return (
            "SW360 map timed out. The server is reachable, but mapping took too long. "
            "Increase CAPYCLI_MAP_TIMEOUT_SEC and retry."
        )

    if "No unique mapping found - manual action needed" in output:
        return (
            "Some dependencies could not be uniquely mapped in SW360. "
            "Proceeding with partial mapping is possible; unmatched items may be created "
            "in the next step or need manual review."
        )
    return None


def get_map_cachefile() -> str:
    """Return a persistent cache path used by `capycli bom map` across jobs."""
    configured = os.environ.get("CAPYCLI_MAP_CACHEFILE", "").strip()
    if configured:
        cachefile = configured
    else:
        cache_root = os.path.join(os.path.expanduser("~"), ".capycli-onboarding")
        cachefile = os.path.join(cache_root, "ComponentCache.json")

    cache_dir = os.path.dirname(cachefile)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
    return cachefile


def map_uses_nocache(component_count: int) -> bool:
    """Decide whether to run `bom map` with `--nocache`.

    For small SBOMs, avoiding full release-cache refresh is usually faster.
    Configure with CAPYCLI_MAP_NOCACHE_THRESHOLD (default: 10).
    """
    threshold = int(os.environ.get("CAPYCLI_MAP_NOCACHE_THRESHOLD", "10"))
    return component_count > 0 and component_count <= threshold


def is_partial_map_result(step_result: Dict[str, Any], mapped_path: str) -> bool:
    """Return True when map exited non-zero due to incomplete mapping but wrote output."""
    exit_code = int(step_result.get("exit_code", -1) or -1)
    stdout = step_result.get("stdout", "") or ""
    return (
        exit_code in (80,)
        and "No unique mapping found - manual action needed" in stdout
        and os.path.isfile(mapped_path)
    )


def is_createcomponents_auth_failure(step_result: Dict[str, Any]) -> bool:
    """Return True if createcomponents failed due to SW360 authorization."""
    output = f"{step_result.get('stdout', '')}\n{step_result.get('stderr', '')}".lower()
    return "not authorized" in output or "you are not authorized" in output


def continue_on_createcomponents_auth_error() -> bool:
    """Whether onboarding should continue when createcomponents hits auth errors."""
    flag = os.environ.get("CAPYCLI_CONTINUE_ON_CREATECOMPONENTS_AUTH_ERROR", "1").strip().lower()
    return flag in ("1", "true", "yes", "on")


def probe_sw360_write_access(base_url: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """Best-effort, non-destructive probe for SW360 write permissions.

    We intentionally send an invalid payload, so a writable token should produce
    a validation-style response (typically 400/422), while a read-only token is
    expected to return 401/403.
    """
    probe_url = f"{base_url}/resource/api/components"
    payload = {"name": "", "version": ""}

    try:
        resp = requests.post(probe_url, headers=headers, json=payload, timeout=15)
        code = resp.status_code

        if code in (401, 403):
            return {
                "write_access": False,
                "http_status": code,
                "message": "Token appears read-only (missing component/project write permission).",
            }

        if code in (200, 201, 400, 404, 405, 409, 415, 422):
            return {
                "write_access": True,
                "http_status": code,
                "message": "Write permission probe passed.",
            }

        return {
            "write_access": None,
            "http_status": code,
            "message": "Write permission could not be determined reliably.",
        }
    except requests.exceptions.Timeout:
        return {
            "write_access": None,
            "http_status": None,
            "message": "Write permission probe timed out.",
        }
    except Exception as exc:
        return {
            "write_access": None,
            "http_status": None,
            "message": f"Write permission probe failed: {str(exc)[:100]}",
        }


def load_sbom_components(path: str) -> List[Dict[str, Any]]:
    """Read a CaPyCli/CycloneDX SBOM file and return a normalized component list.

    Each entry has ``name``, ``version`` and a flattened ``props`` dict built from
    the component's ``properties`` array. Returns an empty list if the file is
    missing or cannot be parsed, so callers can degrade gracefully.
    """
    if not os.path.isfile(path):
        return []
    try:
        with open(path) as fin:
            data = json.load(fin)
    except (OSError, json.JSONDecodeError):
        return []

    components: List[Dict[str, Any]] = []
    for comp in data.get("components", []):
        props = {
            prop.get("name"): prop.get("value")
            for prop in comp.get("properties", [])
            if isinstance(prop, dict) and prop.get("name")
        }
        components.append(
            {
                "name": comp.get("name", ""),
                "version": comp.get("version", ""),
                "props": props,
            }
        )
    return components


def is_good_match(map_code: Optional[str]) -> bool:
    """Return True if the CaPyCli map result code means "already in SW360"."""
    return bool(map_code) and map_code[:1] in GOOD_MATCH_PREFIXES


def parse_create_stdout(stdout: str) -> Dict[str, str]:
    """Best-effort parse of `bom createcomponents` console output.

    Used only as a fallback when the created SBOM file is not available (e.g. the
    create step aborted before writing output). Maps a component's display name
    ("name, version") to one of: found, created, failed.
    """
    statuses: Dict[str, str] = {}
    current: Optional[str] = None

    for raw in stdout.splitlines():
        current = _consume_create_line(raw.rstrip(), current, statuses)

    return statuses


def _consume_create_line(line: str, current: Optional[str], statuses: Dict[str, str]) -> Optional[str]:
    """Update ``statuses`` for a single create-step output line.

    Returns the component name currently being processed (carried to next line).
    """
    already = re.match(r"^ {2}(.+?) already exists$", line)
    if already:
        statuses[already.group(1)] = "found"
        return None

    # A component being processed is printed at exactly two spaces of indent.
    processed = re.match(r"^ {2}(\S.*)$", line)
    if processed:
        text = processed.group(1)
        if "read from SBOM" in text or text.startswith("No client"):
            return current
        statuses.setdefault(text, "failed")
        return text

    if current and ("Release id = " in line or "Release created" in line):
        statuses[current] = "created"
    elif current and "Component creation failed" in line:
        statuses[current] = "failed"
    return current


def display_name(name: str, version: str) -> str:
    """Replicate CaPyCli's component display name format ("name, version")."""
    return f"{name}, {version}" if version else name


def _extract_license_names(component: Dict[str, Any]) -> List[str]:
    """Return normalized license names/ids from a CycloneDX component."""
    names: List[str] = []
    licenses = component.get("licenses", [])
    if not isinstance(licenses, list):
        return names

    for item in licenses:
        if not isinstance(item, dict):
            continue
        lic = item.get("license")
        if not isinstance(lic, dict):
            continue
        name = str(lic.get("id") or lic.get("name") or "").strip()
        if name:
            names.append(name)
    return names


def _purl_ecosystem(purl: str) -> str:
    """Extract ecosystem/type from purl (e.g. pkg:npm/foo -> npm)."""
    if not purl or not purl.startswith("pkg:"):
        return "unknown"
    purl_body = purl[4:]
    return purl_body.split("/", 1)[0] if "/" in purl_body else purl_body


def _percent(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((part / total) * 100.0, 1)


def build_sbom_summary(sbom_content: Dict[str, Any]) -> Dict[str, Any]:
    """Build frontend-friendly summary metrics from generated SBOM."""
    components = sbom_content.get("components", [])
    if not isinstance(components, list):
        components = []

    total = len(components)
    unique_name_version = set()
    duplicate_entries = 0

    license_counter: Counter[str] = Counter()
    ecosystem_counter: Counter[str] = Counter()

    with_license = 0
    with_purl = 0
    with_hash = 0
    with_external_refs = 0
    with_supplier = 0
    with_author = 0

    missing_license: List[str] = []
    missing_purl: List[str] = []

    for comp in components:
        if not isinstance(comp, dict):
            continue

        name = str(comp.get("name", "")).strip()
        version = str(comp.get("version", "")).strip()
        key = (name, version)
        if key in unique_name_version:
            duplicate_entries += 1
        else:
            unique_name_version.add(key)

        comp_label = display_name(name or "<unknown>", version)

        licenses = _extract_license_names(comp)
        if licenses:
            with_license += 1
            for lic in licenses:
                license_counter[lic] += 1
        else:
            missing_license.append(comp_label)

        purl = str(comp.get("purl", "")).strip()
        if purl:
            with_purl += 1
            ecosystem_counter[_purl_ecosystem(purl)] += 1
        else:
            ecosystem_counter["unknown"] += 1
            missing_purl.append(comp_label)

        hashes = comp.get("hashes", [])
        if isinstance(hashes, list) and len(hashes) > 0:
            with_hash += 1

        refs = comp.get("externalReferences", [])
        if isinstance(refs, list) and len(refs) > 0:
            with_external_refs += 1

        supplier = comp.get("supplier")
        if isinstance(supplier, dict) and str(supplier.get("name", "")).strip() not in ("", "N/A"):
            with_supplier += 1

        author = str(comp.get("author", "")).strip()
        if author and author != "N/A":
            with_author += 1

    license_pct = _percent(with_license, total)
    purl_pct = _percent(with_purl, total)
    hash_pct = _percent(with_hash, total)
    refs_pct = _percent(with_external_refs, total)
    supplier_pct = _percent(with_supplier, total)
    author_pct = _percent(with_author, total)

    quality_score = round((0.4 * license_pct) + (0.3 * purl_pct) + (0.3 * hash_pct), 1)
    if quality_score >= 85:
        quality_status = "good"
        quality_meaning = "SBOM is in strong shape for downstream review and sync."
    elif quality_score >= 60:
        quality_status = "fair"
        quality_meaning = "SBOM is usable, but some metadata gaps should be improved before syncing."
    else:
        quality_status = "poor"
        quality_meaning = "SBOM has major metadata gaps and should be improved before trusting it for sync."

    score_breakdown = {
        "license": {
            "weight": 0.4,
            "coverage_percent": license_pct,
            "contribution": round(0.4 * license_pct, 1),
        },
        "purl": {
            "weight": 0.3,
            "coverage_percent": purl_pct,
            "contribution": round(0.3 * purl_pct, 1),
        },
        "hash": {
            "weight": 0.3,
            "coverage_percent": hash_pct,
            "contribution": round(0.3 * hash_pct, 1),
        },
    }

    reasons: List[str] = []
    if license_pct < 100:
        reasons.append(f"{len(missing_license)} component(s) are missing a declared license.")
    if purl_pct < 100:
        reasons.append(f"{len(missing_purl)} component(s) are missing a package URL (purl).")
    if hash_pct < 100:
        missing_hash_count = total - with_hash
        reasons.append(f"{missing_hash_count} component(s) are missing a checksum/hash.")
    if duplicate_entries > 0:
        reasons.append(f"{duplicate_entries} duplicate name/version entries were found.")

    recommendations: List[str] = []
    if license_pct < 100:
        recommendations.append("Add or verify a license for every component.")
    if purl_pct < 100:
        recommendations.append("Ensure every component has a valid purl so tools can identify it consistently.")
    if hash_pct < 100:
        recommendations.append("Add component hashes or source checksums where available.")
    if supplier_pct < 100:
        recommendations.append("Add supplier/manufacturer metadata if your workflow supports it.")
    if author_pct < 100:
        recommendations.append("Add author metadata when it is available from upstream sources.")

    if not recommendations:
        recommendations.append("The SBOM looks complete on the metrics we score; review granularity and component mapping before sync.")

    if quality_status == "poor":
        quality_hint = "Run bom componentcheck and bom granularity, then fill in missing license, purl, and hash data."
    elif quality_status == "fair":
        quality_hint = "Review missing metadata and improve coverage before syncing to SW360."
    else:
        quality_hint = "Quality looks good; continue with validation and SW360 sync." 

    top_licenses = [
        {"license": name, "count": count}
        for name, count in license_counter.most_common(10)
    ]

    ecosystem_items = [
        {"ecosystem": eco, "count": count}
        for eco, count in sorted(ecosystem_counter.items(), key=lambda item: (-item[1], item[0]))
    ]

    dependencies = sbom_content.get("dependencies", [])
    dependency_count = len(dependencies) if isinstance(dependencies, list) else 0

    return {
        "schema_version": 1,
        "components": {
            "total": total,
            "unique_name_version": len(unique_name_version),
            "duplicate_entries": duplicate_entries,
        },
        "coverage": {
            "license_percent": license_pct,
            "purl_percent": purl_pct,
            "hash_percent": hash_pct,
            "external_references_percent": refs_pct,
            "supplier_percent": supplier_pct,
            "author_percent": author_pct,
        },
        "licenses": {
            "unique_count": len(license_counter),
            "top": top_licenses,
        },
        "ecosystems": ecosystem_items,
        "dependencies": {
            "entries": dependency_count,
        },
        "missing": {
            "license_count": len(missing_license),
            "purl_count": len(missing_purl),
            "license_examples": missing_license[:25],
            "purl_examples": missing_purl[:25],
        },
        "quality": {
            "score": quality_score,
            "status": quality_status,
            "formula": "0.4*license + 0.3*purl + 0.3*hash",
            "reference": "documentation/SBOM_Quality.md",
            "methodology": "CaPyCli guidance for SBOM quality, summarized into license, purl, and hash coverage metrics.",
            "meaning": quality_meaning,
            "hint": quality_hint,
            "thresholds": {
                "good": ">= 85",
                "fair": ">= 60 and < 85",
                "poor": "< 60",
            },
            "breakdown": score_breakdown,
            "reasons": reasons,
            "recommendations": recommendations,
        },
    }


def build_sbom_component_details(sbom_content: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build detailed per-component payload for Phase 1 UI consumption."""
    raw_components = sbom_content.get("components", [])
    if not isinstance(raw_components, list):
        return []

    details: List[Dict[str, Any]] = []
    for comp in raw_components:
        if not isinstance(comp, dict):
            continue

        name = str(comp.get("name", "")).strip()
        version = str(comp.get("version", "")).strip()
        purl = str(comp.get("purl", "")).strip()

        licenses = _extract_license_names(comp)
        primary_license = licenses[0] if licenses else ""

        supplier_name = ""
        supplier = comp.get("supplier")
        if isinstance(supplier, dict):
            supplier_name = str(supplier.get("name", "")).strip()

        hashes = comp.get("hashes", [])
        hash_items: List[Dict[str, str]] = []
        if isinstance(hashes, list):
            for item in hashes:
                if not isinstance(item, dict):
                    continue
                alg = str(item.get("alg", "")).strip()
                value = str(item.get("content", "")).strip()
                if alg and value:
                    hash_items.append({"alg": alg, "value": value})

        refs = comp.get("externalReferences", [])
        ref_items: List[Dict[str, str]] = []
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                ref_type = str(ref.get("type", "")).strip()
                ref_url = str(ref.get("url", "")).strip()
                if ref_type and ref_url:
                    ref_items.append({"type": ref_type, "url": ref_url})

        props = comp.get("properties", [])
        prop_items: List[Dict[str, str]] = []
        if isinstance(props, list):
            for prop in props:
                if not isinstance(prop, dict):
                    continue
                prop_name = str(prop.get("name", "")).strip()
                prop_value = str(prop.get("value", "")).strip()
                if prop_name:
                    prop_items.append({"name": prop_name, "value": prop_value})

        details.append(
            {
                # Keep existing fields for backward compatibility.
                "name": name,
                "version": version,
                "purl": purl,
                "license": primary_license,
                # Enriched details for frontend cards/table/drawer.
                "bom_ref": str(comp.get("bom-ref", "")).strip(),
                "type": str(comp.get("type", "")).strip(),
                "description": str(comp.get("description", "")).strip(),
                "author": str(comp.get("author", "")).strip(),
                "supplier": supplier_name,
                "copyright": str(comp.get("copyright", "")).strip(),
                "licenses": licenses,
                "hashes": hash_items,
                "external_references": ref_items,
                "properties": prop_items,
                "has_hash": len(hash_items) > 0,
                "has_external_references": len(ref_items) > 0,
                "ecosystem": _purl_ecosystem(purl) if purl else "unknown",
            }
        )

    return details


def _classify_component(
    comp: Dict[str, Any],
    created_by_key: Dict[tuple, Dict[str, Any]],
    created_by_name: Dict[str, Dict[str, Any]],
    stdout_status: Dict[str, str],
) -> Dict[str, Any]:
    """Determine the SW360 action/linked state for a single mapped component."""
    name = comp["name"]
    version = comp["version"]
    map_code = comp["props"].get(CDX_PROP_MAPRESULT, "")
    found = is_good_match(map_code)

    created_comp = created_by_key.get((name, version)) or created_by_name.get(name)
    sw360_id = created_comp["props"].get(CDX_PROP_SW360ID) if created_comp else None
    if not sw360_id:
        sw360_id = comp["props"].get(CDX_PROP_SW360ID)

    if found:
        action = "found"
    elif sw360_id:
        action = "created"
    else:
        action = stdout_status.get(display_name(name, version), "pending")

    return {
        "name": name,
        "version": version,
        "mapResult": map_code,
        "found": found,
        "action": action,
        "sw360Id": sw360_id,
        "linked": bool(sw360_id) or action in ("found", "created"),
    }


def build_report(
    workdir: str,
    mapped_file: str,
    created_file: str,
    create_stdout: str = "",
    project_stdout: str = "",
) -> Dict[str, Any]:
    """Build a structured per-component onboarding report.

    Primary source is the structured SBOM data written by CaPyCli (reliable).
    The created SBOM tells us which components ended up with an SW360 id; the
    map result distinguishes "found" from "created". When the created SBOM is not
    available (failure path), we fall back to parsing the create step output so
    individual component failures are still surfaced to the UI.
    """
    mapped = load_sbom_components(os.path.join(workdir, mapped_file))
    created = load_sbom_components(os.path.join(workdir, created_file))

    created_by_key: Dict[tuple, Dict[str, Any]] = {}
    created_by_name: Dict[str, Dict[str, Any]] = {}
    for comp in created:
        created_by_key[(comp["name"], comp["version"])] = comp
        created_by_name.setdefault(comp["name"], comp)

    stdout_status = parse_create_stdout(create_stdout) if create_stdout else {}

    components: List[Dict[str, Any]] = []
    summary = {"total": 0, "found": 0, "created": 0, "failed": 0, "linked": 0}

    for comp in mapped:
        entry = _classify_component(comp, created_by_key, created_by_name, stdout_status)
        summary["total"] += 1
        if entry["action"] in summary:
            summary[entry["action"]] += 1
        if entry["linked"]:
            summary["linked"] += 1
        components.append(entry)

    if "Updating project" in project_stdout:
        project_action = "updated"
    elif "Creating project" in project_stdout:
        project_action = "created"
    else:
        project_action = "unknown"

    return {
        "components": components,
        "summary": summary,
        "project_action": project_action,
    }


def step_stdout(results: List[Dict[str, Any]], name: str) -> str:
    """Return the captured stdout for a named pipeline step (or empty string)."""
    for step in results:
        if step.get("step") == name:
            return step.get("stdout", "")
    return ""


def run_step(
    name: str,
    args: List[str],
    cwd: str,
    env: Dict[str, str],
    on_line: Optional[Any] = None,
    timeout_sec: Optional[int] = None,
) -> Dict[str, Any]:
    # Ensure local package imports work even when commands run from temp dirs.
    current_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{PROJECT_ROOT}{os.pathsep}{current_pythonpath}" if current_pythonpath else PROJECT_ROOT
    )

    cmd = [sys.executable, "-m", "capycli", *args]
    if on_line is None:
        try:
            completed = subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired as tex:
            return {
                "step": name,
                "command": " ".join(["capycli", *args]),
                "exit_code": 124,
                "stdout": tex.stdout or "",
                "stderr": (tex.stderr or "") + f"\nStep timed out after {timeout_sec} seconds.",
                "ok": False,
            }
        return {
            "step": name,
            "command": " ".join(["capycli", *args]),
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "ok": completed.returncode == 0,
        }

    # Streaming mode: surface each output line live (used to report per-component
    # progress). stderr is merged into stdout so the UI sees a single stream.
    captured: List[str] = []
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    assert proc.stdout is not None
    start = time.monotonic()
    while True:
        if timeout_sec and (time.monotonic() - start > timeout_sec):
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            return {
                "step": name,
                "command": " ".join(["capycli", *args]),
                "exit_code": 124,
                "stdout": "".join(captured),
                "stderr": f"Step timed out after {timeout_sec} seconds.",
                "ok": False,
            }

        # Avoid blocking forever on readline() when the child process is silent.
        ready, _, _ = select.select([proc.stdout], [], [], 0.5)
        line = proc.stdout.readline() if ready else ""
        if line:
            captured.append(line)
            on_line(line.rstrip("\n"))

        if line == "" and proc.poll() is not None:
            break

    return {
        "step": name,
        "command": " ".join(["capycli", *args]),
        "exit_code": proc.returncode,
        "stdout": "".join(captured),
        "stderr": "",
        "ok": proc.returncode == 0,
    }


# Lines printed by CaPyCli at two-space indent that are NOT per-component entries.
_PROGRESS_NOISE = (
    "read from SBOM", "No client", "cache", "Cachefile", "backups",
    "Loading cache", "Running forced", "cached releases",
    "Checking access to SW360", "Analyzing token", "Do mapping",
)


def component_progress_line(line: str) -> Optional[str]:
    """Return the component label if ``line`` is a per-component progress line.

    Both ``bom map`` and ``bom createcomponents`` print each processed component
    at exactly two spaces of indent (e.g. ``"  lodash, 4.17.21"``). Internal
    status messages share that indent, so known noise is filtered out.
    """
    match = re.match(r"^ {2}(\S.*)$", line)
    if not match:
        return None
    text = match.group(1)
    if any(noise in text for noise in _PROGRESS_NOISE):
        return None
    return text


def make_progress_tracker(job_id: str, plan: List[Dict[str, str]], index: int, total: int) -> Any:
    """Build an ``on_line`` callback that updates per-component sub-progress.

    Each detected component advances a counter and refreshes the job's
    ``progress.detail`` with ``processed`` / ``total`` / ``current``.
    """
    state = {"processed": 0}

    def on_line(line: str) -> None:
        name = component_progress_line(line)
        if name is None:
            return
        state["processed"] += 1
        progress = build_progress(plan, index, "running")
        progress["detail"] = {
            "processed": min(state["processed"], total) if total else state["processed"],
            "total": total,
            "current": name,
        }
        set_job(job_id, progress=progress)

    return on_line


def build_progress(plan: List[Dict[str, str]], active_index: int, phase: str) -> Dict[str, Any]:
    """Build a progress snapshot describing where the pipeline currently is.

    ``active_index`` is the index of the step currently being processed. Steps
    before it are ``done``; the active step takes ``phase`` (running/done/failed);
    steps after it are ``pending``. Use ``active_index == len(plan)`` to mark all
    steps as done.
    """
    steps: List[Dict[str, str]] = []
    for i, item in enumerate(plan):
        if i < active_index:
            state = "done"
        elif i == active_index:
            state = phase
        else:
            state = "pending"
        steps.append({"step": item["step"], "label": item["label"], "state": state})

    total = len(plan)
    done_count = sum(1 for s in steps if s["state"] == "done")
    in_range = 0 <= active_index < total
    return {
        "current_step": plan[active_index]["step"] if in_range else None,
        "current_label": plan[active_index]["label"] if in_range else "Finished",
        "step_index": min(active_index + 1, total),
        "total_steps": total,
        "percent": round(done_count / total * 100) if total else 0,
        "steps": steps,
    }


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> JSONResponse:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return JSONResponse(status_code=404, content={"error": "Job not found."})
    return JSONResponse(content=job)


@app.get("/api/sbom/download/{job_id}")
def download_sbom_components(request: Request, job_id: str) -> Response:
    """Download component-only SBOM JSON for a generated job.

    This endpoint is intended for UI download after phase-1 generation.
    """
    with JOBS_LOCK:
        job = JOBS.get(job_id)

    if not job:
        return JSONResponse(status_code=404, content={"error": "Job not found."})

    sbom_content = job.get("sbom")
    if not isinstance(sbom_content, dict) or not sbom_content:
        return JSONResponse(status_code=409, content={"error": "SBOM is not available. Generate SBOM first."})

    components = job.get("components")
    if not isinstance(components, list):
        components = build_sbom_component_details(sbom_content)

    project_name_raw = (
        request.query_params.get("project_name")
        or request.query_params.get("projectName")
        or str(job.get("project_name", ""))
        or str(job.get("projectName", ""))
    )
    project_version_raw = (
        request.query_params.get("project_version")
        or request.query_params.get("projectVersion")
        or str(job.get("project_version", ""))
        or str(job.get("projectVersion", ""))
    )

    file_project_name = safe_filename_part(project_name_raw, "project")
    file_project_version = safe_filename_part(project_version_raw, "version")
    download_filename = f"sbom_{file_project_name}_{file_project_version}.json"

    payload = {
        "jobId": job_id,
        "component_count": len(components),
        "components": components,
    }

    # Use pretty JSON for easier manual inspection/download readability.
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{download_filename}"'},
    )


@app.post("/api/sbom/check")
async def check_sbom_quality(
    request: Request,
    sbom_job_id: Annotated[Optional[str], Form()] = None,
    sbom_job_id_alias: Annotated[Optional[str], Form(alias="sbomJobId")] = None,
    sbom_file: Annotated[Optional[UploadFile], File(alias="file")] = None,
    sbom_file_alias: Annotated[Optional[UploadFile], File(alias="sbomFile")] = None,
) -> JSONResponse:
    """Validate a generated SBOM and return its quality summary.

    This is intended as the step between SBOM generation and SW360 sync.
    The endpoint accepts either:
    - the jobId returned by ``/api/sbom/generate``; or
    - an uploaded SBOM file from the UI.
    """
    resolved_sbom_job_id = sbom_job_id or sbom_job_id_alias
    resolved_sbom_file = sbom_file or sbom_file_alias

    if resolved_sbom_file is not None and not resolved_sbom_file.filename:
        resolved_sbom_file = None

    if not resolved_sbom_job_id and resolved_sbom_file is None:
        content_type = request.headers.get("content-type", "").lower()
        try:
            if "application/json" in content_type:
                body = await request.json()
                if isinstance(body, dict):
                    resolved_sbom_job_id = body.get("sbom_job_id") or body.get("sbomJobId")
            else:
                form_data = await request.form()
                resolved_sbom_job_id = form_data.get("sbom_job_id") or form_data.get("sbomJobId")
        except (json.JSONDecodeError, ValueError):
            resolved_sbom_job_id = None

    if not resolved_sbom_job_id and resolved_sbom_file is None:
        return JSONResponse(
            status_code=422,
            content={"detail": [{"msg": "Field required", "loc": ["body", "sbom_job_id"]}]},
        )

    sbom_content: Dict[str, Any] = {}
    response_job_id = str(resolved_sbom_job_id) if resolved_sbom_job_id else None

    if resolved_sbom_file is not None:
        try:
            uploaded_bytes = await resolved_sbom_file.read()
            if not uploaded_bytes:
                return JSONResponse(status_code=422, content={"error": "Uploaded SBOM file is empty."})

            with tempfile.TemporaryDirectory(prefix="capycli_sbom_check_") as workdir:
                sbom_path = os.path.join(workdir, resolved_sbom_file.filename or "sbom.json")
                with open(sbom_path, "wb") as handle:
                    handle.write(uploaded_bytes)

                quality_summary = {}
                validation_result = {"valid": False, "spec_version": "1.6"}

                from capycli.common.capycli_bom_support import CaPyCliBom

                validation_result["valid"] = bool(CaPyCliBom.validate_sbom(sbom_path, "1.6", False))
                validation_result["message"] = (
                    "JSON file successfully validated against CycloneDX." if validation_result["valid"]
                    else "SBOM validation failed."
                )

                try:
                    with open(sbom_path, "r", encoding="utf-8") as handle:
                        sbom_content = json.load(handle)
                except (json.JSONDecodeError, ValueError) as exc:
                    return JSONResponse(status_code=422, content={"error": f"Uploaded SBOM is not valid JSON: {str(exc)[:200]}"})

                if not isinstance(sbom_content, dict):
                    return JSONResponse(status_code=422, content={"error": "Uploaded SBOM must be a JSON object."})

                quality_summary = build_sbom_summary(sbom_content)
                return JSONResponse(content={
                    "jobId": response_job_id,
                    "source": "uploaded_file",
                    "validation": validation_result,
                    "quality": quality_summary.get("quality", {}),
                    "sbom_summary": quality_summary,
                })
        except Exception as exc:
            return JSONResponse(status_code=500, content={"error": f"SBOM upload validation failed: {str(exc)[:200]}"})

    with JOBS_LOCK:
        job = JOBS.get(str(resolved_sbom_job_id))

    if not job:
        return JSONResponse(status_code=404, content={"error": f"Job '{resolved_sbom_job_id}' not found."})

    sbom_content = job.get("sbom")
    if not isinstance(sbom_content, dict) or not sbom_content:
        return JSONResponse(status_code=409, content={"error": "SBOM is not available for validation. Generate it first."})

    quality_summary = build_sbom_summary(sbom_content)

    validation_result = {"valid": False, "spec_version": "1.6"}
    try:
        from capycli.common.capycli_bom_support import CaPyCliBom

        with tempfile.TemporaryDirectory(prefix="capycli_sbom_check_") as workdir:
            sbom_path = os.path.join(workdir, "sbom.json")
            with open(sbom_path, "w", encoding="utf-8") as handle:
                json.dump(sbom_content, handle, indent=2)

            validation_result["valid"] = bool(CaPyCliBom.validate_sbom(sbom_path, "1.6", False))
            validation_result["message"] = (
                "JSON file successfully validated against CycloneDX." if validation_result["valid"]
                else "SBOM validation failed."
            )
    except Exception as exc:
        validation_result["message"] = f"SBOM validation error: {str(exc)[:200]}"

    response = {
        "jobId": str(resolved_sbom_job_id),
        "source": "generated_job",
        "validation": validation_result,
        "quality": quality_summary.get("quality", {}),
        "sbom_summary": quality_summary,
    }
    return JSONResponse(content=response)


@app.post("/api/sw360/check")
async def check_sw360_connectivity(
    request: Request,
    sw360_url: Annotated[Optional[str], Form()] = None,
    sw360_token: Annotated[Optional[str], Form()] = None,
    sw360_oauth2: Annotated[bool, Form()] = False,
) -> JSONResponse:
    """Test SW360 connectivity and authentication before running sync.

    Returns details about:
    - URL reachability
    - Authentication status
    - Token type detection
    """
    # Accept both form data and JSON
    resolved_url = sw360_url
    resolved_token = sw360_token
    resolved_oauth2 = sw360_oauth2

    if not all((resolved_url, resolved_token)):
        content_type = request.headers.get("content-type", "").lower()
        try:
            if "application/json" in content_type:
                body = await request.json()
                resolved_url = resolved_url or body.get("sw360_url") or body.get("sw360Url")
                resolved_token = resolved_token or body.get("sw360_token") or body.get("sw360Token")
                oauth2_val = body.get("sw360_oauth2") or body.get("sw360Oauth2")
                if oauth2_val is not None:
                    resolved_oauth2 = str(oauth2_val).lower() in ("true", "1", "yes")
        except (json.JSONDecodeError, ValueError):
            pass

    if not resolved_url:
        return JSONResponse(status_code=422, content={
            "status": "error",
            "message": "sw360_url is required",
        })

    if not resolved_token:
        return JSONResponse(status_code=422, content={
            "status": "error",
            "message": "sw360_token is required",
        })

    # Clean URL
    resolved_url = str(resolved_url).strip().strip("[]").strip('"').strip("'")
    clean_url = normalize_sw360_url(resolved_url)

    result: Dict[str, Any] = {
        "sw360_url": clean_url,
        "url_reachable": False,
        "auth_valid": False,
        "write_access": None,
        "token_type_detected": "unknown",
        "oauth2_flag_sent": resolved_oauth2,
        "errors": [],
        "hints": [],
    }

    # Detect token type
    if "." in resolved_token and resolved_token.count(".") == 2:
        result["token_type_detected"] = "jwt_bearer"
        if not resolved_oauth2:
            result["hints"].append(
                "Token looks like JWT/Bearer format. Consider setting sw360_oauth2=true."
            )
    else:
        result["token_type_detected"] = "plain_api_token"
        if resolved_oauth2:
            result["hints"].append(
                "Token looks like plain API token. Consider setting sw360_oauth2=false."
            )

    # Test URL reachability
    api_url = f"{clean_url}/resource/api/"
    try:
        resp = requests.get(api_url, timeout=10, allow_redirects=True)
        result["url_reachable"] = True
        result["http_status"] = resp.status_code

        if resp.status_code == 401:
            result["errors"].append("SW360 returned 401 Unauthorized (expected without auth header)")
        elif resp.status_code == 403:
            result["errors"].append("SW360 returned 403 Forbidden")
        elif resp.status_code >= 500:
            result["errors"].append(f"SW360 server error: {resp.status_code}")

    except requests.exceptions.Timeout:
        result["errors"].append("Connection timed out after 10 seconds")
        result["hints"].append("Check if SW360 URL is correct and server is running")
    except requests.exceptions.ConnectionError as e:
        result["errors"].append(f"Connection failed: {str(e)[:100]}")
        result["hints"].append("Check network connectivity and URL spelling")
    except Exception as e:
        result["errors"].append(f"Unexpected error: {str(e)[:100]}")

    # Test authentication (if URL is reachable)
    if result["url_reachable"]:
        try:
            headers = {}
            if resolved_oauth2:
                headers["Authorization"] = f"Bearer {resolved_token}"
            else:
                headers["Authorization"] = f"Token {resolved_token}"

            # Try to get user info or projects list as auth test
            test_url = f"{clean_url}/resource/api/projects"
            resp = requests.get(test_url, headers=headers, timeout=15)

            if resp.status_code == 200:
                result["auth_valid"] = True
                result["message"] = "SW360 connection and authentication successful!"

                write_probe = probe_sw360_write_access(clean_url, headers)
                result["write_access"] = write_probe.get("write_access")
                result["write_probe"] = {
                    "http_status": write_probe.get("http_status"),
                    "message": write_probe.get("message", ""),
                }
                if write_probe.get("write_access") is False:
                    result["errors"].append(
                        "Token appears read-only: missing write permission to create components/projects."
                    )
                    result["hints"].append(
                        "Use a SW360 write token (not read-only) for onboarding sync."
                    )
            elif resp.status_code == 401:
                result["errors"].append("Authentication failed: Invalid token")
                if result["token_type_detected"] == "jwt_bearer" and not resolved_oauth2:
                    result["hints"].append("Try setting sw360_oauth2=true for JWT tokens")
                elif result["token_type_detected"] == "plain_api_token" and resolved_oauth2:
                    result["hints"].append("Try setting sw360_oauth2=false for plain API tokens")
            elif resp.status_code == 403:
                result["errors"].append("Token valid but lacks required permissions")
            else:
                result["errors"].append(f"Auth test returned HTTP {resp.status_code}")

        except requests.exceptions.Timeout:
            result["errors"].append("Auth request timed out")
        except Exception as e:
            result["errors"].append(f"Auth test error: {str(e)[:100]}")

    # Final status
    if result["auth_valid"]:
        if result.get("write_access") is False:
            result["status"] = "read_only"
            result["message"] = "SW360 auth succeeded, but token appears read-only."
        else:
            result["status"] = "ok"
    elif result["url_reachable"]:
        result["status"] = "auth_failed"
    else:
        result["status"] = "unreachable"

    # Clear informational errors when auth succeeds and write permission looks usable.
    if result["auth_valid"] and result.get("write_access") is not False:
        result["errors"] = []

    return JSONResponse(content=result)


# =============================================================================
# TWO-PHASE WORKFLOW: SBOM Generation + SW360 Sync (Separated)
# =============================================================================

SBOM_GENERATE_PIPELINE: List[Dict[str, str]] = [
    {"step": "getdependencies", "label": "Detecting dependencies from your file"},
]

SW360_SYNC_PIPELINE: List[Dict[str, str]] = [
    {"step": "map", "label": "Searching components in SW360"},
    {"step": "createcomponents", "label": "Creating missing components in SW360"},
    {"step": "project_create", "label": "Creating or updating the project in SW360"},
    {"step": "project_show", "label": "Reading the final project status"},
]


def process_sbom_generate_job(
    job_id: str,
    ecosystem: str,
    file_name: str,
    file_bytes: bytes,
) -> None:
    """Phase 1: Generate SBOM only (fast, no SW360 interaction)."""
    results: List[Dict[str, Any]] = []
    plan = SBOM_GENERATE_PIPELINE
    env = dict(os.environ)

    def mark(index: int, phase: str) -> None:
        set_job(job_id, progress=build_progress(plan, index, phase))

    set_job(job_id, state="running", started_at=utc_now_iso())
    mark(0, "running")

    try:
        with tempfile.TemporaryDirectory(prefix="capycli_sbom_") as workdir:
            input_path = os.path.join(workdir, file_name)
            with open(input_path, "wb") as fout:
                fout.write(file_bytes)

            sbom = "sbom.json"
            sbom_path = os.path.join(workdir, sbom)

            results.append(run_step(
                "getdependencies",
                ["getdependencies", ECOSYSTEM_COMMANDS[ecosystem], "-i", file_name, "-o", sbom],
                workdir, env
            ))

            if not results[-1]["ok"]:
                mark(0, "failed")
                set_job(
                    job_id,
                    state="failed",
                    success=False,
                    failed_step="getdependencies",
                    steps=results,
                    finished_at=utc_now_iso(),
                )
                return

            # Load and return the SBOM components for display
            components = load_sbom_components(sbom_path)

            # Read full SBOM JSON for storage
            sbom_content: Dict[str, Any] = {}
            if os.path.isfile(sbom_path):
                with open(sbom_path) as f:
                    sbom_content = json.load(f)

            mark(0, "done")
            set_job(
                job_id,
                state="completed",
                success=True,
                phase="sbom_ready",
                message="SBOM generated successfully. Review components and proceed to SW360 sync.",
                sbom=sbom_content,
                sbom_summary=build_sbom_summary(sbom_content),
                components=build_sbom_component_details(sbom_content),
                component_count=len(components),
                progress=build_progress(plan, len(plan), "done"),
                steps=results,
                finished_at=utc_now_iso(),
            )

    except Exception as exc:
        set_job(
            job_id,
            state="failed",
            success=False,
            error=str(exc),
            steps=results,
            finished_at=utc_now_iso(),
        )


def process_sw360_sync_job(
    job_id: str,
    project_name: str,
    project_version: str,
    sbom_content: Dict[str, Any],
    env: Dict[str, str],
    auth_args: List[str],
) -> None:
    """Phase 2: Map and sync SBOM to SW360."""
    results: List[Dict[str, Any]] = []
    plan = SW360_SYNC_PIPELINE
    map_timeout_sec = int(os.environ.get("CAPYCLI_MAP_TIMEOUT_SEC", "600"))
    map_cachefile = get_map_cachefile()

    def mark(index: int, phase: str) -> None:
        set_job(job_id, progress=build_progress(plan, index, phase))

    set_job(job_id, state="running", started_at=utc_now_iso())
    mark(0, "running")

    try:
        with tempfile.TemporaryDirectory(prefix="capycli_sync_") as workdir:
            sbom = "sbom.json"
            sbom_mapped = "sbom.mapped.json"
            sbom_created = "sbom.created.json"
            project_info_file = "projectinfo.json"
            status_file = "status.json"

            # Write the SBOM from Phase 1
            sbom_path = os.path.join(workdir, sbom)
            with open(sbom_path, "w") as f:
                json.dump(sbom_content, f, indent=2)

            with open(os.path.join(workdir, project_info_file), "w") as fout:
                json.dump({
                    "description": "Created by CaPyCLI onboarding API",
                }, fout)

            # Step 1: Map to SW360
            map_total = len(sbom_content.get("components", []))
            use_nocache = map_uses_nocache(map_total)
            map_args = ["bom", "map", "-i", sbom, "-o", sbom_mapped]
            if use_nocache:
                map_args.append("--nocache")
            else:
                map_args.extend(["-cf", map_cachefile])
            map_args.extend(auth_args)

            set_job(
                job_id,
                map_strategy={
                    "mode": "nocache" if use_nocache else "cachefile",
                    "component_count": map_total,
                    "cachefile": None if use_nocache else map_cachefile,
                    "nocache_threshold": int(os.environ.get("CAPYCLI_MAP_NOCACHE_THRESHOLD", "10")),
                },
            )

            results.append(run_step(
                "map",
                map_args,
                workdir, env,
                on_line=make_progress_tracker(job_id, plan, 0, map_total),
                timeout_sec=map_timeout_sec,
            ))

            map_step = results[-1]
            mapped_path = os.path.join(workdir, sbom_mapped)
            map_partial = is_partial_map_result(map_step, mapped_path)

            if map_partial:
                map_step["partial_ok"] = True
                map_step["ok"] = True
                set_job(
                    job_id,
                    map_warning=(
                        "Mapping is incomplete for some components. Proceeding with partial "
                        "mapping; unmatched components may be created in SW360 or need manual review."
                    ),
                )

            if not results[-1]["ok"]:
                mark(0, "failed")
                combined_output = results[-1].get("stdout", "") + "\n" + results[-1].get("stderr", "")
                hint = map_failure_hint(combined_output)
                payload: Dict[str, Any] = {
                    "state": "failed",
                    "success": False,
                    "failed_step": "map",
                    "steps": results,
                    "finished_at": utc_now_iso(),
                }
                if hint:
                    payload["hint"] = hint
                set_job(job_id, **payload)
                return

            # Step 2: Create missing components
            mark(1, "running")
            create_total = len(load_sbom_components(os.path.join(workdir, sbom_mapped)))
            results.append(run_step(
                "createcomponents",
                ["bom", "createcomponents", "-i", sbom_mapped, "-o", sbom_created, *auth_args],
                workdir, env,
                on_line=make_progress_tracker(job_id, plan, 1, create_total),
            ))

            if not results[-1]["ok"]:
                mark(1, "failed")
                report = build_report(workdir, sbom_mapped, sbom_created, create_stdout=results[-1].get("stdout", ""))
                set_job(
                    job_id,
                    state="failed",
                    success=False,
                    failed_step="createcomponents",
                    report=report,
                    steps=results,
                    finished_at=utc_now_iso(),
                )
                return

            # Step 3: Create/update project
            mark(2, "running")
            results.append(run_step(
                "project_create",
                [
                    "project", "create",
                    "-name", project_name,
                    "-version", project_version,
                    "-i", sbom_created,
                    "-source", project_info_file,
                    *auth_args,
                ],
                workdir, env
            ))

            if not results[-1]["ok"]:
                mark(2, "failed")
                report = build_report(
                    workdir,
                    sbom_mapped,
                    sbom_created,
                    create_stdout=step_stdout(results, "createcomponents"),
                    project_stdout=results[-1].get("stdout", ""),
                )
                set_job(
                    job_id,
                    state="failed",
                    success=False,
                    failed_step="project_create",
                    report=report,
                    steps=results,
                    finished_at=utc_now_iso(),
                )
                return

            # Step 4: Show project status
            mark(3, "running")
            results.append(run_step(
                "project_show",
                ["project", "show", "-name", project_name, "-version", project_version, "-o", status_file, *auth_args],
                workdir, env
            ))

            # Build final report
            report = build_report(
                workdir,
                sbom_mapped,
                sbom_created,
                create_stdout=step_stdout(results, "createcomponents"),
                project_stdout=step_stdout(results, "project_create"),
            )

            # Load project status
            status: Dict[str, Any] = {}
            status_path = os.path.join(workdir, status_file)
            if os.path.isfile(status_path):
                try:
                    with open(status_path) as f:
                        status = json.load(f)
                except (OSError, json.JSONDecodeError):
                    pass

            mark(3, "done")
            set_job(
                job_id,
                state="completed",
                success=True,
                phase="sw360_synced",
                message="Project successfully synced to SW360.",
                report=report,
                status=status,
                progress=build_progress(plan, len(plan), "done"),
                steps=results,
                finished_at=utc_now_iso(),
            )

    except Exception as exc:
        set_job(
            job_id,
            state="failed",
            success=False,
            error=str(exc),
            steps=results,
            finished_at=utc_now_iso(),
        )


@app.post("/api/sbom/generate")
async def generate_sbom(
    request: Request,
    background_tasks: BackgroundTasks,
    file: Annotated[UploadFile, File()],
    ecosystem: Optional[str] = None,
) -> JSONResponse:
    """Phase 1: Generate SBOM from dependency file (fast, no SW360 auth needed).

    After completion, poll /api/jobs/{jobId} to get the SBOM content.
    Then call /api/sbom/sync to sync to SW360.
    """
    resolved_ecosystem = (ecosystem or "").strip()
    if not resolved_ecosystem:
        try:
            # Older FastAPI versions may bind Form fields as query params.
            # Read multipart body directly as a compatibility fallback.
            form_data = await request.form()
            if form_data:
                value = form_data.get("ecosystem")
                if value is not None:
                    resolved_ecosystem = str(value).strip()
        except Exception:
            resolved_ecosystem = resolved_ecosystem or ""

    if not resolved_ecosystem:
        return JSONResponse(
            status_code=422,
            content={"detail": [{"msg": "Field required", "loc": ["body", "ecosystem"]}]},
        )

    ecosystem = resolved_ecosystem.lower().strip()
    if ecosystem not in ECOSYSTEM_COMMANDS:
        return JSONResponse(
            status_code=400,
            content={"error": f"Unsupported ecosystem '{ecosystem}'. Supported: {sorted(ECOSYSTEM_COMMANDS)}"},
        )

    file_name = file.filename or "input"
    file_bytes = file.file.read()
    job_id = str(uuid4())

    set_job(
        job_id,
        jobId=job_id,
        state="queued",
        success=None,
        phase="sbom_generating",
        created_at=utc_now_iso(),
        ecosystem=ecosystem,
    )

    background_tasks.add_task(
        process_sbom_generate_job,
        job_id,
        ecosystem,
        file_name,
        file_bytes,
    )

    return JSONResponse(status_code=202, content={"jobId": job_id, "state": "queued", "phase": "sbom_generating"})


@app.post("/api/sbom/sync")
async def sync_sbom_to_sw360(
    request: Request,
    background_tasks: BackgroundTasks,
    sbom_job_id: Annotated[Optional[str], Form()] = None,
    sbom_job_id_alias: Annotated[Optional[str], Form(alias="sbomJobId")] = None,
    project_name: Annotated[Optional[str], Form()] = None,
    project_name_alias: Annotated[Optional[str], Form(alias="projectName")] = None,
    project_version: Annotated[Optional[str], Form()] = None,
    project_version_alias: Annotated[Optional[str], Form(alias="projectVersion")] = None,
    sw360_url: Annotated[Optional[str], Form()] = None,
    sw360_url_alias: Annotated[Optional[str], Form(alias="sw360Url")] = None,
    sw360_token: Annotated[Optional[str], Form()] = None,
    sw360_token_alias: Annotated[Optional[str], Form(alias="sw360Token")] = None,
    sw360_oauth2: Annotated[bool, Form()] = False,
    sw360_oauth2_alias: Annotated[Optional[bool], Form(alias="sw360Oauth2")] = None,
) -> JSONResponse:
    """Phase 2: Sync an existing SBOM (from Phase 1) to SW360.

    Requires the jobId from the /api/sbom/generate response.
    """
    # Accept both snake_case and camelCase field names from frontend payloads.
    resolved_sbom_job_id = sbom_job_id or sbom_job_id_alias
    resolved_project_name = project_name or project_name_alias
    resolved_project_version = project_version or project_version_alias
    resolved_sw360_url = sw360_url or sw360_url_alias
    resolved_sw360_token = sw360_token or sw360_token_alias
    resolved_sw360_oauth2 = sw360_oauth2_alias if sw360_oauth2_alias is not None else sw360_oauth2

    # Fallback for clients/proxies that post JSON or remap body fields in a non-standard way.
    if not all((resolved_sbom_job_id, resolved_project_name, resolved_project_version, resolved_sw360_url, resolved_sw360_token)):
        body_data: Dict[str, Any] = {}
        content_type = request.headers.get("content-type", "").lower()
        try:
            if "application/json" in content_type:
                parsed = await request.json()
                if isinstance(parsed, dict):
                    body_data = parsed
            else:
                form_data = await request.form()
                body_data = {key: value for key, value in form_data.items()}
        except (json.JSONDecodeError, ValueError):
            body_data = {}

        resolved_sbom_job_id = resolved_sbom_job_id or body_data.get("sbom_job_id") or body_data.get("sbomJobId")
        resolved_project_name = resolved_project_name or body_data.get("project_name") or body_data.get("projectName")
        resolved_project_version = resolved_project_version or body_data.get("project_version") or body_data.get("projectVersion")
        resolved_sw360_url = resolved_sw360_url or body_data.get("sw360_url") or body_data.get("sw360Url")
        resolved_sw360_token = resolved_sw360_token or body_data.get("sw360_token") or body_data.get("sw360Token")
        if sw360_oauth2_alias is None and "sw360_oauth2" in body_data:
            resolved_sw360_oauth2 = str(body_data.get("sw360_oauth2")).lower() in ("true", "1", "yes", "on")
        if sw360_oauth2_alias is None and "sw360Oauth2" in body_data:
            resolved_sw360_oauth2 = str(body_data.get("sw360Oauth2")).lower() in ("true", "1", "yes", "on")

    if resolved_sw360_url:
        # Handle accidentally bracketed/quoted URLs, e.g. "[https://sw360.example.com]".
        resolved_sw360_url = str(resolved_sw360_url).strip().strip("[]").strip().strip('"').strip("'")

    if not resolved_sbom_job_id:
        return JSONResponse(status_code=422, content={"detail": [{"msg": "Field required", "loc": ["body", "sbom_job_id"]}]})
    if not resolved_project_name:
        return JSONResponse(status_code=422, content={"detail": [{"msg": "Field required", "loc": ["body", "project_name"]}]})
    if not resolved_project_version:
        return JSONResponse(status_code=422, content={"detail": [{"msg": "Field required", "loc": ["body", "project_version"]}]})
    if not resolved_sw360_url:
        return JSONResponse(status_code=422, content={"detail": [{"msg": "Field required", "loc": ["body", "sw360_url"]}]})
    if not resolved_sw360_token:
        return JSONResponse(status_code=422, content={"detail": [{"msg": "Field required", "loc": ["body", "sw360_token"]}]})

    # Get the SBOM from Phase 1
    with JOBS_LOCK:
        sbom_job = JOBS.get(resolved_sbom_job_id)

    if not sbom_job:
        return JSONResponse(
            status_code=404,
            content={"error": f"SBOM job '{resolved_sbom_job_id}' not found."},
        )

    if sbom_job.get("phase") != "sbom_ready":
        return JSONResponse(
            status_code=400,
            content={"error": f"SBOM job is not ready. Current phase: {sbom_job.get('phase', 'unknown')}"},
        )

    sbom_content = sbom_job.get("sbom")
    if not sbom_content:
        return JSONResponse(
            status_code=400,
            content={"error": "SBOM content not found in job."},
        )

    # Prepare environment
    env = dict(os.environ)
    env["SW360ServerUrl"] = normalize_sw360_url(resolved_sw360_url)
    env["SW360ProductionToken"] = resolved_sw360_token

    auth_args: List[str] = []
    if resolved_sw360_oauth2:
        auth_args.append("-oa")
    auth_args.extend(["-url", env["SW360ServerUrl"], "-t", env["SW360ProductionToken"]])

    # Create new job for SW360 sync
    job_id = str(uuid4())

    set_job(
        job_id,
        jobId=job_id,
        state="queued",
        success=None,
        phase="sw360_syncing",
        created_at=utc_now_iso(),
        project={"name": resolved_project_name, "version": resolved_project_version},
        sbom_job_id=resolved_sbom_job_id,
        component_count=len(sbom_content.get("components", [])),
    )

    background_tasks.add_task(
        process_sw360_sync_job,
        job_id,
        resolved_project_name,
        resolved_project_version,
        sbom_content,
        env,
        auth_args,
    )

    return JSONResponse(status_code=202, content={"jobId": job_id, "state": "queued", "phase": "sw360_syncing"})
