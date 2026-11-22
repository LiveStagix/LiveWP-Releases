#!/usr/bin/env python3
"""Scan a published LiveStagix release APK and publish verified scan metadata."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

RELEASES_API = "https://api.github.com/repos/LiveStagix/LiveWP-Releases"
VT_API = "https://www.virustotal.com/api/v3"
ABI_APK_NAMES = {
    "arm64-v8a": ("LiveStagix_arm64-v8a.apk", "LiveStagix_beta_arm64-v8a.apk"),
    "armeabi-v7a": ("LiveStagix_armeabi-v7a.apk", "LiveStagix_beta_armeabi-v7a.apk"),
    "x86": ("LiveStagix_x86.apk", "LiveStagix_beta_x86.apk"),
    "x86_64": ("LiveStagix_x86_64.apk", "LiveStagix_beta_x86_64.apk"),
}
UNIVERSAL_APK_NAMES = ("LiveStagix.apk", "LiveStagix_beta.apk")
PACKAGE_KEYS = ("universal", "arm64-v8a", "armeabi-v7a", "x86", "x86_64")
DEFAULT_APK_NAME = UNIVERSAL_APK_NAMES[0]
STATUS_PATH = pathlib.Path("security/scan-status.json")
MAX_POLL_ATTEMPTS = 18
POLL_INTERVAL_SECONDS = 20

# Retry only transient failures while downloading the published APK from GitHub.
APK_DOWNLOAD_RETRY_DELAYS = (5, 15, 30)
RETRYABLE_HTTP_STATUS_CODES = frozenset((408, 500, 502, 503, 504))

# Trusted release-signing identity established from the independently verified
# Build 74 APK. Keep this value fixed unless a signing-key rotation is deliberate
# and independently reviewed.
TRUSTED_SIGNER_SHA256 = "4919b3249285918c4c4c894e8b46b1713ae103201fd536d337021d5c7f205e78"



class HttpRequestError(RuntimeError):
    """HTTP error that retains the response status for controlled retry logic."""

    def __init__(self, status_code, message):
        super().__init__(message)
        self.status_code = status_code


class AnalysisPendingError(RuntimeError):
    """VirusTotal has not finished processing an accepted analysis."""


class ReportNotReadyError(RuntimeError):
    """VirusTotal has not published completed file-analysis statistics yet."""


def request_bytes(url, method="GET", data=None, headers=None, retry_delays=()):
    request_headers = {"User-Agent": "LiveStagix-Security-Scan/1.0"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)

    # Retries are opt-in so VirusTotal API requests and uploads keep their existing
    # behaviour. Only the release APK download supplies retry delays.
    for attempt in range(len(retry_delays) + 1):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            if exc.code == 429:
                retry_after = exc.headers.get("Retry-After", "not supplied")
                raise RuntimeError(f"VirusTotal rate limit reached; Retry-After: {retry_after}") from exc

            error = HttpRequestError(
                exc.code, f"HTTP {exc.code} for {url}: {detail[:500]}"
            )
            if exc.code not in RETRYABLE_HTTP_STATUS_CODES or attempt >= len(retry_delays):
                raise error from exc
            retry_reason = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            error = RuntimeError(f"Network request failed for {url}: {getattr(exc, 'reason', exc)}")
            if attempt >= len(retry_delays):
                raise error from exc
            retry_reason = str(getattr(exc, "reason", exc))

        delay = retry_delays[attempt]
        print(
            f"Download request failed ({retry_reason}); retrying in {delay}s "
            f"(retry {attempt + 1}/{len(retry_delays)})."
        )
        time.sleep(delay)

    raise RuntimeError(f"Request failed after retries: {url}")


def request_json(url, method="GET", data=None, headers=None):
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    raw = request_bytes(url, method=method, data=data, headers=request_headers)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Invalid JSON response from {url}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"Unexpected response from {url}")
    return value


def load_release():
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")

    if event_name == "release" and event_path:
        try:
            event = json.loads(pathlib.Path(event_path).read_text(encoding="utf-8"))
            tag = event.get("release", {}).get("tag_name")
        except (OSError, json.JSONDecodeError, AttributeError) as exc:
            raise RuntimeError(f"Cannot read published release event: {exc}") from exc

        if isinstance(tag, str) and tag:
            encoded_tag = urllib.parse.quote(tag, safe="")
            return request_json(RELEASES_API + "/releases/tags/" + encoded_tag)

    # Manual runs and workflow-file changes fall back to the latest published release.
    return request_json(RELEASES_API + "/releases/latest")


def select_apk(release, package_key):
    if package_key not in PACKAGE_KEYS:
        raise RuntimeError("Unsupported APK package key: " + str(package_key))

    assets = release.get("assets")
    if not isinstance(assets, list):
        raise RuntimeError("The published release has no assets list.")

    names = UNIVERSAL_APK_NAMES if package_key == "universal" else ABI_APK_NAMES[package_key]
    apk = next(
        (
            asset
            for asset in assets
            if isinstance(asset, dict) and asset.get("name") in names
        ),
        None,
    )
    if not apk:
        return None, None

    digest = apk.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise RuntimeError("GitHub did not provide SHA-256 metadata for " + apk.get("name", package_key) + ".")

    sha256 = digest[len("sha256:"):].lower()
    if len(sha256) != 64 or any(char not in "0123456789abcdef" for char in sha256):
        raise RuntimeError("GitHub returned a malformed SHA-256 digest for " + apk.get("name", package_key) + ".")

    download_url = apk.get("browser_download_url")
    if not isinstance(download_url, str):
        raise RuntimeError("The APK has no download URL: " + apk.get("name", package_key))

    return apk, sha256


def release_status_fields(release, package_key, apk=None, sha256=None):
    return {
        "releaseTag": release.get("tag_name") or "",
        "releaseName": release.get("name") or release.get("tag_name") or "LiveStagix release",
        "releaseUrl": release.get("html_url") or "https://github.com/LiveStagix/LiveWP-Releases/releases/latest",
        "publishedAt": release.get("published_at"),
        "packageKey": package_key,
        "fileName": apk.get("name") if isinstance(apk, dict) else None,
        "fileSize": apk.get("size") if isinstance(apk, dict) else None,
        "sha256": sha256,
    }


def download_verified(apk, expected_sha256):
    content = request_bytes(
        apk["browser_download_url"],
        retry_delays=APK_DOWNLOAD_RETRY_DELAYS,
    )
    actual_sha256 = hashlib.sha256(content).hexdigest()

    if actual_sha256 != expected_sha256:
        raise RuntimeError("Downloaded APK hash does not match GitHub metadata; refusing to submit it.")

    expected_size = apk.get("size")
    if isinstance(expected_size, int) and expected_size != len(content):
        raise RuntimeError("Downloaded APK size does not match GitHub metadata.")

    if not content:
        raise RuntimeError("Downloaded APK is empty.")

    return content


def locate_apksigner():
    configured = os.environ.get("APKSIGNER", "").strip()
    candidates = [configured] if configured else []

    found = shutil.which("apksigner")
    if found:
        candidates.append(found)

    sdk_roots = [
        os.environ.get("ANDROID_HOME", ""),
        os.environ.get("ANDROID_SDK_ROOT", ""),
    ]
    for root in sdk_roots:
        if root:
            candidates.append(str(pathlib.Path(root) / "build-tools" / "35.0.0" / "apksigner"))

    for candidate in candidates:
        path = pathlib.Path(candidate)
        if path.is_file():
            return str(path)

    raise RuntimeError(
        "Android SDK Build Tools apksigner was not found. "
        "The workflow must install build-tools;35.0.0 before running the scanner."
    )


def verify_apk_signature(content, filename):
    apksigner = locate_apksigner()
    with tempfile.TemporaryDirectory(prefix="livestagix-signature-") as temp_dir:
        apk_path = pathlib.Path(temp_dir) / filename
        apk_path.write_bytes(content)
        try:
            completed = subprocess.run(
                [apksigner, "verify", "--print-certs", str(apk_path)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"Could not execute apksigner: {exc}") from exc

    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
    fingerprints = re.findall(
        r"Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F:]+)",
        output,
        flags=re.IGNORECASE,
    )
    observed = [
        re.sub(r"[^0-9a-f]", "", value.lower())
        for value in fingerprints
    ]
    verified_at = dt.datetime.now(dt.timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")

    if completed.returncode != 0:
        return {
            "status": "invalid",
            "trustedCertificateSha256": TRUSTED_SIGNER_SHA256,
            "observedCertificateSha256": observed,
            "verifiedAt": verified_at,
            "tool": "Android SDK Build Tools apksigner",
        }

    if not observed:
        return {
            "status": "error",
            "trustedCertificateSha256": TRUSTED_SIGNER_SHA256,
            "observedCertificateSha256": [],
            "verifiedAt": verified_at,
            "tool": "Android SDK Build Tools apksigner",
        }

    # This project currently expects one release signer. An unexpected signer
    # count or fingerprint is surfaced as a mismatch, never silently accepted.
    status = "verified" if observed == [TRUSTED_SIGNER_SHA256] else "mismatch"
    return {
        "status": status,
        "trustedCertificateSha256": TRUSTED_SIGNER_SHA256,
        "observedCertificateSha256": observed,
        "verifiedAt": verified_at,
        "tool": "Android SDK Build Tools apksigner",
    }


def multipart_file(filename, content):
    boundary = "----LiveStagixVirusTotal" + uuid.uuid4().hex
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/vnd.android.package-archive\r\n\r\n"
    ).encode("utf-8")
    body = head + content + f"\r\n--{boundary}--\r\n".encode("ascii")
    return body, boundary


def submit_file(api_key, content, filename):
    endpoint = VT_API + "/files"

    if len(content) > 32 * 1024 * 1024:
        response = request_json(VT_API + "/files/upload_url", headers={"x-apikey": api_key})
        endpoint = response.get("data")
        if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
            raise RuntimeError("VirusTotal did not return a valid large-file upload URL.")
        time.sleep(POLL_INTERVAL_SECONDS)

    body, boundary = multipart_file(filename, content)
    response = request_json(
        endpoint,
        method="POST",
        data=body,
        headers={
            "x-apikey": api_key,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )

    analysis_id = response.get("data", {}).get("id")
    if not isinstance(analysis_id, str) or not analysis_id:
        raise RuntimeError("VirusTotal did not return an analysis ID.")
    return analysis_id


def wait_for_analysis(api_key, analysis_id):
    url = VT_API + "/analyses/" + urllib.parse.quote(analysis_id, safe="")
    saw_not_found = False

    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        time.sleep(POLL_INTERVAL_SECONDS)
        try:
            response = request_json(url, headers={"x-apikey": api_key})
        except HttpRequestError as exc:
            if exc.status_code == 404:
                saw_not_found = True
                print(
                    "VirusTotal has not made this analysis ID available yet "
                    f"(HTTP 404; attempt {attempt}/{MAX_POLL_ATTEMPTS}). Retrying."
                )
                continue
            raise

        status = response.get("data", {}).get("attributes", {}).get("status")
        print(f"VirusTotal analysis status: {status or 'unknown'} ({attempt}/{MAX_POLL_ATTEMPTS})")

        if status == "completed":
            return
        if status not in ("queued", "in-progress", "in_progress", None):
            raise RuntimeError(f"Unexpected VirusTotal analysis status: {status}")

    if saw_not_found:
        raise AnalysisPendingError(
            "VirusTotal accepted the APK upload but did not make the returned analysis "
            "ID available within the polling window."
        )
    raise AnalysisPendingError("VirusTotal analysis did not finish within the polling window.")


def read_existing_status():
    try:
        value = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read existing scan status: {exc}") from exc
    return value if isinstance(value, dict) else {}


def packages_from_status(status, release_tag):
    if not isinstance(status, dict):
        return {}
    if (
        status.get("schemaVersion") == 2
        and status.get("releaseTag") == release_tag
        and isinstance(status.get("packages"), dict)
    ):
        return dict(status["packages"])

    # Preserve the old single-universal record during the schema migration.
    if (
        status.get("releaseTag") == release_tag
        and status.get("sha256")
        and status.get("fileName") in UNIVERSAL_APK_NAMES
    ):
        return {"universal": dict(status)}
    return {}


def publish_status_update(package_key):
    """Publish the current per-package status immediately when running in Actions."""
    if os.environ.get("PUBLISH_SCAN_STATUS") != "true":
        return True

    try:
        subprocess.run(
            ["git", "add", str(STATUS_PATH)],
            check=True,
            capture_output=True,
            text=True,
        )
        staged = subprocess.run(
            ["git", "diff", "--cached", "--quiet"],
            check=False,
            capture_output=True,
            text=True,
        )
        if staged.returncode == 1:
            subprocess.run(
                ["git", "commit", "-m", f"Publish {package_key} security status"],
                check=True,
                capture_output=True,
                text=True,
            )
        elif staged.returncode != 0:
            raise RuntimeError(staged.stderr.strip() or "Could not inspect staged scan status.")

        pushed = subprocess.run(
            ["git", "push", "origin", "HEAD:Stable"],
            check=False,
            capture_output=True,
            text=True,
        )
        if pushed.returncode != 0:
            detail = pushed.stderr.strip() or pushed.stdout.strip() or "Git push failed."
            print(
                f"::warning::{package_key}: immediate status publication failed; "
                f"the workflow will retry during final publication. {detail}"
            )
            return False

        print(f"{package_key}: security status published to Stable immediately.")
        return True
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(
            f"::warning::{package_key}: immediate status publication failed; "
            f"the workflow will retry during final publication. {exc}"
        )
        return False


def persist_package_record(release, package_key, record):
    current = read_existing_status()
    packages = packages_from_status(current, release.get("tag_name") or "")
    packages[package_key] = record
    result = {
        "schemaVersion": 2,
        "releaseTag": release.get("tag_name") or "",
        "releaseName": release.get("name") or release.get("tag_name") or "LiveStagix release",
        "releaseUrl": release.get("html_url") or "https://github.com/LiveStagix/LiveWP-Releases/releases/latest",
        "publishedAt": release.get("published_at"),
        "updatedAt": dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0
        ).isoformat().replace("+00:00", "Z"),
        "packages": packages,
    }
    write_status_file(result)
    publish_status_update(package_key)
    return result


def save_report(api_key, release, package_key, apk, sha256, signature):
    report = request_json(VT_API + "/files/" + sha256, headers={"x-apikey": api_key})
    file_data = report.get("data", {})

    returned_hash = file_data.get("id")
    if returned_hash and returned_hash.lower() != sha256:
        raise RuntimeError("VirusTotal returned a report for a different SHA-256 hash.")

    attributes = file_data.get("attributes", {})
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict) or not stats:
        raise ReportNotReadyError("VirusTotal report has no completed engine statistics.")

    clean_stats = {
        str(key): int(value)
        for key, value in stats.items()
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
    }
    if not clean_stats:
        raise ReportNotReadyError("VirusTotal returned no usable engine statistics.")

    timestamp = attributes.get("last_analysis_date")
    if not isinstance(timestamp, (int, float)):
        raise ReportNotReadyError("VirusTotal report has no valid analysis timestamp.")

    analysis_date = dt.datetime.fromtimestamp(
        timestamp, tz=dt.timezone.utc
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    result = {
        **release_status_fields(release, package_key, apk, sha256),
        "status": "available",
        "signature": signature,
        "reportUrl": "https://www.virustotal.com/gui/file/" + sha256,
        "analysisDate": analysis_date,
        "publishedToRepositoryAt": dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0
        ).isoformat().replace("+00:00", "Z"),
        "stats": clean_stats,
    }
    persist_package_record(release, package_key, result)
    return result


def write_step_summary(package_key, result):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    stats = result.get("stats", {})
    with open(summary_path, "a", encoding="utf-8") as summary:
        summary.write(
            "## LiveStagix package verification\n\n"
            f"- Package: `{package_key}`\n"
            f"- Release: {result.get('releaseTag', 'unknown')}\n"
            f"- APK: {result.get('fileName') or 'not available'}\n"
            f"- Scan status: **{result.get('status', 'unknown')}**\n"
            f"- Malicious detections: **{stats.get('malicious', 'not available')}**\n"
            f"- Suspicious detections: **{stats.get('suspicious', 'not available')}**\n"
            f"- Signing verification: **{result.get('signature', {}).get('status', 'not available')}**\n"
            f"- Report: {result.get('reportUrl', 'not published')}\n\n"
            "A scan is a point-in-time signal, not a guarantee that software is completely safe.\n\n"
        )


def write_status_file(result):
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATUS_PATH.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def publish_report_if_ready(api_key, release, package_key, apk, sha256, signature):
    """Publish an existing VirusTotal file report without uploading the APK again."""
    try:
        result = save_report(api_key, release, package_key, apk, sha256, signature)
    except HttpRequestError as exc:
        if exc.status_code != 404:
            raise
        print("VirusTotal has no file report available for this SHA-256 yet.")
        return False
    except ReportNotReadyError as exc:
        print("VirusTotal file report is not complete yet: " + str(exc))
        return False

    write_step_summary(package_key, result)
    print(
        "Published VirusTotal report for "
        + package_key
        + " by SHA-256 without another upload: "
        + result["reportUrl"]
    )
    return True


def write_pending_status(release, package_key, apk, sha256, signature, analysis_id, message):
    """Persist the accepted analysis ID so a later run can resume it safely."""
    result = {
        **release_status_fields(release, package_key, apk, sha256),
        "status": "pending",
        "message": message,
        "signature": signature,
        "analysisId": analysis_id,
        "publishedToRepositoryAt": dt.datetime.now(dt.timezone.utc).replace(
            microsecond=0
        ).isoformat().replace("+00:00", "Z"),
    }
    persist_package_record(release, package_key, result)
    return result


def signature_facts(signature):
    return (
        signature.get("status"),
        signature.get("trustedCertificateSha256"),
        tuple(signature.get("observedCertificateSha256", [])),
    )


def main():
    api_key = os.environ.get("VT_API_KEY", "").strip()
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    package_key = os.environ.get("APK_PACKAGE_KEY", "universal").strip()
    if package_key not in PACKAGE_KEYS:
        raise RuntimeError("APK_PACKAGE_KEY must be one of: " + ", ".join(PACKAGE_KEYS))

    release = load_release()
    try:
        apk, sha256 = select_apk(release, package_key)
    except Exception as error:
        result = {
            **release_status_fields(release, package_key),
            "status": "error",
            "message": str(error),
        }
        persist_package_record(release, package_key, result)
        raise

    if not apk:
        result = {
            **release_status_fields(release, package_key),
            "status": "not_available",
            "message": "This release does not contain this APK package.",
        }
        persist_package_record(release, package_key, result)
        print(f"{package_key}: no matching APK asset in {release.get('tag_name', 'release')}; recorded as unavailable.")
        return

    old_status = read_existing_status()
    old_packages = packages_from_status(old_status, release.get("tag_name") or "")
    old_record = old_packages.get(package_key, {})
    signature = None

    try:
        print(f"Preparing {package_key} from {release.get('tag_name', 'published release')}.")
        content = download_verified(apk, sha256)
        print(f"{package_key}: downloaded APK SHA-256 verified against GitHub release metadata.")

        signature = verify_apk_signature(content, apk.get("name") or DEFAULT_APK_NAME)
        print(f"{package_key}: APK signature verification: {signature['status']}")

        same_file = old_record.get("sha256") == sha256
        if same_file and old_record.get("status") == "available":
            previous_signature = old_record.get("signature")
            if isinstance(previous_signature, dict) and signature_facts(previous_signature) == signature_facts(signature):
                result = {
                    **old_record,
                    **release_status_fields(release, package_key, apk, sha256),
                    "signature": signature,
                }
                persist_package_record(release, package_key, result)
                write_step_summary(package_key, result)
                print(f"{package_key}: this exact APK already has a published report and current signing verification.")
                return

            # Preserve the completed VirusTotal report; refresh signing metadata only.
            result = {
                **old_record,
                **release_status_fields(release, package_key, apk, sha256),
                "signature": signature,
                "publishedToRepositoryAt": dt.datetime.now(dt.timezone.utc).replace(
                    microsecond=0
                ).isoformat().replace("+00:00", "Z"),
            }
            persist_package_record(release, package_key, result)
            write_step_summary(package_key, result)
            print(f"{package_key}: refreshed signing verification for an already scanned APK.")
            return

        if not api_key:
            result = {
                **release_status_fields(release, package_key, apk, sha256),
                "status": "not_published",
                "message": "APK signature was checked, but no VirusTotal report is currently published.",
                "signature": signature,
                "publishedToRepositoryAt": dt.datetime.now(dt.timezone.utc).replace(
                    microsecond=0
                ).isoformat().replace("+00:00", "Z"),
            }
            persist_package_record(release, package_key, result)
            write_step_summary(package_key, result)
            print(f"{package_key}: no VirusTotal API credential configured; signature status published only.")
            return

        # Recover a completed report by hash before resuming or submitting an analysis.
        if publish_report_if_ready(api_key, release, package_key, apk, sha256, signature):
            return

        pending_analysis_id = (
            old_record.get("analysisId")
            if same_file and old_record.get("status") == "pending"
            else None
        )

        if pending_analysis_id:
            analysis_id = pending_analysis_id
            print(f"{package_key}: resuming the accepted VirusTotal analysis; no duplicate upload.")
        elif event_name == "push":
            result = {
                **release_status_fields(release, package_key, apk, sha256),
                "status": "not_published",
                "message": "No completed VirusTotal report is available. A maintenance push does not submit new APK files.",
                "signature": signature,
                "publishedToRepositoryAt": dt.datetime.now(dt.timezone.utc).replace(
                    microsecond=0
                ).isoformat().replace("+00:00", "Z"),
            }
            persist_package_record(release, package_key, result)
            write_step_summary(package_key, result)
            print(f"{package_key}: no report available; maintenance push will not submit a duplicate.")
            return
        else:
            analysis_id = submit_file(api_key, content, apk.get("name") or DEFAULT_APK_NAME)
            print(f"{package_key}: APK submitted to VirusTotal; waiting for analysis.")
            write_pending_status(
                release,
                package_key,
                apk,
                sha256,
                signature,
                analysis_id,
                "VirusTotal accepted this APK. Analysis is processing; its result has not been published yet.",
            )

        try:
            wait_for_analysis(api_key, analysis_id)
        except AnalysisPendingError as exc:
            print("::warning::" + package_key + ": " + str(exc))
            if publish_report_if_ready(api_key, release, package_key, apk, sha256, signature):
                return
            result = write_pending_status(
                release,
                package_key,
                apk,
                sha256,
                signature,
                analysis_id,
                "VirusTotal accepted this APK, but analysis is still processing. A later workflow run can resume the same analysis.",
            )
            write_step_summary(package_key, result)
            print(f"{package_key}: kept the accepted analysis resumable; no duplicate upload was made.")
            return

        # The analysis endpoint can finish before the file-report endpoint is ready.
        if publish_report_if_ready(api_key, release, package_key, apk, sha256, signature):
            return

        result = write_pending_status(
            release,
            package_key,
            apk,
            sha256,
            signature,
            analysis_id,
            "VirusTotal finished its analysis, but the completed file report is not available yet. A later workflow run can retrieve it.",
        )
        write_step_summary(package_key, result)
        print(f"{package_key}: analysis completed, but its file report is not ready yet.")
    except Exception as error:
        result = {
            **release_status_fields(release, package_key, apk, sha256),
            "status": "error",
            "message": str(error),
            "attemptedAt": dt.datetime.now(dt.timezone.utc).replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z"),
        }
        if signature:
            result["signature"] = signature

        # Preserve an accepted analysis ID if a later VirusTotal request fails.
        current_packages = packages_from_status(
            read_existing_status(), release.get("tag_name") or ""
        )
        current_record = current_packages.get(package_key, {})
        if (
            current_record.get("sha256") == sha256
            and current_record.get("analysisId")
        ):
            result["status"] = "pending"
            result["analysisId"] = current_record["analysisId"]
            result["message"] = (
                "The VirusTotal analysis was accepted and can be resumed. "
                "The latest check failed: " + str(error)
            )

        persist_package_record(release, package_key, result)
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("ERROR: " + str(error), file=sys.stderr)
        raise SystemExit(1)
