from __future__ import annotations

import csv
import gzip
import io
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_ARCHIVE_BASE = "https://epss.empiricalsecurity.com"
FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss"

USER_AGENT = "CyberLens-RBVM-ETL/2.0 (ETSIINF-UPM Security Analytics)"


@dataclass(frozen=True)
class FeedConfig:
    nvd_api_key: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3

    @classmethod
    def from_env(cls) -> "FeedConfig":
        key = os.getenv("NVD_API_KEY")
        return cls(nvd_api_key=key.strip() if key and key.strip() else None)

    @property
    def nvd_delay_seconds(self) -> float:
        return 0.7 if self.nvd_api_key else 6.3


def _http_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    max_retries: int = 3,
) -> bytes:
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)

    last_err: Optional[Exception] = None
    for attempt in range(max_retries):
        req = urllib.request.Request(url, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            last_err = exc
            if exc.code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                time.sleep(2.5 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as exc:
            last_err = exc
            if attempt < max_retries - 1:
                time.sleep(2.0 * (attempt + 1))
                continue
            raise

    raise RuntimeError(f"HTTP fetch failed after {max_retries} attempts: {url}") from last_err


def fetch_cisa_kev(config: FeedConfig) -> Tuple[str, Dict[str, Dict[str, Any]]]:
    raw = _http_get(CISA_KEV_URL, timeout=config.timeout, max_retries=config.max_retries)
    payload = json.loads(raw.decode("utf-8"))
    catalog_version = str(payload.get("catalogVersion", "unknown"))

    kev_map: Dict[str, Dict[str, Any]] = {}
    for item in payload.get("vulnerabilities", []):
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        kev_map[cve_id] = {
            "cve_id": cve_id,
            "vendor_project": item.get("vendorProject", ""),
            "product": item.get("product", ""),
            "date_added": item.get("dateAdded"),
            "due_date": item.get("dueDate"),
            "is_ransomware": str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "required_action": item.get("requiredAction", ""),
            "short_description": item.get("shortDescription", ""),
            "cwes": item.get("cwes") or [],
        }

    return catalog_version, kev_map


def _parse_epss_gzip_csv(raw_gz: bytes) -> Tuple[date, Dict[str, Tuple[float, float]]]:
    text = gzip.decompress(raw_gz).decode("utf-8", errors="replace")
    lines = text.splitlines()
    score_date = date.today()
    start_idx = 0

    if lines and lines[0].startswith("#"):
        header_meta = lines[0]
        for token in header_meta.split(","):
            if "score_date:" in token:
                iso_part = token.split("score_date:", 1)[1].strip()[:10]
                try:
                    score_date = date.fromisoformat(iso_part)
                except ValueError:
                    pass
        start_idx = 1

    reader = csv.DictReader(io.StringIO("\n".join(lines[start_idx:])))
    scores: Dict[str, Tuple[float, float]] = {}
    for row in reader:
        cve_id = row.get("cve")
        if not cve_id:
            continue
        try:
            epss_val = float(row["epss"])
            pct_val = float(row["percentile"])
        except (KeyError, ValueError, TypeError):
            continue
        scores[cve_id] = (epss_val, pct_val)

    return score_date, scores


def fetch_epss_snapshot(
    config: FeedConfig,
    target_date: Optional[date] = None,
) -> Tuple[date, Dict[str, Tuple[float, float]]]:
    if target_date is None:
        url = f"{EPSS_ARCHIVE_BASE}/epss_scores-current.csv.gz"
        raw_gz = _http_get(url, timeout=config.timeout, max_retries=config.max_retries)
        return _parse_epss_gzip_csv(raw_gz)

    # Probe exact date or up to 3 days earlier if a daily dump is missing
    last_exc: Optional[Exception] = None
    for offset in range(4):
        candidate = target_date - timedelta(days=offset)
        url = f"{EPSS_ARCHIVE_BASE}/epss_scores-{candidate.isoformat()}.csv.gz"
        try:
            raw_gz = _http_get(url, timeout=config.timeout, max_retries=2)
            return _parse_epss_gzip_csv(raw_gz)
        except Exception as exc:
            last_exc = exc
            continue

    raise RuntimeError(f"Could not fetch EPSS snapshot around {target_date}") from last_exc


def fetch_epss_api_batch(
    cve_ids: List[str],
    config: FeedConfig,
    target_date: Optional[date] = None,
) -> Dict[str, Tuple[float, float]]:
    scores: Dict[str, Tuple[float, float]] = {}
    batch_size = 90
    for idx in range(0, len(cve_ids), batch_size):
        chunk = cve_ids[idx : idx + batch_size]
        params: Dict[str, str] = {"cve": ",".join(chunk)}
        if target_date is not None:
            params["date"] = target_date.isoformat()
        url = f"{FIRST_EPSS_API_URL}?{urllib.parse.urlencode(params)}"
        raw = _http_get(url, timeout=config.timeout, max_retries=config.max_retries)
        payload = json.loads(raw.decode("utf-8"))
        for row in payload.get("data", []):
            cve_id = row.get("cve")
            if not cve_id:
                continue
            try:
                scores[cve_id] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, ValueError, TypeError):
                continue
    return scores


def _nvd_headers(config: FeedConfig) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if config.nvd_api_key:
        headers["apiKey"] = config.nvd_api_key
    return headers


def fetch_nvd_kev_cves(config: FeedConfig) -> List[Dict[str, Any]]:
    """Fetch all NVD CVE records flagged in CISA KEV via single-pass pagination."""
    records: List[Dict[str, Any]] = []
    start_index = 0
    results_per_page = 2000

    while True:
        params = urllib.parse.urlencode(
            {"startIndex": start_index, "resultsPerPage": results_per_page}
        )
        url = f"{NVD_API_URL}?hasKev&{params}"
        raw = _http_get(
            url,
            headers=_nvd_headers(config),
            timeout=max(config.timeout, 45),
            max_retries=config.max_retries,
        )
        payload = json.loads(raw.decode("utf-8"))
        vulns = payload.get("vulnerabilities", [])
        records.extend(vulns)

        total_results = int(payload.get("totalResults", len(records)))
        start_index += len(vulns)
        if not vulns or start_index >= total_results:
            break
        time.sleep(config.nvd_delay_seconds)

    return records


def fetch_nvd_published_window(
    start_dt: datetime,
    end_dt: datetime,
    config: FeedConfig,
    results_per_page: int = 2000,
    start_index: int = 0,
) -> List[Dict[str, Any]]:
    params = urllib.parse.urlencode(
        {
            "pubStartDate": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
    )
    url = f"{NVD_API_URL}?{params}"
    raw = _http_get(
        url,
        headers=_nvd_headers(config),
        timeout=max(config.timeout, 45),
        max_retries=config.max_retries,
    )
    payload = json.loads(raw.decode("utf-8"))
    return payload.get("vulnerabilities", [])
