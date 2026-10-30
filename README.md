# wayback_scraper Q2 (v2.6.0)

> **Q2** is a personal OSINT tool for downloading, preserving, and inspecting historical website captures from the Internet Archive's Wayback Machine. It discovers captures through the CDX API, verifies downloaded bytes, stores unique originals in a canonical local store, and builds an offline archive with dated versions, documents, photos, reports, and an HTML dashboard.

<img width="597" height="301" alt="Q2 terminal interface" src="https://github.com/user-attachments/assets/316766cb-55ed-4b89-af94-769f60398e34" />

## Features

- **No third-party dependencies:** uses the Python standard library; no `pip install` is required.
- **Wayback CDX discovery:** finds historical captures from the Internet Archive.
- **Flexible search scope:** enter a domain to search the domain and its subdomains, or enter a URL with a path to limit the search to that URL path and its descendants.
- **Live CLI progress:** displays the current operation, elapsed time, and available counters in an interactive terminal. It falls back to simple start/finish messages when output is redirected.
- **Bounded CDX retries:** CDX requests use a 30-second timeout and at most one retry for transient failures. A failed CDX request is not treated as proof that no captures exist.
- **Canonical original storage:** downloaded bytes are kept in `_store`; derived offline views are built separately.
- **Deduplicated storage:** a physical content object is stored once and can be referenced by multiple capture records.
- **Incremental updates and recovery:** reruns compare CDX results with the local archive and can restore missing or modified local files.
- **Integrity checks:** verifies Wayback digests, stored SHA-256 hashes, and supported file-structure markers.
- **GZIP-aware derived views:** GZIP-wrapped content can be decoded for usable offline copies while the original downloaded bytes remain in the canonical store.
- **Offline reconstruction:** creates a latest-site view, timestamped versions, document and photo collections, and rewrites supported links in archived HTML and CSS.
- **Reports and dashboard:** generates a change timeline, link graph, contact candidates, document metadata, photo EXIF data, sitemap/robots findings, removed-page information, and an HTML dashboard as applicable to the archive.
- **Manifest and logs:** records archive parameters and provides a local operation log.
- **Threaded downloads with throttling:** uses multiple workers while pacing requests to the archive service.

## Requirements

- Windows (the included `run.bat` launcher is for Windows)
- Python 3.9 or newer
- Internet connection for Wayback searches and downloads
- No external Python packages

## Quick start

### 1. Install Python

Install Python 3.9 or newer and make sure `python` is available in `PATH`.

Check the installation:

```bash
python --version
```

### 2. Download the repository

```bash
git clone https://github.com/AcidOsint/wayback_scraper.git
cd wayback_scraper
```

### 3. Run Q2

On Windows, double-click `run.bat`, or run the script directly:

```bash
python archive_wayback.py
```

### 4. Create or update an archive

Choose **01 — DOWNLOAD / UPDATE WEBSITE ARCHIVE** and enter either:

- a domain, such as `example.com`, to search the full domain and its subdomains; or
- a full URL containing a path, such as `https://example.com/docs/`, to search that URL path and its descendants rather than the entire host; or
- the path to an existing archive directory to update that archive using its saved search scope.

You can optionally set a start date, end date, included file extensions, and excluded file extensions. Leave the date fields empty to use the earliest available captures through the present.

## Main menu

| Option | Action |
|---|---|
| **01** | Download a new archive or update an existing one. Builds the offline views and reports after processing captures. |
| **02** | Rebuild local reports and the HTML dashboard from an existing archive. This mode works offline and does not query Wayback. The removed-page report is preserved from the last online update; if it does not exist, the report explains that an online status-history query is required. |
| **03** | Verify the integrity of the files in an existing archive. |
| **04** | Exit. |

## Archive structure

A typical archive is stored under `downloads/`. Some category folders are created only when matching files exist.

```text
downloads/
└── example.com/
    ├── 00_REPORTS/
    ├── 01_LATEST_SITE/
    ├── 02_DOCUMENTS/          # when documents are present
    ├── 03_PHOTOS/             # when photos are present
    ├── 04_VERSIONS/
    ├── _store/
    ├── _database.csv
    ├── _failed_downloads.csv  # when failed downloads are recorded
    ├── _q2.log
    └── MANIFEST.json
```

- **`_store/`** — canonical storage of original downloaded bytes. Content objects are stored once and reused by the archive's derived views.
- **`_database.csv`** — one row per capture appearance (original URL and timestamp). Multiple rows can reference the same physical content object.
- **`_failed_downloads.csv`** — records failed downloads and their reasons. Permanent failures are deferred rather than retried automatically on every run.
- **`MANIFEST.json`** — records the archive's search scope, date range, filters, capture counts, storage totals, and tool version.
- **`_q2.log`** — operation log for the archive.

## Reports

Reports are written to `00_REPORTS/`. Depending on the content available in an archive, the directory can include:

- `DASHBOARD.html` — local HTML overview with links to available archive sections and reports.
- `change_timeline.txt` — capture history grouped by URL.
- `single_capture_urls.txt` — URLs represented by a single capture.
- `link_graph.txt` — links found in archived HTML and CSS.
- `contacts.txt` and `contacts.csv` — detected email addresses, phone candidates, and social profiles.
- `document_metadata.txt` and `document_metadata.csv` — extracted document metadata.
- `photo_exif.txt` and `photo_exif.csv` — extracted photo EXIF and GPS metadata, when available.
- `sitemap_and_robots.txt` — findings from archived sitemap and robots files.
- `removed_pages.txt` — status-history findings from an online archive update, or an explanation when that analysis is not available.
- `integrity_check.txt` — results from the separate integrity-verification option.

Option 02 rebuilds reports that can be generated from local archive data. It does not contact Wayback; removed-page status history is therefore not refreshed by this option.

## Integrity and recovery

Q2 distinguishes between:

- new captures;
- captures already represented in the local database;
- missing or modified local content;
- transient download failures;
- permanent failures; and
- downloaded content that does not match the digest reported by Wayback.

The canonical store retains the original downloaded bytes. GZIP decoding used for offline views does not replace the stored original. A digest mismatch is rejected rather than silently accepted as the requested historical capture.

The integrity checker verifies stored hashes and performs supported structural checks. A matching checksum confirms that a local file has not changed since it was stored; it does not guarantee that the historical snapshot supplied by Wayback was itself complete or valid. Structural warnings can therefore remain for problematic upstream captures.

## Important notes and limitations

- Q2 depends on the captures and metadata currently available through the Wayback Machine and its CDX service.
- Wayback may respond slowly, return HTTP errors such as 503 or 504, rate-limit requests, or fail to provide a stored capture. A CDX timeout or server error means the result is inconclusive; it does not prove that no capture exists.
- A capture listed by CDX is not a guarantee that the corresponding original bytes can still be retrieved successfully.
- Q2 rejects downloads whose bytes do not match the expected Wayback digest. It does not silently substitute a different capture.
- External resources on unrelated hosts are not automatically included in a domain-scoped archive.
- Large websites and long capture histories can take significant time to process, depending on Wayback availability and network conditions.

## License

MIT License. See [`LICENSE`](LICENSE) for the full license text.
