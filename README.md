# wayback_scraper Q2 (v2.5.1)

> 🇺🇦 **UA:** Автоматизована викачка та відновлення збережених снапшотів сайтів з Wayback Machine. wayback_scraper отримує список історичних захоплень через CDX API, завантажує оригінальні файли, перевіряє їхню цілісність, зберігає унікальні байти в незмінному сховищі та відновлює структуру сайту для локального аналізу.
> 
> 🇬🇧 **EN:** Automated downloading and recovery of archived website snapshots from the Wayback Machine. wayback_scraper retrieves historical captures through the CDX API, downloads original files, verifies their integrity, stores unique bytes in an immutable local store, and rebuilds the website structure for local analysis.

 <img width="597" height="301" alt="изображение" src="https://github.com/user-attachments/assets/316766cb-55ed-4b89-af94-769f60398e34" />

## 🔥 Features

* **Zero Dependencies:** Pure Python. No pip install required.
* **Wayback CDX:** Retrieves historical snapshots directly from the Wayback Machine CDX API.
* **Historical Preservation:** Keeps original downloaded bytes in a canonical immutable store.
* **Deduplicated Storage:** The same physical file is stored only once even when it appears in multiple snapshots.
* **Integrity Verification:** Checks downloaded files against Wayback digests and SHA-256 hashes.
* **Recovery:** Detects missing or modified local files and attempts to restore them from Wayback.
* **Incremental Updates:** Re-running the tool updates an existing archive instead of downloading everything again.
* **Failed Download Queue:** Temporary and permanent failures are tracked separately for later recovery.
* **Safe Interruption:** Ctrl+C stops new work and preserves already completed results.
* **Site Reconstruction:** Builds convenient local views of the archived website, including documents, images, versions and the latest site.
* **Reports:** Generates archive statistics, manifests and integrity reports.
* **Threaded Downloads:** Uses multiple workers with global request throttling.
* **Windows Friendly:** Designed for straightforward use on Windows without external packages.

## 🚀 Quick Start

**1. Install Python**
Make sure Python 3.9+ is installed and available in your system PATH.
Check:
```bash
python --version
```

**2. Download the tool**
```bash
git clone https://github.com/AcidOsint/wayback_scraper.git
cd wayback_scraper
```

**3. Run**
Windows: double-click `run.bat`.
Or run directly:
```bash
python archive_wayback.py
```

**4. Enter a website**
Choose the download/update mode and enter either:
* a domain, or
* an existing archive directory.

The tool will query the Wayback Machine, download available captures and create a local archive.

## 📁 Archive Structure

A typical archive contains:
```text
downloads/
└── example.com/
    ├── 00_ОТЧЁТЫ/
    ├── 01_САЙТ_СВЕЖИЙ/
    ├── 02_ДОКУМЕНТЫ/
    ├── 03_ФОТО/
    ├── 04_ВЕРСИИ/
    ├── _хранилище/
    ├── _база.csv
    └── _не_скачалось.csv
```

* **_хранилище**: Canonical storage of the original downloaded bytes. A physical file is stored once and referenced by the reconstructed archive views.
* **_база.csv**: Capture database containing historical appearances of URLs and their timestamps.
* **_не_скачалось.csv**: Persistent queue of downloads that could not be completed.

## 🔍 Integrity & Recovery

The tool distinguishes between:
* new historical captures;
* already archived captures;
* missing local files;
* modified local files;
* temporary download failures;
* permanent failures;
* files whose downloaded bytes do not match the expected Wayback digest.

The canonical storage is never silently replaced with a different historical capture. If an existing physical file is missing or damaged, the tool can attempt to restore it from the corresponding Wayback capture.

## ⚠️ Important Notes

* wayback_scraper works with the data currently available through the Wayback Machine and its CDX API.
* Wayback captures may be incomplete, unavailable, rate-limited, or return errors. A historical URL existing in CDX does not guarantee that its original bytes can still be downloaded successfully.
* The tool does not silently substitute another capture when the requested historical bytes cannot be verified.
* Large or old websites can take a significant amount of time to process.

## 🛠 Requirements

* Windows
* Python 3.9+
* Internet connection
* No external Python packages required

## 📄 License

MIT License.
See `LICENSE` for the full license text.
