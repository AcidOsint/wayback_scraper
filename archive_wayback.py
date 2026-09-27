#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Q2 - Архиватор сайтов из Wayback Machine (Internet Archive)

Личный OSINT-инструмент. Ключевые особенности:
  - один архив на домен: повторный запуск НЕ качает заново то, что уже есть,
    а доливает только новое (режим мониторинга сайта);
  - файл физически хранится один раз, даже если встречается в 10 снапшотах;
    в удобных папках лежат жёсткие ссылки на него (место не тратится);
  - понятная структура: документы отдельно, фото отдельно, свежая версия
    сайта отдельно, старые версии - по читаемым датам;
  - отчёты: таймлайн изменений, контакты и соцсети, метаданные документов
    (автор/организация/программа), удалённые страницы, sitemap/robots;
  - дашборд: одна HTML-страница, с которой виден весь архив;
  - обновление существующего архива и консервативный долов сетевых ошибок.

Запуск: run.bat (двойной клик) либо python archive_wayback.py
"""

import csv
import hashlib
import html as html_mod
import json
import logging
import os
import re
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser

# ==================== НАСТРОЙКИ ====================
BASE_ARCHIVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "downloads")
MAX_WORKERS = 3            # сколько файлов скачивать одновременно
REQUEST_TIMEOUT = 30       # секунд ожидания на один файл
MAX_RETRIES = 3            # попыток на файл при ошибке сети
RETRY_DELAY = 2            # секунд между повторами (умножается на номер попытки)
CDX_PAGE_SIZE = 100000
MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
REQUEST_PACE_SECONDS = 0.7     # записей за одну страницу CDX-индекса
MAX_SUBDOMAINS_TO_CHECK = 80   # 0 = без ограничения; для организации с сотнями
                                # поддоменов стоит поднять, но каждый - лишний запрос

WELL_KNOWN_SITEMAP_PATHS = [
    "robots.txt", "sitemap.xml", "sitemap_index.xml", "sitemap-index.xml",
    "sitemap1.xml", "wp-sitemap.xml", "sitemap/sitemap.xml",
]

SUBDOMAIN_CANDIDATES = [
    "www", "mail", "webmail", "shop", "blog", "news", "api", "cdn", "static",
    "m", "mobile", "support", "help", "docs", "portal", "intranet", "corp",
    "login", "admin", "cabinet", "old", "test", "dev", "en", "ru",
]
# =====================================================

# --- имена папок и служебных файлов ---
DIR_REPORTS = "00_ОТЧЁТЫ"
DIR_LATEST = "01_САЙТ_СВЕЖИЙ"
DIR_DOCS = "02_ДОКУМЕНТЫ"
DIR_PHOTOS = "03_ФОТО"
DIR_VERSIONS = "04_ВЕРСИИ"
DIR_STORE = "_хранилище"

DB_CSV = "_база.csv"
FAILED_CSV = "_не_скачалось.csv"
LOG_FILE = "_журнал.log"
TOOL_VERSION = "2.5.1"

DB_HEADER = ["digest", "original_url", "timestamp", "mimetype", "statuscode",
             "size_bytes", "sha256", "store_path", "first_seen"]
FAILED_HEADER = ["original_url", "timestamp", "digest", "mimetype",
                 "statuscode", "length", "reason"]

DOC_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt",
            "ods", "odp", "csv", "zip", "rar", "7z", "txt"}
IMG_EXTS = {"jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff", "svg", "ico"}
HTML_EXTS = {"html", "htm", "xhtml", "php", "asp", "aspx", "jsp", "shtml"}

PERMANENT_FAILURE_MARKER = "[PERMANENT]"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINT-archiver/2.0",
}

INVALID_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

LOGGER = logging.getLogger("q2_wayback")
_LINK_WARNED = {"done": False}

RED = "\033[91m"
DIM = "\033[90m"
RESET = "\033[0m"

BANNER_ART = """
 \u2588\u2588\u2588\u2588\u2588\u2588\u2557    \u2588\u2588\u2588\u2588\u2588\u2588\u2557 
\u2588\u2588\u2554\u2550\u2550\u2550\u2588\u2588\u2557   \u255a\u2550\u2550\u2550\u2550\u2588\u2588\u2557
\u2588\u2588\u2551   \u2588\u2588\u2551    \u2588\u2588\u2588\u2588\u2588\u2554\u255d
\u2588\u2588\u2551\u2584\u2584 \u2588\u2588\u2551   \u2588\u2588\u2554\u2550\u2550\u2550\u255d 
\u255a\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255d\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557
 \u255a\u2550\u2550\u2580\u2580\u2550\u255d \u255a\u2550\u255d\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u255d
"""

MENU = """
  01 * СКАЧАТЬ / ОБНОВИТЬ АРХИВ САЙТА
  02 * СОБРАТЬ ОТЧЁТЫ И ДАШБОРД
  03 * ПРОВЕРИТЬ ЦЕЛОСТНОСТЬ АРХИВА
  04 * ВЫХОД
"""


def enable_ansi_on_windows():
    if os.name == "nt":
        os.system("")  # включает обработку ANSI-кодов в cmd.exe


def print_banner():
    enable_ansi_on_windows()
    print(RED + BANNER_ART + RESET)
    print(DIM + f"AUTHOR AcidOsint | BUILD personal | VERSION {TOOL_VERSION} | UNIT Q2 TOOLS" + RESET)
    print(DIM + "=" * 60 + RESET)


SHUTDOWN = threading.Event()


def interruptible_sleep(total_seconds, step=1.0):
    """Обычный time.sleep() на Windows не даёт потоку среагировать на Ctrl+C,
    пока не закончится - при паузе в 600 секунд (Retry-After после 429)
    программа выглядела бы намертво зависшей. Спим мелкими интервалами и
    проверяем общий флаг остановки - тогда прервать можно почти мгновенно."""
    end = time.time() + total_seconds
    while True:
        if SHUTDOWN.is_set():
            return
        remaining = end - time.time()
        if remaining <= 0:
            return
        time.sleep(min(step, remaining))


class Throttle:
    """Общий 'тормоз' на все потоки сразу. Archive.org иногда банит за
    слишком агрессивное скачивание, отвечая 429. Вместо того чтобы каждый
    поток долбил дальше как ни в чём не бывало, все они видят одну и ту же
    команду 'подожди' и синхронно делают паузу."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pause_until = 0.0

    def wait_if_needed(self):
        with self._lock:
            remaining = self._pause_until - time.time()
        if remaining > 0:
            interruptible_sleep(remaining)

    def report_429(self, wait_seconds):
        with self._lock:
            candidate = time.time() + wait_seconds
            if candidate > self._pause_until:
                self._pause_until = candidate


THROTTLE = Throttle()


class RequestPacer:
    """Глобальный интервал между стартами HTTP-запросов."""
    def __init__(self, interval=REQUEST_PACE_SECONDS):
        self.interval = float(interval)
        self._lock = threading.Lock()
        self._next_start = 0.0

    def wait(self):
        # Резервируем слот под запрос и отпускаем lock ДО сна: иначе один
        # спящий поток держит замок и превращает пул из 3 потоков в очередь.
        with self._lock:
            now = time.time()
            start = max(now, self._next_start)
            self._next_start = start + self.interval
        delay = start - now
        if delay > 0:
            interruptible_sleep(delay)


class CircuitBreaker:
    """После серии сетевых/502-504 ошибок ставит все запросы на паузу."""
    def __init__(self, threshold=8, pause=90):
        self.threshold = threshold
        self.pause = pause
        self._lock = threading.Lock()
        self._errors = 0
        self._open_until = 0.0

    def wait(self):
        with self._lock:
            remaining = self._open_until - time.time()
        if remaining > 0:
            interruptible_sleep(remaining)

    def success(self):
        with self._lock:
            self._errors = 0

    def failure(self):
        with self._lock:
            self._errors += 1
            if self._errors >= self.threshold:
                self._open_until = max(self._open_until, time.time() + self.pause)
                self._errors = 0
                LOGGER.warning(f"Circuit breaker: пауза {self.pause} сек после серии сетевых ошибок")


REQUEST_PACER = RequestPacer()
CIRCUIT_BREAKER = CircuitBreaker()

# Координация физических файлов: один digest = один store-файл. Несколько
# одинаковых CDX-записей не должны одновременно писать один и тот же .part.
#
# Это "полосатые" (striped) lock'и: вместо бесконечно растущего словаря
# "путь -> Lock" держим фиксированный пул. Разные файлы иногда попадают на
# один lock и тогда просто ждут друг друга; зато память не растёт вместе с
# количеством уникальных файлов за месяцы работы.
_STORE_LOCK_COUNT = 64
_STORE_LOCKS = [threading.Lock() for _ in range(_STORE_LOCK_COUNT)]
_STORE_VERIFY_CACHE = {}

def _store_lock_for(path):
    key = os.path.abspath(path).lower().encode("utf-8", errors="replace")
    slot = int.from_bytes(hashlib.sha1(key).digest()[:4], "big") % _STORE_LOCK_COUNT
    return _STORE_LOCKS[slot]

def _store_cache_key(path, expected_digest, expected_sha256):
    try:
        st = os.stat(path)
        return (os.path.abspath(path), st.st_mtime_ns, st.st_size,
                str(expected_digest).lower(), str(expected_sha256 or '').lower())
    except OSError:
        return None

def _clear_store_verify_cache(path=None):
    if path is None:
        _STORE_VERIFY_CACHE.clear()
        return
    prefix = os.path.abspath(path)
    for key in list(_STORE_VERIFY_CACHE):
        if key[0] == prefix:
            _STORE_VERIFY_CACHE.pop(key, None)


def parse_retry_after(header_value, default=30):
    """Retry-After бывает либо числом секунд, либо HTTP-датой."""
    if not header_value:
        return default
    header_value = header_value.strip()
    if header_value.isdigit():
        return min(int(header_value), 600)
    try:
        import email.utils
        dt = email.utils.parsedate_to_datetime(header_value)
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
        delta = (dt - now).total_seconds()
        return min(max(int(delta), 1), 600)
    except Exception:
        return default


def urlopen_throttled(req, timeout, context="запрос"):
    """urlopen с общим троттлингом: при 429 ждёт Retry-After (или дефолт)
    и придерживает ВСЕ остальные потоки на это время, не только текущий."""
    THROTTLE.wait_if_needed()
    CIRCUIT_BREAKER.wait()
    REQUEST_PACER.wait()
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            wait = parse_retry_after(e.headers.get("Retry-After"))
            THROTTLE.report_429(wait)
            print(f"    archive.org просит притормозить (429), жду {wait} сек "
                  f"(и остальные потоки тоже)...")
            LOGGER.warning(f"429 на {context}: жду {wait}с")
        if e.code in (502, 503, 504):
            CIRCUIT_BREAKER.failure()
        raise
    except urllib.error.URLError:
        CIRCUIT_BREAKER.failure()
        raise
    except OSError:
        CIRCUIT_BREAKER.failure()
        raise


# ==================== ОБЩИЕ УТИЛИТЫ ====================

def sanitize_segment(name: str) -> str:
    name = INVALID_CHARS.sub("_", name)
    name = name.replace("/", "_").replace("\\", "_").strip(". ")
    if not name:
        name = "_"
    if name.upper() in RESERVED_NAMES:
        name = "_" + name
    return name[:120]


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "http://" + raw
    return raw


def get_domain(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc.lower()


def human_size(num_bytes) -> str:
    try:
        num_bytes = float(num_bytes)
    except (TypeError, ValueError):
        return "?"
    for unit in ["Б", "КБ", "МБ", "ГБ"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} ТБ"


def pretty_ts(ts: str) -> str:
    try:
        return datetime.strptime(str(ts)[:14], "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return str(ts)


def folder_ts(ts: str) -> str:
    """20180412093122 -> 2018-04-12_09-31-22 (читаемое имя папки версии,
    полная точность до секунды - раньше округлялось до минуты, и разные
    захваты в одну минуту физически перетирали друг друга)"""
    try:
        return datetime.strptime(str(ts)[:14], "%Y%m%d%H%M%S").strftime("%Y-%m-%d_%H-%M-%S")
    except (ValueError, TypeError):
        return sanitize_segment(str(ts))


def date_only(ts: str) -> str:
    try:
        return datetime.strptime(str(ts)[:14], "%Y%m%d%H%M%S").strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        return "0000-00-00"


def get_extension(original_url: str) -> str:
    path = urllib.parse.urlsplit(original_url).path
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    return ext or "html"


def setup_logger(domain_dir: str) -> str:
    LOGGER.setLevel(logging.DEBUG)
    LOGGER.handlers.clear()
    log_path = os.path.join(domain_dir, LOG_FILE)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    LOGGER.addHandler(fh)
    LOGGER.propagate = False
    return log_path


def derived_file_matches_store(store_file, derived_file, digest, expected_sha256=""):
    """Проверяет производный НЕ-HTML файл против canonical store."""
    if not os.path.isfile(store_file) or not os.path.isfile(derived_file):
        return False
    try:
        if os.path.samefile(store_file, derived_file):
            return True
    except OSError:
        pass
    try:
        if os.path.getsize(store_file) != os.path.getsize(derived_file):
            return False
        if expected_sha256:
            return _store_file_is_valid(derived_file, digest, expected_sha256)
        store_sha, _ = _sha256_and_size(store_file)
        derived_sha, _ = _sha256_and_size(derived_file)
        return store_sha == derived_sha
    except OSError:
        return False


def link_or_copy(src: str, dst: str):
    """Жёсткая ссылка (не занимает места на диске), с откатом на копирование."""
    if os.path.exists(dst):
        return
    ensure_parent_dir(dst)
    try:
        os.link(src, dst)
        return
    except (OSError, AttributeError) as e:
        if not _LINK_WARNED["done"]:
            print("  (жёсткие ссылки недоступны на этом диске — файлы будут "
                  "копироваться, архив займёт больше места)")
            LOGGER.warning(f"Жёсткие ссылки недоступны: {e}")
            _LINK_WARNED["done"] = True
    with open(src, "rb") as fs, open(dst, "wb") as fd:
        for chunk in iter(lambda: fs.read(1024 * 1024), b""):
            fd.write(chunk)


def ensure_parent_dir(filepath: str):
    """Создаёт папки для файла. Если по пути уже лежит ФАЙЛ (на сайтах бывает:
    /foo - страница и /foo/bar - тоже страница), уводит его в сторону."""
    parent = os.path.dirname(filepath)
    if not parent:
        return
    segments = os.path.normpath(parent).split(os.sep)
    current = segments[0] + os.sep if segments[0] else os.sep
    for seg in segments[1:]:
        current = os.path.join(current, seg)
        if os.path.isfile(current):
            try:
                os.rename(current, current + "__страница")
            except OSError:
                pass
        os.makedirs(current, exist_ok=True)


def domain_dir_for(domain: str) -> str:
    return os.path.join(BASE_ARCHIVE_DIR, sanitize_segment(domain))


def ask_domain_dir():
    raw = input("Адрес сайта или путь к папке архива: ").strip().strip('"')
    if os.path.isdir(raw) and os.path.isfile(os.path.join(raw, DB_CSV)):
        return raw
    domain = get_domain(normalize_url(raw))
    if not domain:
        print("Не понял адрес сайта.")
        return None
    path = domain_dir_for(domain)
    if not os.path.isdir(path):
        print(f"Архив для этого сайта ещё не создан: {path}")
        print("Сначала скачайте сайт (пункт 01).")
        return None
    return path


def domain_from_archive_db(domain_dir):
    """Возвращает настоящий домен сайта из первой пригодной строки _база.csv.

    Это нужно именно для резервных/тестовых копий архива: папка может называться
    например "www.smartenergo.net — копия", но CDX-запросы всё равно должны идти
    к smartenergo.net. Сам архив при этом остаётся полностью изолированным:
    все файлы, БД, отчёты и новые загрузки пишутся только в переданную папку.
    """
    path = os.path.join(domain_dir, DB_CSV)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                raw = (row.get("original_url") or "").strip()
                if not raw:
                    continue
                domain = get_domain(normalize_url(raw))
                if domain:
                    return domain
    except (OSError, csv.Error) as e:
        LOGGER.warning(f"Не удалось определить домен из {path}: {e}")
    return None


def _looks_like_local_path(raw):
    """Не даём опечатанному Windows-пути случайно превратиться в домен."""
    text = raw.strip().strip('"')
    if re.match(r"^[A-Za-z]:[\\/]", text):
        return True
    if text.startswith(("\\\\", "./", "../", ".\\", "..\\")):
        return True
    if "\\" in text or "/" in text:
        # URL уже не считаем локальным путём. Всё остальное с разделителем
        # пути гораздо вероятнее является ошибочным локальным вводом.
        return not re.match(r"^https?://", text, re.IGNORECASE)
    return False


def ask_download_target():
    """Выбирает рабочий архив для пункта 01.

    Можно ввести домен/URL или существующую папку архива. Если ввод явно
    похож на локальный путь, но такой папки нет, программа НЕ отправляет его
    в Wayback как будто это домен — это защищает от тихой ошибки в пути.
    """
    raw = input("Адрес сайта ИЛИ путь к папке архива: ").strip().strip('"')
    if not raw:
        return None, None

    if os.path.isdir(raw):
        db_path = os.path.join(raw, DB_CSV)
        if os.path.isfile(db_path):
            domain = domain_from_archive_db(raw)
            if not domain:
                print("В этой папке есть _база.csv, но не удалось определить домен.")
                return None, None
            path = os.path.abspath(raw)
            print(f"  Тест/обновление существующего архива: {path}")
            print(f"  Домен для Wayback: {domain}")
            return domain, path
        print("Это папка, но в ней нет _база.csv — не похоже на архив Q2.")
        return None, None

    if _looks_like_local_path(raw):
        print(f"Локальная папка не найдена:\n  {raw}")
        print("Проверьте путь. Я не буду отправлять его в Wayback как адрес сайта.")
        return None, None

    domain = get_domain(normalize_url(raw))
    if not domain:
        print("Не понял адрес сайта.")
        return None, None

    path = domain_dir_for(domain)
    os.makedirs(path, exist_ok=True)
    return domain, path


# ==================== CDX (СПИСОК СНАПШОТОВ) ====================

CDX_FIELDS = ["original", "timestamp", "digest", "mimetype", "statuscode", "length"]

CDX_MATCH_CHAIN = [
    ("domain", "весь домен + поддомены (www. и т.п.)"),
    ("prefix", "весь домен без поддоменов"),
    ("exact",  "только главная страница"),
]


def build_cdx_url(domain, date_from, date_to, match_type, resume_key=None):
    url_value = domain if match_type != "exact" else domain.rstrip("/") + "/"
    params = {
        "url": url_value,
        "fl": ",".join(CDX_FIELDS),
        "filter": "statuscode:200",
        "collapse": "digest",
        "limit": str(CDX_PAGE_SIZE),
        "showResumeKey": "true",
    }
    if match_type != "exact":
        params["matchType"] = match_type
    if date_from:
        params["from"] = date_from
    if date_to:
        params["to"] = date_to
    if resume_key:
        params["resumeKey"] = resume_key
    return "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)


def fetch_cdx_page(cdx_url, timeout=90, raw_sink=None):
    req = urllib.request.Request(cdx_url, headers=HEADERS)
    lines = []
    with urlopen_throttled(req, timeout, context="CDX") as resp:
        for raw_line in resp:
            lines.append(raw_line.decode("utf-8", errors="replace").rstrip("\r\n"))

    if raw_sink is not None:
        raw_sink.extend(lines)   # буквально то, что прислал сервер, до всякой обработки

    resume_key = None
    if len(lines) >= 2 and lines[-2] == "" and lines[-1].strip():
        resume_key = lines[-1].strip()
        lines = lines[:-2]

    records = []
    for line in lines:
        if not line:
            continue
        parts = line.split(" ")
        if len(parts) != len(CDX_FIELDS):
            continue
        records.append(dict(zip(CDX_FIELDS, parts)))
    return records, resume_key


def classify_error(exc) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return str(exc.code)
    return type(exc).__name__


def diagnose_failure_message(error_codes: list) -> str:
    if not error_codes:
        return ("Снапшоты не найдены — возможно, этот сайт вообще не попадал в архив, "
                "либо в указанном диапазоне дат ничего нет.")
    if all(c == "503" for c in error_codes):
        return ("Archive.org сейчас НЕ РАБОТАЕТ целиком (ошибка 503 на всех запросах, "
                "даже на самых лёгких). Это не проблема сайта или скрипта — сервис лежит. "
                "Попробуйте через 10-30 минут.")
    if all(c == "504" for c in error_codes):
        return ("Archive.org не успевает обработать запрос (таймаут 504). Обычно это "
                "значит, что у сайта слишком большая история. Попробуйте задать более "
                "узкий диапазон дат.")
    return (f"Archive.org отвечает нестабильно (коды ошибок: {', '.join(error_codes)}). "
            f"Похоже на временные проблемы на их стороне — попробуйте позже.")


def save_raw_cdx_page(domain_dir, match_type, page, raw_lines):
    """Сохраняем полученные CDX-строки до разбора (построчно, как он пришёл, включая
    служебную resumeKey-строку) - это первичный источник всего архива. Если
    завтра понадобится улучшить парсер или найти то, что сейчас
    игнорируется, не придётся заново дёргать archive.org."""
    if not domain_dir or not raw_lines:
        return
    try:
        save_dir = os.path.join(domain_dir, DIR_REPORTS, "cdx_raw")
        os.makedirs(save_dir, exist_ok=True)
        path = os.path.join(save_dir, f"{sanitize_segment(match_type)}_page{page:03d}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(raw_lines))
    except Exception as e:
        LOGGER.debug(f"Не удалось сохранить сырой CDX: {e}")


def fetch_cdx_all_pages(domain, date_from, date_to, match_type, domain_dir=None):
    all_records = []
    resume_key = None
    page = 1
    last_error_code = None

    while True:
        cdx_url = build_cdx_url(domain, date_from, date_to, match_type, resume_key)
        page_records = None
        next_resume_key = None
        raw_lines = []
        max_attempts = 2 if page == 1 else 4

        for attempt in range(1, max_attempts + 1):
            try:
                raw_lines = []
                page_records, next_resume_key = fetch_cdx_page(cdx_url, raw_sink=raw_lines)
                break
            except Exception as e:
                last_error_code = classify_error(e)
                print(f"    попытка {attempt}/{max_attempts} не удалась ({e}). "
                      f"Жду {attempt * 10} сек...")
                LOGGER.warning(f"CDX matchType={match_type} стр.{page} поп.{attempt}: {e}")
                interruptible_sleep(attempt * 10)
                if SHUTDOWN.is_set():
                    break   # попросили остановиться - не лезем в сеть ещё раз

        if SHUTDOWN.is_set() and page_records is None:
            LOGGER.info("CDX: остановлено пользователем во время ретрая")
            return all_records, last_error_code

        if page_records is None:
            if page == 1:
                return [], last_error_code
            print(f"    не удалось скачать страницу {page}, продолжаю с тем, что есть")
            break

        all_records.extend(page_records)
        save_raw_cdx_page(domain_dir, match_type, page, raw_lines)
        print(f"    страница {page}: {len(page_records)} записей "
              f"(всего: {len(all_records)})")

        if not next_resume_key:
            break
        if next_resume_key == resume_key:
            # archive.org иногда отдаёт один и тот же resumeKey раз за разом -
            # без этой защиты страница качалась бы заново до бесконечности
            LOGGER.warning("CDX: archive.org вернул повторяющийся resumeKey, "
                           "останавливаюсь во избежание зацикливания")
            print("    archive.org вернул повторяющийся ключ страницы - останавливаюсь здесь")
            break
        resume_key = next_resume_key
        page += 1

    return all_records, None


def fetch_subdomains_from_crtsh(base_domain, timeout=40):
    """crt.sh - открытая база всех выпущенных SSL-сертификатов. Показывает,
    какие поддомены реально существовали (факты, а не угадайка)."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(base_domain)}&output=json"
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        print(f"    crt.sh недоступен ({e}), использую стандартный список")
        LOGGER.warning(f"crt.sh недоступен для {base_domain}: {e}")
        return []

    names = set()
    for entry in data:
        raw = (entry.get("name_value") or "") + "\n" + (entry.get("common_name") or "")
        for line in raw.split("\n"):
            host = line.strip().lower().lstrip("*.")
            if not host or not host.endswith(base_domain) or host == base_domain:
                continue
            if any(ch in host for ch in " ,@"):
                continue
            names.add(host)

    LOGGER.info(f"crt.sh дал {len(names)} поддоменов для {base_domain}")
    return sorted(names)


def sweep_subdomains(base_domain, date_from, date_to, existing_keys, domain_dir=None):
    print("  Ищу реальные поддомены через crt.sh (база SSL-сертификатов)...")
    real_subs = fetch_subdomains_from_crtsh(base_domain)
    if real_subs:
        print(f"    crt.sh нашёл поддоменов: {len(real_subs)}")

    guessed = [f"{s}.{base_domain}" for s in SUBDOMAIN_CANDIDATES]
    all_candidates = list(dict.fromkeys(real_subs + guessed))
    all_subs = all_candidates if MAX_SUBDOMAINS_TO_CHECK <= 0 else all_candidates[:MAX_SUBDOMAINS_TO_CHECK]
    skipped = len(all_candidates) - len(all_subs)

    msg = f"  Проверяю {len(all_subs)} поддоменов в архиве"
    if skipped:
        msg += f" (ещё {skipped} пропущено - см. MAX_SUBDOMAINS_TO_CHECK в настройках)"
    print(msg + "...")

    found = []
    for sub_domain in all_subs:
        cdx_url = build_cdx_url(sub_domain, date_from, date_to, "prefix")
        try:
            page1_records, resume_key = fetch_cdx_page(cdx_url, timeout=20)
        except Exception as e:
            LOGGER.debug(f"Поддомен {sub_domain}: недоступен ({e})")
            continue

        records = page1_records
        if resume_key:
            # у поддомена реально большая история - не бросаем хвост,
            # докачиваем полностью через нормальную пагинацию
            print(f"    {sub_domain}: большая история, докачиваю все страницы...")
            fuller, _ = fetch_cdx_all_pages(sub_domain, date_from, date_to, "prefix", domain_dir)
            if fuller:
                records = fuller

        new_records = [r for r in records
                       if (r["original"], r["timestamp"]) not in existing_keys]
        if new_records:
            print(f"    {sub_domain}: +{len(new_records)} файлов")
            for r in new_records:
                existing_keys.add((r["original"], r["timestamp"]))
            found.extend(new_records)
    if not found:
        print("    поддомены ничего не добавили")
    if skipped:
        LOGGER.warning(f"Поддомены: пропущено {skipped} из {len(all_candidates)} "
                       f"кандидатов (лимит MAX_SUBDOMAINS_TO_CHECK={MAX_SUBDOMAINS_TO_CHECK})")
    return found, skipped


def discover_wellknown_paths(domain, date_from, date_to, existing_keys):
    """Даже если основной обход не поймал robots.txt/sitemap.xml (например,
    откатились до урезанного режима, или Wayback просто не связал их с
    остальным сайтом) - стоит явно проверить стандартные пути. Дёшево:
    по одному точному запросу на каждый, максимум 7 штук."""
    found = []
    for rel_path in WELL_KNOWN_SITEMAP_PATHS:
        params = {
            "url": f"{domain}/{rel_path}",
            "fl": ",".join(CDX_FIELDS),
            "filter": "statuscode:200",
            "collapse": "digest",
            "limit": "50",
        }
        if date_from:
            params["from"] = date_from
        if date_to:
            params["to"] = date_to
        cdx_url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
        try:
            records, _ = fetch_cdx_page(cdx_url, timeout=15)
        except Exception as e:
            LOGGER.debug(f"well-known {rel_path}: {e}")
            continue
        for r in records:
            key = (r["original"], r["timestamp"])
            if key not in existing_keys:
                existing_keys.add(key)
                found.append(r)
    return found


def fetch_cdx_records(domain, date_from, date_to, domain_dir=None):
    print(f"Запрашиваю у Wayback Machine список снапшотов для: {domain}")
    LOGGER.info(f"CDX: старт {domain}, {date_from or '...'}..{date_to or '...'}")

    used_match_type = None
    records = []
    error_codes = []
    for match_type, description in CDX_MATCH_CHAIN:
        print(f"  Пробую режим: {description}...")
        page_records, error_code = fetch_cdx_all_pages(domain, date_from, date_to,
                                                        match_type, domain_dir)
        if page_records:
            used_match_type = match_type
            records = page_records
            if match_type != "domain":
                print(f"\n  ВНИМАНИЕ: полный обход домена недоступен, использован "
                      f"урезанный режим: {description}\n")
            break
        if error_code:
            error_codes.append(error_code)
        print(f"    режим не ответил, пробую более узкий...")

    existing = {(r["original"], r["timestamp"]) for r in records}

    # После успешного полного domain-CDX отдельный перебор robots/sitemap
    # почти всегда только добавляет лишние запросы и задержку. Он нужен как
    # резервный путь, когда полный обход не сработал или был урезан.
    if not records or used_match_type != "domain":
        wellknown = discover_wellknown_paths(domain, date_from, date_to, existing)
        if wellknown:
            if not records:
                print(f"  Основной обход не ответил, но по стандартным путям "
                      f"нашёл {len(wellknown)} файлов (robots/sitemap)")
            else:
                print(f"  Найдено ещё по стандартным путям (robots/sitemap): {len(wellknown)}")
            records.extend(wellknown)
    elif domain_dir:
        print("  Полный CDX-обход успешен — robots/sitemap дополнительно не опрашиваю.")

    if not records:
        print(diagnose_failure_message(error_codes))
        LOGGER.error(f"CDX: ни один режим не сработал ({error_codes})")
        return [], None

    if used_match_type != "domain":
        extra, _ = sweep_subdomains(domain, date_from, date_to, existing, domain_dir)
        if extra:
            print(f"  Поддомены добавили файлов: {len(extra)}")
            records.extend(extra)

    print(f"Итого найдено уникальных версий файлов: {len(records)}")
    LOGGER.info(f"CDX: итог {len(records)} записей, режим={used_match_type}")
    return records, used_match_type


# ==================== БАЗА АРХИВА ====================

def dedup_by_digest(rows):
    """Один и тот же физический файл (digest) может встречаться в базе
    сотни раз (страница, которая не менялась годами). Для операций, которые
    читают содержимое файла (хэширование, метаданные, EXIF, поиск контактов),
    достаточно сделать это один раз на уникальный digest, а не на каждое
    появление - иначе 500-кратно повторяющаяся главная страница будет
    прочитана и разобрана 500 раз впустую."""
    seen = {}
    for r in rows:
        seen.setdefault(r["digest"], r)
    return list(seen.values())


def load_db(domain_dir):
    """Читает базу архива.

    Важно: строка в базе - это ПОЯВЛЕНИЕ файла (адрес + дата снимка), а не
    уникальное содержимое. Один и тот же неизменившийся файл, встреченный в
    пяти снимках, даст пять строк, но на диске будет лежать один раз
    (все строки ссылаются на один store_path). Без этого ломались бы
    таймлайн, сборка свежей версии сайта и офлайн-ссылки."""
    path = os.path.join(domain_dir, DB_CSV)
    if not os.path.isfile(path):
        return {}, set(), []
    with open(path, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    by_digest = {}
    seen = set()
    for r in rows:
        by_digest.setdefault(r["digest"], r)
        seen.add((r["original_url"], r["timestamp"]))
    return by_digest, seen, rows


def append_db(domain_dir, new_rows):
    """Синхронизирует БД по ключу (original_url, timestamp).

    Повторное появление того же capture после ремонта НЕ добавляется второй
    строкой: существующая запись обновляется новым digest/sha256/size.
    Переписывание атомарное, чтобы Ctrl+C/сбой питания не оставил обрезанный CSV.
    """
    if not new_rows:
        return
    path = os.path.join(domain_dir, DB_CSV)
    rows = []
    if os.path.isfile(path):
        with open(path, encoding='utf-8-sig', newline='') as f:
            rows = list(csv.reader(f))

        if not rows:
            rows = [DB_HEADER.copy()]
        else:
            header = rows[0]
            # Старые архивы могут иметь старую/расширенную схему. Требуем
            # только поля, без которых невозможно безопасно сопоставить capture.
            required = {"original_url", "timestamp"}
            if not required.issubset(set(header)):
                LOGGER.warning('В _база.csv отсутствуют обязательные поля original_url/timestamp — обновление отменено')
                return

            # Простая миграция: приводим существующие строки к текущему
            # порядку DB_HEADER, сохраняя значения известных полей.
            if header != DB_HEADER:
                header_index = {name: i for i, name in enumerate(header)}
                migrated = [DB_HEADER.copy()]
                for old_row in rows[1:]:
                    migrated_row = []
                    for name in DB_HEADER:
                        idx = header_index.get(name)
                        migrated_row.append(old_row[idx] if idx is not None and idx < len(old_row) else "")
                    migrated.append(migrated_row)
                rows = migrated
                LOGGER.info('Мигрирован заголовок _база.csv к текущей схеме')
    else:
        rows = [DB_HEADER.copy()]

    key_to_index = {}
    for i, row in enumerate(rows[1:], start=1):
        if len(row) >= 3:
            key_to_index[(row[1], row[2])] = i

    for row in new_rows:
        if len(row) < len(DB_HEADER):
            continue
        key = (row[1], row[2])
        if key in key_to_index:
            rows[key_to_index[key]] = row
        else:
            key_to_index[key] = len(rows)
            rows.append(row)

    tmp = path + '.tmp'
    try:
        with open(tmp, 'w', newline='', encoding='utf-8-sig') as f:
            csv.writer(f).writerows(rows)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def is_permanent_download_failure(reason):
    """Определяет ошибки, которые бессмысленно долбить на каждом запуске.

    В частности, SHA-1 mismatch означает, что полученные байты не соответствуют
    конкретному historical capture; повтор той же ссылки не должен бесконечно
    перекачивать тот же ответ. HTTP 4xx (кроме 408/429) также считаем
    постоянными. Сетевые сбои остаются временными и продолжают доловливаться.
    """
    if isinstance(reason, urllib.error.HTTPError):
        return 400 <= reason.code < 500 and reason.code not in (408, 429)
    if isinstance(reason, ValueError):
        return True
    text = str(reason).lower()
    permanent_markers = (
        "sha-1 wayback digest не совпал",
        "файл больше лимита",
        "сервер вернул пустой файл",
        "http error 400", "http error 401", "http error 403",
        "http error 404", "http error 405", "http error 406",
        "http error 410", "http error 412", "http error 413",
        "http error 414", "http error 415", "http error 422",
        "http error 423", "http error 424", "http error 425",
        "http error 426", "http error 428", "http error 431",
        "http error 451",
    )
    return any(x in text for x in permanent_markers)


def format_failure_reason(reason):
    text = str(reason)[:300]
    return f"{PERMANENT_FAILURE_MARKER} {text}" if is_permanent_download_failure(reason) else text


def failed_row_is_permanent(row):
    reason = row.get("reason", "")
    if str(reason).lstrip().startswith(PERMANENT_FAILURE_MARKER):
        return True
    # Совместимость со старыми _не_скачалось.csv, созданными до 2.3.
    return is_permanent_download_failure(reason)


def permanent_failure_keys(rows):
    """Ключи permanent-ошибок. Digest входит в ключ намеренно: если Wayback
    позже изменит запись того же URL+timestamp на другой digest, это уже новый
    исторический объект, который можно попробовать скачать."""
    out = set()
    for row in rows or []:
        if failed_row_is_permanent(row):
            out.add(_failed_row_key(row))
    return out


def failed_queue_rows(domain_dir):
    path = os.path.join(domain_dir, FAILED_CSV)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f))
    except (OSError, csv.Error):
        return []


def _failed_row_to_list(row):
    """Нормализует запись очереди независимо от того, пришла ли она из
    DictReader или была только что создана download_one как список."""
    if isinstance(row, dict):
        return [row.get(k, "") for k in FAILED_HEADER]
    return list(row)


def _failed_row_key(row):
    if isinstance(row, dict):
        url = row.get("original_url", "")
        ts = row.get("timestamp", "")
        digest = row.get("digest", "")
    else:
        vals = list(row)
        url = vals[0] if len(vals) > 0 else ""
        ts = vals[1] if len(vals) > 1 else ""
        digest = vals[2] if len(vals) > 2 else ""
    return (str(url), str(ts), str(digest).strip().lower())


def write_failed_csv(domain_dir, failed_rows):
    path = os.path.join(domain_dir, FAILED_CSV)
    normalized = []
    seen = set()
    for row in failed_rows or []:
        vals = _failed_row_to_list(row)
        key = _failed_row_key(vals)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(vals)
    if not normalized:
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass
        return None

    tmp = path + ".tmp"
    try:
        with open(tmp, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(FAILED_HEADER)
            w.writerows(normalized)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
    return path


def normalize_store_digest(url, timestamp, digest):
    d = (digest or "").strip()
    if len(d) < 8 or d in {"-", "?"}:
        return "local_" + hashlib.sha1(f"{url}|{timestamp}".encode("utf-8")).hexdigest()
    return d


def store_path_for(domain_dir, digest):
    safe = sanitize_segment(digest) or "x"
    return os.path.join(domain_dir, DIR_STORE, safe[:2], safe)


def cleanup_part_files(domain_dir):
    store = os.path.join(domain_dir, DIR_STORE)
    removed = 0
    if not os.path.isdir(store):
        return 0
    for root, _, files in os.walk(store):
        for name in files:
            if name.endswith(".part") or name.endswith(".__own_copy"):
                try:
                    os.remove(os.path.join(root, name))
                    removed += 1
                except OSError:
                    pass
    return removed


def hide_store_folder(domain_dir):
    """_хранилище - техническая часть (там файлы лежат под именами-хэшами,
    без расширений). Помечаем её скрытой в Windows, чтобы не путала - в
    обычных папках (Документы/Фото/Версии) лежат ссылки с нормальными
    именами на эти же файлы."""
    if os.name != "nt":
        return
    path = os.path.join(domain_dir, DIR_STORE)
    if not os.path.isdir(path):
        return
    try:
        import ctypes
        FILE_ATTRIBUTE_HIDDEN = 0x02
        ctypes.windll.kernel32.SetFileAttributesW(path, FILE_ATTRIBUTE_HIDDEN)
    except Exception as e:
        LOGGER.debug(f"Не удалось скрыть {path}: {e}")


# ==================== ПУТИ ВНУТРИ ВЕРСИИ ====================

def build_relative_path(original_url):
    """ВАЖНО: путь обязан включать hostname, а не только path. Без этого
    example.com/about/ и blog.example.com/about/ строят один и тот же
    относительный путь 'about/index.html' и физически перетирают друг
    друга на диске при скачивании домена с поддоменами."""
    parsed = urllib.parse.urlsplit(original_url)
    host = sanitize_segment(parsed.netloc.lower()) or "_"
    parts = [sanitize_segment(p) for p in parsed.path.strip("/").split("/") if p]
    if not parts:
        parts = ["index.html"]
    elif "." not in parts[-1]:
        parts.append("index.html")
    if parsed.query:
        stem, ext = os.path.splitext(parts[-1])
        q = hashlib.sha1(parsed.query.encode()).hexdigest()[:12]
        parts[-1] = f"{stem}__q_{q}{ext}"
    return os.path.join(host, *parts)


def guard_path_length(full_path, fallback_dir, original_url, max_len=250):
    """Если путь всё равно вышел длиннее лимита Windows (даже после
    сокращения сегментов в sanitize_segment) - заменяем хвост на короткий
    хэш. Нужна ОДНА функция для всех мест, где строится путь к файлу
    (версии, свежий сайт и т.д.), а не отдельная копия в каждом - иначе
    защиту легко забыть добавить в новом месте, что и произошло с
    build_latest_site."""
    if len(full_path) <= max_len:
        return full_path
    tail = hashlib.sha1(original_url.encode()).hexdigest()[:12]
    ext = os.path.splitext(full_path)[1] or ""
    return os.path.join(fallback_dir, f"{tail}{ext}")


def build_version_path(domain_dir, original_url, timestamp):
    rel = build_relative_path(original_url)
    version_dir = os.path.join(domain_dir, DIR_VERSIONS, folder_ts(timestamp))
    full = os.path.join(version_dir, rel)
    return guard_path_length(full, version_dir, original_url)


# ==================== СКАЧИВАНИЕ ====================

def _sha1_base32_from_file(path):
    import base64
    h = hashlib.sha1()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(256 * 1024), b""):
            size += len(chunk)
            h.update(chunk)
    return base64.b32encode(h.digest()).decode("ascii").rstrip("=").lower(), size


def _sha256_and_size(path):
    h = hashlib.sha256()
    size = 0
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(256 * 1024), b''):
            size += len(chunk)
            h.update(chunk)
    return h.hexdigest(), size


def _verify_store_file(path, expected_digest, expected_sha256=None):
    """Одна проверка физического файла за запуск; результат кэшируется по
    mtime/size. Возвращает (valid, sha256, size), чтобы не читать файл второй раз."""
    key = _store_cache_key(path, expected_digest, expected_sha256)
    if key in _STORE_VERIFY_CACHE:
        return _STORE_VERIFY_CACHE[key]
    try:
        if not os.path.isfile(path) or os.path.getsize(path) <= 0:
            result = (False, '', 0)
        else:
            sha256, size = _sha256_and_size(path)
            valid = True
            if expected_sha256 and sha256.lower() != str(expected_sha256).lower():
                valid = False
            if valid and not str(expected_digest).startswith('local_'):
                digest, _ = _sha1_base32_from_file(path)
                if digest != str(expected_digest).strip().lower():
                    valid = False
            result = (valid, sha256, size)
    except OSError:
        result = (False, '', 0)
    key = _store_cache_key(path, expected_digest, expected_sha256)
    if key is not None:
        _STORE_VERIFY_CACHE[key] = result
    return result


def _store_file_is_valid(path, expected_digest, expected_sha256=None):
    return _verify_store_file(path, expected_digest, expected_sha256)[0]


def _download_to_store(raw_url, store_file, expected_digest):
    part = store_file + ".part"
    try:
        if os.path.exists(part):
            os.remove(part)
    except OSError:
        pass
    req = urllib.request.Request(raw_url, headers=HEADERS)
    real_attempt = 0
    attempts_429 = 0
    max_429_retries = 4
    last_exc = None
    while real_attempt < MAX_RETRIES:
        try:
            ensure_parent_dir(store_file)
            h1 = hashlib.sha1()
            h256 = hashlib.sha256()
            size = 0
            with urlopen_throttled(req, REQUEST_TIMEOUT, context=raw_url) as resp:
                with open(part, "wb") as f:
                    while True:
                        chunk = resp.read(256 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_FILE_BYTES:
                            raise ValueError(f"файл больше лимита {human_size(MAX_FILE_BYTES)}")
                        h1.update(chunk)
                        h256.update(chunk)
                        f.write(chunk)
                    f.flush()
                    os.fsync(f.fileno())
            if size <= 0:
                raise ValueError("сервер вернул пустой файл")
            digest_b32 = __import__("base64").b32encode(h1.digest()).decode("ascii").rstrip("=").lower()
            if not str(expected_digest).startswith("local_") and digest_b32 != str(expected_digest).strip().lower():
                content_type = ""
                content_length = ""
                try:
                    content_type = resp.headers.get("Content-Type", "")
                    content_length = resp.headers.get("Content-Length", "")
                except Exception:
                    pass
                raise ValueError(
                    "SHA-1 Wayback digest не совпал — файл отброшен; "
                    f"expected={str(expected_digest).strip().lower()}, actual={digest_b32}, "
                    f"bytes={size}, Content-Length={content_length or "?"}, Content-Type={content_type or "?"}"
                )
            sha256 = h256.hexdigest()
            os.replace(part, store_file)
            CIRCUIT_BREAKER.success()
            return size, sha256, None
        except urllib.error.HTTPError as e:
            last_exc = e
            if e.code == 429 and attempts_429 < max_429_retries:
                attempts_429 += 1
                continue
            if 400 <= e.code < 500 and e.code not in (408, 429):
                break
            real_attempt += 1
            if real_attempt >= MAX_RETRIES:
                break
            interruptible_sleep(RETRY_DELAY * real_attempt)
        except ValueError as e:
            # Это не сетевой сбой: размер/пустой ответ/digest mismatch.
            # Повторять тот же historical capture бессмысленно.
            last_exc = e
            break
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            last_exc = e
            real_attempt += 1
            if real_attempt >= MAX_RETRIES:
                break
            interruptible_sleep(RETRY_DELAY * real_attempt)
        except Exception as e:
            last_exc = e
            real_attempt += 1
            if real_attempt >= MAX_RETRIES:
                break
            interruptible_sleep(RETRY_DELAY * real_attempt)
        finally:
            if os.path.exists(part):
                try:
                    os.remove(part)
                except OSError:
                    pass
    if last_exc is not None and _local_error_is_permanent(last_exc):
        last_exc = ValueError("[PERMANENT] локальная ошибка файловой системы: " + str(last_exc))
    return None, None, last_exc


def _local_error_is_permanent(exc):
    """Локальные ошибки, которые бессмысленно повторять в этом же запуске."""
    if isinstance(exc, (PermissionError, FileNotFoundError)):
        return True
    if isinstance(exc, OSError) and getattr(exc, "winerror", None) in (123, 206):
        return True
    return False


def download_one(record, domain_dir, db_by_digest, new_db_rows, lock,
                 counters, total, failed_rows):
    url = record['original']
    ts = record['timestamp']
    digest = normalize_store_digest(url, ts, record.get('digest', ''))
    store_file = store_path_for(domain_dir, digest)
    ext = get_extension(url)
    is_html = ext in HTML_EXTS or record.get('mimetype', '').startswith('text/html')

    def fail(reason):
        counters['failed'] += 1
        failed_rows.append([url, ts, record.get('digest', ''), record.get('mimetype', ''),
                            record.get('statuscode', ''), record.get('length', ''), format_failure_reason(reason)])

    # Один физический digest скачивается/проверяется под одним lock. Это важно
    # при collapse=digest и при повторных capture одной версии.
    with _store_lock_for(store_file):
        known = db_by_digest.get(digest)
        expected_sha = known.get('sha256', '') if known else ''
        reused, sha, size = _verify_store_file(store_file, digest, expected_sha)

        if reused:
            with lock:
                counters['reused'] += 1
        else:
            raw_url = f'https://web.archive.org/web/{ts}id_/{url}'
            size, sha, error = _download_to_store(raw_url, store_file, digest)
            if error is not None:
                with lock:
                    fail(error)
                LOGGER.error(f'FAIL {url} @ {ts}: {error}')
                return
            # Файл только что полностью скачан, SHA-1 Wayback digest и
            # SHA-256 уже посчитаны во время стриминга. Кладём результат в тот
            # же кэш, чтобы повторные capture с тем же digest не читали файл
            # с диска ещё раз в этом запуске.
            cache_key = _store_cache_key(store_file, digest, sha)
            if cache_key is not None:
                _STORE_VERIFY_CACHE[cache_key] = (True, sha, size)
            with lock:
                counters['done'] += 1

    try:
        version_file = build_version_path(domain_dir, url, ts)
        if is_html:
            # HTML — отдельная mutable-копия. Никогда не открываем hardlink на
            # запись: atomic replace отсоединяет его от store без лишнего полного
            # копирования старого файла.
            if not os.path.exists(version_file) or os.path.getsize(version_file) <= 0 or not reused:
                atomic_copy_file(store_file, version_file)
        elif (not os.path.exists(version_file) or
              not derived_file_matches_store(store_file, version_file, digest, sha)):
            try:
                if os.path.exists(version_file):
                    os.remove(version_file)
            except OSError:
                pass
            link_or_copy(store_file, version_file)
    except Exception as e:
        LOGGER.error(f'Раскладка {url} @ {ts}: {e}')

    with lock:
        new_db_rows.append([
            digest, url, ts, record.get('mimetype', ''), record.get('statuscode', ''),
            size, sha, os.path.relpath(store_file, domain_dir),
            datetime.now().strftime('%Y-%m-%d %H:%M'),
        ])
        db_by_digest[digest] = {'size_bytes': size, 'sha256': sha, 'store_path': os.path.relpath(store_file, domain_dir)}
        progress = counters['done'] + counters['reused'] + counters['failed']
        if progress % 25 == 0 or progress == total:
            print(f"  [{progress}/{total}] новых: {counters['done']}, уже было: {counters['reused']}, ошибок: {counters['failed']}")


# ==================== РАСКЛАДКА: ДОКУМЕНТЫ, ФОТО, СВЕЖИЙ САЙТ ====================

MIME_TO_EXT = {
    "application/pdf": "pdf",
    "application/msword": "doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.ms-excel": "xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.ms-powerpoint": "ppt",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/rtf": "rtf",
    "application/zip": "zip",
    "application/vnd.oasis.opendocument.text": "odt",
    "application/vnd.oasis.opendocument.spreadsheet": "ods",
    "application/vnd.oasis.opendocument.presentation": "odp",
    "image/jpeg": "jpg", "image/png": "png", "image/gif": "gif",
    "image/webp": "webp", "image/bmp": "bmp", "image/tiff": "tif", "image/svg+xml": "svg",
}


def classify_doc_ext(original_url, mimetype):
    """Расширение по URL - не всегда правда: документ может отдаваться через
    download.php?id=123 или export.asp, и тогда get_extension() вернёт
    'php'/'asp', а файл потеряется - не попадёт ни в 02_ДОКУМЕНТЫ, ни на
    разбор метаданных. Wayback помнит настоящий Content-Type - используем
    его как запасной критерий, когда расширение непохоже на документ."""
    ext = get_extension(original_url)
    if ext in DOC_EXTS or ext in IMG_EXTS:
        return ext
    mime_clean = (mimetype or "").split(";")[0].strip().lower()
    return MIME_TO_EXT.get(mime_clean, ext)


def nice_filename(url, ts, digest, forced_ext=None):
    base = os.path.basename(urllib.parse.urlsplit(url).path) or "файл"
    base = sanitize_segment(urllib.parse.unquote(base))
    stem, ext = os.path.splitext(base)
    if forced_ext and ext.lstrip(".").lower() != forced_ext.lower():
        # реальный тип определили по mimetype (например download.php оказался
        # pdf) - имя файла должно получить рабочее расширение, иначе Windows
        # не поймёт, чем это открывать, даже когда файл лежит в 02_ДОКУМЕНТЫ
        stem = stem or "файл"
        ext = "." + forced_ext
    return f"{date_only(ts)}_{stem}{ext}"


def organize_by_type(domain_dir, all_rows):
    """Документы и фото - в свои папки (жёсткими ссылками, место не тратится)."""
    docs = photos = 0
    dest_owners = {}
    for r in all_rows:
        url, ts, digest = r["original_url"], r["timestamp"], r["digest"]
        ext = classify_doc_ext(url, r.get("mimetype", ""))
        store_file = os.path.join(domain_dir, r["store_path"])
        if not os.path.isfile(store_file):
            continue

        if ext in DOC_EXTS:
            dest_dir = os.path.join(domain_dir, DIR_DOCS, ext)
            docs += 1
        elif ext in IMG_EXTS:
            dest_dir = os.path.join(domain_dir, DIR_PHOTOS)
            photos += 1
        else:
            continue

        name = nice_filename(url, ts, digest, forced_ext=ext)
        dest = os.path.join(dest_dir, name)
        owner_key = os.path.normcase(os.path.normpath(dest))
        owner = dest_owners.get(owner_key)
        if owner is None:
            dest_owners[owner_key] = digest
        elif owner != digest:
            stem, e = os.path.splitext(name)
            dest = os.path.join(dest_dir, f"{stem}_{digest[:6]}{e}")
        try:
            if os.path.exists(dest):
                if derived_file_matches_store(store_file, dest, digest, r.get("sha256", "")):
                    continue
                # Для того же digest это восстановление stale/corrupt derived-файла.
                # При коллизии имени выше уже выбран отдельный digest-suffix.
                os.remove(dest)
            link_or_copy(store_file, dest)
        except Exception as e:
            LOGGER.debug(f"Раскладка по типу {url}: {e}")
    return docs, photos


def build_latest_site(domain_dir, all_rows):
    """Свежая версия каждой страницы в одном месте - чтобы листать как живой сайт."""
    latest = {}
    for r in all_rows:
        key = build_relative_path(r["original_url"])
        cur = latest.get(key)
        if cur is None or r["timestamp"] > cur["timestamp"]:
            latest[key] = r

    placed = []
    for rel, r in latest.items():
        store_file = os.path.join(domain_dir, r["store_path"])
        if not os.path.isfile(store_file):
            continue
        latest_dir = os.path.join(domain_dir, DIR_LATEST)
        dest = guard_path_length(os.path.join(latest_dir, rel), latest_dir, r["original_url"])
        ext = get_extension(r["original_url"])
        is_html = ext in HTML_EXTS or r.get("mimetype", "").startswith("text/html")
        try:
            if is_html:
                if not os.path.exists(dest):
                    atomic_copy_file(store_file, dest)
            else:
                if (not os.path.exists(dest) or
                        not derived_file_matches_store(store_file, dest, r["digest"], r.get("sha256", ""))):
                    if os.path.exists(dest):
                        os.remove(dest)
                    link_or_copy(store_file, dest)
            placed.append((r["original_url"], dest))
        except Exception as e:
            LOGGER.debug(f"Свежий сайт {r['original_url']}: {e}")
    return placed


# ==================== ОФЛАЙН-ССЫЛКИ ====================

REWRITE_ATTR = {"a": "href", "link": "href", "script": "src", "img": "src",
                 "iframe": "src", "form": "action", "source": "src",
                 "video": "src", "audio": "src", "embed": "src"}
SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:")
TAG_RE = re.compile(r"<[^>]+>")


def normalize_link_key(url):
    parts = urllib.parse.urlsplit(urllib.parse.urldefrag(url)[0])
    host = parts.hostname.lower() if parts.hostname else ""
    port = parts.port
    if port and not ((parts.scheme.lower() == "http" and port == 80) or
                     (parts.scheme.lower() == "https" and port == 443)):
        host = f"{host}:{port}"
    path = parts.path or "/"
    path = path.rstrip("/") or "/"
    return urllib.parse.urlunsplit((parts.scheme.lower(), host, path, parts.query, ""))


def _registry_keys(url):
    p = urllib.parse.urlsplit(urllib.parse.urldefrag(url)[0])
    base = urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))
    keys = {normalize_link_key(base)}
    path = p.path or "/"
    if path.endswith("/"):
        keys.add(normalize_link_key(base.rstrip("/") + "/index.html"))
    elif not os.path.splitext(path.rsplit("/", 1)[-1])[1]:
        keys.add(normalize_link_key(base + "/"))
        keys.add(normalize_link_key(base.rstrip("/") + "/index.html"))
    elif path.endswith("/index.html"):
        alt = path[:-10] or "/"
        keys.add(normalize_link_key(p._replace(path=alt).geturl()))
    return keys


def detect_html_encoding(raw_bytes):
    head = raw_bytes[:4096].decode("ascii", errors="ignore")
    m = re.search(r'charset=["\']?\s*([\w-]+)', head, re.IGNORECASE)
    return m.group(1).lower() if m else None


def decode_html(raw_bytes):
    enc = detect_html_encoding(raw_bytes)
    tried = []
    for candidate in filter(None, [enc, "utf-8", "cp1251", "koi8-r", "cp866"]):
        if candidate in tried:
            continue
        tried.append(candidate)
        try:
            return raw_bytes.decode(candidate)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def fix_charset_meta(text):
    meta_re = re.compile(r'<meta[^>]+charset=["\']?[\w-]+["\']?[^>]*>', re.IGNORECASE)
    if meta_re.search(text):
        return meta_re.sub('<meta charset="utf-8">', text, count=1)
    head_re = re.compile(r'(<head[^>]*>)', re.IGNORECASE)
    if head_re.search(text):
        return head_re.sub(r'\1<meta charset="utf-8">', text, count=1)
    return '<meta charset="utf-8">' + text


def _replace_attr_in_raw_tag(raw_tag, attr_name, old_value, new_value):
    """Меняет значение одного атрибута, учитывая HTML-экранирование."""
    candidates = [old_value]
    escaped_html = html_mod.escape(old_value, quote=False)
    if escaped_html != old_value:
        candidates.append(escaped_html)
    for candidate in candidates:
        escaped_val = re.escape(candidate)
        quoted = re.compile(
            r'(\b%s\s*=\s*)(["\'])%s\2' % (re.escape(attr_name), escaped_val),
            re.IGNORECASE)
        new_tag, n = quoted.subn(
            lambda m: f"{m.group(1)}{m.group(2)}{new_value}{m.group(2)}", raw_tag, count=1)
        if n:
            return new_tag, True
        unquoted = re.compile(
            r'(\b%s\s*=\s*)(?!["\'])%s(?=[\s/>]|$)' % (re.escape(attr_name), escaped_val),
            re.IGNORECASE)
        new_tag, n = unquoted.subn(
            lambda m: f'{m.group(1)}"{new_value}"', raw_tag, count=1)
        if n:
            return new_tag, True
    return raw_tag, False


CSS_URL_RE = re.compile(r'url\(\s*(["\']?)([^"\')]+?)\1\s*\)', re.IGNORECASE)
CSS_IMPORT_RE = re.compile(r'@import\s+(["\'])([^"\']+)\1', re.IGNORECASE)


def rewrite_css_content(css_text, base_url, current_path, registry):
    """url(...) и @import "..." в CSS не трогались rewrite'ом ссылок вообще -
    для офлайн-копии это одна из главных причин 'сайт скачался, но выглядит
    как труп' (фоны, шрифты, импортированные стили тянутся с живого сайта).
    Работает и для инлайновых <style>, и для отдельных .css файлов - разница
    только в том, что считать base_url для относительных путей."""
    changed = [0]

    def resolve_and_relativize(link):
        link = link.strip()
        if not link or link.lower().startswith("data:"):
            return None
        try:
            absolute = urllib.parse.urljoin(base_url, link)
        except ValueError:
            return None
        target = registry.get(normalize_link_key(absolute))
        if not target:
            return None
        rel = os.path.relpath(target, os.path.dirname(current_path)).replace(os.sep, "/")
        return rel if rel != link else None

    def replace_url(match):
        quote, link = match.group(1), match.group(2)
        new_link = resolve_and_relativize(link)
        if new_link:
            changed[0] += 1
            q = quote or ""
            return f"url({q}{new_link}{q})"
        return match.group(0)

    def replace_import(match):
        quote, link = match.group(1), match.group(2)
        new_link = resolve_and_relativize(link)
        if new_link:
            changed[0] += 1
            return f"@import {quote}{new_link}{quote}"
        return match.group(0)

    text = CSS_URL_RE.sub(replace_url, css_text)
    text = CSS_IMPORT_RE.sub(replace_import, text)
    return text, changed[0]


SRCSET_TAGS = {"img", "source"}


class LinkRewriter(HTMLParser):
    """Настоящий разбор тегов вместо регулярки по всему файлу. Текст,
    комментарии, script/style и всё остальное копируется как есть -
    трогаются только href/src/action/srcset в конкретных тегах."""

    def __init__(self, resolve_fn, registry=None, base_url=None, current_path=None):
        super().__init__(convert_charrefs=False)
        self.out = []
        self.resolve_fn = resolve_fn
        self.changed = 0
        self._registry = registry
        self._base_url = base_url
        self._current_path = current_path
        self._in_style = False

    def _rewrite_srcset(self, value):
        """srcset='small.jpg 480w, medium.jpg 1024w' - список URL с
        дескрипторами через запятую, каждый URL надо резолвить отдельно."""
        parts, changed_here = [], False
        for chunk in value.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            bits = chunk.split(None, 1)
            url, descriptor = bits[0], (bits[1] if len(bits) > 1 else "")
            new_url = self.resolve_fn(url)
            if new_url and new_url != url:
                changed_here = True
                url = new_url
            parts.append(f"{url} {descriptor}".strip())
        return ", ".join(parts), changed_here

    def _emit_tag(self, tag):
        if tag.lower() == "base":
            # <base href="https://x.ru/"> заставит браузер резолвить ВСЕ
            # относительные ссылки на странице против живого сайта, даже
            # если мы аккуратно переписали их на локальные пути - вся
            # офлайн-навигация сломается молча, без единой ошибки в консоли
            self.out.append("<!-- удалён тег <base>, ломал офлайн-ссылки -->")
            self.changed += 1
            return

        raw = self.get_starttag_text() or ""
        target_attr = REWRITE_ATTR.get(tag.lower())
        if target_attr:
            for name, value in self.get_starttag_attrs():
                if name.lower() != target_attr or not value:
                    continue
                low = value.strip().lower()
                if low.startswith("#") or low.startswith(SKIP_SCHEMES):
                    break
                new_value = self.resolve_fn(value)
                if new_value and new_value != value:
                    raw, ok = _replace_attr_in_raw_tag(raw, target_attr, value, new_value)
                    if ok:
                        self.changed += 1
                break

        if tag.lower() in SRCSET_TAGS:
            for name, value in self.get_starttag_attrs():
                if name.lower() == "srcset" and value:
                    new_srcset, ch = self._rewrite_srcset(value)
                    if ch:
                        raw, ok = _replace_attr_in_raw_tag(raw, "srcset", value, new_srcset)
                        if ok:
                            self.changed += 1
                    break

        self.out.append(raw)

    def get_starttag_attrs(self):
        return self._current_attrs

    def handle_starttag(self, tag, attrs):
        self._current_attrs = attrs
        if tag.lower() == "style":
            self._in_style = True
        self._emit_tag(tag)

    def handle_startendtag(self, tag, attrs):
        self._current_attrs = attrs
        self._emit_tag(tag)

    def handle_endtag(self, tag):
        if tag.lower() == "style":
            self._in_style = False
        self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if self._in_style and self._registry is not None:
            new_css, n = rewrite_css_content(data, self._base_url, self._current_path, self._registry)
            self.changed += n
            self.out.append(new_css)
        else:
            self.out.append(data)

    def handle_comment(self, data):
        self.out.append(f"<!--{data}-->")

    def handle_decl(self, decl):
        self.out.append(f"<!{decl}>")

    def handle_pi(self, data):
        self.out.append(f"<?{data}>")

    def handle_entityref(self, name):
        self.out.append(f"&{name};")

    def handle_charref(self, name):
        self.out.append(f"&#{name};")

    def get_html(self):
        return "".join(self.out)


def break_hardlink_if_needed(path):
    """Совместимость со старыми вызовами. Само копирование здесь больше не
    делаем: безопасная запись должна идти во временный файл + os.replace(),
    что автоматически отсоединяет каталог от общего store-инода."""
    return False


def atomic_write_bytes(path, data):
    ensure_parent_dir(path)
    tmp = path + '.__rewrite_tmp'
    try:
        with open(tmp, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def atomic_copy_file(src, dst):
    ensure_parent_dir(dst)
    tmp = dst + '.__copy_tmp'
    try:
        with open(src, 'rb') as fs, open(tmp, 'wb') as fd:
            for chunk in iter(lambda: fs.read(1024 * 1024), b''):
                fd.write(chunk)
            fd.flush()
            os.fsync(fd.fileno())
        os.replace(tmp, dst)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def rewrite_links_in_group(pairs, edges=None):
    """pairs = [(original_url, абсолютный путь к файлу)] в пределах одной папки.
    edges (опционально) - сюда добавляются (источник, цель, нашли_локально)
    для графа ссылок - раз мы всё равно резолвим каждую ссылку, почти бесплатно
    заодно запомнить, откуда куда она вела."""
    registry = {}
    for url, path in pairs:
        for key in _registry_keys(url):
            registry.setdefault(key, path)

    changed_total = 0
    for url, path in pairs:
        low_path = path.lower()

        if low_path.endswith(".css"):
            try:
                with open(path, "rb") as f:
                    css_raw = f.read()
                css_text = decode_html(css_raw)
                new_css, n = rewrite_css_content(css_text, url, path, registry)
                if n:
                    atomic_write_bytes(path, new_css.encode("utf-8"))
                    changed_total += n
            except Exception as e:
                LOGGER.debug(f"CSS rewrite {path}: {e}")
            continue

        if not low_path.endswith((".html", ".htm", ".xhtml", ".shtml")):
            continue
        try:
            with open(path, "rb") as f:
                raw = f.read()
            text = decode_html(raw)
        except Exception as e:
            LOGGER.debug(f"Rewrite чтение {path}: {e}")
            continue

        def resolve(link, _url=url, _path=path):
            try:
                absolute = urllib.parse.urljoin(_url, link)
            except ValueError:
                return None
            target = registry.get(normalize_link_key(absolute))
            if edges is not None and absolute.startswith(("http://", "https://")):
                edges.append((_url, absolute, target is not None))
            if not target:
                return None
            return os.path.relpath(target, os.path.dirname(_path)).replace(os.sep, "/")

        try:
            rewriter = LinkRewriter(resolve, registry=registry, base_url=url, current_path=path)
            rewriter.feed(text)
            rewriter.close()
            new_text = fix_charset_meta(rewriter.get_html())
        except Exception as e:
            # совсем битая разметка - оставляем файл как есть, не рискуем его испортить
            LOGGER.debug(f"Rewrite разбор {path}: {e}")
            continue

        try:
            atomic_write_bytes(path, new_text.encode("utf-8"))
            changed_total += rewriter.changed
        except Exception as e:
            LOGGER.debug(f"Rewrite запись {path}: {e}")
    return changed_total


def rewrite_all_versions(domain_dir, all_rows, latest_pairs):
    by_version = {}
    for r in all_rows:
        folder = folder_ts(r["timestamp"])
        path = build_version_path(domain_dir, r["original_url"], r["timestamp"])
        if os.path.isfile(path):
            by_version.setdefault(folder, []).append((r["original_url"], path))

    total = 0
    edges = []
    for folder, pairs in by_version.items():
        total += rewrite_links_in_group(pairs, edges)
    total += rewrite_links_in_group(latest_pairs, edges)
    return total, edges


def report_link_graph(domain_dir, edges, all_rows):
    if not edges:
        return None
    known_urls = {r["original_url"] for r in all_rows}
    incoming = {}
    external_domains = {}

    for source, target, is_internal in edges:
        if is_internal:
            incoming.setdefault(target, set()).add(source)
        else:
            host = urllib.parse.urlsplit(target).netloc.lower()
            if host:
                external_domains[host] = external_domains.get(host, 0) + 1

    most_linked = sorted(incoming.items(), key=lambda kv: -len(kv[1]))[:30]

    isolated_pages, isolated_docs = [], []
    for url in known_urls:
        if url in incoming:
            continue
        ext = get_extension(url)
        if ext in HTML_EXTS:
            isolated_pages.append(url)
        elif ext in DOC_EXTS:
            isolated_docs.append(url)

    reports_dir = os.path.join(domain_dir, DIR_REPORTS)
    os.makedirs(reports_dir, exist_ok=True)
    path = os.path.join(reports_dir, "граф_ссылок.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("ГРАФ ССЫЛОК\n")
        f.write(f"Всего связей между страницами: {len(edges)}\n")
        f.write("=" * 78 + "\n\n")

        f.write("САМЫЕ СВЯЗАННЫЕ СТРАНИЦЫ (топ 30 по входящим ссылкам):\n")
        for u, sources in most_linked:
            f.write(f"  {len(sources):>4} вход.  {u}\n")

        f.write(f"\nСТРАНИЦЫ БЕЗ ВХОДЯЩИХ ССЫЛОК ({len(isolated_pages)}):\n")
        f.write("  (на них никто внутри сайта не ссылается - найдены только через CDX,\n"
                "   значит либо убрали ссылку, либо страница никогда и не была публичной)\n")
        for u in sorted(isolated_pages)[:100]:
            f.write(f"  {u}\n")
        if len(isolated_pages) > 100:
            f.write(f"  ... и ещё {len(isolated_pages) - 100}\n")

        f.write(f"\nДОКУМЕНТЫ БЕЗ ССЫЛОК С HTML-СТРАНИЦ ({len(isolated_docs)}):\n")
        for u in sorted(isolated_docs)[:100]:
            f.write(f"  {u}\n")

        f.write(f"\nВНЕШНИЕ ДОМЕНЫ, НА КОТОРЫЕ ССЫЛАЕТСЯ САЙТ ({len(external_domains)}):\n")
        for host, count in sorted(external_domains.items(), key=lambda kv: -kv[1])[:50]:
            f.write(f"  {count:>4}  {host}\n")

    top = most_linked[0][0] if most_linked else "-"
    print(f"  граф ссылок: {len(edges)} связей, изолированных страниц: {len(isolated_pages)}")
    return path


# ==================== УДАЛЁННЫЕ СТРАНИЦЫ ====================

def fetch_status_history(url_value, match_type):
    params = {"url": url_value, "fl": "original,timestamp,statuscode",
              "limit": str(CDX_PAGE_SIZE)}
    if match_type != "exact":
        params["matchType"] = match_type
    cdx_url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(cdx_url, headers=HEADERS)
    with urlopen_throttled(req, 90, context="история статусов") as resp:
        lines = [l.decode("utf-8", errors="replace").strip() for l in resp]
    records = []
    for line in lines:
        parts = line.split(" ")
        if len(parts) == 3:
            records.append({"original": parts[0], "timestamp": parts[1], "statuscode": parts[2]})
    return records


def report_deleted_pages(domain, domain_dir):
    print("\nИщу страницы, которые раньше работали, а потом исчезли...")
    records = []
    for match_type, description in CDX_MATCH_CHAIN:
        url_value = domain if match_type != "exact" else domain.rstrip("/") + "/"
        try:
            records = fetch_status_history(url_value, match_type)
        except Exception as e:
            LOGGER.warning(f"Удалённые: режим {match_type} не ответил ({e})")
            continue
        if records:
            break

    if not records:
        print("  не удалось получить историю статусов (архив недоступен)")
        return []

    by_url = {}
    for r in records:
        by_url.setdefault(r["original"], []).append(r)

    deleted = []
    for url, items in by_url.items():
        items.sort(key=lambda x: x["timestamp"])
        statuses = [i["statuscode"] for i in items]
        if any(s == "200" for s in statuses) and statuses[-1].startswith(("4", "5")):
            last_ok = max(i["timestamp"] for i in items if i["statuscode"] == "200")
            deleted.append({"url": url, "last_ok": last_ok,
                            "died_at": items[-1]["timestamp"],
                            "last_status": statuses[-1]})
    deleted.sort(key=lambda d: d["died_at"], reverse=True)

    reports_dir = os.path.join(domain_dir, DIR_REPORTS)
    os.makedirs(reports_dir, exist_ok=True)
    path = os.path.join(reports_dir, "удалённые_страницы.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"УДАЛЁННЫЕ СТРАНИЦЫ: {domain}\n")
        f.write(f"Проверено адресов: {len(by_url)}   Найдено удалённых: {len(deleted)}\n")
        f.write("=" * 78 + "\n\n")
        for d in deleted:
            f.write(f"{d['url']}\n")
            f.write(f"  работала до: {pretty_ts(d['last_ok'])}\n")
            f.write(f"  стала недоступна ({d['last_status']}): {pretty_ts(d['died_at'])}\n\n")

    print(f"  найдено удалённых страниц: {len(deleted)}")
    return deleted


# ==================== МЕТАДАННЫЕ ДОКУМЕНТОВ ====================

PDF_FIELDS = ["Author", "Creator", "Producer", "Title", "Subject",
              "Company", "CreationDate", "ModDate"]

FLATE_STREAM_RE = re.compile(rb"stream\r?\n(.*?)endstream", re.DOTALL)
MAX_STREAM_INPUT = 400_000   # сжатые потоки крупнее этого не трогаем (обычно это картинки, не метаданные)
MAX_STREAM_OUTPUT = 2_000_000


def looks_like_text(s: str, min_ratio: float = 0.85) -> bool:
    """Отсеивает мусор: если распакованное 'значение' на самом деле битые
    байты сжатого потока, оно будет полно непечатаемых символов."""
    if not s or len(s) > 500:
        return False
    good = sum(1 for ch in s if ch.isprintable())
    return (good / len(s)) >= min_ratio


def is_probably_pdf(data: bytes) -> bool:
    return data[:5] == b"%PDF-"


def is_probably_office_zip(data: bytes) -> bool:
    return data[:2] == b"PK"


PLAUSIBLE_TEXT_RANGES = (
    (0x0000, 0x007F),   # ASCII: латиница, цифры, пунктуация, пробелы
    (0x00A0, 0x024F),   # доп. латиница (умляуты, акценты и т.п.)
    (0x0400, 0x04FF),   # кириллица
)


def looks_like_plausible_script(s: str) -> bool:
    """Для варианта БЕЗ BOM печатаемости недостаточно: случайная пара ASCII-
    байт (например слово 'Word') иногда декодируется в валидный, но
    бессмысленный иероглиф CJK - он тоже 'печатаемый', но это не текст.
    Требуем, чтобы буквы были из ожидаемых для этого инструмента алфавитов."""
    if not s:
        return False
    return all(any(lo <= ord(ch) <= hi for lo, hi in PLAUSIBLE_TEXT_RANGES) for ch in s)


def smart_decode_pdf_bytes(raw: bytes):
    """PDF-строка может быть обычным текстом (PDFDocEncoding, для наших целей
    ~= latin-1) или UTF-16BE. По спецификации UTF-16BE должен начинаться с
    метки FE FF, но часть генераторов (особенно отечественных) эту метку не
    пишет. Поэтому пробуем оба варианта и берём тот, что реально похож на
    текст, а не молча ломаем всё, что без метки."""
    if raw.startswith(b"\xfe\xff"):
        try:
            txt = raw[2:].decode("utf-16-be")
            if looks_like_text(txt):   # BOM - явный сигнал, алфавит не ограничиваем
                return txt
        except UnicodeDecodeError:
            pass
    elif raw.startswith(b"\xff\xfe"):
        try:
            txt = raw[2:].decode("utf-16-le")
            if looks_like_text(txt):
                return txt
        except UnicodeDecodeError:
            pass
    elif len(raw) % 2 == 0 and len(raw) >= 4:
        try:
            txt = raw.decode("utf-16-be")
            # без BOM - доверяем меньше: и печатаемо, и алфавит ожидаемый
            if looks_like_text(txt) and looks_like_plausible_script(txt):
                return txt
        except UnicodeDecodeError:
            pass

    latin = raw.decode("latin-1", errors="replace")
    return latin if looks_like_text(latin) else None


PDF_SIMPLE_ESCAPES = {"n": 0x0A, "r": 0x0D, "t": 0x09, "b": 0x08, "f": 0x0C,
                       "(": 0x28, ")": 0x29, "\\": 0x5C}


def decode_pdf_literal_string(raw: str) -> bytes:
    """raw - содержимое литеральной PDF-строки (между круглыми скобками),
    ещё БЕЗ разбора escape-последовательностей. Каждый символ raw - это
    один исходный байт (строка была прочитана как latin-1). По спецификации
    PDF внутри таких строк не-ASCII текст (включая UTF-16BE с BOM) почти
    всегда закодирован восьмеричными \\ddd-последовательностями - раньше
    они просто копировались как есть, отсюда мешанина вида '\\376\\377...'
    в отчёте вместо настоящего текста."""
    out = bytearray()
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch != "\\":
            out.append(ord(ch) & 0xFF)
            i += 1
            continue
        i += 1
        if i >= n:
            break
        nxt = raw[i]
        if nxt in PDF_SIMPLE_ESCAPES:
            out.append(PDF_SIMPLE_ESCAPES[nxt])
            i += 1
        elif nxt in "01234567":
            digits = nxt
            i += 1
            for _ in range(2):
                if i < n and raw[i] in "01234567":
                    digits += raw[i]
                    i += 1
                else:
                    break
            out.append(int(digits, 8) & 0xFF)
        elif nxt == "\r":
            i += 1
            if i < n and raw[i] == "\n":   # экранированный перенос строки - пропускаем целиком
                i += 1
        elif nxt == "\n":
            i += 1
        else:
            # обратная косая черта перед чем-то незнакомым по спеке игнорируется
            out.append(ord(nxt) & 0xFF)
            i += 1
    return bytes(out)


def _pdf_decode_value(raw: str):
    if raw.startswith("<") and raw.endswith(">"):
        hexpart = re.sub(r"\s", "", raw[1:-1])
        if len(hexpart) % 2:
            hexpart = hexpart[:-1]
        try:
            data = bytes.fromhex(hexpart)
        except ValueError:
            return None
    else:
        inner = raw[1:-1] if raw.startswith("(") and raw.endswith(")") else raw
        data = decode_pdf_literal_string(inner)
    return smart_decode_pdf_bytes(data)


def iter_decompressed_streams(data: bytes):
    """PDF может прятать словарь метаданных внутри сжатого Object Stream
    (/Type/ObjStm) - тогда как текст /Author и т.д. в файле просто не
    встречается, он есть только после распаковки zlib."""
    import zlib
    for m in FLATE_STREAM_RE.finditer(data):
        chunk = m.group(1)
        if len(chunk) > MAX_STREAM_INPUT:
            continue
        try:
            out = zlib.decompressobj().decompress(chunk, MAX_STREAM_OUTPUT)
        except zlib.error:
            continue
        if out:
            yield out.decode("latin-1", errors="replace")


def find_pdf_literal_string(text, start_pos):
    """Начиная с позиции открывающей '(' - ищет парную закрывающую с учётом
    вложенности и экранирования (\\)). Обычная регулярка [^()]* не видит
    вложенные незаэкранированные скобки (легальный PDF-синтаксис вроде
    'Report (Final Draft)') и просто теряет всё поле. Возвращает
    (содержимое_без_внешних_скобок, позиция_после_закрывающей) либо None."""
    depth = 0
    i, n = start_pos, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start_pos + 1:i], i + 1
        i += 1
    return None  # строка не закрыта корректно - битый/обрезанный PDF


def scan_pdf_text_for_fields(text, meta):
    for field in PDF_FIELDS:
        if field in meta:
            continue
        m = re.search(r"/%s\s*" % field, text)
        if not m or m.end() >= len(text):
            continue
        pos = m.end()
        ch = text[pos]

        if ch == "(":
            found = find_pdf_literal_string(text, pos)
            if not found:
                continue
            inner, _ = found
            value = _pdf_decode_value("(" + inner + ")")
        elif ch == "<":
            hex_m = re.match(r"<[0-9A-Fa-f\s]*>", text[pos:])
            if not hex_m:
                continue
            value = _pdf_decode_value(hex_m.group(0))
        else:
            continue

        if value:
            meta[field] = value.strip()
    for tag, field in (("dc:creator", "Author"), ("xmp:CreatorTool", "Creator"),
                        ("pdf:Producer", "Producer"), ("dc:title", "Title")):
        if field in meta:
            continue
        m = re.search(r"<%s[^>]*>(.*?)</%s>" % (tag, tag), text, re.DOTALL)
        if m:
            value = TAG_RE.sub(" ", m.group(1)).strip()
            if value and looks_like_text(value):
                meta[field] = value[:200]


def extract_pdf_metadata(data: bytes):
    """Возвращает (meta, причина_если_пусто). Причина нужна для отчёта -
    чтобы не молчать, когда метаданные не читаются, а объяснить, почему."""
    if not is_probably_pdf(data):
        return {}, "не похоже на настоящий PDF (архив мог отдать страницу-заглушку)"

    meta = {}
    scan_pdf_text_for_fields(data.decode("latin-1", errors="replace"), meta)
    if len(meta) < 2:   # мало что нашли в открытом виде - вероятно, часть сжата
        for stream_text in iter_decompressed_streams(data):
            scan_pdf_text_for_fields(stream_text, meta)
    if not meta:
        return {}, "метаданные не найдены (пустые либо в незнакомом формате)"
    return meta, None


OFFICE_TAGS = {
    "dc:creator": "Author",
    "cp:lastModifiedBy": "LastModifiedBy",
    "dc:title": "Title",
    "dcterms:created": "CreationDate",
    "dcterms:modified": "ModDate",
    "Company": "Company",
    "Application": "Creator",
    "Manager": "Manager",
}


def extract_office_metadata(path):
    with open(path, "rb") as f:
        head = f.read(4)
    if not is_probably_office_zip(head):
        return {}, "не похоже на настоящий docx/xlsx/pptx (архив мог отдать заглушку)"

    meta = {}
    try:
        with zipfile.ZipFile(path) as z:
            for name in ("docProps/core.xml", "docProps/app.xml"):
                if name not in z.namelist():
                    continue
                xml = z.read(name).decode("utf-8", errors="replace")
                for tag, field in OFFICE_TAGS.items():
                    m = re.search(r"<%s[^>]*>(.*?)</%s>" % (tag, tag), xml, re.DOTALL)
                    if m:
                        value = TAG_RE.sub(" ", m.group(1)).strip()
                        if value and looks_like_text(value) and field not in meta:
                            meta[field] = value[:200]
    except (zipfile.BadZipFile, OSError, KeyError) as e:
        return {}, f"файл повреждён или не читается ({e})"
    if not meta:
        return {}, "метаданные не найдены (пустые либо в незнакомом формате)"
    return meta, None


# ==================== EXIF ИЗ ФОТО ====================

EXIF_TAGS = {
    0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
    0x0132: "DateTime", 0x9003: "DateTimeOriginal", 0x8298: "Copyright",
    0x013B: "Artist",
}
GPS_TAGS = {
    0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude",
    0x0006: "GPSAltitude",
}
EXIF_IFD_POINTER = 0x8769
GPS_IFD_POINTER = 0x8825
TIFF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _decode_exif_value(raw, typ, endian):
    import struct
    try:
        if typ == 2:  # ASCII
            return raw.split(b"\x00")[0].decode("ascii", errors="replace").strip()
        if typ in (3, 4):  # SHORT / LONG
            size = 2 if typ == 3 else 4
            fmt = "H" if typ == 3 else "I"
            n = len(raw) // size
            vals = struct.unpack(endian + fmt * n, raw[:size * n]) if n else ()
            return vals[0] if len(vals) == 1 else (list(vals) if vals else None)
        if typ == 5:  # RATIONAL - пары (числитель, знаменатель)
            vals = []
            for i in range(0, len(raw) - 7, 8):
                num, den = struct.unpack(endian + "II", raw[i:i + 8])
                vals.append(num / den if den else 0.0)
            return vals[0] if len(vals) == 1 else (vals or None)
        return None
    except struct.error:
        return None


def _read_ifd(data, offset, endian, tag_map):
    """Читает одну IFD-таблицу TIFF/EXIF. Все офсеты в EXIF отсчитываются от
    начала TIFF-заголовка, который здесь = началу data (сегмент Exif уже
    отрезан от JPEG-обвязки до вызова этой функции)."""
    import struct
    result = {}
    exif_sub = gps_sub = None
    if offset < 0 or offset + 2 > len(data):
        return result, exif_sub, gps_sub
    count = struct.unpack(endian + "H", data[offset:offset + 2])[0]
    pos = offset + 2
    for _ in range(count):
        entry = data[pos:pos + 12]
        if len(entry) < 12:
            break
        tag, typ, cnt = struct.unpack(endian + "HHI", entry[:8])
        size = TIFF_TYPE_SIZES.get(typ, 1) * cnt
        value_bytes = entry[8:12]
        if 0 < size <= 4:
            raw_value = value_bytes[:size]
        elif size > 4:
            voff = struct.unpack(endian + "I", value_bytes)[0]
            raw_value = data[voff:voff + size]
        else:
            raw_value = b""

        if tag == EXIF_IFD_POINTER:
            exif_sub = struct.unpack(endian + "I", value_bytes)[0]
        elif tag == GPS_IFD_POINTER:
            gps_sub = struct.unpack(endian + "I", value_bytes)[0]
        elif tag in tag_map and raw_value:
            value = _decode_exif_value(raw_value, typ, endian)
            if value not in (None, ""):
                result[tag_map[tag]] = value
        pos += 12
    return result, exif_sub, gps_sub


def _gps_to_decimal(dms, ref):
    if not dms or not isinstance(dms, list) or len(dms) != 3 or not ref:
        return None
    degrees, minutes, seconds = dms
    decimal = degrees + minutes / 60 + seconds / 3600
    if str(ref).upper() in ("S", "W"):
        decimal = -decimal
    return round(decimal, 6)


def _parse_tiff_tags(exif_data: bytes, endian: str):
    """Общая часть для JPEG-EXIF и голого TIFF: оба, по сути, содержат один
    и тот же TIFF-заголовок + цепочку IFD, разница только в обёртке снаружи."""
    import struct
    tags = {}
    ifd0_offset = struct.unpack(endian + "I", exif_data[4:8])[0]
    tags, exif_sub, gps_sub = _read_ifd(exif_data, ifd0_offset, endian, EXIF_TAGS)
    if exif_sub:
        sub_tags, _, sub_gps_sub = _read_ifd(exif_data, exif_sub, endian, EXIF_TAGS)
        tags.update(sub_tags)
        if not gps_sub and sub_gps_sub:
            gps_sub = sub_gps_sub   # по стандарту указатель GPS должен быть в IFD0,
                                    # но подстрахуемся, если камера положила его иначе
    if gps_sub:
        gps_tags, _, _ = _read_ifd(exif_data, gps_sub, endian, GPS_TAGS)
        lat = _gps_to_decimal(gps_tags.get("GPSLatitude"), gps_tags.get("GPSLatitudeRef"))
        lon = _gps_to_decimal(gps_tags.get("GPSLongitude"), gps_tags.get("GPSLongitudeRef"))
        if lat is not None and lon is not None:
            tags["GPSLatitudeDecimal"] = lat
            tags["GPSLongitudeDecimal"] = lon
    return tags


def extract_exif(data: bytes):
    """Минимальный, но рабочий разбор EXIF из JPEG и обычного TIFF без
    сторонних библиотек: когда снято, чем снято, и, если есть, координаты
    GPS - для OSINT это ценнее самого факта наличия фотографии."""
    import struct

    if data[:2] == b"\xff\xd8":
        pos, exif_data = 2, None
        while pos + 4 <= len(data):
            if data[pos] != 0xFF:
                break
            marker = data[pos + 1]
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                pos += 2
                continue
            seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            if marker == 0xE1 and data[pos + 4:pos + 10] == b"Exif\x00\x00":
                exif_data = data[pos + 10:pos + 2 + seg_len]
                break
            if marker == 0xDA:   # начало сжатых данных - дальше EXIF искать негде
                break
            pos += 2 + seg_len
        if exif_data is None:
            return {}, "EXIF не найден (фото могло быть пересжато при публикации)"
    elif data[:2] in (b"II", b"MM") and len(data) >= 8:
        # обычный TIFF-файл - он САМ является TIFF-структурой, JPEG-обвязки
        # искать не надо, разбираем напрямую
        exif_data = data
    else:
        return {}, "не похоже на JPEG или TIFF (архив мог отдать заглушку)"

    if exif_data[:2] == b"II":
        endian = "<"
    elif exif_data[:2] == b"MM":
        endian = ">"
    else:
        return {}, "битый заголовок EXIF"

    try:
        tags = _parse_tiff_tags(exif_data, endian)
    except (struct.error, IndexError) as e:
        return {}, f"ошибка разбора EXIF ({e})"

    return tags, (None if tags else "EXIF-блок пуст")


def report_exif(domain_dir, all_rows):
    photo_rows = [r for r in all_rows
                  if classify_doc_ext(r["original_url"], r.get("mimetype", ""))
                  in {"jpg", "jpeg", "tif", "tiff"}]
    if not photo_rows:
        return []

    unique_photos = dedup_by_digest(photo_rows)
    print(f"Читаю EXIF {len(unique_photos)} фото (они покрывают {len(photo_rows)} появлений)...")
    cache = {}
    for r in unique_photos:
        path = os.path.join(domain_dir, r["store_path"])
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as f:
                cache[r["digest"]] = extract_exif(f.read())
        except Exception as e:
            LOGGER.debug(f"EXIF {path}: {e}")

    results = []
    for r in photo_rows:
        cached = cache.get(r["digest"])
        if not cached:
            continue
        tags, reason = cached
        if tags:
            entry = dict(tags)
            entry["_url"] = r["original_url"]
            entry["_timestamp"] = r["timestamp"]
            results.append(entry)

    if not results:
        return []

    with_gps = [t for t in results if "GPSLatitudeDecimal" in t]

    reports_dir = os.path.join(domain_dir, DIR_REPORTS)
    os.makedirs(reports_dir, exist_ok=True)

    csv_path = os.path.join(reports_dir, "exif.csv")
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["адрес", "дата_снимка", "камера", "модель", "программа",
                    "снято_когда", "широта", "долгота"])
        for t in results:
            w.writerow([t["_url"], t["_timestamp"], t.get("Make", ""), t.get("Model", ""),
                        t.get("Software", ""), t.get("DateTimeOriginal", t.get("DateTime", "")),
                        t.get("GPSLatitudeDecimal", ""), t.get("GPSLongitudeDecimal", "")])

    txt_path = os.path.join(reports_dir, "exif.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("EXIF ИЗ ФОТО\n")
        f.write(f"Фото с метаданными: {len(results)} из {len(photo_rows)}\n")
        f.write(f"Фото с координатами GPS: {len(with_gps)}\n")
        f.write("ВАЖНО: EXIF - это то, что записала камера/приложение (может быть подделано\n"
                "или отсутствовать после пересжатия) - не доказательство, а зацепка.\n")
        f.write("=" * 78 + "\n\n")
        if with_gps:
            f.write("ФОТО С GPS-КООРДИНАТАМИ:\n")
            for t in with_gps:
                lat, lon = t["GPSLatitudeDecimal"], t["GPSLongitudeDecimal"]
                f.write(f"  {t['_url']}\n")
                f.write(f"    координаты: {lat}, {lon}  "
                        f"(https://www.google.com/maps?q={lat},{lon})\n")
                if t.get("DateTimeOriginal"):
                    f.write(f"    снято: {t['DateTimeOriginal']}\n")
                f.write("\n")
        f.write("ВСЕ ФОТО С МЕТАДАННЫМИ:\n\n")
        for t in results:
            f.write(f"{t['_url']}  ({pretty_ts(t['_timestamp'])})\n")
            for key, label in (("Make", "камера"), ("Model", "модель"),
                                ("Software", "программа"),
                                ("DateTimeOriginal", "снято"), ("DateTime", "изменено")):
                if t.get(key):
                    f.write(f"    {label}: {t[key]}\n")
            f.write("\n")

    print(f"  EXIF: фото с метаданными {len(results)}, с GPS {len(with_gps)}")
    return results


def report_document_metadata(domain_dir, all_rows):
    doc_rows = [r for r in all_rows
                if classify_doc_ext(r["original_url"], r.get("mimetype", "")) in
                {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"}]
    if not doc_rows:
        return []

    unique_docs = dedup_by_digest(doc_rows)
    print(f"Читаю метаданные {len(unique_docs)} документов "
          f"(они покрывают {len(doc_rows)} появлений)...")
    cache = {}   # digest -> (meta, reason) - один физический файл не читаем дважды
    for r in unique_docs:
        path = os.path.join(domain_dir, r["store_path"])
        if not os.path.isfile(path):
            cache[r["digest"]] = ({}, "файл отсутствует на диске")
            continue
        ext = classify_doc_ext(r["original_url"], r.get("mimetype", ""))
        try:
            if ext == "pdf":
                with open(path, "rb") as f:
                    cache[r["digest"]] = extract_pdf_metadata(f.read())
            else:
                cache[r["digest"]] = extract_office_metadata(path)
        except Exception as e:
            cache[r["digest"]] = ({}, f"неожиданная ошибка ({e})")
            LOGGER.debug(f"Метаданные {path}: {e}\n{traceback.format_exc()}")

    results = []
    skip_reasons = {}
    for r in doc_rows:
        meta, reason = cache[r["digest"]]
        if meta:
            entry = dict(meta)
            entry["_url"] = r["original_url"]
            entry["_timestamp"] = r["timestamp"]
            results.append(entry)
        elif reason:
            skip_reasons[reason] = skip_reasons.get(reason, 0) + 1

    reports_dir = os.path.join(domain_dir, DIR_REPORTS)
    os.makedirs(reports_dir, exist_ok=True)

    csv_path = os.path.join(reports_dir, "метаданные_документов.csv")
    fields = ["_url", "_timestamp", "Author", "LastModifiedBy", "Company", "Manager",
              "Creator", "Producer", "Title", "Subject", "CreationDate", "ModDate"]
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["адрес", "дата_снимка", "автор", "последний_правил", "организация",
                    "руководитель", "программа", "генератор", "заголовок", "тема",
                    "создан", "изменён"])
        for meta in results:
            w.writerow([meta.get(k, "") for k in fields])

    people = {}
    orgs = {}
    for meta in results:
        for key in ("Author", "LastModifiedBy", "Manager"):
            v = (meta.get(key) or "").strip()
            if v and len(v) < 100:
                people[v] = people.get(v, 0) + 1
        v = (meta.get("Company") or "").strip()
        if v:
            orgs[v] = orgs.get(v, 0) + 1

    txt_path = os.path.join(reports_dir, "метаданные_документов.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("МЕТАДАННЫЕ ДОКУМЕНТОВ\n")
        f.write(f"Документов с метаданными: {len(results)} из {len(doc_rows)}\n")
        if skip_reasons:
            f.write("Не удалось прочитать:\n")
            for reason, count in sorted(skip_reasons.items(), key=lambda kv: -kv[1]):
                f.write(f"  {count}  -  {reason}\n")
        f.write("=" * 78 + "\n\n")
        f.write("ЛЮДИ (авторы и те, кто правил файлы):\n")
        for name, count in sorted(people.items(), key=lambda kv: -kv[1]):
            f.write(f"  {name}   (в {count} документах)\n")
        f.write("\nОРГАНИЗАЦИИ:\n")
        for name, count in sorted(orgs.items(), key=lambda kv: -kv[1]):
            f.write(f"  {name}   (в {count} документах)\n")
        f.write("\n" + "=" * 78 + "\nПО ДОКУМЕНТАМ:\n\n")
        for meta in results:
            f.write(f"{meta['_url']}  ({pretty_ts(meta['_timestamp'])})\n")
            for key, label in (("Author", "автор"), ("LastModifiedBy", "последний правил"),
                                ("Company", "организация"), ("Manager", "руководитель"),
                                ("Creator", "программа"), ("Producer", "генератор"),
                                ("Title", "заголовок"), ("CreationDate", "создан"),
                                ("ModDate", "изменён")):
                if meta.get(key):
                    f.write(f"    {label}: {meta[key]}\n")
            f.write("\n")

    print(f"  документов с метаданными: {len(results)}, "
          f"уникальных имён: {len(people)}, организаций: {len(orgs)}")
    return results


# ==================== SITEMAP / ROBOTS ====================

def report_sitemap_robots(domain_dir, all_rows):
    targets = [r for r in all_rows
               if re.search(r"(sitemap[^/]*\.xml|robots\.txt)$",
                            urllib.parse.urlsplit(r["original_url"]).path, re.I)]
    if not targets:
        return []

    known = {normalize_link_key(r["original_url"]) for r in all_rows}
    found_urls = {}
    disallowed = set()
    declared_sitemaps = set()

    for r in targets:
        path = os.path.join(domain_dir, r["store_path"])
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as f:
                text = decode_html(f.read())
        except OSError:
            continue

        if r["original_url"].lower().endswith("robots.txt"):
            for line in text.splitlines():
                m = re.match(r"\s*(Disallow|Allow)\s*:\s*(\S+)", line, re.I)
                if m:
                    disallowed.add(m.group(2))
                m = re.match(r"\s*Sitemap\s*:\s*(\S+)", line, re.I)
                if m:
                    declared_sitemaps.add(m.group(1).strip())
        for m in re.finditer(r"<loc>\s*(.*?)\s*</loc>", text, re.I | re.DOTALL):
            u = m.group(1).strip()
            if u:
                found_urls[u] = r["original_url"]

    missing = [u for u in found_urls if normalize_link_key(u) not in known]
    undiscovered_sitemaps = [u for u in declared_sitemaps
                             if normalize_link_key(u) not in known]

    reports_dir = os.path.join(domain_dir, DIR_REPORTS)
    os.makedirs(reports_dir, exist_ok=True)
    path = os.path.join(reports_dir, "sitemap_и_robots.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("АДРЕСА ИЗ SITEMAP.XML И ROBOTS.TXT\n")
        f.write(f"Найдено адресов в sitemap: {len(found_urls)}\n")
        f.write(f"Из них НЕТ в нашем архиве: {len(missing)}\n")
        f.write(f"Путей, скрытых в robots.txt: {len(disallowed)}\n")
        f.write(f"Sitemap-ов объявлено в robots.txt: {len(declared_sitemaps)}\n")
        f.write("=" * 78 + "\n\n")
        if undiscovered_sitemaps:
            f.write("SITEMAP, УКАЗАННЫЕ В ROBOTS.TXT, НО НЕ ПОПАВШИЕ В АРХИВ\n"
                    "(стоит скачать/проверить руками - могут вести к скрытой структуре сайта):\n")
            for u in sorted(undiscovered_sitemaps):
                f.write(f"  {u}\n")
            f.write("\n")
        f.write("СКРЫТО В ROBOTS.TXT (то, что прятали от поисковиков):\n")
        for d in sorted(disallowed):
            f.write(f"  {d}\n")
        f.write("\nЕСТЬ В SITEMAP, НО НЕТ В АРХИВЕ:\n")
        for u in sorted(missing):
            f.write(f"  {u}\n")
        f.write("\nВСЕ АДРЕСА ИЗ SITEMAP:\n")
        for u in sorted(found_urls):
            f.write(f"  {u}\n")

    print(f"  sitemap/robots: адресов {len(found_urls)}, "
          f"нет в архиве {len(missing)}, скрытых путей {len(disallowed)}, "
          f"необнаруженных sitemap {len(undiscovered_sitemaps)}")
    return missing


# ==================== MANIFEST АРХИВА ====================



def write_manifest(domain_dir, domain, date_from, date_to, include_exts, exclude_exts, all_rows):
    """Самодокументирующийся архив: с какими параметрами качали, когда,
    сколько всего. Пригодится через полгода, когда забудешь, с какими
    настройками запускал прошлый раз."""
    seen_digests = set()
    total_capture_bytes = 0     # сумма по всем появлениям (то, что реально "весит" история)
    unique_storage_bytes = 0    # сколько реально занято на диске (с учётом дедупликации)
    for r in all_rows:
        size = int(r["size_bytes"]) if str(r.get("size_bytes", "")).isdigit() else 0
        total_capture_bytes += size
        if r["digest"] not in seen_digests:
            seen_digests.add(r["digest"])
            unique_storage_bytes += size

    path = os.path.join(domain_dir, "MANIFEST.json")
    archive_created = datetime.now().isoformat(timespec="seconds")
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                archive_created = json.load(f).get("archive_created", archive_created)
        except Exception:
            pass

    manifest = {
        "tool": "Q2 Wayback Archiver",
        "tool_version": TOOL_VERSION,
        "schema_version": 2,
        "domain": domain,
        "date_range": {"from": date_from or None, "to": date_to or None},
        "filters": {
            "include_ext": sorted(include_exts) if include_exts else [],
            "exclude_ext": sorted(exclude_exts) if exclude_exts else [],
        },
        "capture_count": len(all_rows),
        "unique_blob_count": len(seen_digests),
        "total_capture_bytes": total_capture_bytes,
        "unique_storage_bytes": unique_storage_bytes,
        "archive_created": archive_created,
        "last_updated": datetime.now().isoformat(timespec="seconds"),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return path


# ==================== ТАЙМЛАЙН ====================

def report_timeline(domain_dir, all_rows):
    by_url = {}
    for r in all_rows:
        by_url.setdefault(r["original_url"], []).append(r)

    entries = []
    for url, items in by_url.items():
        items.sort(key=lambda x: x["timestamp"])
        def size_of(x):
            try:
                return int(x["size_bytes"])
            except (ValueError, KeyError, TypeError):
                return 0
        entries.append({
            "url": url, "versions": len(items),
            "first": items[0]["timestamp"], "last": items[-1]["timestamp"],
            "first_size": size_of(items[0]), "last_size": size_of(items[-1]),
        })
    entries.sort(key=lambda e: (-e["versions"], e["url"]))
    once = [e for e in entries if e["versions"] == 1]
    once.sort(key=lambda e: e["first"], reverse=True)

    reports_dir = os.path.join(domain_dir, DIR_REPORTS)
    os.makedirs(reports_dir, exist_ok=True)
    path = os.path.join(reports_dir, "таймлайн.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("ТАЙМЛАЙН ИЗМЕНЕНИЙ САЙТА\n")
        f.write(f"Уникальных адресов: {len(entries)}\n")
        f.write("\nВАЖНО про 'последняя версия': архив хранит уникальные версии "
                "контента, а не каждую отдельную проверку сайта. Если страница не "
                "менялась годами, 'последняя' здесь - это дата, когда эта версия "
                "ПОЯВИЛАСЬ, а не дата последнего визита archive.org - тот факт, что "
                "её продолжали видеть неизменной вплоть до сегодня, отдельно не "
                "фиксируется.\n")
        f.write("=" * 78 + "\n\n")
        for e in entries:
            f.write(f"{e['url']}\n")
            f.write(f"  уникальных версий: {e['versions']}\n")
            f.write(f"  первая версия появилась:   {pretty_ts(e['first'])}  ({human_size(e['first_size'])})\n")
            f.write(f"  последняя версия появилась: {pretty_ts(e['last'])}  ({human_size(e['last_size'])})\n")
            if e["versions"] > 1 and e["first_size"] and e["last_size"]:
                delta = e["last_size"] - e["first_size"]
                f.write(f"  изменение размера: {'+' if delta > 0 else '-'}"
                        f"{human_size(abs(delta))}\n")
            f.write("\n")

    once_path = os.path.join(reports_dir, "встречено_один_раз.txt")
    with open(once_path, "w", encoding="utf-8") as f:
        f.write("АДРЕСА, ВСТРЕЧЕННЫЕ В АРХИВЕ ТОЛЬКО ОДИН РАЗ\n")
        f.write("Часто интереснее тысячи неизменных css - могут быть временные "
                "объявления, случайно проиндексированные черновики, утечки.\n")
        f.write(f"Всего таких адресов: {len(once)}\n")
        f.write("=" * 78 + "\n\n")
        for e in once:
            f.write(f"{pretty_ts(e['first'])}  ({human_size(e['first_size'])})  {e['url']}\n")

    print(f"  таймлайн: {len(entries)} уникальных адресов, "
          f"встречены один раз: {len(once)}")
    return entries


# ==================== КОНТАКТЫ ====================

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"(?:\+7|\+3\d{2}|\+\d{1,3}|8)[\s\-()]*\d{2,4}[\s\-()]*\d{2,3}"
                       r"[\s\-()]*\d{2}[\s\-()]*\d{2}")

SOCIAL_PATTERNS = {
    "VK": re.compile(r"https?://(?:www\.)?vk\.com/[A-Za-z0-9_.\-]+(?:\?[^\s\"'<>]*)?", re.I),
    "Telegram": re.compile(r"https?://(?:www\.)?(?:t\.me|telegram\.me)/[A-Za-z0-9_]+(?:\?[^\s\"'<>]*)?", re.I),
    "Instagram": re.compile(r"https?://(?:www\.)?instagram\.com/[A-Za-z0-9_.]+(?:\?[^\s\"'<>]*)?", re.I),
    "Facebook": re.compile(r"https?://(?:www\.)?facebook\.com/[A-Za-z0-9_.\-]+(?:\?[^\s\"'<>]*)?", re.I),
    "Twitter/X": re.compile(r"https?://(?:www\.)?(?:twitter\.com|x\.com)/[A-Za-z0-9_]+(?:\?[^\s\"'<>]*)?", re.I),
    "YouTube": re.compile(
        r"https?://(?:www\.)?(?:youtube\.com/(?:channel|user|c|@)[A-Za-z0-9_/\-]+"
        r"|youtu\.be/[A-Za-z0-9_\-]+)(?:\?[^\s\"'<>]*)?", re.I),
    "LinkedIn": re.compile(r"https?://(?:[a-z]{2}\.)?linkedin\.com/(?:in|company)/[A-Za-z0-9_\-]+(?:\?[^\s\"'<>]*)?", re.I),
    "OK": re.compile(r"https?://(?:www\.)?ok\.ru/[A-Za-z0-9_./\-]+(?:\?[^\s\"'<>]*)?", re.I),
    "WhatsApp": re.compile(r"https?://(?:wa\.me|api\.whatsapp\.com)/[A-Za-z0-9_?=/\-]+", re.I),
}

JUNK_EMAIL_PARTS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js",
                     "example.com", "domain.com", "sentry.io", "@2x", "u003")

PHONE_SEPARATOR_RE = re.compile(r"[\s\-()]")


def clean_phone(raw):
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 11 and digits.startswith("8"):
        digits = "7" + digits[1:]
    if len(digits) < 10 or len(digits) > 15:
        return None
    if len(set(digits)) <= 2:
        return None
    return digits


def phone_confidence(raw_match: str) -> str:
    """Голые 10-11 цифр без единого разделителя - это ЧАСТО не телефон,
    а ИНН, номер заказа, серийник и т.п. Помечаем такие отдельно, чтобы
    не мешать в одну кучу с реально надёжными находками."""
    return "высокая" if PHONE_SEPARATOR_RE.search(raw_match) else "низкая"


class ContactScanner(HTMLParser):
    """Вместо регулярки по всему html-тексту (которая с той же охотой лезет
    внутрь <script>/<style>/комментариев) - настоящий разбор тегов. Видимый
    текст собираем отдельно от содержимого script/style, а ссылки
    (href/src) - отдельным списком, чтобы соцсети/mailto/tel ловились
    даже когда сама ссылка не видна глазами (например, иконка без подписи)."""
    SKIP_TAGS = {"script", "style"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text_chunks = []
        self.hrefs = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
        for name, value in attrs:
            if name.lower() in ("href", "src") and value:
                self.hrefs.append(value)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag.lower() in self.SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            self.text_chunks.append(data)

    def get_text(self):
        return " ".join(self.text_chunks)


def scan_contacts_in_text(html_text, emails, phones, socials, source):
    scanner = ContactScanner()
    try:
        scanner.feed(html_text)
        plain = scanner.get_text()
        hrefs = scanner.hrefs
    except Exception:
        # на совсем кривой разметке парсер иногда спотыкается -
        # откатываемся на грубое, но надёжное снятие тегов
        plain = TAG_RE.sub(" ", html_text)
        hrefs = []

    for href in hrefs:
        low = href.strip().lower()
        if low.startswith("mailto:"):
            addr = href.split(":", 1)[1].split("?")[0].strip().lower()
            if addr and not any(j in addr for j in JUNK_EMAIL_PARTS):
                emails.setdefault(addr, set()).add(source)
        elif low.startswith("tel:"):
            normalized = clean_phone(href.split(":", 1)[1])
            if normalized:
                phones.setdefault(normalized, {"sources": set(), "confidence": "высокая"})
                phones[normalized]["sources"].add(source)
        for network, pattern in SOCIAL_PATTERNS.items():
            m = pattern.search(href)
            if m:
                socials.setdefault((network, m.group(0).rstrip("/")), set()).add(source)

    for network, pattern in SOCIAL_PATTERNS.items():
        for hit in pattern.findall(plain):
            socials.setdefault((network, hit.rstrip("/")), set()).add(source)

    for hit in EMAIL_RE.findall(plain):
        low = hit.lower()
        if not any(junk in low for junk in JUNK_EMAIL_PARTS):
            emails.setdefault(low, set()).add(source)

    for hit in PHONE_RE.findall(plain):
        normalized = clean_phone(hit)
        if normalized:
            entry = phones.setdefault(normalized, {"sources": set(), "confidence": "низкая"})
            entry["sources"].add(source)
            if phone_confidence(hit) == "высокая":
                entry["confidence"] = "высокая"


def report_contacts(domain_dir, all_rows):
    text_rows = [r for r in all_rows
                 if get_extension(r["original_url"]) in HTML_EXTS | {"txt", "xml", "json"}]
    by_digest = {}
    for r in text_rows:
        by_digest.setdefault(r["digest"], []).append(r)
    print(f"Просматриваю {len(by_digest)} текстовых файлов "
          f"(они покрывают {len(text_rows)} появлений)...")

    emails, phones, socials = {}, {}, {}
    scanned = 0

    for digest, group in by_digest.items():
        rep = group[0]
        path = os.path.join(domain_dir, rep["store_path"])
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as f:
                text = decode_html(f.read())
        except Exception:
            continue
        scanned += 1
        # один и тот же контент мог встретиться на разных URL/датах -
        # сканируем один раз, но находки относим ко ВСЕМ появлениям
        sources = {f"{o['original_url']} @ {pretty_ts(o['timestamp'])}" for o in group}
        local_emails, local_phones, local_socials = {}, {}, {}
        scan_contacts_in_text(text, local_emails, local_phones, local_socials, "_")

        for v in local_emails:
            emails.setdefault(v, set()).update(sources)
        for v, d in local_phones.items():
            entry = phones.setdefault(v, {"sources": set(), "confidence": d["confidence"]})
            entry["sources"].update(sources)
            if d["confidence"] == "высокая":
                entry["confidence"] = "высокая"
        for k in local_socials:
            socials.setdefault(k, set()).update(sources)

    high_conf = {v: d for v, d in phones.items() if d["confidence"] == "высокая"}
    low_conf = {v: d for v, d in phones.items() if d["confidence"] == "низкая"}

    reports_dir = os.path.join(domain_dir, DIR_REPORTS)
    os.makedirs(reports_dir, exist_ok=True)

    csv_path = os.path.join(reports_dir, "контакты.csv")
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["тип", "значение", "уверенность", "на_скольких_страницах", "пример_источника"])
        for v, s in sorted(emails.items()):
            w.writerow(["email", v, "высокая", len(s), sorted(s)[0]])
        for v, d in sorted(phones.items()):
            w.writerow(["телефон", "+" + v, d["confidence"], len(d["sources"]), sorted(d["sources"])[0]])
        for (network, link), s in sorted(socials.items()):
            w.writerow([f"соцсеть:{network}", link, "высокая", len(s), sorted(s)[0]])

    txt_path = os.path.join(reports_dir, "контакты.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"КОНТАКТЫ ИЗ АРХИВА\nПросмотрено файлов: {scanned}\n")
        f.write("=" * 78 + "\n\n")
        f.write(f"EMAIL ({len(emails)}):\n")
        for v, s in sorted(emails.items(), key=lambda kv: -len(kv[1])):
            f.write(f"  {v}   (на {len(s)} стр.)\n")

        f.write(f"\nТЕЛЕФОНЫ, НАДЁЖНО ({len(high_conf)}):\n")
        for v, d in sorted(high_conf.items(), key=lambda kv: -len(kv[1]["sources"])):
            f.write(f"  +{v}   (на {len(d['sources'])} стр.)\n")

        if low_conf:
            f.write(f"\nПОХОЖЕ НА ТЕЛЕФОН, НО НЕ ТОЧНО ({len(low_conf)}):\n")
            f.write("  (голые цифры без разделителей - могут оказаться ИНН, номером заказа и т.п.)\n")
            for v, d in sorted(low_conf.items(), key=lambda kv: -len(kv[1]["sources"])):
                f.write(f"  +{v}   (на {len(d['sources'])} стр.)\n")

        by_network = {}
        for (network, link), s in socials.items():
            by_network.setdefault(network, []).append((link, len(s)))
        f.write(f"\nСОЦСЕТИ И МЕССЕНДЖЕРЫ ({len(socials)}):\n")
        for network in sorted(by_network):
            f.write(f"\n  --- {network} ---\n")
            for link, count in sorted(by_network[network], key=lambda x: -x[1]):
                f.write(f"  {link}   (на {count} стр.)\n")

    print(f"  контакты: email {len(emails)}, телефонов {len(high_conf)} "
          f"(+{len(low_conf)} под вопросом), соцсетей {len(socials)}")
    return emails, phones, socials


# ==================== ДАШБОРД ====================

def rel_link(from_dir, target_path):
    rel = os.path.relpath(target_path, from_dir).replace(os.sep, "/")
    return urllib.parse.quote(rel)


def find_dashboard_entry_index(base_dir, domain):
    """Раньше index.html лежал прямо в корне снимка/latest, теперь - на
    уровень глубже, в подпапке hostname (после фикса коллизии поддоменов).
    Сначала пробуем ожидаемый домен, потом любую подпапку (мульти-поддоменный
    снимок), и напоследок - старый плоский формат (архивы, собранные до
    этого фикса)."""
    host = sanitize_segment(domain.lower())
    candidate = os.path.join(base_dir, host, "index.html")
    if os.path.isfile(candidate):
        return candidate
    if os.path.isdir(base_dir):
        for name in sorted(os.listdir(base_dir)):
            candidate2 = os.path.join(base_dir, name, "index.html")
            if os.path.isfile(candidate2):
                return candidate2
    flat = os.path.join(base_dir, "index.html")   # архив старого формата
    if os.path.isfile(flat):
        return flat
    return base_dir


def build_dashboard(domain, domain_dir, all_rows, stats):
    reports_dir = os.path.join(domain_dir, DIR_REPORTS)
    os.makedirs(reports_dir, exist_ok=True)

    versions = sorted({folder_ts(r["timestamp"]) for r in all_rows}, reverse=True)
    seen_digests_for_size = set()
    unique_storage_bytes = 0
    for r in all_rows:
        if r["digest"] in seen_digests_for_size:
            continue
        seen_digests_for_size.add(r["digest"])
        if str(r.get("size_bytes", "")).isdigit():
            unique_storage_bytes += int(r["size_bytes"])

    by_ext = {}
    for r in all_rows:
        ext = get_extension(r["original_url"])
        by_ext[ext] = by_ext.get(ext, 0) + 1

    docs = [r for r in all_rows if classify_doc_ext(r["original_url"], r.get("mimetype", "")) in DOC_EXTS]
    docs.sort(key=lambda r: r["timestamp"], reverse=True)

    e = html_mod.escape
    latest_dir = os.path.join(domain_dir, DIR_LATEST)
    latest_entry = find_dashboard_entry_index(latest_dir, domain)

    reports_files = [
        ("Таймлайн изменений", "таймлайн.txt"),
        ("Встречено только один раз", "встречено_один_раз.txt"),
        ("Граф ссылок", "граф_ссылок.txt"),
        ("Контакты и соцсети", "контакты.txt"),
        ("Контакты (таблица CSV)", "контакты.csv"),
        ("Метаданные документов", "метаданные_документов.txt"),
        ("Метаданные (таблица CSV)", "метаданные_документов.csv"),
        ("EXIF фото (координаты и техника)", "exif.txt"),
        ("EXIF (таблица CSV)", "exif.csv"),
        ("Удалённые страницы", "удалённые_страницы.txt"),
        ("Sitemap и robots.txt", "sitemap_и_robots.txt"),
    ]

    parts = [f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>Q2 — архив {e(domain)}</title>
<style>
 body{{background:#111;color:#ddd;font-family:Consolas,monospace;margin:0;padding:24px}}
 h1{{color:#ff4444;border-bottom:2px solid #ff4444;padding-bottom:8px}}
 h2{{color:#ff6666;margin-top:32px}}
 a{{color:#66aaff;text-decoration:none}} a:hover{{text-decoration:underline}}
 .cards{{display:flex;flex-wrap:wrap;gap:14px;margin:18px 0}}
 .card{{background:#1c1c1c;border:1px solid #333;border-radius:6px;padding:14px 18px;min-width:150px}}
 .num{{font-size:26px;color:#ff4444;font-weight:bold}}
 .lbl{{font-size:12px;color:#888;text-transform:uppercase}}
 table{{border-collapse:collapse;width:100%;margin-top:10px}}
 td,th{{border:1px solid #333;padding:6px 10px;text-align:left;font-size:13px}}
 th{{background:#1c1c1c;color:#ff6666}}
 tr:nth-child(even){{background:#181818}}
 .big{{display:inline-block;background:#1c1c1c;border:1px solid #444;border-radius:6px;
       padding:12px 20px;margin:6px 8px 6px 0}}
 .muted{{color:#777;font-size:12px}}
</style></head><body>
<h1>Q2 — архив {e(domain)}</h1>
<p class="muted">Собран: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>

<div class="cards">
  <div class="card"><div class="num">{len(all_rows)}</div><div class="lbl">файлов всего</div></div>
  <div class="card"><div class="num">{len(versions)}</div><div class="lbl">снимков сайта</div></div>
  <div class="card"><div class="num">{len(docs)}</div><div class="lbl">документов</div></div>
  <div class="card"><div class="num">{human_size(unique_storage_bytes)}</div><div class="lbl">объём на диске</div></div>
  <div class="card"><div class="num">{stats.get('emails', 0)}</div><div class="lbl">email</div></div>
  <div class="card"><div class="num">{stats.get('phones', 0)}</div><div class="lbl">телефонов</div></div>
  <div class="card"><div class="num">{stats.get('people', 0)}</div><div class="lbl">имён в документах</div></div>
  <div class="card"><div class="num">{stats.get('deleted', 0)}</div><div class="lbl">удалённых страниц</div></div>
  <div class="card"><div class="num">{stats.get('gps_photos', 0)}</div><div class="lbl">фото с GPS</div></div>
</div>

<h2>Открыть</h2>
<a class="big" href="{rel_link(reports_dir, latest_entry)}">Свежая версия сайта</a>
<a class="big" href="{rel_link(reports_dir, os.path.join(domain_dir, DIR_DOCS))}">Документы</a>
<a class="big" href="{rel_link(reports_dir, os.path.join(domain_dir, DIR_PHOTOS))}">Фото</a>
<a class="big" href="{rel_link(reports_dir, os.path.join(domain_dir, DIR_VERSIONS))}">Все версии</a>

<h2>Отчёты</h2>
<ul>"""]

    for label, filename in reports_files:
        full = os.path.join(reports_dir, filename)
        if os.path.isfile(full):
            parts.append(f'<li><a href="{urllib.parse.quote(filename)}">{e(label)}</a></li>')
    parts.append("</ul>")

    parts.append("<h2>Снимки сайта по датам</h2><table>"
                  "<tr><th>Дата снимка</th><th>Файлов</th><th>Открыть</th></tr>")
    count_by_version = {}
    for r in all_rows:
        count_by_version[folder_ts(r["timestamp"])] = \
            count_by_version.get(folder_ts(r["timestamp"]), 0) + 1
    for v in versions[:100]:
        vdir = os.path.join(domain_dir, DIR_VERSIONS, v)
        # в снимке может не быть главной страницы (например, попал только PDF) -
        # тогда ведём на саму папку, чтобы ссылка не была битой
        target = find_dashboard_entry_index(vdir, domain)
        label = "открыть" if target != vdir else "папка"
        parts.append(f'<tr><td>{e(v.replace("_", "  "))}</td>'
                     f'<td>{count_by_version.get(v, 0)}</td>'
                     f'<td><a href="{rel_link(reports_dir, target)}">{label}</a></td></tr>')
    parts.append("</table>")
    if len(versions) > 100:
        parts.append(f'<p class="muted">показаны первые 100 из {len(versions)} снимков</p>')

    parts.append("<h2>Документы</h2><table>"
                  "<tr><th>Дата</th><th>Файл</th><th>Адрес на сайте</th></tr>")
    for r in docs[:200]:
        ext = classify_doc_ext(r["original_url"], r.get("mimetype", ""))
        name = nice_filename(r["original_url"], r["timestamp"], r["digest"], forced_ext=ext)
        dest = os.path.join(domain_dir, DIR_DOCS, ext, name)
        link = rel_link(reports_dir, dest)
        parts.append(f'<tr><td>{e(date_only(r["timestamp"]))}</td>'
                     f'<td><a href="{link}">{e(name)}</a></td>'
                     f'<td class="muted">{e(r["original_url"][:80])}</td></tr>')
    parts.append("</table>")
    if len(docs) > 200:
        parts.append(f'<p class="muted">показаны первые 200 из {len(docs)} документов</p>')

    parts.append("<h2>Что внутри архива</h2><table><tr><th>Тип</th><th>Файлов</th></tr>")
    for ext, count in sorted(by_ext.items(), key=lambda kv: -kv[1])[:25]:
        parts.append(f"<tr><td>{e(ext)}</td><td>{count}</td></tr>")
    parts.append("</table></body></html>")

    path = os.path.join(reports_dir, "ДАШБОРД.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))
    return path


# ==================== РЕЖИМ: СКАЧАТЬ / ОБНОВИТЬ ====================

def run_downloads(records, domain_dir, db_by_digest, total=None):
    """Общий запуск скачивания через пул потоков - используется и для
    основного скачивания, и для долавливания неудачных. При Ctrl+C сразу
    выставляет SHUTDOWN: потоки, спящие в троттлинге/ретраях, просыпаются
    за секунду вместо того, чтобы держать программу 'зависшей' до 10 минут
    (см. interruptible_sleep)."""
    SHUTDOWN.clear()
    _clear_store_verify_cache()
    new_db_rows, failed_rows = [], []
    counters = {"done": 0, "reused": 0, "failed": 0}
    lock = threading.Lock()
    total = total if total is not None else len(records)

    ex = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        futures = [ex.submit(download_one, r, domain_dir, db_by_digest, new_db_rows,
                             lock, counters, total, failed_rows) for r in records]
        try:
            for future in as_completed(futures):
                try:
                    future.result()   # без этого исключение внутри потока тонет молча
                except Exception as e:
                    with lock:
                        counters["failed"] += 1
                    print(f"  [Неожиданная ошибка в потоке] {e}")
                    LOGGER.error(f"Необработанное исключение в download_one: {e}\n"
                                 f"{traceback.format_exc()}")
        except KeyboardInterrupt:
            print("\n  Останавливаюсь (Ctrl+C), дожидаюсь текущих закачек...")
            SHUTDOWN.set()
            try:
                ex.shutdown(wait=True, cancel_futures=True)
            except TypeError:
                ex.shutdown(wait=True)  # старый Python без cancel_futures
            raise
        else:
            ex.shutdown(wait=True)
    finally:
        if new_db_rows:
            append_db(domain_dir, new_db_rows)
        write_failed_csv(domain_dir, failed_rows)

    return counters, failed_rows, new_db_rows


def retry_failed_first(domain_dir, db_by_digest):
    """Долов временных ошибок перед обычным CDX-обходом.

    Возвращает статистику этого отдельного этапа, чтобы итоговый отчёт
    не смешивал восстановление со скачиванием новых capture.
    """
    empty_stats = {"done": 0, "reused": 0, "failed": 0, "permanent": 0, "attempted": 0}
    path = os.path.join(domain_dir, FAILED_CSV)
    if not os.path.isfile(path):
        return empty_stats
    with open(path, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        return empty_stats

    permanent_rows = [r for r in rows if failed_row_is_permanent(r)]
    retry_rows = [r for r in rows if not failed_row_is_permanent(r)]

    if permanent_rows:
        print(f"  Постоянных ошибок в очереди: {len(permanent_rows)} — автоматически не повторяю.")
    if not retry_rows:
        print("  Временных ошибок для долова нет.")
        return {**empty_stats, "permanent": len(permanent_rows)}

    answer = input(f"\nВ прошлый раз не скачалось временно {len(retry_rows)} файлов. "
                    f"Попробовать доловить сейчас? [Y/n]: ").strip().lower()
    if answer == "n":
        return {**empty_stats, "permanent": len(permanent_rows), "attempted": 0}

    records = [{"original": r["original_url"], "timestamp": r["timestamp"],
                "digest": r.get("digest", ""), "mimetype": r.get("mimetype", ""),
                "statuscode": r.get("statuscode", ""), "length": r.get("length", "")}
               for r in retry_rows]

    print("Доловливаю...")
    try:
        counters, failed_rows, _ = run_downloads(records, domain_dir, db_by_digest)
    except KeyboardInterrupt:
        print("  Остановлено - уже скачанное сохранено, остальное осталось в очереди.")
        try:
            current_rows = []
            if os.path.isfile(path):
                with open(path, encoding="utf-8-sig") as f:
                    current_rows = list(csv.DictReader(f))
            write_failed_csv(domain_dir, permanent_rows + current_rows)
        except Exception as e:
            LOGGER.error(f"Не удалось восстановить очередь после Ctrl+C: {e}")
        return {**empty_stats, "permanent": len(permanent_rows), "attempted": len(retry_rows)}

    # run_downloads уже записал новые временные ошибки. Возвращаем в очередь
    # постоянные, но больше не пытаемся их скачивать автоматически. Важно:
    # DictReader даёт permanent_rows как dict, поэтому перед записью нормализуем
    # их в CSV-строки; write_failed_csv также дедуплицирует очередь.
    combined = permanent_rows + failed_rows
    write_failed_csv(domain_dir, combined)
    print(f"  доловлено: {counters['done']}, уже было: {counters['reused']}, "
          f"всё ещё временно не вышло: {counters['failed']}, "
          f"постоянных отложено: {len(permanent_rows)}")
    return {
        "done": counters.get("done", 0),
        "reused": counters.get("reused", 0),
        "failed": counters.get("failed", 0),
        "permanent": len(permanent_rows),
        "attempted": len(retry_rows),
    }


def mode_download():
    domain, domain_dir = ask_download_target()
    if not domain_dir:
        return

    log_path = setup_logger(domain_dir)
    cleanup_part_files(domain_dir)

    db_by_digest, seen_occurrences, existing_rows = load_db(domain_dir)
    recovery_stats = {"done": 0, "reused": 0, "failed": 0, "permanent": 0, "attempted": 0}
    if existing_rows:
        print(f"\nАрхив уже существует: {len(existing_rows)} записей в базе.")
        print("Будет докачано новое, а отсутствующие/изменённые физические файлы — восстановлены.")
        recovery_stats = retry_failed_first(domain_dir, db_by_digest)
        if recovery_stats.get("attempted", 0):
            # retry_failed_first уже изменил _база.csv. Перечитываем индексы,
            # иначе seen_occurrences остаётся состоянием ДО восстановления и
            # только что успешно доловленные capture повторно попадут в fresh.
            db_by_digest, seen_occurrences, existing_rows = load_db(domain_dir)
            print(f"  Состояние БД обновлено после долова: {len(seen_occurrences)} появлений.")

    date_from = input("\nДата НАЧАЛА ГГГГММДД (Enter = с самого начала): ").strip()
    date_to = input("Дата КОНЦА ГГГГММДД (Enter = по сегодня): ").strip()
    include_raw = input("Какие типы файлов качать? Enter = все (html,pdf,jpg): ").strip().lower()
    include_exts = {x.strip().lstrip(".") for x in include_raw.split(",") if x.strip()}
    exclude_raw = input("Какие ИСКЛЮЧИТЬ? Enter = ничего (jpg,png,css): ").strip().lower()
    exclude_exts = {x.strip().lstrip(".") for x in exclude_raw.split(",") if x.strip()}

    print()
    records, _ = fetch_cdx_records(domain, date_from, date_to, domain_dir)
    if not records:
        return

    if include_exts or exclude_exts:
        before = len(records)
        records = [r for r in records
                   if (not include_exts or classify_doc_ext(r["original"], r.get("mimetype", "")) in include_exts)
                   and (not exclude_exts or classify_doc_ext(r["original"], r.get("mimetype", "")) not in exclude_exts)]
        print(f"После фильтра по типам: {len(records)} из {before}")

    failed_queue = failed_queue_rows(domain_dir)
    permanent_keys = permanent_failure_keys(failed_queue)
    fresh = []
    repair_count = 0
    permanent_skipped = 0
    for r in records:
        occurrence = (r["original"], r["timestamp"])
        digest = normalize_store_digest(r["original"], r["timestamp"], r.get("digest", ""))
        failure_key = (r["original"], r["timestamp"], str(r.get("digest", "")).strip().lower())
        if failure_key in permanent_keys:
            permanent_skipped += 1
            continue
        known = db_by_digest.get(digest)
        store_file = store_path_for(domain_dir, digest)
        valid = _verify_store_file(store_file, digest, known.get("sha256", "") if known else "")[0]
        if occurrence not in seen_occurrences or not valid:
            fresh.append(r)
            if occurrence in seen_occurrences:
                repair_count += 1
    already = len(records) - len(fresh) - permanent_skipped
    print(f"Состояние CDX: {len(records)} записей")
    print(f"  есть и целы: {already} | новых/на восстановление: {len(fresh)} | permanent пропущено: {permanent_skipped}")
    if repair_count:
        print(f"  Из них повреждены/отсутствуют физически и будут перекачаны: {repair_count}")

    if not fresh:
        print("\nНичего нового — архив уже актуален.")
        answer = input("Всё равно пересобрать папки и отчёты? [y/N]: ").strip().lower()
        if answer != "y":
            return

    total_bytes = sum(int(r.get("length") or 0) for r in fresh
                      if str(r.get("length", "")).isdigit())
    if fresh:
        print(f"\nК скачиванию: {len(fresh)} файлов, примерно {human_size(total_bytes)}")
        if input("Качаем? [Y/n]: ").strip().lower() == "n":
            return

    new_db_rows, failed_rows = [], []
    print(f"\nПапка архива: {domain_dir}")

    failed_csv_path = os.path.join(domain_dir, FAILED_CSV)
    if fresh:
        print(f"Скачиваю ({MAX_WORKERS} потока, общий интервал запросов {REQUEST_PACE_SECONDS:.1f} сек)...\n")
        counters, failed_rows, new_db_rows = run_downloads(fresh, domain_dir, db_by_digest)
        # run_downloads записывает только ошибки этого прохода. Не теряем
        # существующие permanent-записи и не смешиваем их с новой очередью.
        if failed_queue:
            # Очередь, оставшаяся после этапа долова, может содержать и временные
            # ошибки, которые пользователь сознательно отказался долавливать.
            # Их нельзя терять из-за записи результатов основного прохода.
            combined_failed = failed_queue + failed_rows
            failed_path = write_failed_csv(domain_dir, combined_failed)
        else:
            failed_path = failed_csv_path if failed_rows else None
    else:
        print("Скачивать нечего, пересобираю папки и отчёты...")
        counters, failed_rows, new_db_rows = {"done": 0, "reused": 0, "failed": 0}, [], []
        failed_path = failed_csv_path if os.path.isfile(failed_csv_path) else None

    hide_store_folder(domain_dir)

    _, _, all_rows = load_db(domain_dir)

    print("\nРаскладываю по папкам...")
    docs, photos = organize_by_type(domain_dir, all_rows)
    latest_pairs = build_latest_site(domain_dir, all_rows)
    print(f"  документов: {docs}, фото: {photos}, страниц в свежей версии: {len(latest_pairs)}")

    print("Делаю ссылки рабочими для офлайн-просмотра...")
    changed, link_edges = rewrite_all_versions(domain_dir, all_rows, latest_pairs)
    print(f"  переписано ссылок: {changed}")
    report_link_graph(domain_dir, link_edges, all_rows)

    deleted = report_deleted_pages(domain, domain_dir)

    print("\nСобираю отчёты...")
    run_reports(domain, domain_dir, all_rows, deleted_count=len(deleted))
    write_manifest(domain_dir, domain, date_from, date_to, include_exts, exclude_exts, all_rows)

    print("\n" + "=" * 60)
    if recovery_stats.get("attempted", 0):
        print(f"Восстановлено из очереди: {recovery_stats['done']}, "
              f"переиспользовано: {recovery_stats['reused']}, "
              f"временных ошибок осталось: {recovery_stats['failed']}, "
              f"постоянных отложено: {recovery_stats['permanent']}")
    print(f"Скачано в основном обновлении: {counters['done']}, "
          f"переиспользовано: {counters['reused']}, "
          f"ошибок: {counters['failed']}")
    print(f"Архив: {domain_dir}")
    print(f"Журнал: {log_path}")
    if failed_path:
        queue_now = failed_queue_rows(domain_dir)
        pending_t = sum(1 for r in queue_now if not failed_row_is_permanent(r))
        pending_p = sum(1 for r in queue_now if failed_row_is_permanent(r))
        if pending_t and pending_p:
            print(f"\nВ очереди: временных {pending_t}, постоянных {pending_p}. Временные предложу доловить при следующем запуске.")
        elif pending_t:
            print(f"\nНе скачалось временно: {pending_t} — при следующем запуске предложу доловить.")
        elif pending_p:
            print(f"\nПостоянных проблем отложено: {pending_p} — автоматически повторять не буду.")
    print("=" * 60)


# ==================== РЕЖИМ: ОТЧЁТЫ ====================

def run_reports(domain, domain_dir, all_rows, deleted_count=0):
    entries = report_timeline(domain_dir, all_rows)
    emails, phones, socials = report_contacts(domain_dir, all_rows)
    meta_results = report_document_metadata(domain_dir, all_rows)
    exif_results = report_exif(domain_dir, all_rows)
    report_sitemap_robots(domain_dir, all_rows)

    people = set()
    for meta in meta_results:
        for key in ("Author", "LastModifiedBy", "Manager"):
            v = (meta.get(key) or "").strip()
            if v:
                people.add(v)

    gps_count = sum(1 for t in exif_results if "GPSLatitudeDecimal" in t)
    stats = {"emails": len(emails), "phones": len(phones), "socials": len(socials),
             "people": len(people), "deleted": deleted_count, "urls": len(entries),
             "gps_photos": gps_count}
    dashboard = build_dashboard(domain, domain_dir, all_rows, stats)
    print(f"\nДашборд: {dashboard}")
    print("Открой его двойным кликом — оттуда виден весь архив.")
    return dashboard


def mode_reports():
    domain_dir = ask_domain_dir()
    if not domain_dir:
        return
    setup_logger(domain_dir)
    cleanup_part_files(domain_dir)
    hide_store_folder(domain_dir)
    _, _, all_rows = load_db(domain_dir)
    if not all_rows:
        print("База архива пуста — сначала скачайте сайт (пункт 01).")
        return
    domain = domain_from_archive_db(domain_dir) or os.path.basename(domain_dir.rstrip(os.sep))

    deleted_path = os.path.join(domain_dir, DIR_REPORTS, "удалённые_страницы.txt")
    deleted_count = 0
    if os.path.isfile(deleted_path):
        with open(deleted_path, encoding="utf-8") as f:
            m = re.search(r"Найдено удалённых:\s*(\d+)", f.read())
            if m:
                deleted_count = int(m.group(1))

    print(f"\nАрхив: {domain_dir}\nФайлов в базе: {len(all_rows)}\n")
    run_reports(domain, domain_dir, all_rows, deleted_count)


# ==================== РЕЖИМ: ПРОВЕРКА ЦЕЛОСТНОСТИ ====================

def inspect_file_structure(path, mimetype='', original_url=''):
    """Консервативная sanity-проверка формата поверх SHA-256."""
    ext = get_extension(original_url).lower()
    mime = (mimetype or '').split(';')[0].strip().lower()
    try:
        size = os.path.getsize(path)
        if size <= 0:
            return 'BROKEN', 'пустой файл'
        with open(path, 'rb') as f:
            head = f.read(16)
            f.seek(max(0, size - 4096))
            tail = f.read(4096)

        if ext == 'pdf' or mime == 'application/pdf' or head.startswith(b'%PDF-'):
            if not head.startswith(b'%PDF-'):
                return 'BROKEN', 'нет сигнатуры %PDF-'
            if b'%%EOF' not in tail:
                return 'WARNING', 'в хвосте не найден %%EOF'
            if b'startxref' not in tail:
                return 'WARNING', 'в хвосте не найден startxref'
            return 'OK', ''

        if ext in {'jpg', 'jpeg'} or mime == 'image/jpeg':
            if not head.startswith(b'\xff\xd8'):
                return 'BROKEN', 'нет JPEG SOI'
            if not tail.endswith(b'\xff\xd9'):
                return 'WARNING', 'нет JPEG EOI в самом конце'
            return 'OK', ''

        if ext == 'png' or mime == 'image/png':
            if not head.startswith(b'\x89PNG\r\n\x1a\n'):
                return 'BROKEN', 'нет PNG-сигнатуры'
            if b'IEND' not in tail:
                return 'WARNING', 'в хвосте не найден IEND'
            return 'OK', ''

        if ext == 'gif' or mime == 'image/gif':
            if not (head.startswith(b'GIF87a') or head.startswith(b'GIF89a')):
                return 'BROKEN', 'нет GIF-сигнатуры'
            if not tail.endswith(b'\x3b'):
                return 'WARNING', 'нет GIF trailer'
            return 'OK', ''

        if ext in {'tif', 'tiff'} or mime == 'image/tiff':
            if not (head.startswith(b'II*\x00') or head.startswith(b'MM\x00*')):
                return 'BROKEN', 'нет TIFF-сигнатуры'
            return 'OK', ''

        if ext in {'zip', 'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp'} or mime == 'application/zip':
            try:
                with zipfile.ZipFile(path) as zf:
                    bad = zf.testzip()
                return ('BROKEN', f'ошибка CRC ZIP: {bad}') if bad else ('OK', '')
            except zipfile.BadZipFile:
                return 'BROKEN', 'битая ZIP-структура/central directory'
            except OSError as e:
                return 'WARNING', f'не удалось проверить ZIP: {e}'

        if mime.startswith('text/html') or ext in HTML_EXTS:
            low = head.lower()
            if not any(x in low for x in (b'<html', b'<!doctype', b'<head', b'<body')):
                return 'WARNING', 'HTML-сигнатура не обнаружена в начале файла'
            return 'OK', ''

        return 'OK', ''
    except OSError as e:
        return 'BROKEN', f'ошибка чтения: {e}'


def mode_verify():
    domain_dir = ask_domain_dir()
    if not domain_dir:
        return
    _, _, all_rows = load_db(domain_dir)
    if not all_rows:
        print('База архива пуста.')
        return

    occurrences = {}
    for r in all_rows:
        occurrences.setdefault(r['digest'], []).append(r)
    unique_rows = dedup_by_digest(all_rows)
    print(f'Проверяю {len(unique_rows)} уникальных файлов (они покрывают {len(all_rows)} появлений в архиве)...')

    ok = missing = mismatch = broken = warning = upstream_suspect = 0
    metadata_repairs = []
    problems = []
    for r in unique_rows:
        count = len(occurrences[r['digest']])
        tail = f' (и ещё {count - 1} появлений этого же файла)' if count > 1 else ''
        path = os.path.join(domain_dir, r['store_path'])
        if not os.path.isfile(path):
            missing += 1
            problems.append(f'ОТСУТСТВУЕТ: {r["original_url"]} @ {r["timestamp"]}{tail}')
            continue
        expected_digest = str(r.get('digest', '')).strip()
        expected_sha = str(r.get('sha256', '')).strip()
        valid, sha, _ = _verify_store_file(path, expected_digest, expected_sha)
        if not valid:
            try:
                actual_sha, _ = _sha256_and_size(path)
            except OSError as e:
                missing += 1
                problems.append(f'НЕ ЧИТАЕТСЯ: {r["original_url"]} @ {r["timestamp"]}: {e}{tail}')
                continue
            if expected_sha and actual_sha.lower() != expected_sha.lower():
                mismatch += 1
                problems.append(f'ИЗМЕНЁН: {r["original_url"]} @ {r["timestamp"]} (SHA-256 не совпал){tail}')
            elif not expected_digest.startswith('local_'):
                mismatch += 1
                problems.append(f'ИЗМЕНЁН: {r["original_url"]} @ {r["timestamp"]} (Wayback SHA-1 digest не совпал){tail}')
            else:
                mismatch += 1
                problems.append(f'ИЗМЕНЁН: {r["original_url"]} @ {r["timestamp"]} (контрольная сумма не совпала){tail}')
            continue

        # Если физический файл полностью подтверждён Wayback SHA-1, но в старой
        # базе отсутствует SHA-256/размер, можно восстановить только метаданные —
        # сеть для этого не нужна. Обновляем все появления этого digest ниже.
        if (not expected_sha or not str(r.get('size_bytes', '')).isdigit() or
                int(r.get('size_bytes') or 0) <= 0):
            metadata_repairs.append((expected_digest, sha, os.path.getsize(path)))

        status, detail = inspect_file_structure(path, r.get('mimetype', ''), r.get('original_url', ''))
        if status == 'BROKEN':
            broken += 1
            upstream_suspect += 1
            problems.append(f'СТРУКТУРНО БИТ: {r["original_url"]} @ {r["timestamp"]}: {detail}{tail} | SHA совпадает; вероятно, проблема самого snapshot/Wayback')
        elif status == 'WARNING':
            warning += 1
            problems.append(f'ПРЕДУПРЕЖДЕНИЕ: {r["original_url"]} @ {r["timestamp"]}: {detail}{tail}')
        else:
            ok += 1

    if metadata_repairs:
        repair_by_digest = {d: (sha, size) for d, sha, size in metadata_repairs}
        repaired_rows = []
        for row in all_rows:
            d = str(row.get('digest', '')).strip()
            if d in repair_by_digest:
                sha, size = repair_by_digest[d]
                row2 = dict(row)
                row2['sha256'] = sha
                row2['size_bytes'] = str(size)
                repaired_rows.append([
                    row2['digest'], row2['original_url'], row2['timestamp'], row2.get('mimetype', ''),
                    row2.get('statuscode', ''), row2.get('size_bytes', ''), row2.get('sha256', ''),
                    row2.get('store_path', ''), row2.get('first_seen', ''),
                ])
        if repaired_rows:
            append_db(domain_dir, repaired_rows)
            print(f"  Восстановлены метаданные БД без скачивания: {len(repaired_rows)} появлений.")

    reports_dir = os.path.join(domain_dir, DIR_REPORTS)
    os.makedirs(reports_dir, exist_ok=True)
    path = os.path.join(reports_dir, 'проверка_целостности.txt')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f'ПРОВЕРКА ЦЕЛОСТНОСТИ от {datetime.now().strftime("%Y-%m-%d %H:%M")}\n')
        f.write(f'Всего появлений в базе: {len(all_rows)}, уникальных физических файлов: {len(unique_rows)}\n')
        f.write(f'OK: {ok} | предупреждения: {warning} | структурно битые: {broken} | отсутствует: {missing} | SHA-256 изменён: {mismatch}\n')
        f.write(f'Из структурно битых с совпавшими контрольными суммами: {upstream_suspect} — вероятно, проблема historical snapshot/Wayback\n')
        f.write(f'Восстановлено метаданных БД без скачивания: {len(metadata_repairs)} физических файлов\n\n')
        f.write('\n'.join(problems))

    print(f'\nOK: {ok}, предупреждения: {warning}, структурно битые: {broken}, отсутствует: {missing}, SHA-256 изменён: {mismatch}')
    if upstream_suspect:
        print(f'  Из структурно битых с совпавшими контрольными суммами: {upstream_suspect} — вероятно проблема snapshot/Wayback')
    print(f'Отчёт: {path}')


# ==================== ГЛАВНАЯ ====================

def main():
    os.makedirs(BASE_ARCHIVE_DIR, exist_ok=True)
    print_banner()
    print(RED + MENU + RESET)
    choice = input("Выбор > ").strip().lstrip("0") or "1"

    if choice == "1":
        mode_download()
    elif choice == "2":
        mode_reports()
    elif choice == "3":
        mode_verify()
    elif choice == "4":
        return
    else:
        print("Нет такого пункта.")

    input("\nНажмите Enter для выхода...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nОстановлено пользователем.")
    except Exception:
        print("\nПроизошла непредвиденная ошибка:")
        traceback.print_exc()
        input("\nНажмите Enter для выхода...")


