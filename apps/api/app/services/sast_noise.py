from __future__ import annotations

from pathlib import PurePosixPath


IGNORED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    "coverage",
    "__pycache__",
    "vendor",
    "vendors",
    "third_party",
    "bower_components",
}

IGNORED_FILE_SUFFIXES = (
    ".min.js",
    ".min.css",
    ".bundle.js",
    ".bundle.css",
    ".map",
)

IGNORED_PATH_PREFIXES = (
    "public/assets/",
    "public/vendor/",
    "static/vendor/",
    "static/assets/",
)


def normalize_scan_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def is_noise_path(path: str) -> bool:
    normalized = normalize_scan_path(path)
    pure_path = PurePosixPath(normalized)
    parts = set(pure_path.parts)
    if parts.intersection(IGNORED_DIRS):
        return True
    if normalized.endswith(IGNORED_FILE_SUFFIXES):
        return True
    return any(normalized.startswith(prefix) for prefix in IGNORED_PATH_PREFIXES)


def noise_reason(path: str) -> str | None:
    normalized = normalize_scan_path(path)
    pure_path = PurePosixPath(normalized)
    parts = set(pure_path.parts)
    if parts.intersection({"vendor", "vendors", "third_party", "node_modules", "bower_components"}):
        return "third_party_code"
    if normalized.endswith((".min.js", ".min.css", ".bundle.js", ".bundle.css", ".map")):
        return "minified_or_bundled_asset"
    if parts.intersection({"dist", "build", "target", "coverage"}) or any(
        normalized.startswith(prefix) for prefix in IGNORED_PATH_PREFIXES
    ):
        return "generated_or_static_asset"
    return None
