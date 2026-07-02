"""Print translation coverage of each `.ts` catalog against a base language.

Compares every `<code>.ts` file in ``src/gpg_meister/i18n/`` against a base
catalog (``en.ts`` by default) and prints a compact Markdown table with each
language's coverage percentage and translated-string count, ready to paste into
the "Improve Language Support" tracking issue (#1).

Usage:
    python scripts/translation_coverage.py            # base = en
    python scripts/translation_coverage.py --base de  # compare against de.ts

A string counts as *translated* when its <translation> is non-empty and is not
marked ``type="unfinished"``. Keys are (context, source) pairs, so the same
source text in two contexts is tracked separately.
"""

from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
I18N_DIR = ROOT / "src" / "gpg_meister" / "i18n"

# key = (context name, source string)
Key = tuple[str, str]

_LANGUAGE_NAMES = {
    "en": "English",
    "de": "German",
    "fr": "French",
    "es": "Spanish",
    "tr": "Turkish",
    "it": "Italian",
    "pt": "Portuguese",
    "pt-BR": "Portuguese (Brazil)",
    "nl": "Dutch",
    "pl": "Polish",
    "uk": "Ukrainian",
    "ja": "Japanese",
    "ko": "Korean",
    "zh-CN": "Chinese (Simplified)",
    "ar": "Arabic",
    "he": "Hebrew",
}


def _language_name(code: str) -> str:
    return _LANGUAGE_NAMES.get(code, code)


def _parse(ts_path: Path) -> tuple[set[Key], set[Key]]:
    """Return (all_keys, translated_keys) for a .ts file."""
    root = ET.parse(ts_path).getroot()
    all_keys: set[Key] = set()
    translated: set[Key] = set()
    for context in root.findall("context"):
        name = (context.findtext("name") or "").strip()
        for message in context.findall("message"):
            source = message.findtext("source")
            if source is None:
                continue
            key = (name, source)
            all_keys.add(key)
            node = message.find("translation")
            if node is None:
                continue
            if (node.text or "").strip() and node.get("type") != "unfinished":
                translated.add(key)
    return all_keys, translated


def build_table(base_code: str) -> str:
    base_path = I18N_DIR / f"{base_code}.ts"
    if not base_path.exists():
        raise SystemExit(f"base catalog not found: {base_path.relative_to(ROOT)}")

    base_keys, _ = _parse(base_path)
    total = len(base_keys)
    if total == 0:
        raise SystemExit(f"base catalog {base_path.name} has no strings")

    rows = [
        "## Translation coverage",
        "",
        f"Base: `{base_code}.ts` — {total} translatable strings.",
        "",
        "| Language | Coverage | Strings |",
        "| --- | --- | --- |",
        f"| {_language_name(base_code)} | 100% | {total} / {total} |",
    ]
    for path in sorted(p for p in I18N_DIR.glob("*.ts") if p.stem != base_code):
        _, translated = _parse(path)
        covered = len(base_keys & translated)
        pct = round(covered / total * 100)
        rows.append(f"| {_language_name(path.stem)} | {pct}% | {covered} / {total} |")
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base", default="en", help="base locale code to compare against (default: en)"
    )
    args = parser.parse_args()
    print(build_table(args.base))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
