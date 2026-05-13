from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
I18N_DIR = ROOT / "src" / "gpg_meister" / "i18n"


def _assert_complete(ts_path: Path) -> None:
    content = ts_path.read_text(encoding="utf-8")
    unfinished = re.findall(r'<translation\b[^>]*\btype="unfinished"', content)
    if unfinished:
        raise SystemExit(
            f"{ts_path.name} still has {len(unfinished)} unfinished translation entries"
        )


def main() -> int:
    ts_files = sorted(I18N_DIR.glob("*.ts"))
    if not ts_files:
        raise SystemExit("no .ts translation files found")

    lrelease = ROOT / ".venv" / "bin" / "pyside6-lrelease"
    if not lrelease.exists():
        raise SystemExit("missing .venv/bin/pyside6-lrelease; run `uv sync --extra dev` first")

    for ts_path in ts_files:
        _assert_complete(ts_path)
        qm_path = ts_path.with_suffix(".qm")
        subprocess.run(  # noqa: S603
            [str(lrelease), str(ts_path), "-qm", str(qm_path)],
            check=True,
            cwd=ROOT,
        )
        print(f"built {qm_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
