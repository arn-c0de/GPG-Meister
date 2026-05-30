"""Main application window — tab container and startup check display (planv2.md §4.8)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QLabel,
    QMainWindow,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.config import AppPage
from gpg_meister.ui.errors.user_error import ErrorSeverity
from gpg_meister.ui.widgets.warning_banner import WarningBanner

if TYPE_CHECKING:
    from gpg_meister.startup.environment_check import CheckResult

# Tab order and display labels — the single source of truth for both the
# placeholders built at startup and the real views installed later.
_TAB_DEFS: list[tuple[AppPage, str]] = [
    (AppPage.KEYS, "Keys"),
    (AppPage.MESSAGES, "Messages"),
    (AppPage.VAULT, "Vault"),
    (AppPage.SETTINGS, "Settings"),
    (AppPage.HELP, "Help"),
]


class _PlaceholderTab(QWidget):
    """Placeholder tab shown while a feature is not yet loaded."""

    def __init__(self, name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        label = QLabel(f"{name} — not yet implemented")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)


class MainWindow(QMainWindow):
    """Application main window.

    Tab order: Keys | Messages | Vault | Settings | Help
    Startup warnings from environment_check are displayed as dismissible banners
    at the top of the window.
    """

    current_page_changed: Signal = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("GPG Meister")
        self.setMinimumSize(820, 780)
        _icon_path = Path(__file__).parent.parent / "logo.png"
        if _icon_path.exists():
            self.setWindowIcon(QIcon(str(_icon_path)))
        self._banners: list[WarningBanner] = []
        self._tab_pages: list[AppPage] = []
        self._tab_labels: dict[AppPage, str] = dict(_TAB_DEFS)
        self._build_ui()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        self._root_layout = QVBoxLayout(central)
        self._root_layout.setContentsMargins(0, 0, 0, 0)
        self._root_layout.setSpacing(0)

        self._banner_container = QWidget()
        self._banner_layout = QVBoxLayout(self._banner_container)
        self._banner_layout.setContentsMargins(8, 4, 8, 0)
        self._banner_layout.setSpacing(4)
        self._root_layout.addWidget(self._banner_container)

        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        self._tabs.setMovable(False)
        self._root_layout.addWidget(self._tabs, stretch=1)

        for page, label in _TAB_DEFS:
            self._add_tab(_PlaceholderTab(label), label, page)
        self._tabs.currentChanged.connect(self._emit_current_page_changed)

        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)

    def show_startup_results(self, result: CheckResult) -> None:
        """Display banners for warnings produced by environment_check.run_all_checks()."""
        for warning in result.warnings:
            severity = (
                ErrorSeverity.ERROR
                if warning.code in {
                    "config_world_readable",
                    "config_unsafe_permissions",
                    "config_readable_by_others",
                    "missing_packages",
                }
                else ErrorSeverity.WARNING
            )
            banner = WarningBanner(warning.message, severity=severity, dismissible=True)
            self._banner_layout.addWidget(banner)
            self._banners.append(banner)

        if not result.mlock_available:
            info_banner = WarningBanner(
                "mlock is not available on this system. "
                "Key material may be paged to disk during low-memory conditions.",
                severity=ErrorSeverity.INFO,
                dismissible=True,
            )
            self._banner_layout.addWidget(info_banner)
            self._banners.append(info_banner)

    def show_status(self, message: str, timeout_ms: int = 4000) -> None:
        self._status_bar.showMessage(message, timeout_ms)

    def install_tab(self, page: AppPage, view: QWidget) -> None:
        """Replace a page's placeholder tab with its real view.

        The index and label are looked up from the tabs built in ``_build_ui``,
        so callers never repeat the tab order or hard-code an index.
        """
        try:
            index = self._tab_pages.index(page)
        except ValueError:
            raise ValueError(
                f"install_tab: {page!r} is not registered in _TAB_DEFS — add it to _build_ui first"
            ) from None
        self._tabs.removeTab(index)
        self._tabs.insertTab(index, view, self._tab_labels[page])
        self._tab_pages[index] = page

    def current_page(self) -> AppPage:
        page = self._page_at(self._tabs.currentIndex())
        return page if page is not None else AppPage.KEYS

    def set_current_page(self, page: AppPage) -> bool:
        for index, tab_page in enumerate(self._tab_pages):
            if tab_page == page:
                self._tabs.setCurrentIndex(index)
                return True
        return False

    def show_backup_reminder(self, uid: str) -> None:
        """Show a one-time backup banner after a key is created."""
        banner = WarningBanner(
            f'New key "{uid}" created. Create a vault backup so you can restore it later.',
            severity=ErrorSeverity.WARNING,
            dismissible=True,
            action_text="Back up now…",
        )
        banner.action_clicked.connect(lambda: self.set_current_page(AppPage.VAULT))
        self._banner_layout.addWidget(banner)
        self._banners.append(banner)

    def _add_tab(self, widget: QWidget, label: str, page: AppPage) -> None:
        self._tabs.addTab(widget, label)
        self._tab_pages.append(page)

    def _emit_current_page_changed(self, index: int) -> None:
        page = self._page_at(index)
        if page is not None:
            self.current_page_changed.emit(page.value)

    def _page_at(self, index: int) -> AppPage | None:
        if index < 0 or index >= len(self._tab_pages):
            return None
        return self._tab_pages[index]
