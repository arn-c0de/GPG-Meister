"""Main application window — tab container and startup check display (planv2.md §4.8)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
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
        self.setMinimumSize(820, 560)
        self._banners: list[WarningBanner] = []
        self._tab_pages: list[AppPage] = []
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

        self._add_tab(_PlaceholderTab("Keys"), "Keys", AppPage.KEYS)
        self._add_tab(_PlaceholderTab("Messages"), "Messages", AppPage.MESSAGES)
        self._add_tab(_PlaceholderTab("Vault"), "Vault", AppPage.VAULT)
        self._add_tab(_PlaceholderTab("Settings"), "Settings", AppPage.SETTINGS)
        self._add_tab(_PlaceholderTab("Help"), "Help", AppPage.HELP)
        self._tabs.currentChanged.connect(self._emit_current_page_changed)

        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)

    def show_startup_results(self, result: CheckResult) -> None:
        """Display banners for warnings produced by environment_check.run_all_checks()."""
        for warning in result.warnings:
            severity = (
                ErrorSeverity.ERROR
                if warning.code in {"config_world_readable", "missing_packages"}
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

    def install_keys_tab(self, view: QWidget) -> None:
        """Replace the placeholder Keys tab with the real KeyListView."""
        self.replace_tab(0, view, "Keys", AppPage.KEYS)

    def install_messages_tab(self, view: QWidget) -> None:
        """Replace the placeholder Messages tab with the real MessagesTabView."""
        self.replace_tab(1, view, "Messages", AppPage.MESSAGES)

    def install_vault_tab(self, view: QWidget) -> None:
        """Replace the placeholder Vault tab with the real VaultTabView."""
        self.replace_tab(2, view, "Vault", AppPage.VAULT)

    def install_settings_tab(self, view: QWidget) -> None:
        """Replace the placeholder Settings tab with the real SettingsView."""
        self.replace_tab(3, view, "Settings", AppPage.SETTINGS)

    def install_help_tab(self, view: QWidget) -> None:
        """Replace the placeholder Help tab with the real HelpView."""
        self.replace_tab(4, view, "Help", AppPage.HELP)

    def replace_tab(self, index: int, widget: QWidget, label: str, page: AppPage) -> None:
        """Replace a placeholder tab with a real view."""
        self._tabs.removeTab(index)
        self._tabs.insertTab(index, widget, label)
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
        )
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
