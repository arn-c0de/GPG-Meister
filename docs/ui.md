# UI Layer

The UI code lives in `src/gpg_meister/ui`.

It uses PySide6 and follows an MVVM-like split:

- views build widgets
- viewmodels manage state and call services
- workers run blocking tasks in background threads

## `main_window.py`

`MainWindow` is the app shell.

It provides:

- the top-level tab layout
- startup warning banners
- a status bar
- methods to install the real tab views after wiring

The placeholder-tab approach keeps the startup structure simple and clear.

## Viewmodels

Each feature area has its own ViewModel files under `ui/keys`, `ui/messages`, `ui/vault`, and `ui/settings`.

They are responsible for:

- starting service calls
- handling results and errors
- exposing state through Qt signals

The UI does not perform cryptographic work directly.

## `worker.py`

This is the shared background task helper.

It wraps a callable in a `QRunnable` and emits:

- `result`
- `error`
- `finished`

One useful implementation detail:

it keeps a Python reference to live workers so PySide does not garbage-collect them before the thread pool runs them.

## Key UI area

The keys section is currently one of the best examples of the architecture.

It includes:

- key list view
- key list viewmodel
- key creation dialog
- public key import dialog
- first-launch wizard
- key detail dialog with editable usage context

The detail dialog now supports editing:

- label
- platform
- purpose
- notes

This data is saved through `KeyService`, not directly in the UI.

## Messages and vault UI

The message and vault tabs follow the same pattern:

- view collects user input
- viewmodel triggers a service
- background worker prevents UI freeze
- result is rendered back into the widgets

## Design reality

The plan describes a clean MVVM architecture, and the current code mostly follows it.

It is not a heavy framework-driven MVVM implementation. It is a practical Qt version:

- signal-based communication
- service-driven viewmodels
- low logic in widgets

That is a good fit for this project size.
