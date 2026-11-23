"""A Windows notification-area (system tray) icon, using only ctypes.

`lantern web --tray` runs the dashboard server on a background thread and
this icon on the main thread. Double-click or "Open dashboard" opens the
browser; "Quit Lantern" stops the server and removes the icon. No network
or file access happens here, and nothing outside the standard library is
needed. On other systems `is_supported()` is False and `TrayIcon.run` raises.
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Callable

_IS_WINDOWS = os.name == "nt"

WM_NULL = 0x0000
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_USER = 0x0400
WM_TRAY = WM_USER + 1
WM_APP = 0x8000
WM_SHOW_PENDING = WM_APP + 2  # posted by notify() from another thread
NIN_BALLOONUSERCLICK = WM_USER + 5
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205

NIM_ADD = 0
NIM_MODIFY = 1
NIM_DELETE = 2
NIF_MESSAGE = 0x1
NIF_ICON = 0x2
NIF_TIP = 0x4
NIF_INFO = 0x10
NIIF_INFO = 0x1
INFO_TITLE_MAX = 63
INFO_TEXT_MAX = 255

MF_STRING = 0x0
MF_SEPARATOR = 0x800
TPM_RIGHTBUTTON = 0x2
TPM_NONOTIFY = 0x80
TPM_RETURNCMD = 0x100

ID_OPEN = 1
ID_QUIT = 2
IDI_APPLICATION = 32512
TOOLTIP_MAX = 127  # szTip holds 128 UTF-16 units including the terminator


def is_supported() -> bool:
    """True where a tray icon can be shown (Windows)."""
    return _IS_WINDOWS


def clip_tooltip(text: str) -> str:
    """The tooltip as the notification area will show it: at most 127 characters."""
    return text[:TOOLTIP_MAX]


class TrayIcon:
    """One tray icon with an Open and a Quit command, and notifications.

    ``on_open`` runs on the tray thread when the user double-clicks the icon,
    chooses "Open dashboard", or clicks a notification. ``on_quit`` runs once
    when the user chooses "Quit Lantern", before the icon is removed. `stop`
    and `notify` may be called from any thread.
    """

    def __init__(
        self,
        tooltip: str,
        on_open: Callable[[], None],
        on_quit: Callable[[], None],
        icon_path: str | None = None,
    ) -> None:
        self.tooltip = clip_tooltip(tooltip)
        self.on_open = on_open
        self.on_quit = on_quit
        self.icon_path = icon_path
        self._hwnd = None
        self._ready = threading.Event()
        self._quit_called = False
        self._error: BaseException | None = None
        self._pending: tuple[str, str] | None = None
        self._pending_lock = threading.Lock()

    # -- public ----------------------------------------------------------

    def wait_ready(self, timeout: float = 5.0) -> bool:
        """True once the icon is in the notification area (or run() failed)."""
        return self._ready.wait(timeout)

    def stop(self) -> None:
        """Ask the tray loop to finish. Safe from any thread, and safe to repeat."""
        hwnd = self._hwnd
        if not _IS_WINDOWS or not hwnd:
            return
        import ctypes

        ctypes.WinDLL("user32").PostMessageW(hwnd, WM_CLOSE, 0, 0)

    def notify(self, title: str, text: str) -> bool:
        """Show a notification from the icon. Safe from any thread.

        Only the newest message is kept if several arrive before the tray
        thread shows them. False when the icon is not running.
        """
        with self._pending_lock:
            self._pending = (str(title)[:INFO_TITLE_MAX], str(text)[:INFO_TEXT_MAX])
        hwnd = self._hwnd
        if not _IS_WINDOWS or not hwnd:
            return False
        import ctypes

        return bool(ctypes.WinDLL("user32").PostMessageW(hwnd, WM_SHOW_PENDING, 0, 0))

    def _take_pending(self) -> tuple[str, str] | None:
        with self._pending_lock:
            pending, self._pending = self._pending, None
        return pending

    def run(self) -> None:
        """Show the icon and handle its messages until Quit or `stop`. Blocks."""
        if not _IS_WINDOWS:
            raise RuntimeError("The tray icon is available on Windows only.")
        try:
            self._run_windows()
        except BaseException as exc:
            self._error = exc
            self._ready.set()
            raise

    # -- Windows ---------------------------------------------------------

    def _run_windows(self) -> None:  # pragma: no cover - needs a Windows desktop
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        LRESULT = ctypes.c_ssize_t
        WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [
                ("style", wintypes.UINT),
                ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HANDLE),
                ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
            ]

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8),
            ]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("hWnd", wintypes.HWND),
                ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT),
                ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128),
                ("dwState", wintypes.DWORD),
                ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256),
                ("uTimeoutOrVersion", wintypes.UINT),
                ("szInfoTitle", wintypes.WCHAR * 64),
                ("dwInfoFlags", wintypes.DWORD),
                ("guidItem", GUID),
                ("hBalloonIcon", wintypes.HICON),
            ]

        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = LRESULT
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        user32.RegisterClassW.restype = wintypes.ATOM
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
        user32.RegisterWindowMessageW.restype = wintypes.UINT
        user32.CreatePopupMenu.restype = wintypes.HMENU
        user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
        user32.TrackPopupMenu.argtypes = [
            wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.LPVOID,
        ]
        user32.DestroyMenu.argtypes = [wintypes.HMENU]
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        user32.LoadIconW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
        user32.LoadIconW.restype = wintypes.HICON
        shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        shell32.Shell_NotifyIconW.restype = wintypes.BOOL
        shell32.ExtractIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT]
        shell32.ExtractIconW.restype = wintypes.HICON
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE

        hinstance = kernel32.GetModuleHandleW(None)
        taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")
        icon = self._load_icon(user32, shell32, hinstance)

        data = NOTIFYICONDATAW()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        data.uID = 1
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        data.uCallbackMessage = WM_TRAY
        data.hIcon = icon
        data.szTip = self.tooltip

        def add_icon() -> bool:
            return bool(shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(data)))

        def show_pending() -> None:
            pending = self._take_pending()
            if pending is None:
                return
            title, text = pending
            flags = data.uFlags
            data.uFlags = NIF_INFO
            data.szInfoTitle = title
            data.szInfo = text
            data.dwInfoFlags = NIIF_INFO
            try:
                shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(data))
            finally:
                data.uFlags = flags
                data.szInfo = ""
                data.szInfoTitle = ""

        def show_menu(hwnd) -> None:
            menu = user32.CreatePopupMenu()
            try:
                user32.AppendMenuW(menu, MF_STRING, ID_OPEN, "Open dashboard")
                user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
                user32.AppendMenuW(menu, MF_STRING, ID_QUIT, "Quit Lantern")
                point = wintypes.POINT()
                user32.GetCursorPos(ctypes.byref(point))
                # Required so the menu closes when the user clicks elsewhere.
                user32.SetForegroundWindow(hwnd)
                command = user32.TrackPopupMenu(
                    menu, TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD,
                    point.x, point.y, 0, hwnd, None,
                )
                user32.PostMessageW(hwnd, WM_NULL, 0, 0)
            finally:
                user32.DestroyMenu(menu)
            if command == ID_OPEN:
                self._safely(self.on_open)
            elif command == ID_QUIT:
                self._quit(user32, hwnd)

        def window_proc(hwnd, message, wparam, lparam):
            try:
                if message == WM_TRAY:
                    event = lparam & 0xFFFF
                    if event in (WM_LBUTTONDBLCLK, NIN_BALLOONUSERCLICK):
                        self._safely(self.on_open)
                    elif event == WM_RBUTTONUP:
                        show_menu(hwnd)
                    return 0
                if message == WM_SHOW_PENDING:
                    show_pending()
                    return 0
                if taskbar_created and message == taskbar_created:
                    add_icon()  # Explorer restarted: put the icon back
                    return 0
                if message == WM_CLOSE:
                    self._quit(user32, hwnd)
                    return 0
                if message == WM_DESTROY:
                    shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(data))
                    user32.PostQuitMessage(0)
                    return 0
            except BaseException as exc:  # never let an exception cross into Windows
                self._error = exc
            return user32.DefWindowProcW(hwnd, message, wparam, lparam)

        proc = WNDPROC(window_proc)  # keep a reference for the life of the window
        class_name = f"LanternTray{os.getpid()}"
        wndclass = WNDCLASSW()
        wndclass.lpfnWndProc = proc
        wndclass.hInstance = hinstance
        wndclass.lpszClassName = class_name
        if not user32.RegisterClassW(ctypes.byref(wndclass)):
            raise OSError(ctypes.get_last_error(), "Could not register the tray window class.")
        hwnd = user32.CreateWindowExW(0, class_name, "Lantern", 0, 0, 0, 0, 0, None, None, hinstance, None)
        if not hwnd:
            user32.UnregisterClassW(class_name, hinstance)
            raise OSError(ctypes.get_last_error(), "Could not create the tray window.")
        data.hWnd = hwnd
        self._hwnd = hwnd
        try:
            if not add_icon():
                raise OSError(ctypes.get_last_error(), "Could not add the tray icon.")
            self._ready.set()
            show_pending()  # a notify() that came before the window existed
            message = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(message))
                user32.DispatchMessageW(ctypes.byref(message))
        finally:
            self._hwnd = None
            user32.UnregisterClassW(class_name, hinstance)

    def _load_icon(self, user32, shell32, hinstance):  # pragma: no cover
        import ctypes

        candidates = []
        if self.icon_path:
            candidates.append(self.icon_path)
        if getattr(sys, "frozen", False):
            candidates.append(sys.executable)  # the exe carries the Lantern icon
        for path in candidates:
            if os.path.isfile(path):
                handle = shell32.ExtractIconW(hinstance, path, 0)
                if handle and handle != 1:  # 1 means "not an icon file"
                    return handle
        return user32.LoadIconW(None, ctypes.c_void_p(IDI_APPLICATION))

    def _quit(self, user32, hwnd) -> None:  # pragma: no cover
        if not self._quit_called:
            self._quit_called = True
            self._safely(self.on_quit)
        user32.DestroyWindow(hwnd)

    def _safely(self, callback: Callable[[], None]) -> None:
        try:
            callback()
        except Exception:
            # A failed browser launch must not take the tray down.
            pass
