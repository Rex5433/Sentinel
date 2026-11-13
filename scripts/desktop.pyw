"""Windowless Windows entry point; keep bootstrap failures visible."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from scripts.desktop import main
    main()
except Exception:
    import traceback
    folder = Path(__file__).resolve().parents[1] / "tmp"
    folder.mkdir(exist_ok=True)
    with (folder / "desktop-error.txt").open("w", encoding="utf-8") as stream:
        traceback.print_exc(file=stream)
    import ctypes
    ctypes.windll.user32.MessageBoxW(None, "Sentinel could not start. See tmp/desktop-error.txt in this folder.\nUse Python 3.11+ with Tcl/Tk installed.", "Sentinel", 0x10)
