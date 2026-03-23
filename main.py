def main() -> None:
    try:
        from src.gui import main as gui_main
    except ModuleNotFoundError as exc:
        if exc.name == "tkinter":
            raise RuntimeError("tkinter is required to launch the desktop GUI") from exc
        raise
    gui_main()


if __name__ == "__main__":
    main()
