from __future__ import annotations

import queue
import socket
import threading
import tkinter.filedialog as filedialog
from pathlib import Path

import customtkinter as ctk

from src.udp_client import (
    TransferPaused,
    create_downloader,
    create_uploader,
    list_server_files,
)
from src.udp_server import ThreadedRUDPServer


def discover_local_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


class RFTPApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.title("RFTP Central Server Transfer")
        self.geometry("1400x720")
        self.minsize(1200, 640)

        self.local_ip = discover_local_ip()
        self.upload_queue: queue.Queue[dict[str, object]] = queue.Queue()
        self.download_queue: queue.Queue[dict[str, object]] = queue.Queue()
        self.server_queue: queue.Queue[dict[str, object]] = queue.Queue()
        self.upload_thread: threading.Thread | None = None
        self.download_thread: threading.Thread | None = None
        self.upload_transfer = None
        self.download_transfer = None
        self.upload_socket: socket.socket | None = None
        self.download_socket: socket.socket | None = None
        self.server_thread: threading.Thread | None = None
        self.server: ThreadedRUDPServer | None = None
        self.list_thread: threading.Thread | None = None
        self.download_file_buttons: list[ctk.CTkButton] = []

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_home_view()
        self._build_server_view()
        self._build_client_view()
        self.show_home()

        self.after(100, self.process_queues)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    @staticmethod
    def _drain_queue(q: queue.Queue[dict[str, object]], limit: int = 40) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        for _ in range(limit):
            if q.empty():
                break
            items.append(q.get_nowait())
        return items

    def _build_home_view(self) -> None:
        self.home_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame.grid_columnconfigure((0, 1), weight=1, uniform="role")
        self.home_frame.grid_rowconfigure(0, weight=1)

        intro = ctk.CTkFrame(self.home_frame, corner_radius=24)
        intro.grid(row=0, column=0, columnspan=2, padx=28, pady=(28, 16), sticky="ew")
        intro.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(intro, text="RFTP", font=ctk.CTkFont(size=38, weight="bold")).grid(
            row=0, column=0, padx=28, pady=(28, 8), sticky="w"
        )
        ctk.CTkLabel(
            intro,
            text="Choose how you want to use this machine on the network. Run the central server here, or use this machine as a client to upload and download files.",
            wraplength=920,
            justify="left",
        ).grid(row=1, column=0, padx=28, pady=(0, 28), sticky="w")

        server_card = ctk.CTkFrame(self.home_frame, corner_radius=24)
        server_card.grid(row=1, column=0, padx=(28, 12), pady=(0, 28), sticky="nsew")
        server_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(server_card, text="Server", font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, padx=24, pady=(24, 8), sticky="w"
        )
        ctk.CTkLabel(
            server_card,
            text="Host the shared file server. Other devices upload files to this machine and download files from it.",
            wraplength=420,
            justify="left",
        ).grid(row=1, column=0, padx=24, pady=(0, 18), sticky="w")
        ctk.CTkLabel(server_card, text=f"Detected LAN IP: {self.local_ip}").grid(
            row=2, column=0, padx=24, pady=(0, 18), sticky="w"
        )
        ctk.CTkButton(server_card, text="Continue As Server", height=44, command=self.show_server).grid(
            row=3, column=0, padx=24, pady=(0, 24), sticky="ew"
        )

        client_card = ctk.CTkFrame(self.home_frame, corner_radius=24)
        client_card.grid(row=1, column=1, padx=(12, 28), pady=(0, 28), sticky="nsew")
        client_card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(client_card, text="Client", font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, padx=24, pady=(24, 8), sticky="w"
        )
        ctk.CTkLabel(
            client_card,
            text="Connect to an existing server to upload local files or browse and download shared files.",
            wraplength=420,
            justify="left",
        ).grid(row=1, column=0, padx=24, pady=(0, 18), sticky="w")
        ctk.CTkLabel(client_card, text="Use the server's LAN IP and port to connect.").grid(
            row=2, column=0, padx=24, pady=(0, 18), sticky="w"
        )
        ctk.CTkButton(client_card, text="Continue As Client", height=44, command=self.show_client).grid(
            row=3, column=0, padx=24, pady=(0, 24), sticky="ew"
        )

    def _build_server_view(self) -> None:
        self.server_view = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.server_view.grid_columnconfigure(0, weight=1)
        self.server_view.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self.server_view, corner_radius=18)
        header.grid(row=0, column=0, padx=18, pady=(18, 10), sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(header, text="Back", width=100, command=self.show_home).grid(
            row=0, column=0, padx=16, pady=16, sticky="w"
        )
        ctk.CTkLabel(header, text="Server Workspace", font=ctk.CTkFont(size=26, weight="bold")).grid(
            row=0, column=1, padx=12, pady=16, sticky="w"
        )

        self.server_panel = self._create_server_panel(self.server_view)
        self.server_panel.grid(row=1, column=0, padx=18, pady=(0, 18), sticky="nsew")

    def _build_client_view(self) -> None:
        self.client_view = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.client_view.grid_columnconfigure((0, 1), weight=1, uniform="client")
        self.client_view.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self.client_view, corner_radius=18)
        header.grid(row=0, column=0, columnspan=2, padx=18, pady=(18, 10), sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(header, text="Back", width=100, command=self.show_home).grid(
            row=0, column=0, padx=16, pady=16, sticky="w"
        )
        ctk.CTkLabel(header, text="Client Workspace", font=ctk.CTkFont(size=26, weight="bold")).grid(
            row=0, column=1, padx=12, pady=16, sticky="w"
        )

        self.upload_panel = self._create_upload_panel(self.client_view)
        self.upload_panel.grid(row=1, column=0, padx=(18, 9), pady=(0, 18), sticky="nsew")

        self.download_panel = self._create_download_panel(self.client_view)
        self.download_panel.grid(row=1, column=1, padx=(9, 18), pady=(0, 18), sticky="nsew")

    def _create_server_panel(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        panel = ctk.CTkFrame(parent, corner_radius=18)
        panel.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(panel, text="Server", font=ctk.CTkFont(size=24, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(20, 8), sticky="w"
        )
        ctk.CTkLabel(
            panel,
            text="Run the central server here. Clients on the network upload files to it and download files from it.",
            wraplength=900,
            justify="left",
        ).grid(row=1, column=0, padx=20, pady=(0, 18), sticky="w")

        self.server_ip_var = ctk.StringVar(value="0.0.0.0")
        self.server_port_var = ctk.StringVar(value="9000")
        self.server_dir_var = ctk.StringVar(value=str((Path.cwd() / "server_storage").resolve()))
        self.server_status_var = ctk.StringVar(value="Server stopped")
        self.server_progress_var = ctk.StringVar(value="No active server transfers")
        self.local_ip_var = ctk.StringVar(value=f"Clients should connect to: {self.local_ip}")

        network_row = ctk.CTkFrame(panel, fg_color="transparent")
        network_row.grid(row=2, column=0, padx=20, pady=(0, 12), sticky="ew")
        network_row.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkEntry(network_row, textvariable=self.server_ip_var, placeholder_text="Bind IP").grid(
            row=0, column=0, padx=(0, 8), sticky="ew"
        )
        ctk.CTkEntry(network_row, textvariable=self.server_port_var, placeholder_text="Port").grid(
            row=0, column=1, padx=(8, 0), sticky="ew"
        )
        ctk.CTkLabel(network_row, textvariable=self.local_ip_var, anchor="w").grid(
            row=1, column=0, columnspan=2, pady=(8, 0), sticky="ew"
        )

        storage_row = ctk.CTkFrame(panel, fg_color="transparent")
        storage_row.grid(row=3, column=0, padx=20, pady=(0, 12), sticky="ew")
        storage_row.grid_columnconfigure(0, weight=1)
        ctk.CTkEntry(storage_row, textvariable=self.server_dir_var, placeholder_text="Server storage directory").grid(
            row=0, column=0, padx=(0, 10), sticky="ew"
        )
        ctk.CTkButton(storage_row, text="Browse", width=96, command=self.choose_server_dir).grid(
            row=0, column=1, sticky="ew"
        )

        button_row = ctk.CTkFrame(panel, fg_color="transparent")
        button_row.grid(row=4, column=0, padx=20, pady=(4, 16), sticky="ew")
        button_row.grid_columnconfigure((0, 1), weight=1)
        self.server_start_button = ctk.CTkButton(button_row, text="Start Server", command=self.start_server)
        self.server_start_button.grid(row=0, column=0, padx=(0, 8), sticky="ew")
        self.server_stop_button = ctk.CTkButton(
            button_row,
            text="Stop Server",
            command=self.stop_server,
            state="disabled",
        )
        self.server_stop_button.grid(row=0, column=1, padx=(8, 0), sticky="ew")

        ctk.CTkLabel(panel, textvariable=self.server_progress_var, wraplength=900, justify="left").grid(
            row=5, column=0, padx=20, pady=(0, 8), sticky="w"
        )
        ctk.CTkLabel(panel, textvariable=self.server_status_var, wraplength=900, justify="left").grid(
            row=6, column=0, padx=20, pady=(0, 20), sticky="w"
        )
        return panel

    def _create_upload_panel(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        panel = ctk.CTkFrame(parent, corner_radius=18)
        panel.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(panel, text="Upload", font=ctk.CTkFont(size=24, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(20, 8), sticky="w"
        )
        ctk.CTkLabel(
            panel,
            text="Send a local file up to the central server. Other clients can download it once the upload completes.",
            wraplength=520,
            justify="left",
        ).grid(row=1, column=0, padx=20, pady=(0, 18), sticky="w")

        self.upload_file_var = ctk.StringVar()
        self.upload_host_var = ctk.StringVar(value=self.local_ip)
        self.upload_port_var = ctk.StringVar(value="9000")
        self.upload_status_var = ctk.StringVar(value="Idle")
        self.upload_progress_var = ctk.StringVar(value="0 / 0 chunks acknowledged")

        file_row = ctk.CTkFrame(panel, fg_color="transparent")
        file_row.grid(row=2, column=0, padx=20, pady=(0, 12), sticky="ew")
        file_row.grid_columnconfigure(0, weight=1)
        ctk.CTkEntry(file_row, textvariable=self.upload_file_var, placeholder_text="File to upload").grid(
            row=0, column=0, padx=(0, 10), sticky="ew"
        )
        ctk.CTkButton(file_row, text="Browse", width=96, command=self.choose_upload_file).grid(
            row=0, column=1, sticky="ew"
        )

        network_row = ctk.CTkFrame(panel, fg_color="transparent")
        network_row.grid(row=3, column=0, padx=20, pady=(0, 12), sticky="ew")
        network_row.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkEntry(network_row, textvariable=self.upload_host_var, placeholder_text="Server IP").grid(
            row=0, column=0, padx=(0, 8), sticky="ew"
        )
        ctk.CTkEntry(network_row, textvariable=self.upload_port_var, placeholder_text="Port").grid(
            row=0, column=1, padx=(8, 0), sticky="ew"
        )

        upload_buttons = ctk.CTkFrame(panel, fg_color="transparent")
        upload_buttons.grid(row=4, column=0, padx=20, pady=(4, 16), sticky="ew")
        upload_buttons.grid_columnconfigure((0, 1, 2), weight=1)
        self.upload_button = ctk.CTkButton(upload_buttons, text="Start Upload", command=self.start_upload)
        self.upload_button.grid(row=0, column=0, padx=(0, 6), sticky="ew")
        self.upload_pause_button = ctk.CTkButton(
            upload_buttons,
            text="Pause",
            command=self.pause_upload,
            state="disabled",
        )
        self.upload_pause_button.grid(row=0, column=1, padx=6, sticky="ew")
        self.upload_resume_button = ctk.CTkButton(
            upload_buttons,
            text="Resume",
            command=self.resume_upload,
            state="disabled",
        )
        self.upload_resume_button.grid(row=0, column=2, padx=(6, 0), sticky="ew")

        self.upload_progress = ctk.CTkProgressBar(panel)
        self.upload_progress.grid(row=5, column=0, padx=20, pady=(0, 8), sticky="ew")
        self.upload_progress.set(0)
        ctk.CTkLabel(panel, textvariable=self.upload_progress_var).grid(
            row=6, column=0, padx=20, pady=(0, 8), sticky="w"
        )
        ctk.CTkLabel(panel, textvariable=self.upload_status_var, wraplength=520, justify="left").grid(
            row=7, column=0, padx=20, pady=(0, 20), sticky="w"
        )
        return panel

    def _create_download_panel(self, parent: ctk.CTkFrame) -> ctk.CTkFrame:
        panel = ctk.CTkFrame(parent, corner_radius=18)
        panel.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(panel, text="Download", font=ctk.CTkFont(size=24, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(20, 8), sticky="w"
        )
        ctk.CTkLabel(
            panel,
            text="Browse the central server, choose a file, and save it locally while progress updates live.",
            wraplength=520,
            justify="left",
        ).grid(row=1, column=0, padx=20, pady=(0, 18), sticky="w")

        self.download_name_var = ctk.StringVar()
        self.download_save_var = ctk.StringVar(value=str((Path.cwd() / "downloads").resolve()))
        self.download_host_var = ctk.StringVar(value=self.local_ip)
        self.download_port_var = ctk.StringVar(value="9000")
        self.download_status_var = ctk.StringVar(value="Idle")
        self.download_progress_var = ctk.StringVar(value="0 / 0 chunks received")

        ctk.CTkEntry(panel, textvariable=self.download_name_var, placeholder_text="Remote filename on server").grid(
            row=2, column=0, padx=20, pady=(0, 12), sticky="ew"
        )

        save_row = ctk.CTkFrame(panel, fg_color="transparent")
        save_row.grid(row=3, column=0, padx=20, pady=(0, 12), sticky="ew")
        save_row.grid_columnconfigure(0, weight=1)
        ctk.CTkEntry(save_row, textvariable=self.download_save_var, placeholder_text="Destination folder").grid(
            row=0, column=0, padx=(0, 10), sticky="ew"
        )
        ctk.CTkButton(save_row, text="Browse", width=96, command=self.choose_download_path).grid(
            row=0, column=1, sticky="ew"
        )

        network_row = ctk.CTkFrame(panel, fg_color="transparent")
        network_row.grid(row=4, column=0, padx=20, pady=(0, 12), sticky="ew")
        network_row.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkEntry(network_row, textvariable=self.download_host_var, placeholder_text="Server IP").grid(
            row=0, column=0, padx=(0, 8), sticky="ew"
        )
        ctk.CTkEntry(network_row, textvariable=self.download_port_var, placeholder_text="Port").grid(
            row=0, column=1, padx=(8, 0), sticky="ew"
        )

        list_row = ctk.CTkFrame(panel, fg_color="transparent")
        list_row.grid(row=5, column=0, padx=20, pady=(0, 12), sticky="nsew")
        list_row.grid_columnconfigure(0, weight=1)
        self.refresh_button = ctk.CTkButton(list_row, text="Refresh Server Files", command=self.refresh_server_files)
        self.refresh_button.grid(row=0, column=0, sticky="ew")
        self.file_browser = ctk.CTkScrollableFrame(
            list_row,
            label_text="Available Server Files",
            height=220,
        )
        self.file_browser.grid(row=1, column=0, pady=(10, 0), sticky="nsew")
        self.file_browser.grid_columnconfigure(0, weight=1)
        self.render_server_files([])

        download_buttons = ctk.CTkFrame(panel, fg_color="transparent")
        download_buttons.grid(row=6, column=0, padx=20, pady=(4, 16), sticky="ew")
        download_buttons.grid_columnconfigure((0, 1, 2), weight=1)
        self.download_button = ctk.CTkButton(download_buttons, text="Start Download", command=self.start_download)
        self.download_button.grid(row=0, column=0, padx=(0, 6), sticky="ew")
        self.download_pause_button = ctk.CTkButton(
            download_buttons,
            text="Pause",
            command=self.pause_download,
            state="disabled",
        )
        self.download_pause_button.grid(row=0, column=1, padx=6, sticky="ew")
        self.download_resume_button = ctk.CTkButton(
            download_buttons,
            text="Resume",
            command=self.resume_download,
            state="disabled",
        )
        self.download_resume_button.grid(row=0, column=2, padx=(6, 0), sticky="ew")

        self.download_progress = ctk.CTkProgressBar(panel)
        self.download_progress.grid(row=7, column=0, padx=20, pady=(0, 8), sticky="ew")
        self.download_progress.set(0)
        ctk.CTkLabel(panel, textvariable=self.download_progress_var).grid(
            row=8, column=0, padx=20, pady=(0, 8), sticky="w"
        )
        ctk.CTkLabel(panel, textvariable=self.download_status_var, wraplength=520, justify="left").grid(
            row=9, column=0, padx=20, pady=(0, 20), sticky="w"
        )
        return panel

    def show_home(self) -> None:
        self.server_view.grid_forget()
        self.client_view.grid_forget()
        self.home_frame.grid(row=0, column=0, sticky="nsew")

    def show_server(self) -> None:
        self.home_frame.grid_forget()
        self.client_view.grid_forget()
        self.server_view.grid(row=0, column=0, sticky="nsew")

    def show_client(self) -> None:
        self.home_frame.grid_forget()
        self.server_view.grid_forget()
        self.client_view.grid(row=0, column=0, sticky="nsew")

    def choose_server_dir(self) -> None:
        selected = filedialog.askdirectory()
        if selected:
            self.server_dir_var.set(selected)

    def choose_upload_file(self) -> None:
        selected = filedialog.askopenfilename()
        if selected:
            self.upload_file_var.set(selected)

    def choose_download_path(self) -> None:
        selected = filedialog.askdirectory()
        if selected:
            self.download_save_var.set(selected)

    def select_server_file(self, selection: str) -> None:
        self.download_name_var.set(selection.split(" (", 1)[0])

    def render_server_files(self, files: list[tuple[str, int]]) -> None:
        for button in self.download_file_buttons:
            button.destroy()
        self.download_file_buttons.clear()

        if not files:
            button = ctk.CTkButton(self.file_browser, text="No files loaded", state="disabled", anchor="w")
            button.grid(row=0, column=0, sticky="ew", pady=(0, 6))
            self.download_file_buttons.append(button)
            return

        for index, (name, size) in enumerate(files):
            label = f"{name} ({size} bytes)"
            button = ctk.CTkButton(
                self.file_browser,
                text=label,
                anchor="w",
                command=lambda current=label: self.select_server_file(current),
            )
            button.grid(row=index, column=0, sticky="ew", pady=(0, 6))
            self.download_file_buttons.append(button)

    def refresh_server_files(self) -> None:
        if self.list_thread is not None and self.list_thread.is_alive():
            return
        host = self.download_host_var.get().strip()
        try:
            port = int(self.download_port_var.get().strip())
        except ValueError:
            self.download_status_var.set("Port must be an integer")
            return

        self.download_status_var.set("Loading server file list")
        self.refresh_button.configure(state="disabled")

        def worker() -> None:
            try:
                files = list_server_files(host, port)
                self.download_queue.put({"type": "list", "files": files})
            except Exception as exc:
                self.download_queue.put({"type": "error", "status": str(exc)})

        self.list_thread = threading.Thread(target=worker, daemon=True)
        self.list_thread.start()

    def start_server(self) -> None:
        if self.server_thread is not None and self.server_thread.is_alive():
            return

        host = self.server_ip_var.get().strip() or "0.0.0.0"
        storage_dir = self.server_dir_var.get().strip() or str((Path.cwd() / "server_storage").resolve())
        try:
            port = int(self.server_port_var.get().strip())
            self.server = ThreadedRUDPServer(
                host,
                port,
                storage_dir,
                event_callback=lambda event: self.server_queue.put(event),
            )
        except (ValueError, OSError) as exc:
            self.server_status_var.set(str(exc))
            return

        self.server_status_var.set(f"Server listening on {host}:{port}")
        self.server_progress_var.set(f"Storage: {storage_dir}")
        self.server_start_button.configure(state="disabled")
        self.server_stop_button.configure(state="normal")

        def worker() -> None:
            try:
                self.server.serve_forever()
            except Exception as exc:
                self.server_queue.put({"type": "error", "status": str(exc)})
            finally:
                self.server_queue.put({"type": "server_stopped", "status": "Server stopped"})

        self.server_thread = threading.Thread(target=worker, daemon=True)
        self.server_thread.start()

    def stop_server(self) -> None:
        if self.server is not None:
            self.server_status_var.set("Stopping server")
            self.server_stop_button.configure(state="disabled")
            self.server.close()
            self.server = None

    def start_upload(self) -> None:
        if self.upload_thread is not None and self.upload_thread.is_alive():
            return

        file_path = self.upload_file_var.get().strip()
        host = self.upload_host_var.get().strip()
        try:
            port = int(self.upload_port_var.get().strip())
        except ValueError:
            self.upload_status_var.set("Port must be an integer")
            return

        if not Path(file_path).is_file():
            self.upload_status_var.set("Choose a valid file to upload")
            return

        self.upload_progress.set(0)
        self.upload_progress_var.set("0 / 0 chunks acknowledged")
        self.upload_status_var.set("Starting upload")
        self.upload_button.configure(state="disabled")
        self.upload_pause_button.configure(state="normal")
        self.upload_resume_button.configure(state="disabled")

        self.upload_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.upload_socket.settimeout(1.0)
        self.upload_transfer = create_uploader(
            self.upload_socket,
            (host, port),
            file_path,
            max_retries=5,
            max_resumes=3,
            progress_callback=lambda done, total: self.upload_queue.put(
                {"type": "progress", "done": done, "total": total}
            ),
            status_callback=lambda status: self.upload_queue.put({"type": "status", "status": status}),
        )
        self._run_upload_worker()

    def _run_upload_worker(self) -> None:
        if self.upload_transfer is None:
            return

        def worker() -> None:
            try:
                self.upload_transfer.transfer()
                self.upload_queue.put({"type": "complete", "status": "Upload finished"})
            except TransferPaused:
                self.upload_queue.put({"type": "paused", "status": "Upload paused"})
            except Exception as exc:
                self.upload_queue.put({"type": "error", "status": str(exc)})

        self.upload_thread = threading.Thread(target=worker, daemon=True)
        self.upload_thread.start()

    def pause_upload(self) -> None:
        if self.upload_transfer is not None:
            self.upload_transfer.pause()
            self.upload_pause_button.configure(state="disabled")
            self.upload_resume_button.configure(state="normal")
            self.upload_status_var.set("Upload paused")

    def resume_upload(self) -> None:
        if self.upload_transfer is None or (self.upload_thread is not None and self.upload_thread.is_alive()):
            return
        self.upload_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.upload_socket.settimeout(1.0)
        self.upload_transfer.replace_socket(self.upload_socket)
        self.upload_transfer.resume()
        self.upload_status_var.set("Resuming upload")
        self.upload_pause_button.configure(state="normal")
        self.upload_resume_button.configure(state="disabled")
        self._run_upload_worker()

    def start_download(self) -> None:
        if self.download_thread is not None and self.download_thread.is_alive():
            return

        filename = self.download_name_var.get().strip()
        if not filename:
            self.download_status_var.set("Enter the server filename to download")
            return

        host = self.download_host_var.get().strip()
        save_dir = Path(self.download_save_var.get().strip() or str((Path.cwd() / "downloads").resolve()))
        save_path = save_dir / Path(filename).name
        try:
            port = int(self.download_port_var.get().strip())
        except ValueError:
            self.download_status_var.set("Port must be an integer")
            return

        self.download_progress.set(0)
        self.download_progress_var.set("0 / 0 chunks received")
        self.download_status_var.set("Starting download")
        self.download_button.configure(state="disabled")
        self.download_pause_button.configure(state="normal")
        self.download_resume_button.configure(state="disabled")

        self.download_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.download_socket.settimeout(1.0)
        self.download_transfer = create_downloader(
            self.download_socket,
            (host, port),
            filename,
            str(save_path),
            max_retries=5,
            max_resumes=3,
            progress_callback=lambda done, total: self.download_queue.put(
                {"type": "progress", "done": done, "total": total}
            ),
            status_callback=lambda status: self.download_queue.put({"type": "status", "status": status}),
        )
        self._run_download_worker()

    def _run_download_worker(self) -> None:
        if self.download_transfer is None:
            return

        def worker() -> None:
            try:
                self.download_transfer.transfer()
                self.download_queue.put({"type": "complete", "status": "Download finished"})
            except TransferPaused:
                self.download_queue.put({"type": "paused", "status": "Download paused"})
            except Exception as exc:
                self.download_queue.put({"type": "error", "status": str(exc)})

        self.download_thread = threading.Thread(target=worker, daemon=True)
        self.download_thread.start()

    def pause_download(self) -> None:
        if self.download_transfer is not None:
            self.download_transfer.pause()
            self.download_pause_button.configure(state="disabled")
            self.download_resume_button.configure(state="normal")
            self.download_status_var.set("Download paused")

    def resume_download(self) -> None:
        if self.download_transfer is None or (self.download_thread is not None and self.download_thread.is_alive()):
            return
        self.download_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.download_socket.settimeout(1.0)
        self.download_transfer.replace_socket(self.download_socket)
        self.download_transfer.resume()
        self.download_status_var.set("Resuming download")
        self.download_pause_button.configure(state="normal")
        self.download_resume_button.configure(state="disabled")
        self._run_download_worker()

    def process_queues(self) -> None:
        for event in self._drain_queue(self.upload_queue):
            event_type = str(event["type"])
            if event_type == "progress":
                done = int(event["done"])
                total = max(1, int(event["total"]))
                self.upload_progress.set(done / total)
                self.upload_progress_var.set(f"{done} / {total} chunks acknowledged")
            elif event_type in {"status", "complete", "error", "paused"}:
                self.upload_status_var.set(str(event["status"]))
                if event_type == "paused":
                    self.upload_resume_button.configure(state="normal")
                if event_type in {"complete", "error"}:
                    self.upload_button.configure(state="normal")
                    self.upload_pause_button.configure(state="disabled")
                    self.upload_resume_button.configure(state="disabled")
                    if event_type == "complete":
                        self.upload_progress.set(1)
                    if self.upload_socket is not None:
                        self.upload_socket.close()
                        self.upload_socket = None
                    self.upload_transfer = None

        for event in self._drain_queue(self.download_queue):
            event_type = str(event["type"])
            if event_type == "progress":
                done = int(event["done"])
                total = max(1, int(event["total"]))
                self.download_progress.set(done / total)
                self.download_progress_var.set(f"{done} / {total} chunks received")
            elif event_type in {"status", "complete", "paused"}:
                self.download_status_var.set(str(event["status"]))
                if event_type == "paused":
                    self.download_resume_button.configure(state="normal")
                if event_type == "complete":
                    self.download_button.configure(state="normal")
                    self.download_pause_button.configure(state="disabled")
                    self.download_resume_button.configure(state="disabled")
                    self.download_progress.set(1)
                    if self.download_socket is not None:
                        self.download_socket.close()
                        self.download_socket = None
                    self.download_transfer = None
            elif event_type == "list":
                files = [(str(name), int(size)) for name, size in event["files"]]
                self.render_server_files(files)
                self.refresh_button.configure(state="normal")
                self.list_thread = None
                self.download_status_var.set(
                    "Select a server file from the list" if files else "Server has no files yet"
                )
                if files:
                    self.select_server_file(f"{files[0][0]} ({files[0][1]} bytes)")
            elif event_type == "error":
                self.refresh_button.configure(state="normal")
                self.download_button.configure(state="normal")
                self.download_pause_button.configure(state="disabled")
                self.download_resume_button.configure(state="disabled")
                self.list_thread = None
                self.download_status_var.set(str(event["status"]))
                if self.download_socket is not None:
                    self.download_socket.close()
                    self.download_socket = None
                self.download_transfer = None

        for event in self._drain_queue(self.server_queue):
            event_type = str(event["type"])
            if event_type in {"progress", "complete"}:
                mode = str(event.get("mode", "transfer"))
                filename = str(event.get("filename", "file"))
                received = int(event.get("received", 0))
                total = int(event.get("total", 0))
                self.server_progress_var.set(f"{mode.title()}: {filename} ({received}/{total})")
                self.server_status_var.set(str(event.get("status", "")))
            elif event_type == "error":
                self.server_status_var.set(str(event.get("status", "Server error")))
            elif event_type == "server_stopped":
                self.server_status_var.set(str(event["status"]))
                self.server_start_button.configure(state="normal")
                self.server_stop_button.configure(state="disabled")
                self.server = None
                self.server_thread = None

        self.after(100, self.process_queues)

    def on_close(self) -> None:
        self.stop_server()
        self.destroy()


def main() -> None:
    app = RFTPApp()
    app.mainloop()
