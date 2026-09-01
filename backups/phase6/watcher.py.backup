import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class RDRSFileEventHandler(FileSystemEventHandler):

    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self.callback("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.callback("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.callback("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.callback("MOVED", event.dest_path)


def start_watching(folder, callback):

    folder = Path(folder).expanduser().resolve()

    if not folder.exists():
        folder.mkdir(parents=True, exist_ok=True)

    if not folder.is_dir():
        raise ValueError(f"Not a directory: {folder}")

    observer = Observer()

    handler = RDRSFileEventHandler(callback)

    observer.schedule(
        handler,
        str(folder),
        recursive=True
    )

    observer.start()

    print(f"🟢 RDRS monitoring active: {folder}")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n🛑 Stopping RDRS monitoring...")

    finally:
        observer.stop()
        observer.join()
