import argparse
import ctypes
import logging
import os
import shutil
import string
import subprocess
from datetime import datetime
from pathlib import Path

# Known worm/masquerade filenames and autorun artifacts (all lowercase)
TARGET_MALWARE_NAMES = {
    "autorun.inf",
    "file explorer.exe",
    "file_explorer.exe",
    "explorer.exe",
    "desktop.ini",
}


def get_non_system_drives() -> list[str]:
    """Return connected drive roots (e.g., ['E:\\', 'F:\\']) excluding C:\\."""
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    # Drive types: 2 = Removable, 3 = Fixed (external/secondary drives)
    allowed_types = {2, 3}

    for idx, letter in enumerate(string.ascii_uppercase):
        if letter == "C":
            continue
        if bitmask & (1 << idx):
            root = f"{letter}:\\"
            dtype = ctypes.windll.kernel32.GetDriveTypeW(root)
            if dtype in allowed_types and os.path.exists(root):
                drives.append(root)
    return drives


def setup_logger(log_path: Path) -> logging.Logger:
    logger = logging.getLogger("drive_recovery")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(formatter)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


def unhide_drive(root: str, dry_run: bool, logger: logging.Logger) -> None:
    if dry_run:
        logger.info(f"[DRY-RUN] Would run: attrib -h -r -s /s /d {root}*.*")
        return

    subprocess.run(
        ["attrib", "-h", "-r", "-s", "/s", "/d", os.path.join(root, "*.*")],
        check=False,
    )
    logger.info(f"Unhid files and folders on {root}")


def restore_from_decoy_folders(root: str, dry_run: bool, logger: logging.Logger) -> None:
    """Move items out of decoy folders like MAYUNDO back to drive root without overwriting."""
    base = Path(root)
    for item in base.iterdir():
        if not item.is_dir():
            continue
        if item.name.upper() == "MAYUNDO":
            logger.info(f"Found decoy folder: {item}")
            for child in item.iterdir():
                dest = base / child.name
                if dest.exists():
                    logger.warning(f"Skipped moving {child} because {dest} already exists")
                    continue
                if dry_run:
                    logger.info(f"[DRY-RUN] Would move {child} -> {dest}")
                else:
                    try:
                        shutil.move(str(child), str(dest))
                        logger.info(f"Restored {child.name} to {root}")
                    except OSError as exc:
                        logger.error(f"Failed to move {child}: {exc}")

            # Remove MAYUNDO only if it is now empty
            if not dry_run:
                try:
                    if not any(item.iterdir()):
                        item.rmdir()
                        logger.info(f"Removed empty decoy folder: {item}")
                except OSError as exc:
                    logger.warning(f"Could not remove {item}: {exc}")


def remove_shortcuts_and_virus_exe(root: str, dry_run: bool, logger: logging.Logger) -> None:
    """Delete .lnk shortcuts and known USB worm executables/autorun files."""
    base = Path(root)

    for current_root, _, files in os.walk(base):
        current_path = Path(current_root)
        for fname in files:
            fpath = current_path / fname
            lower_name = fname.lower()
            is_shortcut = lower_name.endswith(".lnk")
            is_known_malware = lower_name in TARGET_MALWARE_NAMES

            # Also flag root-level .exe files that match a folder name on the drive (classic folder-masquerade)
            is_folder_masquerade_exe = (
                current_path == base
                and lower_name.endswith(".exe")
                and (base / fpath.stem).is_dir()
            )

            if is_shortcut or is_known_malware or is_folder_masquerade_exe:
                reason = (
                    "shortcut (.lnk)"
                    if is_shortcut
                    else "known worm/autorun file"
                    if is_known_malware
                    else "folder-masquerade .exe"
                )
                if dry_run:
                    logger.info(f"[DRY-RUN] Would delete ({reason}): {fpath}")
                else:
                    try:
                        fpath.unlink()
                        logger.info(f"Deleted ({reason}): {fpath}")
                    except OSError as exc:
                        logger.warning(f"Could not delete {fpath}: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unhide files, restore from MAYUNDO, and remove shortcuts/worm .exe files."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what will be moved or deleted without changing files.",
    )
    args = parser.parse_args()

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / f"recovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logger = setup_logger(log_file)

    drives = get_non_system_drives()
    if not drives:
        logger.info("No non-system drives detected.")
        return

    for drive in drives:
        logger.info(f"=== Processing {drive} ===")
        unhide_drive(drive, dry_run=args.dry_run, logger=logger)
        restore_from_decoy_folders(drive, dry_run=args.dry_run, logger=logger)
        remove_shortcuts_and_virus_exe(drive, dry_run=args.dry_run, logger=logger)

    logger.info(f"Done. Full log saved at: {log_file.resolve()}")


if __name__ == "__main__":
    main()