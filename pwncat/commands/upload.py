#!/usr/bin/env python3
import os
import time
import hashlib
import gzip
import tempfile
from pathlib import Path

from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    DownloadColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

import pwncat
from pwncat.util import console, copyfileobj, human_readable_size, human_readable_delta
from pwncat.commands import Complete, Parameter, CommandDefinition
from pwncat.platform import PlatformError


def compute_file_hash(file_path, chunk_size=8192):
    """Compute MD5 hash of a file"""
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
    return md5.hexdigest()


def compress_file(source_path, compress_threshold=1024*1024):  # 1MB threshold
    """Compress file if it exceeds threshold"""
    file_size = os.path.getsize(source_path)
    
    if file_size < compress_threshold:
        return source_path, False
    
    # Create temporary compressed file
    temp_fd, temp_path = tempfile.mkstemp(suffix='.gz')
    try:
        with open(source_path, 'rb') as src:
            with gzip.open(temp_fd, 'wb', compresslevel=6) as dst:
                copyfileobj(src, dst, lambda n: None)
        
        compressed_size = os.path.getsize(temp_path)
        if compressed_size < file_size * 0.9:  # Only use if saves at least 10%
            console.log(f"[yellow]Compressing {human_readable_size(file_size)} → {human_readable_size(compressed_size)}[/yellow]")
            return temp_path, True
        
        os.unlink(temp_path)
        return source_path, False
    except Exception:
        try:
            os.unlink(temp_path)
        except:
            pass
        return source_path, False


def upload_file_recursive(
    local_path, remote_base, platform, task_id, progress, upload_errors,
    recursive=False, compress=False, resume=False, rate_limit=None
):
    """Upload a file or directory recursively"""
    
    local = Path(local_path)
    
    if local.is_file():
        remote_path = remote_base / local.name if isinstance(remote_base, Path) else Path(str(remote_base)) / local.name
        
        # Check for resume
        if resume and remote_path.exists():
            try:
                remote_size = remote_path.stat().st_size
                local_size = local.stat().st_size
                if remote_size == local_size:
                    # Verify hash if possible
                    try:
                        remote_hash = platform.run(["md5sum", str(remote_path)], capture_output=True).stdout.strip().split()[0].decode()
                        local_hash = compute_file_hash(local)
                        if remote_hash == local_hash:
                            progress.update(task_id, advance=1, status=f"Skipped (already exists): {remote_path}")
                            return None
                    except:
                        pass  # Hash check failed, continue with upload
            except:
                pass
        
        # Compress if requested
        source_path = local
        compressed = False
        if compress:
            source_path, compressed = compress_file(local)
            if compressed:
                remote_path = remote_path.with_suffix(remote_path.suffix + '.gz')
        
        try:
            # Upload file
            with open(source_path, "rb") as src:
                with platform.open(remote_path, "wb") as dst:
                    if rate_limit:
                        # Rate limiting
                        chunk_size = min(8192, rate_limit // 10)  # Send in 100ms chunks
                        bytes_sent = 0
                        start_time = time.time()
                        
                        while True:
                            chunk = src.read(chunk_size)
                            if not chunk:
                                break
                            
                            dst.write(chunk)
                            bytes_sent += len(chunk)
                            
                            # Sleep to maintain rate
                            elapsed = time.time() - start_time
                            expected_time = bytes_sent / rate_limit
                            if elapsed < expected_time:
                                time.sleep(expected_time - elapsed)
                    else:
                        copyfileobj(src, dst, lambda n: None)
            
            # Decompress on remote if needed
            if compressed:
                platform.run(["gunzip", "-f", str(remote_path)], capture_output=True)
                remote_path = remote_path.with_suffix('')
            
            progress.update(task_id, advance=1, status=f"Uploaded: {remote_path}")
            return None
            
        except Exception as e:
            error = f"{local} → {remote_path}: {e}"
            upload_errors.append(error)
            progress.update(task_id, advance=1, status=f"Error: {remote_path}")
            return error
        finally:
            if compressed and source_path != local:
                try:
                    os.unlink(source_path)
                except:
                    pass
    
    elif local.is_dir() and recursive:
        # Create remote directory
        remote_dir = remote_base / local.name if isinstance(remote_base, Path) else Path(str(remote_base)) / local.name
        try:
            platform.run(["mkdir", "-p", str(remote_dir)], capture_output=True, check=True)
        except:
            pass
        
        # Upload contents
        for item in local.iterdir():
            upload_file_recursive(
                item, remote_dir, platform, task_id, progress, upload_errors,
                recursive=True, compress=compress, resume=resume, rate_limit=rate_limit
            )
    
    return None


class Command(CommandDefinition):
    """
    Upload a file or directory from the local host to the remote host.
    Supports recursive directory upload, compression, resume, and rate limiting.
    """

    PROG = "upload"
    ARGS = {
        "source": Parameter(Complete.LOCAL_FILE),
        "destination": Parameter(
            Complete.REMOTE_FILE,
            nargs="?",
        ),
        "--recursive,-r": Parameter(
            Complete.NONE,
            action="store_true",
            help="Recursively upload directories"
        ),
        "--compress,-c": Parameter(
            Complete.NONE,
            action="store_true",
            help="Compress large files automatically"
        ),
        "--resume,-R": Parameter(
            Complete.NONE,
            action="store_true",
            help="Resume interrupted transfers (skip existing files)"
        ),
        "--rate-limit,-l": Parameter(
            Complete.NONE,
            type=int,
            metavar="BYTES_PER_SEC",
            help="Limit upload speed (bytes per second)"
        ),
    }

    def run(self, manager: "pwncat.manager.Manager", args):

        local = Path(args.source)
        
        if not local.exists():
            self.parser.error(f"{args.source}: no such file or directory")
        
        if not args.destination:
            args.destination = f"./{local.name}"
        
        remote = Path(args.destination)
        
        # Handle recursive directory upload
        if local.is_dir():
            if not args.recursive:
                self.parser.error(f"{args.source} is a directory. Use --recursive to upload directories.")
            
            # Get all files for progress tracking
            file_list = []
            for root, dirs, files in os.walk(local):
                for file in files:
                    file_list.append(Path(root) / file)
            
            if not file_list:
                console.log("[yellow]No files to upload[/yellow]")
                return
            
            upload_errors = []
            total_files = len(file_list)
            
            with Progress(
                TextColumn("[bold cyan]{task.fields[status]}", justify="right"),
                BarColumn(bar_width=None),
                "[progress.percentage]{task.percentage:>3.1f}%",
                "•",
                TimeRemainingColumn(),
            ) as progress:
                task_id = progress.add_task(
                    "upload",
                    status="Uploading files",
                    total=total_files,
                    start=True,
                )
                
                upload_file_recursive(
                    local, remote.parent, manager.target.platform, task_id, progress, upload_errors,
                    recursive=True, compress=args.compress, resume=args.resume,
                    rate_limit=args.rate_limit
                )
            
            uploaded_count = total_files - len(upload_errors)
            console.log(
                f"Finished uploading {uploaded_count} files, {len(upload_errors)} errors."
            )
            if upload_errors:
                console.log("The following errors occurred during upload:")
                for err in upload_errors:
                    console.log(f"    {err}")
            return
        
        # Single file upload
        progress = Progress(
            TextColumn("[bold cyan]{task.fields[filename]}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            DownloadColumn(),
            "•",
            TransferSpeedColumn(),
            "•",
            TimeRemainingColumn(),
        )

        try:
            # Check for resume
            if args.resume and remote.exists():
                try:
                    remote_size = remote.stat().st_size
                    local_size = local.stat().st_size
                    if remote_size == local_size:
                        # Verify hash
                        try:
                            remote_hash = manager.target.platform.run(
                                ["md5sum", str(remote)], capture_output=True
                            ).stdout.strip().split()[0].decode()
                            local_hash = compute_file_hash(local)
                            if remote_hash == local_hash:
                                console.log(f"[green]File already exists and matches: {remote}[/green]")
                                return
                        except:
                            pass
                except:
                    pass
            
            # Compress if requested
            source_path = local
            compressed = False
            if args.compress:
                source_path, compressed = compress_file(local)
                if compressed:
                    remote = remote.with_suffix(remote.suffix + '.gz')
            
            length = os.path.getsize(source_path)
            started = time.time()
            
            with progress:
                task_id = progress.add_task(
                    "upload", filename=str(remote), total=length, start=False
                )

                with open(source_path, "rb") as source:
                    with manager.target.platform.open(remote, "wb") as destination:
                        progress.start_task(task_id)
                        
                        if args.rate_limit:
                            # Rate limiting
                            chunk_size = min(8192, args.rate_limit // 10)
                            bytes_sent = 0
                            rate_start = time.time()
                            
                            while True:
                                chunk = source.read(chunk_size)
                                if not chunk:
                                    break
                                
                                destination.write(chunk)
                                bytes_sent += len(chunk)
                                progress.update(task_id, advance=len(chunk))
                                
                                # Sleep to maintain rate
                                elapsed = time.time() - rate_start
                                expected_time = bytes_sent / args.rate_limit
                                if elapsed < expected_time:
                                    time.sleep(expected_time - elapsed)
                        else:
                            copyfileobj(
                                source,
                                destination,
                                lambda count: progress.update(task_id, advance=count),
                            )
                        
                        progress.update(task_id, filename="draining buffers...")
                        progress.stop_task(task_id)

                    progress.start_task(task_id)
                    progress.update(task_id, filename=str(remote))
            
            # Decompress on remote if needed
            if compressed:
                manager.target.platform.run(["gunzip", "-f", str(remote)], capture_output=True)
                remote = remote.with_suffix('')
            
            elapsed = time.time() - started
            console.log(
                f"uploaded [cyan]{human_readable_size(length)}[/cyan] "
                f"in [green]{human_readable_delta(elapsed)}[/green]"
            )
            
        except (
            FileNotFoundError,
            PermissionError,
            IsADirectoryError,
            PlatformError,
        ) as exc:
            self.parser.error(str(exc))
        finally:
            if compressed and source_path != local:
                try:
                    os.unlink(source_path)
                except:
                    pass