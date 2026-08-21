#!/usr/bin/env python3
"""TCP terminal with exact ELF or signed public-symbol fault analysis."""

from __future__ import annotations

import argparse
import codecs
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import BinaryIO, Iterable, Optional

from symbol_bundle import (
    SymbolBundle,
    find_or_download_bundle,
    read_elf_identity,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9090
DEFAULT_PUBLIC_KEY = Path(__file__).with_name("trusted_symbol_public.pem")
DEFAULT_SYMBOL_CACHE = Path.home() / ".gaschanger" / "symbols"
DEVICE_BUILD_PATTERN = re.compile(r"\bbuild_id=([0-9a-fA-F]{32})\b")
FAULT_RECORD_PATTERN = re.compile(
    r"\bfault boot=[^\r\n]*\bcount=(\d+)[^\r\n]*"
    r"\bfault_build_id=([0-9a-fA-F]{32})?[^\r\n]*[\r\n]+"
    r"fault_regs pc=(0x[0-9a-fA-F]{8}) lr=(0x[0-9a-fA-F]{8})"
)

def find_addr2line() -> Optional[Path]:
    executable = shutil.which("arm-none-eabi-addr2line")
    if executable:
        return Path(executable)
    if sys.platform == "win32":
        candidates = list(
            Path("C:/ST").glob(
                "STM32CubeIDE_*/STM32CubeIDE/plugins/"
                "*gnu-tools*/tools/bin/arm-none-eabi-addr2line.exe"
            )
        )
        if candidates:
            return max(candidates, key=lambda candidate: candidate.stat().st_mtime)
    return None


def symbolize_address(elf_path: Path, address: str) -> str:
    addr2line = find_addr2line()
    if addr2line is None:
        return f"{address} -> addr2line not found"
    result = subprocess.run(
        [str(addr2line), "-e", str(elf_path), "-f", "-C", "-i", address],
        check=False,
        capture_output=True,
        text=True,
        timeout=5.0,
    )
    details = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode != 0 or not details:
        return f"{address} -> symbol lookup failed"
    return f"{address} -> " + " <- ".join(details)


class FaultAnalyzer:
    """Gate fault symbolization on exact running-build and fault-build identity."""

    def __init__(
        self,
        elf_path: Optional[Path] = None,
        symbol_bundle: Optional[SymbolBundle] = None,
    ) -> None:
        if (elf_path is None) == (symbol_bundle is None):
            raise ValueError("select exactly one ELF or signed symbol bundle")
        self.elf_path = elf_path.resolve() if elf_path is not None else None
        self.symbol_bundle = symbol_bundle
        if self.elf_path is not None:
            self.identity = read_elf_identity(self.elf_path)
            self.source_tag = "ELF"
            self.source_description = str(self.elf_path)
        else:
            assert symbol_bundle is not None
            self.identity = symbol_bundle.identity
            self.source_tag = "GCSYM"
            self.source_description = str(symbol_bundle.bundle_path)
        self.device_build_id: Optional[str] = None
        self._buffer = ""
        self._identity_reported: Optional[str] = None
        self._seen_faults: set[tuple[str, str, Optional[str]]] = set()

    def feed(self, text: str) -> list[str]:
        self._buffer = (self._buffer + text)[-8192:]
        messages: list[str] = []
        device_matches = list(DEVICE_BUILD_PATTERN.finditer(self._buffer))
        if device_matches:
            self.device_build_id = device_matches[-1].group(1).lower()

        elf_id = self.identity["build_id"].lower()
        if self.device_build_id is not None:
            state = "match" if self.device_build_id == elf_id else "mismatch"
            if state != self._identity_reported:
                if state == "match":
                    messages.append(
                        f"[{self.source_tag}] Exact build match: "
                        f"HW {self.identity['hardware_revision']} / "
                        f"FW {self.identity['firmware_version']} / {elf_id} "
                        f"({self.source_description})"
                    )
                else:
                    messages.append(
                        f"[{self.source_tag}] BLOCKED: running firmware build "
                        f"{self.device_build_id} != symbol build {elf_id}; "
                        "fault symbolization disabled"
                    )
                self._identity_reported = state

        for match in FAULT_RECORD_PATTERN.finditer(self._buffer):
            count_text, captured_fault_id, pc, lr = match.groups()
            if int(count_text) == 0:
                continue
            fault_build_id = (
                captured_fault_id.lower() if captured_fault_id is not None else None
            )
            key = (pc.lower(), lr.lower(), fault_build_id)
            if key in self._seen_faults:
                continue
            # A retained boot message can arrive before the automatic version
            # reply. Keep it pending until the running build is known.
            if self.device_build_id is None:
                continue
            self._seen_faults.add(key)
            if self.device_build_id != elf_id:
                continue
            if fault_build_id != elf_id:
                actual = fault_build_id or "missing"
                messages.append(
                    f"[{self.source_tag}] BLOCKED: retained fault build "
                    f"{actual} != symbol build {elf_id}; addresses not decoded"
                )
                continue
            messages.append(
                f"[{self.source_tag}] Fault addresses (exact build verified):"
            )
            if self.elf_path is not None:
                pc_result = symbolize_address(self.elf_path, pc)
                lr_result = symbolize_address(self.elf_path, lr)
            else:
                assert self.symbol_bundle is not None
                pc_result = self.symbol_bundle.symbolize(pc)
                lr_result = self.symbol_bundle.symbolize(lr)
            messages.append(f"[{self.source_tag}] PC " + pc_result)
            messages.append(f"[{self.source_tag}] LR " + lr_result)
        return messages


class DeferredSymbolAnalyzer:
    """Load/download the signed bundle after the device reports its build ID."""

    def __init__(
        self,
        cache_directory: Path,
        public_key_path: Path,
        base_url: Optional[str],
    ) -> None:
        self.cache_directory = cache_directory
        self.public_key_path = public_key_path
        self.base_url = base_url
        self.analyzer: Optional[FaultAnalyzer] = None
        self.device_build_id: Optional[str] = None
        self._buffer = ""
        self._attempted_build_id: Optional[str] = None

    def feed(self, text: str) -> list[str]:
        if self.analyzer is not None:
            messages = self.analyzer.feed(text)
            self.device_build_id = self.analyzer.device_build_id
            return messages
        self._buffer = (self._buffer + text)[-8192:]
        matches = list(DEVICE_BUILD_PATTERN.finditer(self._buffer))
        if not matches:
            return []
        self.device_build_id = matches[-1].group(1).lower()
        if self._attempted_build_id == self.device_build_id:
            return []
        self._attempted_build_id = self.device_build_id
        try:
            bundle = find_or_download_bundle(
                self.device_build_id,
                self.cache_directory,
                self.public_key_path,
                self.base_url,
            )
            self.analyzer = FaultAnalyzer(symbol_bundle=bundle)
            return [
                f"[GCSYM] Verified signed symbols: {bundle.bundle_path}"
            ] + self.analyzer.feed(self._buffer)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            return [f"[GCSYM] Symbols unavailable: {error}; raw addresses retained"]


def create_analyzer(
    elf_path: Optional[Path],
    symbol_path: Optional[Path],
    symbol_cache: Optional[Path],
    symbol_url: Optional[str],
    public_key: Path,
) -> Optional[FaultAnalyzer | DeferredSymbolAnalyzer]:
    if elf_path is not None and symbol_path is not None:
        raise ValueError("--elf and --symbols are mutually exclusive")
    if elf_path is not None:
        return FaultAnalyzer(elf_path=elf_path)
    if symbol_path is not None:
        signature = symbol_path.with_suffix(".gcsym.sig")
        return FaultAnalyzer(
            symbol_bundle=SymbolBundle(symbol_path, signature, public_key)
        )
    if symbol_cache is not None or symbol_url:
        return DeferredSymbolAnalyzer(
            symbol_cache or DEFAULT_SYMBOL_CACHE, public_key, symbol_url
        )
    return None


def connect(host: str, port: int, timeout: float) -> socket.socket:
    connection = socket.create_connection((host, port), timeout=timeout)
    connection.settimeout(0.1)
    return connection


def run_commands(
    host: str,
    port: int,
    commands: Iterable[str],
    timeout: float,
    log_path: Optional[Path] = None,
    elf_path: Optional[Path] = None,
    symbol_path: Optional[Path] = None,
    symbol_cache: Optional[Path] = None,
    symbol_url: Optional[str] = None,
    public_key: Path = DEFAULT_PUBLIC_KEY,
) -> str:
    command_list = list(commands)
    analyzer = create_analyzer(
        elf_path, symbol_path, symbol_cache, symbol_url, public_key
    )
    if analyzer is not None and "version" not in command_list:
        command_list.insert(0, "version")
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    log_file: Optional[BinaryIO] = None

    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = log_path.open("ab")

    try:
        with connect(host, port, timeout) as connection:
            def receive_until_prompt(limit: float) -> bool:
                recent = b""
                while time.monotonic() < limit:
                    try:
                        data = connection.recv(4096)
                    except socket.timeout:
                        continue
                    if not data:
                        return False
                    chunks.append(data)
                    if log_file is not None:
                        log_file.write(data)
                        log_file.flush()
                    recent = (recent + data)[-64:]
                    if b"GasChanger> " in recent:
                        return True
                return False

            # Consume the retained startup prompt before associating replies with
            # commands. It is fine if the target was attached after that prompt.
            receive_until_prompt(min(deadline, time.monotonic() + 0.3))

            for command in command_list:
                connection.sendall(command.rstrip("\r\n").encode("utf-8") + b"\n")
                if not receive_until_prompt(deadline):
                    break

            while not command_list and time.monotonic() < deadline:
                try:
                    data = connection.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                chunks.append(data)
                if log_file is not None:
                    log_file.write(data)
                    log_file.flush()
    finally:
        if log_file is not None:
            log_file.close()

    output = b"".join(chunks).decode("utf-8", errors="replace")
    if analyzer is not None:
        messages = analyzer.feed(output)
        if analyzer.device_build_id is None:
            messages.append(
                "[SYMBOL] BLOCKED: device did not return build_id; "
                "fault symbolization disabled"
            )
        if messages:
            output += "\n" + "\n".join(messages) + "\n"
    return output


def run_interactive(
    host: str,
    port: int,
    timeout: float,
    log_path: Optional[Path] = None,
    elf_path: Optional[Path] = None,
    symbol_path: Optional[Path] = None,
    symbol_cache: Optional[Path] = None,
    symbol_url: Optional[str] = None,
    public_key: Path = DEFAULT_PUBLIC_KEY,
) -> None:
    connection = connect(host, port, timeout)
    stop = threading.Event()
    log_file: Optional[BinaryIO] = None
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    analyzer = create_analyzer(
        elf_path, symbol_path, symbol_cache, symbol_url, public_key
    )

    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = log_path.open("ab")

    def receive() -> None:
        try:
            while not stop.is_set():
                try:
                    data = connection.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                if log_file is not None:
                    log_file.write(data)
                    log_file.flush()
                decoded = decoder.decode(data)
                sys.stdout.write(decoded)
                sys.stdout.flush()
                if analyzer is not None:
                    for message in analyzer.feed(decoded):
                        print(f"\n{message}")
        finally:
            stop.set()

    receiver = threading.Thread(target=receive, name="rtt-receiver", daemon=True)
    print(f"[RTT] Connected to {host}:{port}. Press Ctrl+C to exit.")
    if isinstance(analyzer, FaultAnalyzer):
        print(f"[RTT] Verifying exact symbols: {analyzer.source_description}")
    elif isinstance(analyzer, DeferredSymbolAnalyzer):
        print("[RTT] Signed symbols will be selected from the device build ID.")
    else:
        print("[RTT] No ELF selected; automatic fault symbolization is disabled.")
    print("[RTT] Checking the firmware console...")
    receiver.start()
    try:
        # The boot banner may already have been consumed by an earlier RTT
        # session. A read-only ping guarantees visible feedback on reconnect.
        connection.sendall(b"version\nping\n" if analyzer is not None else b"ping\n")
        while not stop.is_set():
            try:
                line = input()
            except EOFError:
                break
            connection.sendall(line.encode("utf-8") + b"\n")
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        connection.close()
        receiver.join(timeout=1.0)
        if log_file is not None:
            log_file.close()


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Connect to the GasChanger console exposed by OpenOCD RTT."
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--log", type=Path)
    parser.add_argument(
        "--elf",
        type=Path,
        help="Exact ELF expected on the target; enables guarded fault symbolization.",
    )
    parser.add_argument(
        "--symbols",
        type=Path,
        help="Signed .gcsym file; its adjacent .sig file is required.",
    )
    parser.add_argument(
        "--symbol-cache",
        type=Path,
        help="Directory containing <build_id>.gcsym and signature files.",
    )
    parser.add_argument(
        "--symbol-url",
        default=os.environ.get("GASCHANGER_SYMBOL_URL"),
        help="HTTPS base URL used when signed symbols are absent locally.",
    )
    parser.add_argument(
        "--public-key", type=Path, default=DEFAULT_PUBLIC_KEY
    )
    parser.add_argument(
        "--command",
        action="append",
        default=[],
        help="Send a command non-interactively; may be repeated.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        if args.command:
            output = run_commands(
                args.host,
                args.port,
                args.command,
                args.timeout,
                args.log,
                args.elf,
                args.symbols,
                args.symbol_cache,
                args.symbol_url,
                args.public_key,
            )
            sys.stdout.write(output)
            return 0
        run_interactive(
            args.host,
            args.port,
            args.timeout,
            args.log,
            args.elf,
            args.symbols,
            args.symbol_cache,
            args.symbol_url,
            args.public_key,
        )
        return 0
    except (ConnectionError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"RTT connection failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
