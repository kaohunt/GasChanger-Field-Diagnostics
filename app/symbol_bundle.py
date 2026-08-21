#!/usr/bin/env python3
"""Signed, code-free GasChanger symbol bundle support."""

from __future__ import annotations

import bisect
import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


SYMBOL_FORMAT = "gaschanger-symbols-v1"
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
BUILD_MARKER_PATTERN = re.compile(
    rb"GASCHANGER_BUILD_INFO\|hw=([^|]+)\|fw=([^|]+)\|"
    rb"id=([0-9a-f]{32})\|git=([^|]+)\|dirty=([^|]+)\|"
    rb"config=([^|]+)\|source=([0-9a-f]{64})\|utc=([^|]+)\|end"
)


def read_elf_identity(elf_path: Path) -> dict[str, str]:
    match = BUILD_MARKER_PATTERN.search(elf_path.read_bytes())
    if match is None:
        raise ValueError(f"firmware build marker not found in ELF: {elf_path}")
    fields = (
        "hardware_revision",
        "firmware_version",
        "build_id",
        "git",
        "dirty",
        "config",
        "source_id",
        "build_utc",
    )
    return {
        name: value.decode("ascii") for name, value in zip(fields, match.groups())
    }


def find_openssl() -> Optional[Path]:
    executable = shutil.which("openssl")
    if executable:
        return Path(executable)
    if os.name == "nt":
        candidates = (
            Path("C:/Program Files/Git/usr/bin/openssl.exe"),
            Path("C:/Program Files/Git/mingw64/bin/openssl.exe"),
        )
        for candidate in candidates:
            if candidate.is_file():
                return candidate
    return None


def public_key_id(public_key_path: Path) -> str:
    normalized = b"".join(public_key_path.read_bytes().split())
    return hashlib.sha256(normalized).hexdigest()[:16]


def verify_signature(
    bundle_path: Path, signature_path: Path, public_key_path: Path
) -> None:
    openssl = find_openssl()
    if openssl is None:
        raise ValueError("OpenSSL was not found; signed symbols cannot be verified")
    result = subprocess.run(
        [
            str(openssl),
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(public_key_path),
            "-rawin",
            "-in",
            str(bundle_path),
            "-sigfile",
            str(signature_path),
        ],
        check=False,
        capture_output=True,
        timeout=10.0,
    )
    if result.returncode != 0:
        raise ValueError(f"invalid symbol-bundle signature: {bundle_path}")


@dataclass(frozen=True)
class PublicSymbol:
    start: int
    end: int
    name: str


class SymbolBundle:
    def __init__(
        self,
        bundle_path: Path,
        signature_path: Path,
        public_key_path: Path,
    ) -> None:
        self.bundle_path = bundle_path.resolve()
        verify_signature(self.bundle_path, signature_path, public_key_path)
        raw = self.bundle_path.read_bytes()
        if len(raw) > MAX_BUNDLE_BYTES:
            raise ValueError("symbol bundle exceeds size limit")
        document = json.loads(raw.decode("utf-8"))
        if document.get("format") != SYMBOL_FORMAT:
            raise ValueError("unsupported symbol-bundle format")
        identity = document.get("identity")
        symbols = document.get("symbols")
        if not isinstance(identity, dict) or not isinstance(symbols, list):
            raise ValueError("malformed symbol bundle")
        build_id = str(identity.get("build_id", "")).lower()
        if re.fullmatch(r"[0-9a-f]{32}", build_id) is None:
            raise ValueError("invalid symbol-bundle build ID")
        expected_key_id = str(document.get("signing_key_id", ""))
        if expected_key_id != public_key_id(public_key_path):
            raise ValueError("symbol bundle was signed by an untrusted key")

        parsed: list[PublicSymbol] = []
        for item in symbols:
            if not isinstance(item, dict):
                raise ValueError("malformed public symbol")
            start = int(str(item["start"]), 16)
            end = int(str(item["end"]), 16)
            name = str(item["name"])
            if not (0x08000000 <= start < end <= 0x08100000):
                raise ValueError("public symbol is outside STM32 flash")
            if not name or len(name) > 160 or any(ord(char) < 0x20 for char in name):
                raise ValueError("invalid public symbol name")
            parsed.append(PublicSymbol(start, end, name))
        parsed.sort(key=lambda symbol: symbol.start)
        for previous, current in zip(parsed, parsed[1:]):
            if previous.end > current.start:
                raise ValueError("overlapping public symbols")

        self.identity = {str(key): str(value) for key, value in identity.items()}
        self.identity["build_id"] = build_id
        self._symbols = parsed
        self._starts = [symbol.start for symbol in parsed]

    def symbolize(self, address_text: str) -> str:
        address = int(address_text, 16) & ~1
        index = bisect.bisect_right(self._starts, address) - 1
        if index < 0:
            return f"{address_text} -> unknown"
        symbol = self._symbols[index]
        if address >= symbol.end:
            return f"{address_text} -> unknown"
        offset = address - symbol.start
        suffix = f"+0x{offset:X}" if offset else ""
        return f"{address_text} -> {symbol.name}{suffix}"


def _download(url: str, destination: Path) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("public symbol URL must use HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "GasChanger-RTT/1"})
    with urllib.request.urlopen(request, timeout=10.0) as response:
        data = response.read(MAX_BUNDLE_BYTES + 1)
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError("downloaded symbol file exceeds size limit")
    destination.write_bytes(data)


def find_or_download_bundle(
    build_id: str,
    cache_directory: Path,
    public_key_path: Path,
    base_url: Optional[str] = None,
) -> SymbolBundle:
    normalized_id = build_id.lower()
    if re.fullmatch(r"[0-9a-f]{32}", normalized_id) is None:
        raise ValueError("invalid device build ID")
    cache_directory.mkdir(parents=True, exist_ok=True)
    bundle_path = cache_directory / f"{normalized_id}.gcsym"
    signature_path = cache_directory / f"{normalized_id}.gcsym.sig"

    if not (bundle_path.is_file() and signature_path.is_file()):
        if not base_url:
            raise FileNotFoundError(f"signed symbols not found for {normalized_id}")
        base = base_url.rstrip("/") + "/"
        temporary_bundle = bundle_path.with_suffix(".gcsym.download")
        temporary_signature = signature_path.with_suffix(".sig.download")
        _download(urllib.parse.urljoin(base, bundle_path.name), temporary_bundle)
        _download(urllib.parse.urljoin(base, signature_path.name), temporary_signature)
        try:
            verified = SymbolBundle(
                temporary_bundle, temporary_signature, public_key_path
            )
            if verified.identity["build_id"] != normalized_id:
                raise ValueError("downloaded symbols have a different build ID")
            temporary_bundle.replace(bundle_path)
            temporary_signature.replace(signature_path)
        finally:
            temporary_bundle.unlink(missing_ok=True)
            temporary_signature.unlink(missing_ok=True)

    bundle = SymbolBundle(bundle_path, signature_path, public_key_path)
    if bundle.identity["build_id"] != normalized_id:
        raise ValueError("cached symbols have a different build ID")
    return bundle
