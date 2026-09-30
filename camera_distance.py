#!/usr/bin/env python3
"""Patch Dota 2's client.dll to change the default camera distance (dota_camera_distance cvar).

Locates the camera-distance constant fresh on every run by following the chain:
cvar-name string -> `lea reg, [rip+disp32]` reference to it -> nearby RIP-relative
float load -> the constant itself. This survives game updates that move the
constant around, unlike hardcoded-offset patchers.
"""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import json
import os
import shutil
import struct
import subprocess
import sys
import traceback
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional

if sys.platform == "win32":
    import winreg
else:
    winreg = None


# ==================== CONSTANTS ====================

CVAR_NAME = b"dota_camera_distance"
DEFAULT_VALUE = 1200.0

LEA_WINDOW_BEFORE = 160
LEA_WINDOW_AFTER = 64

USER_MIN, USER_MAX = 1000, 2500
AUTO_SAFE_MIN, AUTO_SAFE_MAX = 1000, 2000
ALREADY_PATCHED_MIN, ALREADY_PATCHED_MAX = 1000, 2500
WARN_ABOVE = 1800

SIG_BEFORE_VALUES = (750.0, 900.0, 950.0)
SIG_AFTER_BYTES = (bytes.fromhex("72F97FBF"), bytes.fromhex("0000C8C2"))  # -0.9999, -100.0

STEAM_APPID = "570"
DOTA_DLL_RELATIVE = Path("steamapps") / "common" / "dota 2 beta" / "game" / "dota" / "bin" / "win64" / "client.dll"
BACKUP_SUFFIX = ".bak"
CONFIG_FILENAME = "config.json"
CONFIG_SCHEMA_VERSION = 1

IMAGE_SCN_MEM_EXECUTE = 0x20000000

SM_CXSCREEN, SM_CYSCREEN = 0, 1
PROCESS_PER_MONITOR_DPI_AWARE = 2
RATIO_4_3_MAX = 1.4
RATIO_ULTRAWIDE_MIN = 2.2


# ==================== MESSAGES ====================

MESSAGES = {
    "err.dota_running": "Dota 2 appears to be running. Close it before changing client.dll.",
    "err.dll_not_found": "Could not locate client.dll automatically. Use --dll PATH to specify it, "
                          "or run --diagnose for details.",
    "err.pe_parse": "The selected file does not look like a valid client.dll ({error}).",
    "err.nothing_found": "Could not find the camera distance constant in this client.dll. "
                          "Please open a GitHub issue and attach the output of --diagnose.",
    "err.multiple_lea_refs": "Found more than one code reference to the cvar name string; refusing to guess. "
                              "Run --diagnose and open a GitHub issue.",
    "err.no_backup": "No backup (.bak) file was found next to client.dll; nothing to restore.",
    "err.ambiguous_noninteractive": "Multiple candidates found and running non-interactively; refusing to guess. "
                                     "Re-run interactively or pass --candidate N.",
    "err.ambiguous_declined": "No candidate selected; aborting without changes.",
    "err.invalid_distance": "Distance must be between {min} and {max}.",
    "err.no_distance_specified": "No distance specified and no saved value available; pass --distance N.",
    "err.verify_failed": "Wrote the new value but verification failed on re-read. The backup was not modified.",
    "err.unexpected": "Unexpected error: {error}",
    "info.dll_path": "client.dll: {path}",
    "info.already_patched": "This file already looks patched: current value is {value}.",
    "info.stock_default": "Found the stock default value (1200.0).",
    "info.signature_mismatch": "Warning: the surrounding bytes don't match the expected signature. "
                                "This may still be correct after a game update, but double-check with --diagnose.",
    "info.alias_warning": "Warning: {count} code references point at this constant; "
                           "it might not be used only for the camera.",
    "info.candidates_intro": "Multiple candidates found:",
    "info.backup_created": "Created backup: {path}",
    "info.backup_stale": "Warning: the existing backup's size differs from the current client.dll; "
                          "it may be from an older game version. Consider deleting it.",
    "info.patch_unchanged": "Value is already {value}; nothing to write.",
    "info.patch_success": "Camera distance changed: {old} -> {new}",
    "info.restore_success": "client.dll restored from backup.",
    "info.restore_current_value": "Current value after restore: {value}",
    "info.launching": "Launching Dota 2...",
    "info.resolution_hint": "Detected resolution {w}x{h}: a distance around {lo}-{hi} is a reasonable heuristic "
                             "starting point (not an official recommendation).",
    "info.console_hint": "Check in-game: open the console and type 'dota_camera_distance' to see the new value. "
                          "Enable the console via the '-console' launch option if needed.",
    "info.distance_warning_high": "Warning: values above {threshold} may cause rendering artifacts "
                                   "or fog at the edge of the view.",
    "prompt.choose_candidate": "Choose a candidate [1-{n}] (empty to abort): ",
    "prompt.use_candidate": "Use value {value}? [y/N]: ",
    "prompt.enter_distance": "Enter camera distance [{min}-{max}] (default {default}): ",
    "diagnose.title": "camera_distance --diagnose report",
}


def tr(msg_id: str, **kwargs) -> str:
    """Look up a message id and format it with the given keyword arguments."""
    text = MESSAGES.get(msg_id, f"[[{msg_id}]]")
    return text.format(**kwargs) if kwargs else text


# ==================== EXCEPTIONS ====================

class PEParseError(Exception):
    """Raised when a file does not look like a valid PE image."""


class VdfError(Exception):
    """Raised on malformed VDF (Valve KeyValues) text."""


class PatchVerificationError(Exception):
    """Raised when a post-write re-read of the patched bytes doesn't match the intended value."""


# ==================== DATA MODEL ====================

@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    pointer_to_raw_data: int
    size_of_raw_data: int
    characteristics: int


@dataclass(frozen=True)
class PEImage:
    """A minimally parsed PE/COFF image: just enough of the header to convert offsets <-> RVAs."""

    data: bytes
    sections: tuple

    @classmethod
    def from_bytes(cls, data: bytes) -> "PEImage":
        """Parse the DOS/NT/section headers of a PE file."""
        if len(data) < 0x40:
            raise PEParseError("file too small to contain a DOS header")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        nt = e_lfanew
        if nt + 24 > len(data) or data[nt:nt + 4] != b"PE\x00\x00":
            raise PEParseError("missing PE signature; not a valid PE file")
        number_of_sections = struct.unpack_from("<H", data, nt + 6)[0]
        size_of_optional_header = struct.unpack_from("<H", data, nt + 20)[0]
        section_table_start = nt + 24 + size_of_optional_header
        sections = []
        for i in range(number_of_sections):
            o = section_table_start + 40 * i
            if o + 40 > len(data):
                raise PEParseError("section table extends past end of file")
            name = data[o:o + 8].rstrip(b"\x00").decode("latin-1")
            virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data = struct.unpack_from(
                "<IIII", data, o + 8
            )
            characteristics = struct.unpack_from("<I", data, o + 36)[0]
            sections.append(
                Section(name, virtual_address, virtual_size, pointer_to_raw_data, size_of_raw_data, characteristics)
            )
        return cls(data=data, sections=tuple(sections))

    def rva_to_offset(self, rva: int) -> Optional[int]:
        """Convert a relative virtual address to a file offset, or None if unmapped."""
        for s in self.sections:
            span = max(s.virtual_size, s.size_of_raw_data)
            if s.virtual_address <= rva < s.virtual_address + span:
                delta = rva - s.virtual_address
                if delta < s.size_of_raw_data:
                    return s.pointer_to_raw_data + delta
                return None
        return None

    def offset_to_rva(self, offset: int) -> Optional[int]:
        """Convert a file offset to a relative virtual address, or None if outside any section's raw data."""
        for s in self.sections:
            if s.pointer_to_raw_data <= offset < s.pointer_to_raw_data + s.size_of_raw_data:
                return s.virtual_address + (offset - s.pointer_to_raw_data)
        return None

    def executable_sections(self):
        return [s for s in self.sections if s.characteristics & IMAGE_SCN_MEM_EXECUTE]

    def read_f32(self, offset: int) -> float:
        return struct.unpack_from("<f", self.data, offset)[0]


@dataclass(frozen=True)
class RipRef:
    kind: str  # "lea" | "sse_load"
    mnemonic: str
    insn_offset: int
    disp32_offset: int
    disp32: int
    target_rva: Optional[int] = None
    target_offset: Optional[int] = None


@dataclass(frozen=True)
class Candidate:
    load_ref: RipRef
    constant_offset: int
    constant_rva: int
    value: float


class Status(Enum):
    OK = "ok"
    NO_STRING = "no_string"
    NO_LEA_REF = "no_lea_ref"
    MULTIPLE_LEA_REFS = "multiple_lea_refs"
    NO_CANDIDATE = "no_candidate"
    MULTIPLE_CANDIDATES = "multiple_candidates"
    VALUE_OUT_OF_RANGE = "value_out_of_range"


@dataclass
class SearchResult:
    status: Status
    string_offsets: list = field(default_factory=list)
    string_rva: Optional[int] = None
    lea_refs: list = field(default_factory=list)
    chosen_lea: Optional[RipRef] = None
    candidates: list = field(default_factory=list)
    chosen_candidate: Optional[Candidate] = None
    signature_ok: Optional[bool] = None
    alias_count: Optional[int] = None
    is_already_patched: bool = False
    current_value: Optional[float] = None


@dataclass
class BackupStatus:
    path: Path
    created: bool
    stale: bool


@dataclass
class PatchResult:
    offset: int
    old_value: float
    new_value: float
    verified: bool
    backup: BackupStatus
    unchanged: bool


# ==================== BYTE-PATTERN SCANNERS ====================
#
# Manual bytes.find()-anchored scanning rather than `re`: the instructions we're
# looking for have variable-length optional prefixes, and a regex with `.{4}` for
# the disp32 bytes needs re.DOTALL (disp32 routinely contains 0x0A). Anchoring on
# the rarer fixed opcode byte via bytes.find (C-implemented) is simpler and faster.

def _sse_mnemonic(prefix: Optional[int], opcode2: int) -> str:
    table = {
        (None, 0x10): "movups", (0x66, 0x10): "movupd",
        (0xF3, 0x10): "movss", (0xF2, 0x10): "movsd",
        (None, 0x28): "movaps", (0x66, 0x28): "movapd",
    }
    return table.get((prefix, opcode2), f"unknown(0f{opcode2:02x})")


def iter_lea_rip(data: bytes, start: int = 0, end: Optional[int] = None) -> Iterator[RipRef]:
    """Yield every `lea reg, [rip+disp32]` instruction in data[start:end].

    Pattern: REX (0x48 or 0x4C) + 0x8D + modrm with (modrm & 0xC7) == 0x05 + disp32.
    """
    end = len(data) if end is None else end
    pos = start
    while True:
        idx = data.find(b"\x8D", pos, end)
        if idx == -1:
            break
        if idx + 6 > end:
            break  # end is a hard bound; no larger idx will fit either
        if idx >= 1:
            rex, modrm = data[idx - 1], data[idx + 1]
            if rex in (0x48, 0x4C) and (modrm & 0xC7) == 0x05:
                disp32_offset = idx + 2
                disp32 = struct.unpack_from("<i", data, disp32_offset)[0]
                yield RipRef("lea", "lea", idx - 1, disp32_offset, disp32)
        pos = idx + 1


def iter_rip_sse_load(data: bytes, start: int = 0, end: Optional[int] = None) -> Iterator[RipRef]:
    """Yield RIP-relative SSE loads (movups/movupd/movss/movsd/movaps/movapd) in data[start:end].

    Pattern: [0x66|0xF2|0xF3]? [REX 0x40-0x4F]? 0x0F (0x10|0x28) modrm disp32,
    with (modrm & 0xC7) == 0x05. Anchored on the 0x0F opcode byte.
    """
    end = len(data) if end is None else end
    pos = start
    while True:
        idx = data.find(b"\x0F", pos, end)
        if idx == -1:
            break
        if idx + 3 <= end and data[idx + 1] in (0x10, 0x28) and (data[idx + 2] & 0xC7) == 0x05:
            disp32_offset = idx + 3
            if disp32_offset + 4 <= end:
                disp32 = struct.unpack_from("<i", data, disp32_offset)[0]
                insn_start = idx
                prefix = None
                if insn_start - 1 >= 0 and 0x40 <= data[insn_start - 1] <= 0x4F:
                    insn_start -= 1
                if insn_start - 1 >= 0 and data[insn_start - 1] in (0x66, 0xF2, 0xF3):
                    prefix = data[insn_start - 1]
                    insn_start -= 1
                mnem = _sse_mnemonic(prefix, data[idx + 1])
                yield RipRef("sse_load", mnem, insn_start, disp32_offset, disp32)
        pos = idx + 1


def iter_rip_refs(data: bytes, start: int = 0, end: Optional[int] = None,
                   kinds=("lea", "sse_load")) -> Iterator[RipRef]:
    """Merge iter_lea_rip and iter_rip_sse_load, sorted by instruction offset."""
    refs = []
    if "lea" in kinds:
        refs.extend(iter_lea_rip(data, start, end))
    if "sse_load" in kinds:
        refs.extend(iter_rip_sse_load(data, start, end))
    refs.sort(key=lambda r: r.insn_offset)
    return iter(refs)


def with_targets(pe: PEImage, refs) -> Iterator[RipRef]:
    """Resolve each RipRef's target_rva/target_offset from its disp32 and file position."""
    for r in refs:
        after_disp32_rva = pe.offset_to_rva(r.disp32_offset + 4)
        if after_disp32_rva is None:
            continue
        target_rva = after_disp32_rva + r.disp32
        target_offset = pe.rva_to_offset(target_rva)
        yield dataclasses.replace(r, target_rva=target_rva, target_offset=target_offset)


# ==================== SEARCH ORCHESTRATION ====================

def find_cvar_string_offsets(data: bytes, name: bytes = CVAR_NAME) -> list:
    """Find every NUL-terminated occurrence of `name` in `data`. Returns offsets of the first name byte."""
    pattern = b"\x00" + name + b"\x00"
    offsets = []
    i = data.find(pattern)
    while i != -1:
        offsets.append(i + 1)
        i = data.find(pattern, i + 1)
    return offsets


def _executable_spans(pe: PEImage):
    sections = pe.executable_sections()
    if sections:
        return [(s.pointer_to_raw_data, s.pointer_to_raw_data + s.size_of_raw_data) for s in sections]
    return [(0, len(pe.data))]


def find_string_lea_refs(pe: PEImage, string_rvas: set) -> list:
    """Find every `lea` in the executable sections whose RIP-relative target is one of string_rvas."""
    matches = []
    for lo, hi in _executable_spans(pe):
        for ref in with_targets(pe, iter_lea_rip(pe.data, lo, hi)):
            if ref.target_rva in string_rvas:
                matches.append(ref)
    return matches


def find_constant_candidates(pe: PEImage, lea_ref: RipRef,
                              before: int = LEA_WINDOW_BEFORE, after: int = LEA_WINDOW_AFTER) -> list:
    """Find RIP-relative float loads within [-before, +after] bytes of lea_ref, resolved to their values."""
    lo = max(0, lea_ref.insn_offset - before)
    hi = min(len(pe.data), lea_ref.insn_offset + after)
    candidates = []
    for ref in with_targets(pe, iter_rip_sse_load(pe.data, lo, hi)):
        if ref.target_offset is None or ref.target_offset + 4 > len(pe.data):
            continue
        value = pe.read_f32(ref.target_offset)
        candidates.append(Candidate(ref, ref.target_offset, ref.target_rva, value))
    return candidates


def check_signature(data: bytes, constant_offset: int) -> bool:
    """Soft confidence check: does the real-patch float layout around the constant match?

    Before: 750.0, 900.0, 950.0. After: -0.9999, -100.0. Never raises; a mismatch (including
    out-of-bounds) just returns False, since this is a warning-only heuristic that can
    legitimately stop matching after a future game update.
    """
    try:
        before_bytes = [struct.pack("<f", v) for v in SIG_BEFORE_VALUES]
        for i, expect in enumerate(reversed(before_bytes)):
            off = constant_offset - 4 * (i + 1)
            if off < 0 or data[off:off + 4] != expect:
                return False
        for i, expect in enumerate(SIG_AFTER_BYTES):
            off = constant_offset + 4 * (i + 1)
            if off + 4 > len(data) or data[off:off + 4] != expect:
                return False
        return True
    except Exception:
        return False


def count_rip_references_to(pe: PEImage, target_rva: int, kinds=("lea", "sse_load")) -> int:
    """Count lea/SSE-load instructions anywhere in the executable sections targeting target_rva.

    Scoped to just these two instruction shapes (no full disassembler - out of scope for a
    stdlib-only tool); still a reasonable, bounded definition for a soft "is this constant
    shared with something else" warning.
    """
    count = 0
    for lo, hi in _executable_spans(pe):
        for ref in with_targets(pe, iter_rip_refs(pe.data, lo, hi, kinds=kinds)):
            if ref.target_rva == target_rva:
                count += 1
    return count


def classify_value(value: float):
    """Classify a resolved constant value. Returns (is_already_patched, Status)."""
    if value == 1200.0:
        return False, Status.OK
    if AUTO_SAFE_MIN <= value <= AUTO_SAFE_MAX:
        return True, Status.OK
    if ALREADY_PATCHED_MIN <= value <= ALREADY_PATCHED_MAX:
        return True, Status.VALUE_OUT_OF_RANGE
    return False, Status.VALUE_OUT_OF_RANGE


def run_search(pe: PEImage, cvar_name: bytes = CVAR_NAME,
                before: int = LEA_WINDOW_BEFORE, after: int = LEA_WINDOW_AFTER) -> SearchResult:
    """Run the full string -> lea -> RIP-load -> constant search. Read-only; never writes."""
    string_offsets = find_cvar_string_offsets(pe.data, cvar_name)
    if not string_offsets:
        return SearchResult(status=Status.NO_STRING, string_offsets=[])

    string_rvas = {pe.offset_to_rva(o) for o in string_offsets}
    string_rvas.discard(None)
    string_rva = next(iter(string_rvas), None)

    lea_refs = find_string_lea_refs(pe, string_rvas)
    if not lea_refs:
        return SearchResult(status=Status.NO_LEA_REF, string_offsets=string_offsets, string_rva=string_rva)
    if len(lea_refs) > 1:
        return SearchResult(status=Status.MULTIPLE_LEA_REFS, string_offsets=string_offsets,
                             string_rva=string_rva, lea_refs=lea_refs)

    chosen_lea = lea_refs[0]
    candidates = find_constant_candidates(pe, chosen_lea, before, after)
    if not candidates:
        return SearchResult(status=Status.NO_CANDIDATE, string_offsets=string_offsets, string_rva=string_rva,
                             lea_refs=lea_refs, chosen_lea=chosen_lea)
    if len(candidates) > 1:
        return SearchResult(status=Status.MULTIPLE_CANDIDATES, string_offsets=string_offsets,
                             string_rva=string_rva, lea_refs=lea_refs, chosen_lea=chosen_lea, candidates=candidates)

    candidate = candidates[0]
    is_already_patched, status = classify_value(candidate.value)
    signature_ok = check_signature(pe.data, candidate.constant_offset)
    alias_count = count_rip_references_to(pe, candidate.constant_rva)

    return SearchResult(
        status=status,
        string_offsets=string_offsets,
        string_rva=string_rva,
        lea_refs=lea_refs,
        chosen_lea=chosen_lea,
        candidates=[candidate],
        chosen_candidate=candidate,
        signature_ok=signature_ok,
        alias_count=alias_count,
        is_already_patched=is_already_patched,
        current_value=candidate.value,
    )


# ==================== VDF PARSER ====================
# Minimal hand-written parser for Valve's KeyValues text format - just enough to pull
# "path" strings out of libraryfolders.vdf. No #base includes, no conditional blocks.

def _tokenize_vdf(text: str) -> list:
    """Tokenize flat KeyValues text into (kind, value) pairs; kind in {STR, OPEN, CLOSE}."""
    tokens = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if c == "{":
            tokens.append(("OPEN", "{"))
            i += 1
            continue
        if c == "}":
            tokens.append(("CLOSE", "}"))
            i += 1
            continue
        if c == '"':
            i += 1
            buf = []
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    nxt = text[i + 1]
                    if nxt == '"':
                        buf.append('"')
                        i += 2
                        continue
                    if nxt == "\\":
                        buf.append("\\")
                        i += 2
                        continue
                    if nxt == "n":
                        buf.append("\n")
                        i += 2
                        continue
                    if nxt == "t":
                        buf.append("\t")
                        i += 2
                        continue
                    buf.append(text[i])
                    i += 1
                    continue
                buf.append(text[i])
                i += 1
            i += 1  # skip closing quote
            tokens.append(("STR", "".join(buf)))
            continue
        i += 1  # skip unexpected bare character outside quotes
    return tokens


def _parse_vdf_object(tokens, pos):
    result = {}
    while pos < len(tokens) and tokens[pos][0] != "CLOSE":
        if tokens[pos][0] != "STR":
            raise VdfError(f"expected key at token {pos}")
        key = tokens[pos][1]
        pos += 1
        if pos < len(tokens) and tokens[pos][0] == "OPEN":
            pos += 1
            value, pos = _parse_vdf_object(tokens, pos)
            if pos < len(tokens) and tokens[pos][0] == "CLOSE":
                pos += 1
        elif pos < len(tokens) and tokens[pos][0] == "STR":
            value = tokens[pos][1]
            pos += 1
        else:
            raise VdfError(f"expected value at token {pos}")
        result[key] = value
    return result, pos


def parse_vdf(text: str) -> dict:
    """Parse a minimal subset of Valve's KeyValues (VDF) text format: one root object."""
    tokens = _tokenize_vdf(text)
    if not tokens or tokens[0][0] != "STR":
        raise VdfError("empty or malformed VDF")
    root_key = tokens[0][1]
    pos = 1
    if pos < len(tokens) and tokens[pos][0] == "OPEN":
        pos += 1
        value, pos = _parse_vdf_object(tokens, pos)
    else:
        raise VdfError("expected root object")
    return {root_key: value}


# ==================== STEAM / CLIENT.DLL DISCOVERY ====================

def read_steam_install_path() -> Optional[Path]:
    """Locate the Steam install directory via the registry."""
    if winreg is None:
        return None
    for hive, subkey, value_name in (
        (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath"),
    ):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                value, _ = winreg.QueryValueEx(key, value_name)
                if value:
                    return Path(value)
        except OSError:
            continue
    return None


def enumerate_steam_libraries(steam_path: Path) -> list:
    """Parse steamapps/libraryfolders.vdf under steam_path; return every library root path found."""
    vdf_path = steam_path / "steamapps" / "libraryfolders.vdf"
    try:
        text = vdf_path.read_text(encoding="utf-8", errors="replace")
        data = parse_vdf(text)
    except (OSError, VdfError):
        return []
    root = data.get("libraryfolders", {})
    libs = []
    if isinstance(root, dict):
        for entry in root.values():
            if isinstance(entry, dict) and "path" in entry:
                libs.append(Path(entry["path"]))
    return libs


def find_client_dll(explicit: Optional[str] = None) -> Optional[Path]:
    """Resolve the path to client.dll: explicit override, else Steam registry + library discovery."""
    if explicit:
        p = Path(explicit)
        return p if p.is_file() else None
    steam_path = read_steam_install_path()
    if steam_path is None:
        return None
    candidates = [steam_path] + enumerate_steam_libraries(steam_path)
    seen = set()
    for lib in candidates:
        key = str(lib).lower()
        if key in seen:
            continue
        seen.add(key)
        dll = lib / DOTA_DLL_RELATIVE
        if dll.is_file():
            return dll
    return None


# ==================== DPI / RESOLUTION HEURISTIC ====================

def get_primary_screen_resolution() -> Optional[tuple]:
    """Best-effort physical resolution of the primary monitor, DPI-aware. None on any failure."""
    if sys.platform != "win32":
        return None
    try:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE)
        except (AttributeError, OSError):
            ctypes.windll.user32.SetProcessDPIAware()
        width = ctypes.windll.user32.GetSystemMetrics(SM_CXSCREEN)
        height = ctypes.windll.user32.GetSystemMetrics(SM_CYSCREEN)
        if width > 0 and height > 0:
            return (width, height)
    except Exception:
        pass
    return None


def recommend_distance_for_resolution(width: int, height: int) -> Optional[tuple]:
    """Heuristic camera-distance suggestion band based on aspect ratio. Not an official recommendation."""
    if height <= 0:
        return None
    ratio = width / height
    if ratio < RATIO_4_3_MAX:
        return (1500, 1600)
    if ratio < RATIO_ULTRAWIDE_MIN:
        return (1400, 1500)
    return (1300, 1400)


# ==================== CONFIG ====================

def get_app_dir() -> Path:
    """Directory config.json lives in: next to the frozen exe, or next to this script.

    sys.executable (not sys._MEIPASS, PyInstaller onefile's temp extraction dir, and not
    sys.argv[0]) stays stable next to wherever the user placed the exe.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def load_config() -> dict:
    path = get_app_dir() / CONFIG_FILENAME
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(config: dict) -> None:
    path = get_app_dir() / CONFIG_FILENAME
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


# ==================== FILE SAFETY ====================

def is_dota_running() -> bool:
    """Check via tasklist whether dota2.exe is currently running."""
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq dota2.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return any(line.strip().lower().startswith('"dota2.exe"') for line in proc.stdout.splitlines())


def backup_path_for(dll_path: Path) -> Path:
    return dll_path.with_name(dll_path.name + BACKUP_SUFFIX)


def ensure_backup(dll_path: Path) -> BackupStatus:
    """Create a .bak copy of dll_path if one doesn't already exist.

    Staleness is judged by file size only, not mtime: our own patch changes mtime but
    never size, so size-only avoids a false "stale" flag right after our own first patch.
    """
    backup = backup_path_for(dll_path)
    if not backup.exists():
        shutil.copy2(dll_path, backup)
        return BackupStatus(backup, created=True, stale=False)
    stale = os.path.getsize(dll_path) != os.path.getsize(backup)
    return BackupStatus(backup, created=False, stale=stale)


def write_patched_float(dll_path: Path, offset: int, value: float) -> None:
    with open(dll_path, "r+b") as f:
        f.seek(offset)
        f.write(struct.pack("<f", value))


def verify_patch(dll_path: Path, offset: int, expected_value: float) -> bool:
    with open(dll_path, "rb") as f:
        f.seek(offset)
        actual = f.read(4)
    return actual == struct.pack("<f", expected_value)


def restore_backup(dll_path: Path) -> None:
    backup = backup_path_for(dll_path)
    if not backup.exists():
        raise FileNotFoundError(str(backup))
    shutil.copy2(backup, dll_path)


def patch_distance(dll_path: Path, candidate: Candidate, new_distance: float) -> PatchResult:
    """Back up, write, and verify the new camera-distance constant."""
    backup = ensure_backup(dll_path)
    old_value = candidate.value
    if struct.pack("<f", new_distance) == struct.pack("<f", old_value):
        return PatchResult(candidate.constant_offset, old_value, new_distance,
                            verified=True, backup=backup, unchanged=True)
    write_patched_float(dll_path, candidate.constant_offset, new_distance)
    verified = verify_patch(dll_path, candidate.constant_offset, new_distance)
    if not verified:
        raise PatchVerificationError(
            f"wrote {new_distance} at offset {hex(candidate.constant_offset)} but re-read did not match"
        )
    return PatchResult(candidate.constant_offset, old_value, new_distance,
                        verified=True, backup=backup, unchanged=False)


# ==================== CLI ====================

def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="camera_distance",
        description="Patch Dota 2's client.dll to change the default camera distance.",
    )
    parser.add_argument("--dll", metavar="PATH", help="Path to client.dll (overrides auto-detection)")
    parser.add_argument("--distance", type=float, metavar="N",
                         help=f"Desired camera distance ({USER_MIN}-{USER_MAX})")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--restore", action="store_true", help="Restore client.dll from the .bak backup")
    mode.add_argument("--diagnose", action="store_true", help="Print a diagnostic report; never writes")
    parser.add_argument("--launch", action="store_true", help="Apply the saved distance, then launch Dota 2")
    parser.add_argument("--yes", "-y", action="store_true", help="Never prompt interactively; abort instead")
    parser.add_argument("--candidate", type=int, metavar="N", default=None,
                         help="Pick candidate #N (1-based) when multiple were found")
    return parser


def cmd_diagnose(args: argparse.Namespace) -> int:
    """Print-only diagnostic report: discovery, search results, candidate context. Never writes."""
    print("=" * 60)
    print(tr("diagnose.title"))
    print("=" * 60)

    steam_path = read_steam_install_path()
    print(f"Steam path (registry): {steam_path if steam_path else '(not found)'}")
    if steam_path is not None:
        libraries = enumerate_steam_libraries(steam_path)
        print(f"Steam libraries found: {len(libraries)}")
        for lib in [steam_path] + libraries:
            dll = lib / DOTA_DLL_RELATIVE
            print(f"  probing: {dll}  exists={dll.is_file()}")

    dll_path = find_client_dll(args.dll)
    if dll_path is None:
        print()
        print(tr("err.dll_not_found"))
        return 3

    print()
    print(f"client.dll: {dll_path}")
    print(f"size: {dll_path.stat().st_size} bytes")

    data = dll_path.read_bytes()
    try:
        pe = PEImage.from_bytes(data)
    except PEParseError as exc:
        print(f"PE parse error: {exc}")
        return 3

    print(f"sections: {[s.name for s in pe.sections]}")

    result = run_search(pe)
    print()
    print(f"status: {result.status.value}")
    print(f"string occurrences: {len(result.string_offsets)} ({[hex(o) for o in result.string_offsets]})")
    print(f"string RVA: {hex(result.string_rva) if result.string_rva is not None else 'n/a'}")
    print(f"lea references to string: {len(result.lea_refs)}")
    for ref in result.lea_refs:
        target = hex(ref.target_rva) if ref.target_rva is not None else "n/a"
        print(f"  lea @ {hex(ref.insn_offset)}  disp32={ref.disp32}  target_rva={target}")

    if result.chosen_lea is not None:
        print(f"chosen lea: {hex(result.chosen_lea.insn_offset)}")
        print(f"candidates in window [-{LEA_WINDOW_BEFORE},+{LEA_WINDOW_AFTER}]: {len(result.candidates)}")
        for c in result.candidates:
            sig = check_signature(data, c.constant_offset)
            print(f"  constant @ {hex(c.constant_offset)}  value={c.value}  signature_match={sig}  "
                  f"load_insn={hex(c.load_ref.insn_offset)} ({c.load_ref.mnemonic})")

    if result.chosen_candidate is not None:
        print()
        print(f"resolved constant offset: {hex(result.chosen_candidate.constant_offset)}")
        print(f"current value: {result.chosen_candidate.value}")
        print(f"signature check: {'OK' if result.signature_ok else 'MISMATCH (warning only)'}")
        print(f"alias references to this constant: {result.alias_count}")
        print(f"already patched: {result.is_already_patched}")

    print("=" * 60)
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    """Restore client.dll from its .bak backup."""
    dll_path = find_client_dll(args.dll)
    if dll_path is None:
        print(tr("err.dll_not_found"))
        return 3
    if is_dota_running():
        print(tr("err.dota_running"))
        return 2
    backup = backup_path_for(dll_path)
    if not backup.exists():
        print(tr("err.no_backup"))
        return 6
    restore_backup(dll_path)
    print(tr("info.restore_success"))

    try:
        data = dll_path.read_bytes()
        pe = PEImage.from_bytes(data)
        result = run_search(pe)
        if result.chosen_candidate is not None:
            print(tr("info.restore_current_value", value=result.chosen_candidate.value))
    except Exception:
        pass

    print()
    print(tr("info.console_hint"))
    return 0


def _print_candidates(candidates, data: bytes) -> None:
    print(tr("info.candidates_intro"))
    for i, c in enumerate(candidates, start=1):
        sig = check_signature(data, c.constant_offset)
        print(f"  [{i}] offset={hex(c.constant_offset)}  value={c.value}  "
              f"signature_match={sig}  via {c.load_ref.mnemonic}@{hex(c.load_ref.insn_offset)}")


def cmd_patch(args: argparse.Namespace, config: dict, noninteractive: bool) -> int:
    """Resolve, search, and (unless aborted) patch the camera distance constant."""
    dll_path = find_client_dll(args.dll or config.get("dll_path"))
    if dll_path is None:
        print(tr("err.dll_not_found"))
        return 3

    if is_dota_running():
        print(tr("err.dota_running"))
        return 2

    print(tr("info.dll_path", path=str(dll_path)))
    data = dll_path.read_bytes()
    try:
        pe = PEImage.from_bytes(data)
    except PEParseError as exc:
        print(tr("err.pe_parse", error=str(exc)))
        return 3

    result = run_search(pe)

    if result.status in (Status.NO_STRING, Status.NO_LEA_REF, Status.NO_CANDIDATE):
        print(tr("err.nothing_found"))
        return 5

    if result.status == Status.MULTIPLE_LEA_REFS:
        print(tr("err.multiple_lea_refs"))
        for ref in result.lea_refs:
            target = hex(ref.target_rva) if ref.target_rva is not None else "n/a"
            print(f"  lea @ {hex(ref.insn_offset)} -> target_rva={target}")
        return 4

    candidate = None
    if result.status in (Status.MULTIPLE_CANDIDATES, Status.VALUE_OUT_OF_RANGE):
        candidates = result.candidates
        _print_candidates(candidates, data)
        if args.candidate is not None:
            idx = args.candidate - 1
            if 0 <= idx < len(candidates):
                candidate = candidates[idx]
        if candidate is None:
            if noninteractive:
                print(tr("err.ambiguous_noninteractive"))
                return 4
            if len(candidates) == 1:
                answer = input(tr("prompt.use_candidate", value=candidates[0].value)).strip().lower()
                if answer in ("y", "yes"):
                    candidate = candidates[0]
            else:
                choice = input(tr("prompt.choose_candidate", n=len(candidates))).strip()
                if choice.isdigit() and 1 <= int(choice) <= len(candidates):
                    candidate = candidates[int(choice) - 1]
        if candidate is None:
            print(tr("err.ambiguous_declined"))
            return 4
    else:
        candidate = result.chosen_candidate

    signature_ok = check_signature(data, candidate.constant_offset)
    alias_count = count_rip_references_to(pe, candidate.constant_rva)
    is_already_patched = candidate.value != 1200.0 and ALREADY_PATCHED_MIN <= candidate.value <= ALREADY_PATCHED_MAX

    if is_already_patched:
        print(tr("info.already_patched", value=candidate.value))
    else:
        print(tr("info.stock_default"))
    if not signature_ok:
        print(tr("info.signature_mismatch"))
    if alias_count > 1:
        print(tr("info.alias_warning", count=alias_count))

    new_distance = args.distance
    if new_distance is None and args.launch:
        new_distance = config.get("distance")
    if new_distance is None:
        if noninteractive:
            print(tr("err.no_distance_specified"))
            return 8
        res = get_primary_screen_resolution()
        if res is not None:
            hint = recommend_distance_for_resolution(*res)
            if hint is not None:
                print(tr("info.resolution_hint", lo=hint[0], hi=hint[1], w=res[0], h=res[1]))
        default_value = config.get("distance", candidate.value)
        raw = input(tr("prompt.enter_distance", min=USER_MIN, max=USER_MAX, default=default_value)).strip()
        new_distance = float(raw) if raw else float(default_value)

    if not (USER_MIN <= new_distance <= USER_MAX):
        print(tr("err.invalid_distance", min=USER_MIN, max=USER_MAX))
        return 8
    if new_distance > WARN_ABOVE:
        print(tr("info.distance_warning_high", threshold=WARN_ABOVE))

    try:
        patch_result = patch_distance(dll_path, candidate, new_distance)
    except PatchVerificationError:
        print(tr("err.verify_failed"))
        return 7

    if patch_result.backup.created:
        print(tr("info.backup_created", path=str(patch_result.backup.path)))
    elif patch_result.backup.stale:
        print(tr("info.backup_stale"))

    if patch_result.unchanged:
        print(tr("info.patch_unchanged", value=new_distance))
    else:
        print(tr("info.patch_success", old=patch_result.old_value, new=patch_result.new_value))

    config["distance"] = new_distance
    config["dll_path"] = str(dll_path)
    config["schema_version"] = CONFIG_SCHEMA_VERSION
    save_config(config)

    print()
    print(tr("info.console_hint"))

    if args.launch:
        print(tr("info.launching"))
        os.startfile(f"steam://rungameid/{STEAM_APPID}")

    return 0


def main(argv: Optional[list] = None) -> int:
    """Entry point. Never calls sys.exit itself, so it's directly unit-testable."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.launch and (args.restore or args.diagnose):
        parser.error("--launch cannot be combined with --restore or --diagnose")
    if args.distance is not None and (args.restore or args.diagnose):
        parser.error("--distance cannot be combined with --restore or --diagnose")

    config = load_config()
    noninteractive = args.yes or args.launch or not sys.stdin.isatty()

    try:
        if args.restore:
            return cmd_restore(args)
        if args.diagnose:
            return cmd_diagnose(args)
        return cmd_patch(args, config, noninteractive)
    except KeyboardInterrupt:
        print()
        return 130
    except Exception as exc:
        print(tr("err.unexpected", error=str(exc)), file=sys.stderr)
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
