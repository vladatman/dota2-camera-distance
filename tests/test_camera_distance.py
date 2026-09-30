"""Tests for camera_distance.py, including a synthetic PE fixture built by hand."""

import struct
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import camera_distance as cd


# ==================== SYNTHETIC PE BUILDER ====================
#
# Assembles a minimal-but-valid PE: DOS header, NT headers (SizeOfOptionalHeader=0,
# since PEImage.from_bytes never reads any optional-header field - a deliberate
# simplification, do not "fix" by adding a real optional header), two sections
# (.text, .rdata). Disp32 values are always computed from the same RVA arithmetic
# the production code uses, never hand-derived.

NT_HEADER_OFFSET = 0x40
SECTION_TABLE_OFFSET = 0x58  # NT(0x40) + sig(4) + COFF(20) + SizeOfOptionalHeader(0)
HEADER_REGION_SIZE = 0x200

TEXT_VA = 0x1000
TEXT_FILE_OFFSET = 0x200
TEXT_SIZE = 0x200
RDATA_VA = 0x2000
RDATA_SIZE = 0x200

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040

# .text local offsets (all 7-byte instructions unless noted)
DECOY1_LOCAL = 0x00   # 10 bytes: C7 83 <disp32> 00 00 96 44
DECOY2_LOCAL = 0x20   # 7 bytes: C7 41 <disp8> 00 00 96 44
EXTRA_LOAD_LOCAL = 0xF0
MOV_LOCAL = 0x100
LEA_LOCAL = 0x107
EXTRA_LEA_LOCAL = 0x180
ALIAS_REF_LOCAL = 0x1C0

# .rdata local offsets
SIG_BEFORE_LOCAL = 0x00   # 750.0, 900.0, 950.0 at +0, +4, +8
CONST_LOCAL = 0x0C        # the real 1200.0 constant
SIG_AFTER_LOCAL = 0x10    # -0.9999 at +0x10, -100.0 at +0x14
STRING_NUL_LOCAL = 0x20
STRING_LOCAL = 0x21
EXTRA_CANDIDATE_LOCAL = 0x50

CVAR_NAME = b"dota_camera_distance"


@dataclass
class Layout:
    data: bytes
    text_va: int
    text_file_offset: int
    rdata_va: int
    rdata_file_offset: int
    string_file_offset: int
    string_rva: int
    lea_file_offset: int
    movups_file_offset: int
    constant_file_offset: int
    constant_rva: int
    extra_lea_file_offset: int = None
    extra_candidate_file_offset: int = None
    alias_ref_file_offset: int = None


def _pack_section_header(name: bytes, virtual_size, virtual_address, size_of_raw_data,
                          pointer_to_raw_data, characteristics) -> bytes:
    name = name[:8].ljust(8, b"\x00")
    return name + struct.pack(
        "<IIIIIIHHI",
        virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data,
        0, 0, 0, 0, characteristics,
    )


def _disp32(target_rva: int, insn_start_local: int, section_va: int = TEXT_VA) -> int:
    field_end_rva = section_va + insn_start_local + 7
    return target_rva - field_end_rva


def _poke_float(data: bytes, offset: int, value: float) -> bytes:
    buf = bytearray(data)
    struct.pack_into("<f", buf, offset, value)
    return bytes(buf)


def build_pe(*, extra_lea_ref=False, extra_load_candidate=False, extra_alias_ref=False,
             include_decoys=True, corrupt_signature=False):
    """Build a minimal synthetic client.dll-shaped PE exercising the search algorithm."""
    rdata = bytearray(RDATA_SIZE)
    struct.pack_into("<f", rdata, SIG_BEFORE_LOCAL + 0, 750.0)
    struct.pack_into("<f", rdata, SIG_BEFORE_LOCAL + 4, 900.0)
    struct.pack_into("<f", rdata, SIG_BEFORE_LOCAL + 8, 950.0)
    struct.pack_into("<f", rdata, CONST_LOCAL, 1200.0)
    rdata[SIG_AFTER_LOCAL:SIG_AFTER_LOCAL + 4] = bytes.fromhex("72F97FBF")
    rdata[SIG_AFTER_LOCAL + 4:SIG_AFTER_LOCAL + 8] = bytes.fromhex("0000C8C2")
    if corrupt_signature:
        struct.pack_into("<f", rdata, SIG_BEFORE_LOCAL + 8, 111.0)

    rdata[STRING_NUL_LOCAL] = 0
    rdata[STRING_LOCAL:STRING_LOCAL + len(CVAR_NAME)] = CVAR_NAME
    rdata[STRING_LOCAL + len(CVAR_NAME)] = 0

    if extra_load_candidate:
        struct.pack_into("<f", rdata, EXTRA_CANDIDATE_LOCAL, 1450.0)

    string_rva = RDATA_VA + STRING_LOCAL
    const_rva = RDATA_VA + CONST_LOCAL

    text = bytearray(TEXT_SIZE)
    if include_decoys:
        text[DECOY1_LOCAL:DECOY1_LOCAL + 2] = bytes([0xC7, 0x83])
        struct.pack_into("<i", text, DECOY1_LOCAL + 2, 0x00001234)
        text[DECOY1_LOCAL + 6:DECOY1_LOCAL + 10] = struct.pack("<f", 1200.0)

        text[DECOY2_LOCAL:DECOY2_LOCAL + 2] = bytes([0xC7, 0x41])
        text[DECOY2_LOCAL + 2] = 0x08
        text[DECOY2_LOCAL + 3:DECOY2_LOCAL + 7] = struct.pack("<f", 1200.0)

    mov_disp32 = _disp32(const_rva, MOV_LOCAL)
    text[MOV_LOCAL:MOV_LOCAL + 3] = bytes([0x0F, 0x10, 0x15])
    struct.pack_into("<i", text, MOV_LOCAL + 3, mov_disp32)

    lea_disp32 = _disp32(string_rva, LEA_LOCAL)
    text[LEA_LOCAL:LEA_LOCAL + 3] = bytes([0x48, 0x8D, 0x05])
    struct.pack_into("<i", text, LEA_LOCAL + 3, lea_disp32)

    if extra_load_candidate:
        extra_target_rva = RDATA_VA + EXTRA_CANDIDATE_LOCAL
        extra_disp32 = _disp32(extra_target_rva, EXTRA_LOAD_LOCAL)
        text[EXTRA_LOAD_LOCAL:EXTRA_LOAD_LOCAL + 3] = bytes([0x0F, 0x10, 0x15])
        struct.pack_into("<i", text, EXTRA_LOAD_LOCAL + 3, extra_disp32)

    if extra_lea_ref:
        extra_lea_disp32 = _disp32(string_rva, EXTRA_LEA_LOCAL)
        text[EXTRA_LEA_LOCAL:EXTRA_LEA_LOCAL + 3] = bytes([0x48, 0x8D, 0x05])
        struct.pack_into("<i", text, EXTRA_LEA_LOCAL + 3, extra_lea_disp32)

    if extra_alias_ref:
        alias_disp32 = _disp32(const_rva, ALIAS_REF_LOCAL)
        text[ALIAS_REF_LOCAL:ALIAS_REF_LOCAL + 3] = bytes([0x0F, 0x10, 0x15])
        struct.pack_into("<i", text, ALIAS_REF_LOCAL + 3, alias_disp32)

    text = bytes(text)
    rdata = bytes(rdata)
    rdata_file_offset = TEXT_FILE_OFFSET + len(text)

    header = bytearray(HEADER_REGION_SIZE)
    struct.pack_into("<I", header, 0x3C, NT_HEADER_OFFSET)
    header[NT_HEADER_OFFSET:NT_HEADER_OFFSET + 4] = b"PE\x00\x00"
    struct.pack_into("<H", header, NT_HEADER_OFFSET + 4, 0x8664)  # Machine
    struct.pack_into("<H", header, NT_HEADER_OFFSET + 6, 2)       # NumberOfSections
    struct.pack_into("<H", header, NT_HEADER_OFFSET + 20, 0)      # SizeOfOptionalHeader
    struct.pack_into("<H", header, NT_HEADER_OFFSET + 22, 0x0022)  # Characteristics

    text_header = _pack_section_header(
        b".text", len(text), TEXT_VA, len(text), TEXT_FILE_OFFSET,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    )
    rdata_header = _pack_section_header(
        b".rdata", len(rdata), RDATA_VA, len(rdata), rdata_file_offset,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    )
    header[SECTION_TABLE_OFFSET:SECTION_TABLE_OFFSET + 40] = text_header
    header[SECTION_TABLE_OFFSET + 40:SECTION_TABLE_OFFSET + 80] = rdata_header

    data = bytes(header) + text + rdata

    layout = Layout(
        data=data,
        text_va=TEXT_VA,
        text_file_offset=TEXT_FILE_OFFSET,
        rdata_va=RDATA_VA,
        rdata_file_offset=rdata_file_offset,
        string_file_offset=rdata_file_offset + STRING_LOCAL,
        string_rva=string_rva,
        lea_file_offset=TEXT_FILE_OFFSET + LEA_LOCAL,
        movups_file_offset=TEXT_FILE_OFFSET + MOV_LOCAL,
        constant_file_offset=rdata_file_offset + CONST_LOCAL,
        constant_rva=const_rva,
        extra_lea_file_offset=(TEXT_FILE_OFFSET + EXTRA_LEA_LOCAL) if extra_lea_ref else None,
        extra_candidate_file_offset=(rdata_file_offset + EXTRA_CANDIDATE_LOCAL) if extra_load_candidate else None,
        alias_ref_file_offset=(TEXT_FILE_OFFSET + ALIAS_REF_LOCAL) if extra_alias_ref else None,
    )
    return data, layout


# ==================== PE / SCANNER UNIT TESTS ====================

def test_pe_from_bytes_parses_sections():
    data, layout = build_pe()
    pe = cd.PEImage.from_bytes(data)
    assert [s.name for s in pe.sections] == [".text", ".rdata"]
    assert pe.sections[0].virtual_address == layout.text_va
    assert pe.sections[0].pointer_to_raw_data == layout.text_file_offset
    assert pe.sections[1].virtual_address == layout.rdata_va
    assert pe.sections[1].pointer_to_raw_data == layout.rdata_file_offset


def test_offset_rva_roundtrip():
    data, layout = build_pe()
    pe = cd.PEImage.from_bytes(data)
    for offset in (layout.text_file_offset + 5, layout.rdata_file_offset + 5, layout.constant_file_offset):
        rva = pe.offset_to_rva(offset)
        assert rva is not None
        assert pe.rva_to_offset(rva) == offset


def test_iter_lea_rip_finds_expected_and_ignores_noise():
    blob = bytearray(64)
    blob[10:13] = bytes([0x48, 0x8D, 0x05])
    struct.pack_into("<i", blob, 13, 100)
    blob[30:33] = bytes([0x48, 0x8D, 0x00])  # modrm mod!=00/r!=101 -> should not match
    refs = list(cd.iter_lea_rip(bytes(blob)))
    assert len(refs) == 1
    assert refs[0].insn_offset == 10
    assert refs[0].disp32 == 100


@pytest.mark.parametrize("prefix,opcode2,mnemonic", [
    (None, 0x10, "movups"),
    (0xF3, 0x10, "movss"),
    (0xF2, 0x10, "movsd"),
    (None, 0x28, "movaps"),
])
def test_iter_rip_sse_load_finds_movups_and_variants(prefix, opcode2, mnemonic):
    blob = bytearray(64)
    pos = 10
    if prefix is not None:
        blob[pos] = prefix
        pos += 1
    blob[pos:pos + 3] = bytes([0x0F, opcode2, 0x15])
    struct.pack_into("<i", blob, pos + 3, 200)
    refs = list(cd.iter_rip_sse_load(bytes(blob)))
    assert len(refs) == 1
    assert refs[0].mnemonic == mnemonic
    assert refs[0].disp32 == 200


# ==================== CORE ALGORITHM ====================

def test_run_search_finds_true_constant_and_ignores_decoys():
    data, layout = build_pe()
    pe = cd.PEImage.from_bytes(data)
    result = cd.run_search(pe)
    assert result.status == cd.Status.OK
    assert result.chosen_candidate is not None
    assert result.chosen_candidate.value == 1200.0
    assert result.chosen_candidate.constant_offset == layout.constant_file_offset
    assert result.signature_ok is True
    assert result.is_already_patched is False


def test_signature_check_passes_on_real_layout():
    data, layout = build_pe()
    assert cd.check_signature(data, layout.constant_file_offset) is True


def test_signature_check_fails_gracefully_when_layout_differs():
    data, layout = build_pe(corrupt_signature=True)
    assert cd.check_signature(data, layout.constant_file_offset) is False


def test_multiple_lea_refs_refuses_auto_patch(tmp_path, monkeypatch):
    data, layout = build_pe(extra_lea_ref=True)
    pe = cd.PEImage.from_bytes(data)
    result = cd.run_search(pe)
    assert result.status == cd.Status.MULTIPLE_LEA_REFS
    assert len(result.lea_refs) == 2

    dll = tmp_path / "client.dll"
    dll.write_bytes(data)
    monkeypatch.setattr(cd, "is_dota_running", lambda: False)
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    rc = cd.main(["--dll", str(dll), "--distance", "1500", "--yes"])
    assert rc == 4


def test_multiple_candidates_refuses_auto_patch(tmp_path, monkeypatch):
    data, layout = build_pe(extra_load_candidate=True)
    pe = cd.PEImage.from_bytes(data)
    result = cd.run_search(pe)
    assert result.status == cd.Status.MULTIPLE_CANDIDATES
    assert len(result.candidates) == 2

    dll = tmp_path / "client.dll"
    dll.write_bytes(data)
    monkeypatch.setattr(cd, "is_dota_running", lambda: False)
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    rc = cd.main(["--dll", str(dll), "--distance", "1500", "--yes"])
    assert rc == 4


def test_alias_count_warns_when_shared():
    data, layout = build_pe(extra_alias_ref=True)
    pe = cd.PEImage.from_bytes(data)
    result = cd.run_search(pe)
    assert result.status == cd.Status.OK
    assert result.alias_count == 2


# ==================== PATCH / BACKUP / RESTORE ====================

def test_patch_writes_correct_bytes_only(tmp_path, monkeypatch):
    data, layout = build_pe()
    dll = tmp_path / "client.dll"
    dll.write_bytes(data)
    monkeypatch.setattr(cd, "is_dota_running", lambda: False)
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    rc = cd.main(["--dll", str(dll), "--distance", "1500", "--yes"])
    assert rc == 0
    patched = dll.read_bytes()
    assert len(patched) == len(data)
    diff_positions = [i for i in range(len(data)) if data[i] != patched[i]]
    allowed = set(range(layout.constant_file_offset, layout.constant_file_offset + 4))
    assert diff_positions, "expected at least one changed byte"
    assert set(diff_positions) <= allowed
    assert struct.unpack_from("<f", patched, layout.constant_file_offset)[0] == 1500.0


def test_backup_created_on_first_patch(tmp_path, monkeypatch):
    data, layout = build_pe()
    dll = tmp_path / "client.dll"
    dll.write_bytes(data)
    monkeypatch.setattr(cd, "is_dota_running", lambda: False)
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    cd.main(["--dll", str(dll), "--distance", "1500", "--yes"])
    backup = tmp_path / "client.dll.bak"
    assert backup.exists()
    assert backup.read_bytes() == data


def test_backup_not_overwritten_on_second_patch(tmp_path, monkeypatch):
    data, layout = build_pe()
    dll = tmp_path / "client.dll"
    dll.write_bytes(data)
    monkeypatch.setattr(cd, "is_dota_running", lambda: False)
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    cd.main(["--dll", str(dll), "--distance", "1500", "--yes"])
    cd.main(["--dll", str(dll), "--distance", "1600", "--yes"])
    backup = tmp_path / "client.dll.bak"
    assert backup.read_bytes() == data


def test_backup_stale_detected_by_size_mismatch(tmp_path):
    dll = tmp_path / "client.dll"
    backup = tmp_path / "client.dll.bak"
    dll.write_bytes(b"\x00" * 100)
    backup.write_bytes(b"\x00" * 50)
    status = cd.ensure_backup(dll)
    assert status.created is False
    assert status.stale is True


def test_restore_reverts_to_backup(tmp_path, monkeypatch):
    data, layout = build_pe()
    dll = tmp_path / "client.dll"
    dll.write_bytes(data)
    monkeypatch.setattr(cd, "is_dota_running", lambda: False)
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    cd.main(["--dll", str(dll), "--distance", "1500", "--yes"])
    rc = cd.main(["--dll", str(dll), "--restore"])
    assert rc == 0
    assert dll.read_bytes() == data


def test_restore_without_backup_errors(tmp_path, monkeypatch):
    data, layout = build_pe()
    dll = tmp_path / "client.dll"
    dll.write_bytes(data)
    monkeypatch.setattr(cd, "is_dota_running", lambda: False)
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    rc = cd.main(["--dll", str(dll), "--restore"])
    assert rc == 6


def test_already_patched_detected_and_offered(tmp_path, monkeypatch):
    data, layout = build_pe()
    dll = tmp_path / "client.dll"
    dll.write_bytes(data)
    monkeypatch.setattr(cd, "is_dota_running", lambda: False)
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    cd.main(["--dll", str(dll), "--distance", "1450", "--yes"])
    pe = cd.PEImage.from_bytes(dll.read_bytes())
    result = cd.run_search(pe)
    assert result.is_already_patched is True
    assert result.current_value == 1450.0


def test_value_out_of_range_requires_confirmation(tmp_path, monkeypatch):
    data, layout = build_pe()
    data = _poke_float(data, layout.constant_file_offset, 2200.0)
    dll = tmp_path / "client.dll"
    dll.write_bytes(data)
    monkeypatch.setattr(cd, "is_dota_running", lambda: False)
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)

    pe = cd.PEImage.from_bytes(data)
    result = cd.run_search(pe)
    assert result.status == cd.Status.VALUE_OUT_OF_RANGE

    rc = cd.main(["--dll", str(dll), "--distance", "1500", "--yes"])
    assert rc == 4


# ==================== SUPPORTING UNITS ====================

def test_vdf_parser_minimal():
    text = (
        '"libraryfolders"\n'
        "{\n"
        '\t"0"\n'
        "\t{\n"
        '\t\t"path"\t\t"C:\\\\Program Files (x86)\\\\Steam"\n'
        "\t}\n"
        '\t"1"\n'
        "\t{\n"
        '\t\t"path"\t\t"E:\\\\SteamLibrary"\n'
        "\t}\n"
        "}\n"
    )
    data = cd.parse_vdf(text)
    libs = [entry["path"] for entry in data["libraryfolders"].values()]
    assert libs == ["C:\\Program Files (x86)\\Steam", "E:\\SteamLibrary"]


def test_find_client_dll_uses_explicit_override(tmp_path):
    dll = tmp_path / "client.dll"
    dll.write_bytes(b"\x00")
    assert cd.find_client_dll(str(dll)) == dll


def test_find_client_dll_uses_explicit_override_missing(tmp_path):
    missing = tmp_path / "nope.dll"
    assert cd.find_client_dll(str(missing)) is None


def test_find_client_dll_searches_libraries(tmp_path, monkeypatch):
    steam_path = tmp_path / "Steam"
    lib_path = tmp_path / "Lib"
    dll_dir = lib_path / cd.DOTA_DLL_RELATIVE.parent
    dll_dir.mkdir(parents=True)
    dll_path = dll_dir / "client.dll"
    dll_path.write_bytes(b"\x00")

    monkeypatch.setattr(cd, "read_steam_install_path", lambda: steam_path)
    monkeypatch.setattr(cd, "enumerate_steam_libraries", lambda p: [lib_path])

    assert cd.find_client_dll(None) == dll_path


def test_get_app_dir_uses_executable_when_frozen(tmp_path, monkeypatch):
    fake_exe = tmp_path / "somewhere" / "camera_distance.exe"
    fake_exe.parent.mkdir(parents=True)
    fake_exe.write_bytes(b"\x00")
    monkeypatch.setattr(cd.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cd.sys, "executable", str(fake_exe))
    assert cd.get_app_dir() == fake_exe.parent


def test_config_load_save_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    cd.save_config({"distance": 1500, "schema_version": 1})
    assert cd.load_config() == {"distance": 1500, "schema_version": 1}


def test_config_load_corrupt_json_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    (tmp_path / cd.CONFIG_FILENAME).write_text("{not valid json", encoding="utf-8")
    assert cd.load_config() == {}


def test_tr_formats_message_and_flags_unknown_id():
    assert cd.tr("err.dota_running") == cd.MESSAGES["err.dota_running"]
    assert cd.tr("nonexistent.id") == "[[nonexistent.id]]"
    assert cd.tr("err.invalid_distance", min=1000, max=2500) == "Distance must be between 1000 and 2500."


@pytest.mark.parametrize("width,height,expected", [
    (1920, 1080, (1400, 1500)),
    (2560, 1600, (1400, 1500)),
    (1280, 1024, (1500, 1600)),
    (3440, 1440, (1300, 1400)),
])
def test_recommend_distance_for_resolution_buckets(width, height, expected):
    assert cd.recommend_distance_for_resolution(width, height) == expected


def test_cli_diagnose_never_writes(tmp_path, monkeypatch):
    data, layout = build_pe()
    dll = tmp_path / "client.dll"
    dll.write_bytes(data)
    monkeypatch.setattr(cd, "is_dota_running", lambda: False)
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    rc = cd.main(["--dll", str(dll), "--diagnose"])
    assert rc == 0
    assert dll.read_bytes() == data
    assert not (tmp_path / "client.dll.bak").exists()
    assert not (tmp_path / cd.CONFIG_FILENAME).exists()


def test_cli_dll_not_found_exit_code(tmp_path, monkeypatch):
    monkeypatch.setattr(cd, "get_app_dir", lambda: tmp_path)
    missing = tmp_path / "nope.dll"
    rc = cd.main(["--dll", str(missing)])
    assert rc == 3
