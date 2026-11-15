import os
import re
import sys
import struct
import subprocess

import pytest

import Evtx.Evtx as evtx
import Evtx.Recovery as recovery

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP = os.path.join(ROOT, "evtx_scripts", "evtx_dump.py")

DIAGNOSTIC_RE = re.compile(
    r"^evtx_dump: chunk=(?P<chunk>-|\d+) record=(?P<record>-|\d+) "
    r"offset=(?P<offset>0x[0-9a-f]+) code=(?P<code>[A-Z0-9_]+) detail=.*$"
)


def run_dump(path):
    """
    run evtx_dump as a subprocess against the given file.

    Returns:
      tuple[int, bytes, bytes]: exit status, stdout and stderr.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, DUMP, path],
        capture_output=True,
        env=env,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def diagnostics(stderr):
    """
    parse and validate every diagnostic line found on stderr.

    Returns:
      list[dict]: one dict per line, with chunk/record/offset/code.
    """
    parsed = []
    for line in stderr.decode("utf-8").splitlines():
        m = DIAGNOSTIC_RE.match(line)
        assert m, "unparseable stderr line: {!r}".format(line)
        parsed.append(
            {
                "chunk": None if m.group("chunk") == "-" else int(m.group("chunk")),
                "record": None if m.group("record") == "-" else int(m.group("record")),
                "offset": int(m.group("offset"), 16),
                "code": m.group("code"),
            }
        )
    return parsed


def assert_complete_xml(stdout):
    text = stdout.decode("utf-8")
    assert text.startswith('<?xml version="1.1" encoding="utf-8" standalone="yes" ?>\n')
    assert "<Events>\n" in text
    assert text.endswith("</Events>\n")


def rewrite(src, dst, mutate):
    with open(src, "rb") as f:
        data = bytearray(f.read())
    mutate(data)
    with open(dst, "wb") as f:
        f.write(bytes(data))
    return dst


def chunk_offset(index):
    return 0x1000 + index * 0x10000


def first_record_offset(chunk_index):
    return chunk_offset(chunk_index) + 0x200


def test_clean_file_is_unchanged_and_silent(data_path):
    """
    a fully valid file must produce the same bytes as before and no stderr.
    """
    status, stdout, stderr = run_dump(os.path.join(data_path, "system.evtx"))
    assert status == 0
    assert stderr == b""
    assert_complete_xml(stdout)

    with evtx.Evtx(os.path.join(data_path, "system.evtx")) as log:
        expected = (
            ('<?xml version="1.1" encoding="utf-8" standalone="yes" ?>\n' "\n<Events>\n")
            + "".join(record.xml() + "\n" for record in log.records())
            + "</Events>\n"
        )
    assert stdout.decode("utf-8") == expected


def test_clean_file_output_is_deterministic(data_path):
    path = os.path.join(data_path, "security.evtx")
    first = run_dump(path)
    second = run_dump(path)
    assert first == second
    assert first[0] == 0
    assert first[2] == b""


def test_malformed_values_are_reported_and_xml_completes(data_path):
    """
    the malformed dns log has one good record and four with undecodable
    values.  all five must be accounted for, and the document must close.
    """
    path = os.path.join(data_path, "dns_log_malformed.evtx")
    status, stdout, stderr = run_dump(path)
    assert status != 0
    assert_complete_xml(stdout)
    assert stdout.decode("utf-8").count("<Event ") == 1

    found = diagnostics(stderr)
    assert [d["code"] for d in found] == [recovery.BINXML_VALUE_DECODE] * 4
    assert [d["record"] for d in found] == [2, 3, 4, 5]
    assert all(d["chunk"] == 0 for d in found)

    # each diagnostic points at the undecodable BinXML value node itself,
    # inside the corresponding record, not at the record header.
    for diagnostic in found:
        assert first_record_offset(0) < diagnostic["offset"] < chunk_offset(1)


def test_binxml_value_offset_points_into_the_named_record(data_path):
    """
    a BinXML value diagnostic must carry the absolute offset of the value
    node that could not be decoded.
    """
    with evtx.Evtx(os.path.join(data_path, "dns_log_malformed.evtx")) as log:
        records = {record.record_num(): (record.offset(), record.offset() + record.size()) for record in log.records()}

    status, _stdout, stderr = run_dump(os.path.join(data_path, "dns_log_malformed.evtx"))
    assert status != 0
    for diagnostic in diagnostics(stderr):
        start, end = records[diagnostic["record"]]
        assert start <= diagnostic["offset"] < end


def test_truncated_file_still_dumps_recovered_records(data_path, tmp_path):
    """
    a file cut in the middle of a chunk must still parse to a complete
    document, recover the earlier chunks, and report what went missing.
    """
    src = os.path.join(data_path, "system.evtx")
    with open(src, "rb") as f:
        raw = f.read()
    truncated = tmp_path / "truncated.evtx"
    # keep the first 8 chunks whole, then half of chunk 8.
    truncated.write_bytes(raw[: chunk_offset(8) + 0x8000])

    status, stdout, stderr = run_dump(str(truncated))
    assert status != 0
    assert_complete_xml(stdout)

    found = diagnostics(stderr)
    codes = [d["code"] for d in found]
    assert recovery.CHUNK_TRUNCATED in codes
    assert any(d["chunk"] == 8 for d in found)

    # every record number declared by every chunk is either recovered,
    # present but undecodable (and reported), or explicitly reported missing;
    # nothing is dropped silently.
    recovered = {int(m) for m in re.findall(rb"<EventRecordID>(\d+)</EventRecordID>", stdout)}
    reported_missing = {d["record"] for d in found if d["code"] == recovery.RECORD_MISSING}
    damaged = {d["record"] for d in found if d["record"] is not None and d["code"] not in (recovery.RECORD_MISSING,)}

    with evtx.Evtx(src) as log:
        declared = set()
        for chunk in log.chunks():
            declared.update(range(chunk.log_first_record_number(), chunk.log_last_record_number() + 1))
    assert recovered.isdisjoint(reported_missing)
    assert recovered | damaged | reported_missing >= declared
    assert recovered | reported_missing | damaged == declared


def test_corrupt_record_length_is_reported_and_scan_continues(data_path, tmp_path):
    """
    a wrecked record length must not hide the records that follow it.
    """
    src = os.path.join(data_path, "system.evtx")
    broken = tmp_path / "bad_length.evtx"

    def mutate(data):
        struct.pack_into("<I", data, first_record_offset(1) + 0x4, 0xFFFFF)

    rewrite(src, str(broken), mutate)

    status, stdout, stderr = run_dump(str(broken))
    assert status != 0
    assert_complete_xml(stdout)

    found = diagnostics(stderr)
    assert any(
        d["code"] == recovery.RECORD_SIZE_INVALID
        and d["chunk"] == 1
        and d["record"] == 12202
        and d["offset"] == first_record_offset(1)
        for d in found
    )
    # the damaged record is named by its own diagnostic, so it is accounted
    # for; it is not additionally reported as merely missing.
    assert not any(d["code"] == recovery.RECORD_MISSING for d in found)
    # records after the damaged one are still found.
    recovered = {int(m) for m in re.findall(rb"<EventRecordID>(\d+)</EventRecordID>", stdout)}
    assert 12203 in recovered


def test_checksum_mismatch_is_reported_without_data_loss(data_path, tmp_path):
    """
    a data checksum mismatch is reported, and the records are still dumped.
    """
    src = os.path.join(data_path, "system.evtx")
    broken = tmp_path / "bad_checksum.evtx"

    def mutate(data):
        data[first_record_offset(0) + 0x100] ^= 0x01

    rewrite(src, str(broken), mutate)

    status, stdout, stderr = run_dump(str(broken))
    assert status != 0
    assert_complete_xml(stdout)

    found = diagnostics(stderr)
    assert [d["code"] for d in found] == [recovery.CHUNK_DATA_CHECKSUM]
    assert found[0]["chunk"] == 0
    assert found[0]["offset"] == chunk_offset(0)

    # the damaged byte lives inside record payload, so it still renders; it
    # ends up in the output as a slightly different value, not as a lost event.
    status, clean_stdout, _ = run_dump(src)
    assert status == 0
    assert stdout.count(b"<Event ") == clean_stdout.count(b"<Event ")


def test_corrupt_chunk_magic_is_reported_and_chunk_records_reconciled(data_path, tmp_path):
    src = os.path.join(data_path, "system.evtx")
    broken = tmp_path / "bad_chunk_magic.evtx"

    def mutate(data):
        data[chunk_offset(3) : chunk_offset(3) + 8] = b"XXXXXXXX"

    rewrite(src, str(broken), mutate)

    status, stdout, stderr = run_dump(str(broken))
    assert status != 0
    assert_complete_xml(stdout)

    found = diagnostics(stderr)
    assert any(
        d["code"] == recovery.CHUNK_MAGIC_INVALID and d["chunk"] == 3 and d["offset"] == chunk_offset(3) for d in found
    )


def test_declared_but_absent_records_are_named(data_path, tmp_path):
    """
    records whose bytes are gone must be named by record number, not silently
    dropped from the output.
    """
    src = os.path.join(data_path, "system.evtx")
    broken = tmp_path / "missing_records.evtx"

    positions = []

    def mutate(data):
        position = first_record_offset(0)
        while True:
            magic, size, _record_num = struct.unpack_from("<IIQ", data, position)
            if magic != 0x2A2A:
                break
            positions.append((position, size))
            position += size
        # erase records 3, 4, 5 and 6 of chunk 0 (record numbers 12051..12054).
        for start, size in positions[2:6]:
            data[start : start + size] = b"\x00" * size

    rewrite(src, str(broken), mutate)

    status, stdout, stderr = run_dump(str(broken))
    assert status != 0
    assert_complete_xml(stdout)

    found = diagnostics(stderr)
    missing = sorted(d["record"] for d in found if d["code"] == recovery.RECORD_MISSING)
    assert missing == [12051, 12052, 12053, 12054]
    assert all(d["chunk"] == 0 for d in found if d["code"] == recovery.RECORD_MISSING)

    recovered = {int(m) for m in re.findall(rb"<EventRecordID>(\d+)</EventRecordID>", stdout)}
    assert recovered.isdisjoint(missing)
    assert 12055 in recovered


def test_damaged_input_is_deterministic(data_path, tmp_path):
    """
    the same damaged bytes must produce the same output on every run.
    """
    src = os.path.join(data_path, "system.evtx")
    broken = tmp_path / "truncated.evtx"
    with open(src, "rb") as f:
        raw = f.read()
    broken.write_bytes(raw[: chunk_offset(8) + 0x4000])

    first = run_dump(str(broken))
    second = run_dump(str(broken))
    assert first == second
    assert first[0] != 0
    assert first[1].endswith(b"</Events>\n")


def test_record_xml_exception_types_are_unchanged(data_path):
    """
    record.xml() keeps raising the original exception types for bad records.
    """
    with evtx.Evtx(os.path.join(data_path, "dns_log_malformed.evtx")) as log:
        bad_records = [record for chunk in log.chunks() for record in chunk.records()][1:]
        assert len(bad_records) == 4
        for record in bad_records:
            with pytest.raises(UnicodeDecodeError):
                record.xml()
