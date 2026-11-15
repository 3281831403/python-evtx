#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Best-effort recovery of records from truncated or corrupted EVTX files.
"""
Scan an EVTX file without trusting it.

The regular parser stops at the first structure it cannot read.  This module
walks the file chunk by chunk and record by record, recovers every structure
that can still be decoded, and describes every structure it had to skip with
one `Diagnostic` per damaged structure.  It never silently drops records:

  - each chunk is reconciled against the record number range declared in its
    chunk header.  Declared record numbers for which no record was recovered
    are reported with `RECORD_MISSING`.
  - file and chunk checksums are verified and mismatches are reported.
  - truncated records, chunks and files are reported at the offset at which
    the damage was found.

Every diagnostic carries the chunk index, the record number (or `-` when the
record number itself could not be read), an absolute file offset and a stable
error code that identifies the reason.
"""

from __future__ import absolute_import

import struct
import binascii

from .Evtx import Record, ChunkHeader

FILE_HEADER_SIZE = 0x1000
FILE_HEADER_CHECKSUM_END = 0x78
FILE_HEADER_CHECKSUM_OFFSET = 0x7C

CHUNK_SIZE = 0x10000
CHUNK_HEADER_SIZE = 0x200
CHUNK_HEADER_CHECKSUM_OFFSET = 0x7C
CHUNK_DATA_CHECKSUM_OFFSET = 0x34
CHUNK_NEXT_RECORD_OFFSET = 0x30
CHUNK_LOG_FIRST_RECORD_NUMBER = 0x18
CHUNK_LOG_LAST_RECORD_NUMBER = 0x20

RECORD_MAGIC = 0x2A2A
RECORD_MAGIC_BYTES = b"\x2a\x2a\x00\x00"
MIN_RECORD_SIZE = 0x1C
MAX_RECORD_SIZE = 0x10000

# a chunk can hold at most a few thousand records; a wider declared range
# means the chunk header is corrupt and must not drive reconciliation.
MAX_DECLARED_RECORD_RANGE = 0x10000


# error codes. these are stable identifiers that appear on stderr.
FILE_TRUNCATED = "FILE_TRUNCATED"
FILE_MAGIC_INVALID = "FILE_MAGIC_INVALID"
FILE_HEADER_CHECKSUM = "FILE_HEADER_CHECKSUM"
FILE_HEADER_SIZE_INVALID = "FILE_HEADER_SIZE_INVALID"
FILE_UNREADABLE = "FILE_UNREADABLE"
FILE_RECOVERY_ABORTED = "FILE_RECOVERY_ABORTED"
CHUNK_TRUNCATED = "CHUNK_TRUNCATED"
CHUNK_MAGIC_INVALID = "CHUNK_MAGIC_INVALID"
CHUNK_HEADER_CHECKSUM = "CHUNK_HEADER_CHECKSUM"
CHUNK_DATA_CHECKSUM = "CHUNK_DATA_CHECKSUM"
CHUNK_OFFSETS_INVALID = "CHUNK_OFFSETS_INVALID"
CHUNK_RECORD_RANGE_INVALID = "CHUNK_RECORD_RANGE_INVALID"
CHUNK_SCAN_FAILED = "CHUNK_SCAN_FAILED"
RECORD_MAGIC_INVALID = "RECORD_MAGIC_INVALID"
RECORD_TRUNCATED = "RECORD_TRUNCATED"
RECORD_SIZE_INVALID = "RECORD_SIZE_INVALID"
RECORD_LENGTH_MISMATCH = "RECORD_LENGTH_MISMATCH"
RECORD_HEADER_INVALID = "RECORD_HEADER_INVALID"
RECORD_MISSING = "RECORD_MISSING"
RECORD_RENDER_FAILED = "RECORD_RENDER_FAILED"
BINXML_VALUE_DECODE = "BINXML_VALUE_DECODE"
BINXML_NODE_DECODE = "BINXML_NODE_DECODE"
BINXML_TEMPLATE_MISSING = "BINXML_TEMPLATE_MISSING"


def _one_line(value):
    return " ".join(str(value).split())


class Diagnostic(object):
    """
    One damaged structure discovered while recovering a file.
    """

    def __init__(self, code, chunk_index, record_num, absolute_offset, detail=""):
        self.code = code
        self.chunk_index = chunk_index
        self.record_num = record_num
        self.absolute_offset = absolute_offset
        self.detail = _one_line(detail)

    def format(self):
        """
        render the diagnostic as a single deterministic stderr line.
        """
        chunk = "-" if self.chunk_index is None else str(self.chunk_index)
        record = "-" if self.record_num is None else str(self.record_num)
        return "evtx_dump: chunk={} record={} offset=0x{:x} code={} detail={}".format(
            chunk, record, self.absolute_offset, self.code, self.detail
        )

    def __repr__(self):
        return "Diagnostic({!r}, chunk_index={!r}, record_num={!r}, absolute_offset={!r})".format(
            self.code, self.chunk_index, self.record_num, self.absolute_offset
        )


class RecoveredRecord(object):
    """
    A record that was successfully decoded and rendered to XML.
    """

    def __init__(self, chunk_index, record_num, absolute_offset, xml):
        self.chunk_index = chunk_index
        self.record_num = record_num
        self.absolute_offset = absolute_offset
        self.xml = xml

    def __repr__(self):
        return "RecoveredRecord(chunk_index={!r}, record_num={!r}, absolute_offset={!r})".format(
            self.chunk_index, self.record_num, self.absolute_offset
        )


def _u16(buf, offset):
    return struct.unpack_from("<H", buf, offset)[0]


def _u32(buf, offset):
    return struct.unpack_from("<I", buf, offset)[0]


def _u64(buf, offset):
    return struct.unpack_from("<Q", buf, offset)[0]


def _crc32(data):
    return binascii.crc32(data) & 0xFFFFFFFF


def _all_zero(buf, start, end):
    """
    @return True if buf[start:end] contains only NUL bytes.
    """
    return not any(buf[start:end])


def _record_number_if_available(buf, offset, end):
    """
    read a record number from a possibly damaged record header.

    @return The record number, or None when it cannot be read or is clearly
      not a real record number (record numbers start at 1).
    """
    if offset + 0x10 <= end:
        try:
            record_num = _u64(buf, offset + 0x8)
        except struct.error:
            return None
        return record_num or None
    return None


def _record_header_plausible(buf, offset, end, in_range=None):
    """
    decide whether `offset` looks like the start of a complete record.

    this is used to resynchronize after a damaged record.  requiring a
    plausible size, a plausible following boundary and, when the chunk
    declares one, a plausible record number keeps us from treating a stray
    0x00002a2a in record data or unused chunk slack as a record.
    """
    if offset + MIN_RECORD_SIZE > end:
        return False
    try:
        size = _u32(buf, offset + 0x4)
    except struct.error:
        return False
    if size < MIN_RECORD_SIZE or size > MAX_RECORD_SIZE:
        return False
    if offset + size > end:
        return False
    if in_range is not None:
        try:
            if not in_range(_u64(buf, offset + 0x8)):
                return False
        except struct.error:
            return False
    following = offset + size
    if following + 4 <= end:
        try:
            if _u32(buf, following) != RECORD_MAGIC:
                return False
        except struct.error:
            return False
    return True


def _record_body_plausible(buf, offset, end):
    """
    decide whether the record body at `offset` is intact even if the magic is not.

    used to recover a record whose magic alone was damaged.  the length must be
    sane, fit in the record area, and agree with the trailing length copy.
    """
    if offset + MIN_RECORD_SIZE > end:
        return False
    try:
        size = _u32(buf, offset + 0x4)
    except struct.error:
        return False
    if size < MIN_RECORD_SIZE or size > MAX_RECORD_SIZE:
        return False
    if offset + size > end:
        return False
    try:
        return _u32(buf, offset + size - 0x4) == size
    except struct.error:
        return False


def _find_next_record(buf, start, end, in_range=None):
    """
    find the next plausible record header in [start, end).

    @return The absolute offset, or None.
    """
    position = start
    while position + MIN_RECORD_SIZE <= end:
        found = buf.find(RECORD_MAGIC_BYTES, position, end)
        if found < 0:
            return None
        if _record_header_plausible(buf, found, end, in_range=in_range):
            return found
        position = found + 1
    return None


def _classify_render_error(exc, record_offset):
    """
    map an exception raised while rendering a record to a stable error code
    and the best available absolute offset.

    Views annotates decoding failures with the failing node's offset and type,
    so a bad BinXML value is reported at the value node, not at the record.
    """
    node_offset = getattr(exc, "evtx_absolute_offset", None)
    node_type = getattr(exc, "evtx_node_type", None)
    if node_offset is None:
        # an overrun knows exactly where the read was attempted.
        node_offset = getattr(exc, "absolute_offset", None)

    if isinstance(exc, KeyError):
        # a resident template or name string referenced by an offset in the
        # chunk's global tables could not be loaded.
        return BINXML_TEMPLATE_MISSING, node_offset if node_offset is not None else record_offset
    if node_offset is None:
        return RECORD_RENDER_FAILED, record_offset
    if node_type is None:
        # not a failure while decoding a BinXML structure, e.g. malformed
        # XML names or a substitution index that does not exist.
        return RECORD_RENDER_FAILED, node_offset
    if getattr(exc, "evtx_value_node", False):
        return BINXML_VALUE_DECODE, node_offset
    return BINXML_NODE_DECODE, node_offset


def _error_detail(exc):
    try:
        message = "{}: {}".format(type(exc).__name__, exc)
    except Exception:
        message = type(exc).__name__
    return _one_line(message)


def _scan_records(buf, chunk, chunk_index, scan_start, scan_end, in_range=None):
    """
    walk the record area of one chunk.

    @param in_range (Optional) A predicate that decides whether a record
       number is plausible for this chunk.  Used when resynchronizing after
       damage, to avoid mistaking stale bytes in chunk slack for records.

    @return tuple(list of RecoveredRecord events, list of Diagnostics,
                  set of record numbers present in the chunk).
    """
    records = []
    diagnostics = []
    present = set()

    position = scan_start
    while position < scan_end:
        remaining = scan_end - position

        if remaining < 4:
            if not _all_zero(buf, position, scan_end):
                diagnostics.append(
                    Diagnostic(
                        RECORD_TRUNCATED,
                        chunk_index,
                        _record_number_if_available(buf, position, scan_end),
                        position,
                        "record header is truncated ({} bytes remain)".format(remaining),
                    )
                )
            break

        magic = _u32(buf, position)
        if magic != RECORD_MAGIC:
            if _all_zero(buf, position, scan_end):
                # unused slack at the end of the record area.
                break
            body_plausible = remaining >= MIN_RECORD_SIZE and _record_body_plausible(buf, position, scan_end)
            diagnostics.append(
                Diagnostic(
                    RECORD_MAGIC_INVALID,
                    chunk_index,
                    _record_number_if_available(buf, position, scan_end),
                    position,
                    "expected record magic 0x00002a2a, found 0x{:08x}".format(magic),
                )
            )
            if not body_plausible:
                following = _find_next_record(buf, position + 1, scan_end, in_range=in_range)
                if following is None:
                    break
                position = following
                continue
            # the magic is damaged, but the rest of the record structure is
            # intact.  recover the record rather than discarding an otherwise
            # readable event; the diagnostic above already reports the damage.

        if remaining < MIN_RECORD_SIZE:
            diagnostics.append(
                Diagnostic(
                    RECORD_TRUNCATED,
                    chunk_index,
                    _record_number_if_available(buf, position, scan_end),
                    position,
                    "record header is truncated ({} bytes remain)".format(remaining),
                )
            )
            break

        size = _u32(buf, position + 0x4)
        record_num = _u64(buf, position + 0x8)

        # a record header was found here, so this record number is accounted
        # for.  if the record is damaged, the diagnostic below names it.
        if record_num:
            present.add(record_num)

        if size < MIN_RECORD_SIZE or size > MAX_RECORD_SIZE:
            diagnostics.append(
                Diagnostic(
                    RECORD_SIZE_INVALID,
                    chunk_index,
                    record_num,
                    position,
                    "record length {} is outside the valid range {}..{}".format(size, MIN_RECORD_SIZE, MAX_RECORD_SIZE),
                )
            )
            following = _find_next_record(buf, position + 4, scan_end, in_range=in_range)
            if following is None:
                break
            position = following
            continue

        if position + size > scan_end:
            diagnostics.append(
                Diagnostic(
                    RECORD_TRUNCATED,
                    chunk_index,
                    record_num,
                    position,
                    "record length {} extends past the end of the record area at 0x{:x}".format(size, scan_end),
                )
            )
            following = _find_next_record(buf, position + 4, scan_end, in_range=in_range)
            if following is None:
                break
            position = following
            continue

        size2 = _u32(buf, position + size - 0x4)
        if size2 != size:
            diagnostics.append(
                Diagnostic(
                    RECORD_LENGTH_MISMATCH,
                    chunk_index,
                    record_num,
                    position,
                    "record length fields disagree: size={} size2={}".format(size, size2),
                )
            )

        try:
            record = Record(buf, position, chunk)
        except Exception as exc:
            diagnostics.append(
                Diagnostic(
                    RECORD_HEADER_INVALID,
                    chunk_index,
                    record_num,
                    position,
                    _error_detail(exc),
                )
            )
            following = _find_next_record(buf, position + 4, scan_end, in_range=in_range)
            if following is None:
                break
            position = following
            continue

        try:
            xml = record.xml()
        except Exception as exc:
            code, offset = _classify_render_error(exc, position)
            diagnostics.append(Diagnostic(code, chunk_index, record_num, offset, _error_detail(exc)))
        else:
            records.append(RecoveredRecord(chunk_index, record_num, position, xml))

        position += size

    return records, diagnostics, present


def _scan_chunk(buf, chunk_index, chunk_start, chunk_end, file_length):
    """
    scan one chunk, including its header checksums and record reconciliation.
    """
    available_end = min(chunk_end, file_length)
    truncated = chunk_end > file_length

    if truncated:
        yield Diagnostic(
            CHUNK_TRUNCATED,
            chunk_index,
            None,
            chunk_start,
            "chunk extends to 0x{:x} but the file ends at 0x{:x}".format(chunk_end, file_length),
        )

    if available_end - chunk_start < CHUNK_HEADER_SIZE:
        return

    magic = bytes(buf[chunk_start : chunk_start + 0x8])
    header_valid = magic == b"ElfChnk\x00"
    declared_first = None
    declared_last = None

    chunk = ChunkHeader(buf, chunk_start)

    try:
        declared_first = _u64(buf, chunk_start + CHUNK_LOG_FIRST_RECORD_NUMBER)
        declared_last = _u64(buf, chunk_start + CHUNK_LOG_LAST_RECORD_NUMBER)
        next_record_offset = _u32(buf, chunk_start + CHUNK_NEXT_RECORD_OFFSET)
    except struct.error:
        declared_first = None
        declared_last = None
        next_record_offset = None

    if not header_valid:
        yield Diagnostic(
            CHUNK_MAGIC_INVALID,
            chunk_index,
            None,
            chunk_start,
            "expected chunk magic b'ElfChnk\\x00', found {!r}".format(magic),
        )
    else:
        header_data = bytes(buf[chunk_start : chunk_start + FILE_HEADER_CHECKSUM_END])
        header_data += bytes(buf[chunk_start + 0x80 : chunk_start + CHUNK_HEADER_SIZE])
        stored_header_checksum = _u32(buf, chunk_start + CHUNK_HEADER_CHECKSUM_OFFSET)
        if _crc32(header_data) != stored_header_checksum:
            yield Diagnostic(
                CHUNK_HEADER_CHECKSUM,
                chunk_index,
                None,
                chunk_start,
                "stored 0x{:08x}, calculated 0x{:08x}".format(stored_header_checksum, _crc32(header_data)),
            )

        if not truncated:
            if next_record_offset is not None and CHUNK_HEADER_SIZE <= next_record_offset <= CHUNK_SIZE:
                stored_data_checksum = _u32(buf, chunk_start + CHUNK_DATA_CHECKSUM_OFFSET)
                data = bytes(buf[chunk_start + CHUNK_HEADER_SIZE : chunk_start + next_record_offset])
                if _crc32(data) != stored_data_checksum:
                    yield Diagnostic(
                        CHUNK_DATA_CHECKSUM,
                        chunk_index,
                        None,
                        chunk_start,
                        "stored 0x{:08x}, calculated 0x{:08x} over 0x200..0x{:x}".format(
                            stored_data_checksum, _crc32(data), next_record_offset
                        ),
                    )
            else:
                yield Diagnostic(
                    CHUNK_OFFSETS_INVALID,
                    chunk_index,
                    None,
                    chunk_start,
                    "next record offset {!r} is outside 0x200..0x10000".format(next_record_offset),
                )

    # when a record has to be located again after damage, only accept a
    # candidate whose record number falls in the range this chunk declares.
    in_range = None
    if (
        header_valid
        and declared_first is not None
        and declared_last is not None
        and 0 < declared_first <= declared_last
        and declared_last - declared_first <= MAX_DECLARED_RECORD_RANGE
    ):
        in_range = lambda record_num: declared_first <= record_num <= declared_last

    # the record area is bounded by the next-record offset when that value is
    # usable.  when the chunk is truncated or the header is unreadable, fall
    # back to what is actually present in the file.
    if next_record_offset is not None and CHUNK_HEADER_SIZE <= next_record_offset <= CHUNK_SIZE:
        scan_end = min(chunk_start + next_record_offset, available_end)
    else:
        scan_end = available_end

    records, diagnostics, present = _scan_records(
        buf, chunk, chunk_index, chunk_start + CHUNK_HEADER_SIZE, scan_end, in_range=in_range
    )

    for record in records:
        yield record
    for diagnostic in diagnostics:
        yield diagnostic

    # reconcile the records we recovered against the range declared by the
    # chunk header.  a number is accounted for if a record structure was
    # present, even if that record failed to render (it has its own
    # diagnostic, which names the record number).  this runs even when the
    # chunk magic is damaged, as long as the declared range itself is usable.
    if declared_first is not None and declared_last is not None:
        if declared_first == 0 and declared_last == 0:
            pass  # an empty chunk declares no records.
        elif not (0 < declared_first <= declared_last) or (declared_last - declared_first > MAX_DECLARED_RECORD_RANGE):
            yield Diagnostic(
                CHUNK_RECORD_RANGE_INVALID,
                chunk_index,
                None,
                chunk_start,
                "declared record range {}..{} is not usable".format(declared_first, declared_last),
            )
        else:
            for record_num in range(declared_first, declared_last + 1):
                if record_num in present:
                    continue
                yield Diagnostic(
                    RECORD_MISSING,
                    chunk_index,
                    record_num,
                    chunk_start,
                    "declared in chunk record range {}..{} but no record was recovered".format(
                        declared_first, declared_last
                    ),
                )
    elif declared_first is None and declared_last is None:
        # no record number range could be read, so the chunk cannot be
        # reconciled; report the count that actually went missing as unknown
        # rather than implying the chunk was complete.
        recovered_count = sum(1 for record in records if record.record_num is not None)
        yield Diagnostic(
            CHUNK_RECORD_RANGE_INVALID,
            chunk_index,
            None,
            chunk_start,
            "chunk header record range could not be read; recovered {} record(s)".format(recovered_count),
        )


def _recover(buf):
    """
    yield RecoveredRecord and Diagnostic instances for the given file buffer.
    """
    file_length = len(buf)

    if file_length < 0x8:
        yield Diagnostic(
            FILE_TRUNCATED,
            None,
            None,
            0,
            "file is {} bytes, too short for an EVTX file header".format(file_length),
        )
        return

    magic = bytes(buf[0:0x8])
    if magic != b"ElfFile\x00":
        yield Diagnostic(
            FILE_MAGIC_INVALID,
            None,
            None,
            0,
            "expected file magic b'ElfFile\\x00', found {!r}".format(magic),
        )

    if file_length < FILE_HEADER_SIZE:
        yield Diagnostic(
            FILE_TRUNCATED,
            None,
            None,
            0,
            "file is {} bytes, too short for the {} byte file header".format(file_length, FILE_HEADER_SIZE),
        )
        return

    stored_checksum = _u32(buf, FILE_HEADER_CHECKSUM_OFFSET)
    calculated_checksum = _crc32(bytes(buf[0:FILE_HEADER_CHECKSUM_END]))
    if stored_checksum != calculated_checksum:
        yield Diagnostic(
            FILE_HEADER_CHECKSUM,
            None,
            None,
            0,
            "stored 0x{:08x}, calculated 0x{:08x}".format(stored_checksum, calculated_checksum),
        )

    try:
        header_chunk_size = _u16(buf, 0x28)
        chunk_count = _u16(buf, 0x2A)
    except struct.error:
        yield Diagnostic(FILE_TRUNCATED, None, None, 0, "file header could not be read")
        return

    if header_chunk_size != FILE_HEADER_SIZE:
        yield Diagnostic(
            FILE_HEADER_SIZE_INVALID,
            None,
            None,
            0,
            "header chunk size {} is not {}".format(header_chunk_size, FILE_HEADER_SIZE),
        )
        header_chunk_size = FILE_HEADER_SIZE

    for chunk_index in range(chunk_count):
        chunk_start = header_chunk_size + chunk_index * CHUNK_SIZE
        chunk_end = chunk_start + CHUNK_SIZE
        if chunk_start >= file_length:
            yield Diagnostic(
                CHUNK_TRUNCATED,
                chunk_index,
                None,
                chunk_start,
                "chunk is declared by the file header but the file ends at 0x{:x}".format(file_length),
            )
            continue
        try:
            for item in _scan_chunk(buf, chunk_index, chunk_start, chunk_end, file_length):
                yield item
        except Exception as exc:
            # a scan failure in one chunk must not abandon the rest of the
            # file.  report it against the chunk and continue with the next.
            yield Diagnostic(
                CHUNK_SCAN_FAILED,
                chunk_index,
                None,
                chunk_start,
                _error_detail(exc),
            )


def recover(buf):
    """
    recover records and diagnostics from an EVTX file buffer.

    Args:
      buf (bytes-like): the complete contents of the EVTX file.

    Yields:
      RecoveredRecord for every record that could be decoded, and Diagnostic
      for every damaged structure, in file order.
    """
    return _recover(buf)
