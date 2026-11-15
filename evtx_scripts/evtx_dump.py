#!/usr/bin/env python
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
#   Version v0.1.1
#
#   Exit status:
#     0: every declared record was recovered and every checksum verified.
#     1: the input was truncated or corrupted; the XML written to stdout is
#        complete, and each damaged structure was reported on stderr.
#     2: the input could not be read as an EVTX file at all.
import sys

import Evtx.Views as e_views
import Evtx.Recovery as e_recovery


def dump(stream, label, out, err):
    """
    dump the given EVTX file as a complete XML document.

    Args:
      stream (binary file-like): the EVTX file contents.
      label (str): the name of the input, used in diagnostics.
      out (text stream): receives the XML document.
      err (text stream): receives one line per damaged structure.

    Returns:
      int: the process exit status.
    """
    try:
        buf = stream.read()
    except Exception as exc:
        err.write(
            "evtx_dump: chunk=- record=- offset=0x0 code={} detail={}: {}\n".format(
                e_recovery.FILE_UNREADABLE, label, exc
            )
        )
        return 2

    out.write(e_views.XML_HEADER)
    out.write("\n")
    out.write("<Events>\n")

    diagnostics = 0
    try:
        for event in e_recovery.recover(buf):
            if isinstance(event, e_recovery.RecoveredRecord):
                out.write(event.xml)
                out.write("\n")
            else:
                diagnostics += 1
                err.write(event.format())
                err.write("\n")
    except Exception as exc:
        # recovery itself must not abort the XML document.  report the failure
        # and close the document so the output is still well-formed.
        err.write(
            "evtx_dump: chunk=- record=- offset=0x0 code={} detail={}: {}\n".format(
                e_recovery.FILE_RECOVERY_ABORTED, label, exc
            )
        )
        diagnostics += 1
    out.write("</Events>\n")

    if diagnostics:
        return 1
    return 0


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Dump a binary EVTX file into XML.")
    parser.add_argument("evtx", type=str, help="Path to the Windows EVTX event log file")
    args = parser.parse_args()

    try:
        with open(args.evtx, "rb") as f:
            status = dump(f, args.evtx, sys.stdout, sys.stderr)
    except OSError as exc:
        sys.stderr.write(
            "evtx_dump: chunk=- record=- offset=0x0 code={} detail={}: {}\n".format(
                e_recovery.FILE_UNREADABLE, args.evtx, exc
            )
        )
        return 2

    sys.stdout.flush()
    sys.stderr.flush()
    return status


if __name__ == "__main__":
    sys.exit(main())
