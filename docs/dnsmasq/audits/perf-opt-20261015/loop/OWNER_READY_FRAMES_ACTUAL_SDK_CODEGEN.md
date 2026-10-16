# Actual5c SDK owner frame check

The actual frozen G/5c ELF, own link map and build receipts were rehashed
locally from already-downloaded artifacts. The GNU input ranges and exact
file-backed executable bytes confirm the two outlines reached the SDK build.
No remote access, rebuild or new measurement occurred.

| Emitted function | G bytes/frame | 5c bytes/frame |
| --- | ---: | ---: |
| step | 17608 / 2400 | 4692 / 640 |
| ready DHCP helper | in step | 4408 / 2016 |
| requested dump helper | in step | 8884 / 1072 |
| wait_for_files | 7304 / 352 | 7192 / 352 |

Both complete SDK ELFs remain2,145,051B. This is a relocation of work behind
existing gates, not12KiB removed from the executable. Active calls nest the
helper understep; no maximum-stack reduction follows. The wait change belongs
to inherited6ab work; G/5c does not isolate the two new outlines. Original
owner32 and A53ten decide performance, with all earlier adverse6ab evidence
retained.

[Actualartifact, code-byte hashes and prologues](owner-ready-frames-actual-sdk-codegen.json).
