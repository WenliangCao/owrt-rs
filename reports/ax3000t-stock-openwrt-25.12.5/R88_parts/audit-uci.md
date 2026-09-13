# uci-rs audit (subagent, read-only, HEAD 7eccfb0)

Rust: components/uci/src/; C: private/stage6/src/uci/.

## 1. Findings
| id | class | sev | title | Rust evidence | C reference | verify |
|---|---|---|---|---|---|---|
| U1 | confirmed | P2 (agent) → **P3 (root agent)** | Renaming a section/option to non-UTF-8 bytes lossily converts the in-memory name (Section.name: String); export/show/commit *in the same process* (a `uci batch`) print/persist U+FFFD where C keeps raw bytes. The delta file itself is written raw and byte-correct (test rename_to_non_utf8_is_accepted_like_c); on replay both sides reject the line via validate_name, so separate CLI invocations are unaffected. Reclassified P3: reachable only by one batch that renames to invalid UTF-8 and then shows/exports/commits before exiting | ops.rs:405-438 (419 from_utf8_lossy); model.rs:162; export.rs:41 quoted(w, sec.name.as_bytes()); file::commit via export_package | list.c:486-513 uci_rename raw strdup | batch: rename to $'\xff\xfe' then show/export; diff bytes |

## 2. Overhead
1. ReadCache (read_cache.rs, INPUT_LIMIT 32 KiB / ENTRY_LIMIT 128 KiB) is wired only into rpcd, not the CLI; the once-per-process CLI cannot benefit (OS page cache covers disk I/O).
2. Raw FFI opendir/readdir fast path (file.rs:259-321, Linux aarch64/x86_64) alongside std::fs::read_dir fallback (file.rs:218): complexity for a few dozen files; guarded by dirent_layout_matches_linux_sdk test. Maintainability cost, not a correctness finding.
3. try_literal_line (parse.rs:593, added 911f0b5/424e779 on 2026-09-11 after the last uci audit) has no C equivalent to diff against; correctness rests on unit/fuzz coverage. Highest-value target for the next r24 fuzz pass.

## 3. Checked, equivalent to libuci
FLAG_EXPORT_NAME default off, -n/-N only (context.rs:55 vs libuci.c:59); commit atomicity sequence (lock → save+reimport+reflush → zero-change early return → mkstemp → flock temp (ENOSYS tolerated) → write+fsync → close → realpath+stat+chmod+rename, unlink on failure; file.rs:123-197 vs file.c:755-830); delta command chars (delta.c:153); anonymous names djbhash (ops.rs:331,343); Cmd::Add replay fixup (delta.c:160-259); do_add raw exit code (bin/uci-rs.rs:411-426 vs cli.c:441); show_changes format (cli.c:260-335); rename live-vs-replay validation asymmetry shared with libuci; export escaping and byte-faithful values (export.rs:9-22); error codes/strings 1-7 (error.rs:5-24); args_os raw bytes; strtol whitespace incl. \v (ops.rs:206); parse.c out of scope (schema helper for library consumers); mkstemp/flock wrappers (sys.rs:18-75); CLI option set and getopt string vs cli.c.

## 4. Unverified
- uci_validate_name/str/package C definitions not located (only uci_validate_text util.c:91); Rust character classes not compared char-for-char.
- list.c uci_delete (550), uci_add_list (595), uci_del_list (649), uci_set (681) bodies not read; ops.rs:480/590/649 rest on their C-derived doc comments.
- Carried-forward candidates not re-derived: add_list ""-vs-NULL; uci_import feof() vs Rust EOF flag.
- Whether the mkstemp'd temp file is flock'd before write (file.c ~796) — file.rs:174-197 not read in full.
- r16/r24/r83 tools and tests/config_listing.rs, tests/read_cache_files.rs not read; "193-step" vs R16's "175/175" unreconciled.
- U1 not executed end-to-end.
