//! cli.c: the /sbin/uci command line tool.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(dead_code))]

use crate::context::{Context, FLAG_EXPORT_NAME, FLAG_PERROR, FLAG_STRICT};
use crate::delta;
use crate::error::Error;
use crate::export;
use crate::file;
use crate::model::{Cmd, Package, Ptr};
use crate::ops;
use crate::parse::{self, Pctx};
use crate::show;
use std::io::{self, BufRead, BufReader, Write};

const MAX_ARGS: usize = 4;

const FLAG_MERGE: u32 = 1 << 0;
const FLAG_QUIET: u32 = 1 << 1;
const FLAG_NOCOMMIT: u32 = 1 << 2;
const FLAG_BATCH: u32 = 1 << 3;
const FLAG_SHOW_EXT: u32 = 1 << 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CliCmd {
    Get,
    Set,
    AddList,
    DelList,
    Del,
    Rename,
    Revert,
    Reorder,
    Show,
    Changes,
    Export,
    Commit,
    Add,
    Import,
    Help,
}

/// one command-line argument, byte for byte
type Arg = Vec<u8>;

/// argument as text where libuci uses it as a C string for names, paths and
/// commands (those are validated to ASCII-only sets, so lossy is exact there)
fn s(a: &[u8]) -> String {
    String::from_utf8_lossy(a).into_owned()
}

struct Cli {
    ctx: Context<'static>,
    flags: u32,
    delimiter: String,
    appname: String,
    /// `-f FILE`, or stdin opened on first use (batch / import only)
    input: Option<Box<dyn BufRead>>,
    /// uci_lookup_section_ref state: (type, idx) list and current ref
    /// feof(input) as seen by uci_batch
    batch_eof: bool,
    /// the surviving `ctx->pctx` of uci_batch_cmd (see Pctx::carry)
    batch_carry: Option<parse::Carry>,
}

fn strerror_str(e: &io::Error) -> String {
    owrt_platform::unix::error_text(e.raw_os_error().unwrap_or(0))
}

impl Cli {
    fn usage(&self) {
        let _ = write!(
            io::stderr(),
            "Usage: {} [<options>] <command> [<arguments>]\n\n\
Commands:\n\
\tbatch\n\
\texport     [<config>]\n\
\timport     [<config>]\n\
\tchanges    [<config>]\n\
\tcommit     [<config>]\n\
\tadd        <config> <section-type>\n\
\tadd_list   <config>.<section>.<option>=<string>\n\
\tdel_list   <config>.<section>.<option>=<string>\n\
\tshow       [<config>[.<section>[.<option>]]]\n\
\tget        <config>.<section>[.<option>]\n\
\tset        <config>.<section>[.<option>]=<value>\n\
\tdelete     <config>[.<section>[[.<option>][=<id>]]]\n\
\trename     <config>.<section>[.<option>]=<name>\n\
\trevert     <config>[.<section>[.<option>]]\n\
\treorder    <config>.<section>=<position>\n\
\n\
Options:\n\
\t-c <path>  set the search path for config files (default: /etc/config)\n\
\t-C <path>  set the search path for config override files (default: /var/run/uci)\n\
\t-d <str>   set the delimiter for list values in uci show\n\
\t-f <file>  use <file> as input instead of stdin\n\
\t-m         when importing, merge data into an existing package\n\
\t-n         name unnamed sections on export (default)\n\
\t-N         don't name unnamed sections\n\
\t-p <path>  add a search path for config change files\n\
\t-P <path>  add a search path for config change files and use as default\n\
\t-t <path>  set save path for config change files\n\
\t-q         quiet mode (don't print error messages)\n\
\t-s         force strict mode (stop on parser errors, default)\n\
\t-S         disable strict mode\n\
\t-X         do not use extended syntax on 'show'\n\
\n",
            self.appname
        );
    }

    fn cli_perror(&self) {
        if self.flags & FLAG_QUIET != 0 {
            return;
        }
        parse::perror(&self.ctx, Some(&self.appname));
    }

    fn cli_error(&self, msg: &str) {
        if self.flags & FLAG_QUIET != 0 {
            return;
        }
        let _ = write!(io::stderr(), "{msg}");
    }

    fn show_changes(&self, out: &mut impl Write, p: &Package) {
        for h in &p.saved_delta {
            let (prefix, op) = match h.cmd {
                Cmd::Remove => ("-", "="),
                Cmd::ListAdd => ("", "+="),
                Cmd::ListDel => ("", "-="),
                _ => ("", "="),
            };
            let _ = write!(out, "{}{}.{}", prefix, p.name, h.section);
            if let Some(o) = &h.option {
                let _ = write!(out, ".{o}");
            }
            if h.cmd != Cmd::Remove {
                let _ = out.write_all(op.as_bytes());
                show::print_value(out, h.value.as_deref().unwrap_or(b""));
            }
            let _ = out.write_all(b"\n");
        }
    }

    fn lookup(&mut self, ptr: &mut Ptr, tuple: &[u8]) -> bool {
        match ops::lookup_ptr(&mut self.ctx, ptr, Some(tuple), true) {
            Ok(()) => true,
            Err(e) => {
                self.ctx.err = Some(e);
                false
            }
        }
    }

    /// package_cmd
    fn package_cmd(&mut self, cmd: CliCmd, tuple: &[u8]) -> i32 {
        let mut ptr = Ptr::default();
        if !self.lookup(&mut ptr, tuple) {
            self.cli_perror();
            return 1;
        }
        let mut ret = 1;
        let stdout = io::stdout();
        // export renders into one sized buffer and writes it whole; only the
        // per-line commands need the writer's own 8 KiB buffer
        let mut out = io::BufWriter::with_capacity(
            if cmd == CliCmd::Export { 0 } else { 8192 },
            stdout.lock(),
        );
        'out: {
            match cmd {
                CliCmd::Changes => {
                    if let Some(pidx) = ptr.p {
                        let p = &self.ctx.root[pidx];
                        self.show_changes(&mut out, p);
                    }
                }
                CliCmd::Commit => {
                    if self.flags & FLAG_NOCOMMIT != 0 {
                        ret = 0;
                        break 'out;
                    }
                    if let Some(pidx) = ptr.p {
                        if let Err(e) = file::commit(&mut self.ctx, pidx, false) {
                            self.ctx.err = Some(e);
                            drop(out);
                            self.cli_perror();
                            self.unload_ptr(&ptr);
                            return ret;
                        }
                    }
                }
                CliCmd::Export => {
                    if let Some(pidx) = ptr.p {
                        // one buffer sized for the package, one write(2)
                        let p = &self.ctx.root[pidx];
                        let mut buf = Vec::with_capacity(export::size_hint(p));
                        if export::export_package(&mut buf, self.ctx.flags, p, true).is_err() {
                            break 'out;
                        }
                        // libuci's uci_export ignores fprintf errors on stdout.
                        let _ = out.write_all(&buf);
                    }
                }
                CliCmd::Show => {
                    if !ptr.complete() {
                        self.ctx.err = Some(Error::NotFound);
                        drop(out);
                        self.cli_perror();
                        self.unload_ptr(&ptr);
                        return ret;
                    }
                    let pidx = ptr.p.expect("package");
                    let mut show =
                        show::Show::new(self.flags & FLAG_SHOW_EXT != 0, self.delimiter.as_bytes());
                    let p = &self.ctx.root[pidx];
                    if let (Some(sidx), Some(oidx)) = (ptr.s, ptr.o) {
                        show.option(&mut out, p, &p.sections[sidx], oidx, true);
                    } else if let Some(sidx) = ptr.s {
                        show.section(&mut out, p, &p.sections[sidx]);
                    } else {
                        show.package(&mut out, p);
                    }
                }
                _ => {}
            }
            ret = 0;
        }
        let _ = out.flush();
        drop(out);
        self.unload_ptr(&ptr);
        ret
    }

    /// The batch/import source: `-f FILE`, else stdin, opened lazily so a
    /// plain `get`/`set`/`export` never allocates a reader it will not use.
    fn take_input(&mut self) -> Box<dyn BufRead> {
        self.input
            .take()
            .unwrap_or_else(|| Box::new(BufReader::new(io::stdin())))
    }

    fn unload_ptr(&mut self, ptr: &Ptr) {
        if let Some(pidx) = ptr.p {
            if pidx < self.ctx.root.len() {
                self.ctx.unload(pidx);
            }
        }
    }

    /// uci_do_import
    fn do_import(&mut self, argv: &[Arg]) -> i32 {
        let argc = argv.len();
        if argc > 2 {
            return 255;
        }
        let name = if argc == 2 {
            Some(s(&argv[1]))
        } else if self.flags & FLAG_MERGE != 0 {
            return 255;
        } else {
            None
        };
        let mut merge_idx = None;
        if self.flags & FLAG_MERGE != 0 {
            if let Some(n) = &name {
                if let Ok(i) = file::load(&mut self.ctx, n) {
                    merge_idx = Some(i);
                }
            }
        }
        let mut input = self.take_input();
        let ret = parse::import(
            &mut self.ctx,
            &mut *input,
            name.as_deref(),
            merge_idx,
            name.is_some(),
        );
        self.input = Some(input);
        let ret: Result<(), Error> = match ret {
            Err(e) => Err(e),
            Ok(package) => {
                if merge_idx.is_some() {
                    match package {
                        Some(pidx) => delta::save(&mut self.ctx, pidx),
                        None => Ok(()),
                    }
                } else {
                    // loop through all config sections and overwrite existing data
                    let mut r = Ok(());
                    for i in 0..self.ctx.root.len() {
                        r = file::commit(&mut self.ctx, i, true);
                    }
                    r
                }
            }
        };
        if let Err(e) = ret {
            self.ctx.err = Some(e);
            self.cli_perror();
            return 1;
        }
        0
    }

    /// uci_do_package_cmd
    fn do_package_cmd(&mut self, cmd: CliCmd, argv: &[Arg]) -> i32 {
        let argc = argv.len();
        if argc > 2 {
            return 255;
        }
        if argc == 2 {
            return self.package_cmd(cmd, &argv[1]);
        }
        let configs = match file::list_config_files(&self.ctx) {
            Ok(c) => c,
            Err(e) => {
                self.ctx.err = Some(e);
                self.cli_perror();
                return 1;
            }
        };
        for c in configs {
            self.package_cmd(cmd, c.as_bytes());
        }
        0
    }

    /// uci_do_add
    fn do_add(&mut self, argv: &[Arg]) -> i32 {
        if argv.len() != 3 {
            return 255;
        }
        let result: Result<String, Error> = (|| {
            let pidx = file::load(&mut self.ctx, &s(&argv[1]))?;
            let sidx = ops::add_section(&mut self.ctx, pidx, &s(&argv[2]), false)?;
            let name = self.ctx.root[pidx].sections[sidx].name.clone();
            delta::save(&mut self.ctx, pidx)?;
            Ok(name)
        })();
        match result {
            Err(e) => {
                self.ctx.err = Some(e);
                self.cli_perror();
                e as i32
            }
            Ok(name) => {
                let _ = writeln!(io::stdout(), "{name}");
                0
            }
        }
    }

    /// uci_do_section_cmd
    fn do_section_cmd(&mut self, cmd: CliCmd, argv: &[Arg]) -> i32 {
        if argv.len() != 2 {
            return 255;
        }
        let mut ptr = Ptr::default();
        if !self.lookup(&mut ptr, &argv[1]) {
            self.cli_perror();
            return 1;
        }
        if ptr.value.is_some()
            && !matches!(
                cmd,
                CliCmd::Set
                    | CliCmd::Del
                    | CliCmd::AddList
                    | CliCmd::DelList
                    | CliCmd::Rename
                    | CliCmd::Reorder
            )
        {
            return 1;
        }
        let mut ret: Result<(), Error> = Ok(());
        match cmd {
            CliCmd::Get => {
                if !ptr.complete() {
                    self.ctx.err = Some(Error::NotFound);
                    self.cli_perror();
                    return 1;
                }
                let p = &self.ctx.root[ptr.p.expect("package")];
                let stdout = io::stdout();
                let mut out = stdout.lock();
                if let (Some(sidx), Some(oidx)) = (ptr.s, ptr.o) {
                    let v = p.sections[sidx].options[oidx].value.clone();
                    show::Show::new(self.flags & FLAG_SHOW_EXT != 0, self.delimiter.as_bytes())
                        .value(&mut out, &v, false);
                } else if let Some(sidx) = ptr.s {
                    let _ = writeln!(out, "{}", p.sections[sidx].ty);
                }
                let _ = out.flush();
            }
            CliCmd::Rename => ret = ops::rename(&mut self.ctx, &mut ptr, false),
            CliCmd::Revert => ret = delta::revert(&mut self.ctx, &mut ptr),
            CliCmd::Set => ret = ops::set(&mut self.ctx, &mut ptr, false),
            CliCmd::AddList => ret = ops::add_list(&mut self.ctx, &mut ptr, false),
            CliCmd::DelList => ret = ops::del_list(&mut self.ctx, &mut ptr, false),
            CliCmd::Reorder => {
                let (Some(sidx), Some(value)) = (ptr.s, ptr.value.clone()) else {
                    self.ctx.err = Some(Error::NotFound);
                    self.cli_perror();
                    return 1;
                };
                let pidx = ptr.p.expect("package");
                ret = ops::reorder_section(
                    &mut self.ctx,
                    pidx,
                    sidx,
                    delta::strtoul_int(&String::from_utf8_lossy(&value)),
                    false,
                );
            }
            CliCmd::Del => {
                // `if (ptr.value && !sscanf(ptr.value, "%d", &dummy)) return 1;`
                // sscanf returns EOF for an empty or all-whitespace value, and
                // EOF is truthy, so only a value that starts a non-number is
                // rejected. `uci delete p.s.o=` deletes the whole option.
                if let Some(v) = &ptr.value {
                    if ops::sscanf_int_no_match(v) {
                        return 1;
                    }
                }
                ret = ops::delete(&mut self.ctx, &mut ptr, false);
            }
            _ => {}
        }

        // no save necessary for get / revert
        if matches!(cmd, CliCmd::Get | CliCmd::Revert) {
            return 0;
        }
        if ret.is_ok() {
            if let Some(pidx) = ptr.p {
                ret = delta::save(&mut self.ctx, pidx);
            }
        }
        if let Err(e) = ret {
            self.ctx.err = Some(e);
            self.cli_perror();
            return 1;
        }
        0
    }

    /// uci_batch_cmd
    fn batch_cmd(&mut self) -> i32 {
        let mut argv: Vec<Arg> = Vec::new();
        let mut input = self.take_input();
        let mut pctx = Pctx::new(&mut *input);
        // uci_parse_argument reuses ctx->pctx across batch commands, so the
        // line counter (and the grown line buffer) continue where the previous
        // command left them.
        if let Some(c) = self.batch_carry {
            pctx.restore(c);
        }
        parse::parse_argument_line(&mut pctx);
        let mut error = false;
        let mut i = 0;
        let mut too_many = false;
        loop {
            if i == MAX_ARGS {
                too_many = true;
                break;
            }
            match parse::parse_argument_bytes(&mut pctx) {
                Ok(arg) => {
                    if arg.is_empty() {
                        break;
                    }
                    argv.push(arg);
                    i += 1;
                }
                Err(e) => {
                    self.ctx.err = Some(e);
                    error = true;
                    break;
                }
            }
        }
        let eof = pctx.eof;
        let carry = pctx.carry();
        // That same context stays allocated for the whole command, so
        // uci_get_errorstr appends ` (<reason>) at line N, byte B` to every
        // parse error the command itself raises.
        self.ctx.pctx = Some(carry.info);
        self.batch_carry = Some(carry);
        drop(pctx);
        self.input = Some(input);
        if too_many {
            self.cli_error("Too many arguments\n");
            return 1;
        }
        if error {
            self.cli_perror();
            argv.clear();
        }
        if eof {
            self.batch_eof = true;
        }
        if argv.is_empty() {
            return 0;
        }
        if argv[0].eq_ignore_ascii_case(b"exit") {
            return 254;
        }
        let ret = self.uci_cmd(&argv);
        // The batch context survives only while it is still the one
        // uci_parse_argument allocated: a command that parsed a file either
        // freed it (uci_cleanup) or left it pointing at another stream, which
        // the next uci_parse_argument cleans up. Either way the next command
        // starts a fresh context, and the line counter restarts at 1.
        if self.ctx.pctx != Some(carry.info) {
            self.batch_carry = None;
        }
        ret
    }

    /// uci_batch
    fn batch(&mut self) -> i32 {
        self.flags |= FLAG_BATCH;
        while !self.batch_eof {
            let ret = self.batch_cmd();
            if ret == 254 {
                return 0;
            } else if ret == 255 {
                self.cli_error("Unknown command\n");
            }
            // clean up
            self.ctx.root.clear();
        }
        self.flags &= !FLAG_BATCH;
        0
    }

    /// uci_cmd
    fn uci_cmd(&mut self, argv: &[Arg]) -> i32 {
        let command = &argv[0];
        let cmd = match command.as_slice() {
            c if c.eq_ignore_ascii_case(b"batch") && self.flags & FLAG_BATCH == 0 => {
                return self.batch()
            }
            c if c.eq_ignore_ascii_case(b"show") => CliCmd::Show,
            c if c.eq_ignore_ascii_case(b"changes") => CliCmd::Changes,
            c if c.eq_ignore_ascii_case(b"export") => CliCmd::Export,
            c if c.eq_ignore_ascii_case(b"commit") => CliCmd::Commit,
            c if c.eq_ignore_ascii_case(b"get") => CliCmd::Get,
            c if c.eq_ignore_ascii_case(b"set") => CliCmd::Set,
            c if c.eq_ignore_ascii_case(b"ren") || c.eq_ignore_ascii_case(b"rename") => {
                CliCmd::Rename
            }
            c if c.eq_ignore_ascii_case(b"revert") => CliCmd::Revert,
            c if c.eq_ignore_ascii_case(b"reorder") => CliCmd::Reorder,
            c if c.eq_ignore_ascii_case(b"del") || c.eq_ignore_ascii_case(b"delete") => CliCmd::Del,
            c if c.eq_ignore_ascii_case(b"import") => CliCmd::Import,
            c if c.eq_ignore_ascii_case(b"help") => CliCmd::Help,
            c if c.eq_ignore_ascii_case(b"add") => CliCmd::Add,
            c if c.eq_ignore_ascii_case(b"add_list") => CliCmd::AddList,
            c if c.eq_ignore_ascii_case(b"del_list") => CliCmd::DelList,
            _ => return 255,
        };
        match cmd {
            CliCmd::AddList
            | CliCmd::DelList
            | CliCmd::Get
            | CliCmd::Set
            | CliCmd::Del
            | CliCmd::Rename
            | CliCmd::Revert
            | CliCmd::Reorder => self.do_section_cmd(cmd, argv),
            CliCmd::Show | CliCmd::Export | CliCmd::Commit | CliCmd::Changes => {
                self.do_package_cmd(cmd, argv)
            }
            CliCmd::Import => self.do_import(argv),
            CliCmd::Add => self.do_add(argv),
            CliCmd::Help => {
                self.usage();
                0
            }
        }
    }
}

pub fn run(raw: Vec<Arg>) -> ! {
    let appname = raw.first().map(|a| s(a)).unwrap_or_else(|| "uci".into());
    let mut cli = Cli {
        ctx: Context::new(),
        flags: FLAG_SHOW_EXT,
        delimiter: " ".into(),
        appname: appname.clone(),
        input: None,
        batch_eof: false,
        batch_carry: None,
    };
    let mut input_is_file = false;

    // getopt(argc, argv, "c:C:d:f:LmnNp:P:qsSt:X") with musl semantics:
    // no permutation, stop at the first non-option.
    const OPTSTRING: &str = "c:C:d:f:LmnNp:P:qsSt:X";
    let mut optind = 1usize;
    'opts: while optind < raw.len() {
        // only the option words are converted; the command tuple stays bytes
        let arg = s(&raw[optind]);
        if arg == "--" {
            optind += 1;
            break;
        }
        if !arg.starts_with('-') || arg.len() == 1 {
            break;
        }
        let cluster: Vec<char> = arg[1..].chars().collect();
        optind += 1;
        let mut k = 0;
        while k < cluster.len() {
            let c = cluster[k];
            k += 1;
            let pos = OPTSTRING.find(c).filter(|_| c != ':');
            let Some(pos) = pos else {
                let _ = writeln!(io::stderr(), "{appname}: unrecognized option: {c}");
                cli.usage();
                std::process::exit(0);
            };
            let takes_arg = OPTSTRING.as_bytes().get(pos + 1) == Some(&b':');
            let optarg: Option<String> = if takes_arg {
                if k < cluster.len() {
                    let rest: String = cluster[k..].iter().collect();
                    k = cluster.len();
                    Some(rest)
                } else if optind < raw.len() {
                    optind += 1;
                    Some(s(&raw[optind - 1]))
                } else {
                    let _ = writeln!(io::stderr(), "{appname}: option requires an argument: {c}");
                    cli.usage();
                    std::process::exit(0);
                }
            } else {
                None
            };
            match c {
                'c' => cli.ctx.set_confdir(&optarg.unwrap_or_default()),
                'C' => cli.ctx.set_conf2dir(&optarg.unwrap_or_default()),
                'd' => cli.delimiter = optarg.unwrap_or_default(),
                'f' => {
                    if input_is_file {
                        cli.cli_error("Too many input files.\n");
                        std::process::exit(1);
                    }
                    match std::fs::File::open(optarg.unwrap_or_default()) {
                        Ok(f) => {
                            cli.input = Some(Box::new(BufReader::new(f)));
                            input_is_file = true;
                        }
                        Err(e) => {
                            cli.cli_error(&format!("uci: {}", strerror_str(&e)));
                            std::process::exit(1);
                        }
                    }
                }
                'm' => cli.flags |= FLAG_MERGE,
                's' => cli.ctx.flags |= FLAG_STRICT,
                'S' => {
                    cli.ctx.flags &= !FLAG_STRICT;
                    cli.ctx.flags |= FLAG_PERROR;
                }
                'n' => cli.ctx.flags |= FLAG_EXPORT_NAME,
                'N' => cli.ctx.flags &= !FLAG_EXPORT_NAME,
                'p' => {
                    let _ = delta::add_delta_path(&mut cli.ctx, &optarg.unwrap_or_default());
                }
                'P' => {
                    delta::set_savedir(&mut cli.ctx, &optarg.unwrap_or_default());
                    cli.flags |= FLAG_NOCOMMIT;
                }
                'q' => cli.flags |= FLAG_QUIET,
                't' => delta::set_savedir(&mut cli.ctx, &optarg.unwrap_or_default()),
                'X' => cli.flags &= !FLAG_SHOW_EXT,
                _ => {
                    // 'L' and anything else without a case: usage, exit 0
                    cli.usage();
                    std::process::exit(0);
                }
            }
            if takes_arg {
                continue 'opts;
            }
        }
    }

    let rest = &raw[optind..];
    if rest.is_empty() {
        cli.usage();
        std::process::exit(0);
    }
    let ret = cli.uci_cmd(rest);
    if ret == 255 {
        cli.usage();
    }
    let _ = io::stdout().flush();
    std::process::exit(ret & 0xff);
}
