//! libubox's `json_script`: the rule language behind both procd triggers and
//! `/etc/hotplug.json`. One engine, two callers.
//!
//! Source of truth is libubox's `json_script.c` at the revision this image
//! ships. It walks blobmsg directly rather than building a parallel tree,
//! which is also what the C does.
//!
//! Grammar, informally:
//!
//! ```text
//! block   := [ cmd, cmd, ... ] | cmd
//! cmd     := [ "if", expr, block, block? ]
//!          | [ "case", "VAR", { "value": block, ... } ]
//!          | [ "return" ]
//!          | [ "include", "name" ]
//!          | [ name, arg, ... ]            -- anything else is a command
//! expr    := [ "eq"|"regex", "VAR", str|[str,...] ]
//!          | [ "has", str|[str,...] ]
//!          | [ "and"|"or", expr, ... ]
//!          | [ "not", expr ]
//!          | [ "isdir", str ]
//! ```
//!
//! Command arguments go through `%`-expansion: `%VAR%` substitutes, `%%` is a
//! literal `%`, and an odd number of `%` is an error. A `%VAR%` naming an
//! unset variable expands to nothing rather than failing -- that asymmetry is
//! deliberate in the C and callers rely on it.

use std::collections::BTreeMap;
use std::ffi::CString;

use owrt_ubus::blob::{Field, MsgType};

/// What running a block produced: the commands, in order, with their
/// arguments already expanded.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Run {
    pub commands: Vec<(String, Vec<String>)>,
    /// Errors the C would have passed to `handle_error`. Collected rather
    /// than printed so a harness can compare them.
    pub errors: Vec<String>,
}

/// Truth value of an expression. `Err` is the C's negative return, which is
/// distinct from false: `if` treats it as "run neither branch".
type Truth = Result<bool, ()>;

pub struct Ctx<'a> {
    vars: &'a BTreeMap<String, String>,
    out: Run,
    /// `ctx->abort`, set by `return`.
    abort: bool,
}

/// Run one block against one variable set.
pub fn run(block: Field<'_>, vars: &BTreeMap<String, String>) -> Run {
    let mut ctx = Ctx { vars, out: Run::default(), abort: false };
    ctx.process_cmd(block);
    ctx.out
}

impl Ctx<'_> {
    fn find_var(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }

    fn error(&mut self, what: &str) {
        self.out.errors.push(what.to_string());
    }

    /// `json_process_cmd()`. A block is an array; if its first element is a
    /// string the whole array is one command, otherwise each element is
    /// itself a block. `return` propagates as a value below -1.
    fn process_cmd(&mut self, block: Field<'_>) -> i32 {
        if block.ty != MsgType::Array as u32 {
            self.error("Unexpected element type");
            return -1;
        }
        for (i, cur) in block.children().enumerate() {
            if self.abort {
                break;
            }
            if cur.ty == MsgType::String as u32 && i == 0 {
                return self.process_one_cmd(block);
            }
            let ret = self.process_cmd(cur);
            if ret < -1 {
                return ret;
            }
        }
        0
    }

    /// `__json_process_cmd()`.
    fn process_one_cmd(&mut self, cur: Field<'_>) -> i32 {
        let Some(name) = first_string(cur) else {
            self.error("Unexpected element type");
            return -1;
        };
        match name {
            "if" => return self.handle_if(cur),
            "case" => return self.handle_case(cur),
            "return" => {
                // handle_return: -2, which json_process_cmd propagates.
                self.abort = true;
                return -2;
            }
            "include" => {
                // Only procd's trigger context defines a second file, and it
                // only ever resolves the trigger's own type. Nothing on this
                // device uses `include`, so it is a no-op with a recorded
                // reason rather than a silent success.
                self.error("include: no script files are registered");
                return 0;
            }
            _ => {}
        }
        // Anything else is a command: expand every argument after the name.
        let mut args = Vec::new();
        for (i, a) in cur.children().enumerate() {
            if i == 0 {
                continue;
            }
            match a.as_str() {
                Some(pattern) => match self.eval_string(pattern) {
                    Ok(s) => args.push(s),
                    Err(()) => {
                        self.error("Unterminated variable reference in string");
                        return -1;
                    }
                },
                // A non-string argument is copied through untouched.
                None => args.push(non_string_repr(a)),
            }
        }
        self.out.commands.push((name.to_string(), args));
        0
    }

    /// `handle_if`: [name, expr, then, else?]. An expression that errors runs
    /// neither branch.
    fn handle_if(&mut self, cur: Field<'_>) -> i32 {
        let parts: Vec<Field> = cur.children().collect();
        if parts.len() < 3 {
            return 0;
        }
        match self.process_expr(parts[1]) {
            Err(()) => 0,
            Ok(true) => self.process_cmd(parts[2]),
            Ok(false) => {
                if parts.len() < 4 {
                    0
                } else {
                    self.process_cmd(parts[3])
                }
            }
        }
    }

    /// `handle_case`: [name, "VAR", { value: block }]. An unset variable
    /// matches nothing, including a key that happens to be empty.
    fn handle_case(&mut self, cur: Field<'_>) -> i32 {
        let parts: Vec<Field> = cur.children().collect();
        if parts.len() < 3 {
            return 0;
        }
        let Some(varname) = parts[1].as_str() else {
            return 0;
        };
        let Some(val) = self.find_var(varname).map(str::to_string) else {
            return 0;
        };
        for arm in parts[2].children() {
            if arm.name == val {
                return self.process_cmd(arm);
            }
        }
        0
    }

    /// `json_process_expr()`.
    fn process_expr(&mut self, cur: Field<'_>) -> Truth {
        if cur.ty != MsgType::Array as u32 {
            self.error("Unexpected element type");
            return Err(());
        }
        let Some(name) = first_string(cur) else {
            self.error("Unexpected element type");
            return Err(());
        };
        match name {
            "eq" => self.expr_eq_regex(cur, false),
            "regex" => self.expr_eq_regex(cur, true),
            "has" => self.expr_has(cur),
            "and" => self.expr_and_or(cur, true),
            "or" => self.expr_and_or(cur, false),
            "not" => self.expr_not(cur),
            "isdir" => self.expr_isdir(cur),
            // An unknown expression reaches handle_expr, which this context
            // does not define, and the return value stays the -1 from
            // __json_process_type.
            _ => Err(()),
        }
    }

    /// `expr_eq_regex`. An unset variable is FALSE, not an error -- that is
    /// what makes `[ "eq", "ACTION", "add" ]` safe on a message with no
    /// ACTION at all.
    fn expr_eq_regex(&mut self, cur: Field<'_>, regex: bool) -> Truth {
        let parts: Vec<Field> = cur.children().collect();
        if parts.len() < 3 {
            return Err(());
        }
        let Some(varname) = parts[1].as_str() else {
            return Err(());
        };
        let Some(val) = self.find_var(varname).map(str::to_string) else {
            return Ok(false);
        };
        let pat = parts[2];
        if let Some(p) = pat.as_str() {
            return Ok(eq_or_regex(&val, p, regex));
        }
        if pat.ty == MsgType::Array as u32 {
            for c in pat.children() {
                let Some(p) = c.as_str() else {
                    self.error("Unexpected element type");
                    return Err(());
                };
                if eq_or_regex(&val, p, regex) {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        self.error("Unexpected element type");
        Err(())
    }

    fn expr_has(&mut self, cur: Field<'_>) -> Truth {
        let parts: Vec<Field> = cur.children().collect();
        if parts.len() < 2 {
            return Err(());
        }
        let arg = parts[1];
        if let Some(n) = arg.as_str() {
            return Ok(self.find_var(n).is_some());
        }
        if arg.ty == MsgType::Array as u32 {
            for c in arg.children() {
                let Some(n) = c.as_str() else {
                    self.error("Unexpected element type");
                    return Err(());
                };
                if self.find_var(n).is_some() {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        self.error("Unexpected element type");
        Err(())
    }

    /// `expr_and_or`. Element 0 is the operator name and is skipped. Short
    /// circuits on the first operand that differs from the identity.
    fn expr_and_or(&mut self, cur: Field<'_>, and: bool) -> Truth {
        for (i, c) in cur.children().enumerate() {
            if i < 1 {
                continue;
            }
            let ret = self.process_expr(c)?;
            if ret != and {
                return Ok(ret);
            }
        }
        Ok(and)
    }

    fn expr_not(&mut self, cur: Field<'_>) -> Truth {
        let parts: Vec<Field> = cur.children().collect();
        if parts.len() < 2 || parts[1].ty != MsgType::Array as u32 {
            return Err(());
        }
        Ok(!self.process_expr(parts[1])?)
    }

    fn expr_isdir(&mut self, cur: Field<'_>) -> Truth {
        let parts: Vec<Field> = cur.children().collect();
        if parts.len() < 2 {
            return Err(());
        }
        let Some(pattern) = parts[1].as_str() else {
            return Err(());
        };
        let path = self.eval_string(pattern).map_err(|_| ())?;
        Ok(std::fs::metadata(&path).map(|m| m.is_dir()).unwrap_or(false))
    }

    /// `eval_string()`. `%` toggles variable mode; an empty name (`%%`) is a
    /// literal `%`; an unset variable contributes nothing; an odd number of
    /// `%` leaves the toggle set and is an error.
    fn eval_string(&self, pattern: &str) -> Result<String, ()> {
        // The C toggles a flag every time it consumes a '%', then reads the
        // flag for the segment that follows. Splitting on '%' says the same
        // thing more directly: segment 0 is literal, and each '%' flips, so
        // segment i is a variable reference exactly when i is odd.
        let segs: Vec<&str> = pattern.split('%').collect();
        let mut out = String::new();
        for (i, seg) in segs.iter().enumerate() {
            if i.is_multiple_of(2) {
                out.push_str(seg);
                continue;
            }
            if seg.is_empty() {
                // `%%` -- an empty name is a literal percent.
                out.push('%');
            } else if let Some(v) = self.find_var(seg) {
                out.push_str(v);
            }
            // An unset name contributes nothing; the C `continue`s here.
        }
        // n segments means n-1 delimiters, and the C's flag ends set when
        // that count is odd -- an unterminated reference.
        if segs.len().is_multiple_of(2) {
            return Err(());
        }
        Ok(out)
    }
}

/// The first element of an array, if it is a string. Both `process_expr` and
/// `__json_process_cmd` require this shape before dispatching.
fn first_string<'a>(cur: Field<'a>) -> Option<&'a str> {
    cur.children().next().and_then(|f| f.as_str())
}

/// A non-string command argument is added verbatim by `blobmsg_add_blob`.
/// Rendering it as text is only for the harness comparison; the daemon side
/// never execs a non-string argv element usefully anyway.
fn non_string_repr(f: Field<'_>) -> String {
    if let Some(b) = f.as_bool() {
        return b.to_string();
    }
    if let Some(u) = f.as_u32() {
        return u.to_string();
    }
    String::new()
}

extern "C" {
    fn regcomp(preg: *mut u8, pattern: *const u8, cflags: i32) -> i32;
    fn regexec(
        preg: *const u8,
        string: *const u8,
        nmatch: usize,
        pmatch: *mut u8,
        eflags: i32,
    ) -> i32;
    fn regfree(preg: *mut u8);
}

const REG_EXTENDED: i32 = 1;
const REG_NOSUB: i32 = 1 << 3;
/// `regex_t` is opaque and its size differs per libc. 256 bytes is larger
/// than glibc's (64) and musl's (32 on this target); over-allocating is safe
/// because only the library ever writes into it.
const REGEX_T_SIZE: usize = 256;

/// `eq_regex_cmp()`. Plain equality, or POSIX extended regex through the
/// platform's own regcomp/regexec -- the same implementation the C calls, so
/// there is no second regex dialect to keep in step. A pattern that fails to
/// compile is false, exactly as in the C.
fn eq_or_regex(s: &str, pattern: &str, regex: bool) -> bool {
    if !regex {
        return s == pattern;
    }
    let (Ok(cpat), Ok(cs)) = (CString::new(pattern), CString::new(s)) else {
        return false;
    };
    let mut reg = [0u8; REGEX_T_SIZE];
    // SAFETY: `reg` is a zeroed buffer at least as large as regex_t on this
    // platform, and `cpat` is a NUL-terminated string that outlives the call.
    if unsafe { regcomp(reg.as_mut_ptr(), cpat.as_ptr() as *const u8, REG_EXTENDED | REG_NOSUB) }
        != 0
    {
        return false;
    }
    // SAFETY: `reg` was successfully compiled above; nmatch 0 with a null
    // pmatch is what REG_NOSUB expects.
    let hit = unsafe {
        regexec(reg.as_ptr(), cs.as_ptr() as *const u8, 0, std::ptr::null_mut(), 0) == 0
    };
    // SAFETY: frees the compiled regex exactly once.
    unsafe { regfree(reg.as_mut_ptr()) };
    hit
}

#[cfg(test)]
mod tests {
    use super::*;
    use owrt_ubus::blob::BlobBuf;

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// Build `[ [ "if", ["eq","ACT","go"], [ ["run_script","x","%WHO%"] ] ] ]`
    /// -- the exact shape a service's trigger script has.
    fn if_eq_script() -> BlobBuf {
        let mut b = BlobBuf::new();
        let outer = b.msg_open_array("script");
        {
            let ifc = b.msg_open_array("");
            b.msg_string("", "if");
            {
                let e = b.msg_open_array("");
                b.msg_string("", "eq");
                b.msg_string("", "ACT");
                b.msg_string("", "go");
                b.msg_close(e);
            }
            {
                let then = b.msg_open_array("");
                let cmd = b.msg_open_array("");
                b.msg_string("", "run_script");
                b.msg_string("", "x");
                b.msg_string("", "%WHO%");
                b.msg_close(cmd);
                b.msg_close(then);
            }
            b.msg_close(ifc);
        }
        b.msg_close(outer);
        b
    }

    fn run_script(b: &BlobBuf, v: &BTreeMap<String, String>) -> Run {
        let f = owrt_ubus::blob::fields(b.payload()).next().expect("one field");
        run(f, v)
    }

    #[test]
    fn an_if_eq_rule_runs_its_command_with_the_variable_expanded() {
        let b = if_eq_script();
        let out = run_script(&b, &vars(&[("ACT", "go"), ("WHO", "first")]));
        assert_eq!(out.errors, Vec::<String>::new());
        assert_eq!(
            out.commands,
            vec![("run_script".to_string(), vec!["x".to_string(), "first".to_string()])]
        );
    }

    #[test]
    fn a_false_expression_runs_nothing() {
        let b = if_eq_script();
        let out = run_script(&b, &vars(&[("ACT", "stop"), ("WHO", "second")]));
        assert!(out.commands.is_empty());
    }

    #[test]
    fn an_unset_variable_expands_to_nothing_rather_than_failing() {
        let b = if_eq_script();
        let out = run_script(&b, &vars(&[("ACT", "go")]));
        assert_eq!(
            out.commands,
            vec![("run_script".to_string(), vec!["x".to_string(), String::new()])]
        );
    }

    #[test]
    fn percent_rules() {
        let v = vars(&[("A", "1")]);
        let ctx = Ctx { vars: &v, out: Run::default(), abort: false };
        assert_eq!(ctx.eval_string("plain").unwrap(), "plain");
        assert_eq!(ctx.eval_string("%A%").unwrap(), "1");
        assert_eq!(ctx.eval_string("x%A%y").unwrap(), "x1y");
        // %% is a literal percent.
        assert_eq!(ctx.eval_string("%%").unwrap(), "%");
        assert_eq!(ctx.eval_string("a%%b").unwrap(), "a%b");
        // An unset name contributes nothing at all.
        assert_eq!(ctx.eval_string("x%NOPE%y").unwrap(), "xy");
        // An odd number of percents is an error, not a literal.
        assert!(ctx.eval_string("%A").is_err());
        assert!(ctx.eval_string("a%b%c%").is_err());
    }

    #[test]
    fn regex_uses_posix_extended_syntax() {
        assert!(eq_or_regex("eth0", "^eth[0-9]+$", true));
        assert!(!eq_or_regex("wlan0", "^eth[0-9]+$", true));
        // ERE alternation, which a basic-regex engine would treat literally.
        assert!(eq_or_regex("br-lan", "^(eth|br)-", true));
        // A pattern that cannot compile is false, not an error.
        assert!(!eq_or_regex("x", "[", true));
        // Without the flag it is plain equality, metacharacters and all.
        assert!(!eq_or_regex("eth0", "^eth[0-9]+$", false));
        assert!(eq_or_regex("^eth[0-9]+$", "^eth[0-9]+$", false));
    }
}
