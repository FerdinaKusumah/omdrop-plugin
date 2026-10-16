//! The subset of Python `argparse` the advertisers use: long options with a
//! value (`--x V` or `--x=V`), flags, an optional value (`nargs='?'`), last
//! occurrence wins, `-h`/`--help`, and errors on stderr with exit status 2.

use std::collections::HashMap;
use std::io::Write;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `action='store_true'`.
    Flag,
    /// Takes exactly one value.
    Value,
    /// `nargs='?'`: takes the next word if it is not an option.
    Optional,
}

pub struct Opt {
    pub name: &'static str,
    pub kind: Kind,
    pub metavar: &'static str,
    pub help: &'static str,
}

/// What the parser found: `Some(None)` for a flag or a bare optional option.
pub struct Parsed {
    values: HashMap<&'static str, Option<String>>,
}

/// Parsing stopped: print this and exit with this status.
pub struct Exit {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Exit {
    pub fn emit(self) -> i32 {
        let _ = std::io::stdout().write_all(self.stdout.as_bytes());
        let _ = std::io::stderr().write_all(self.stderr.as_bytes());
        self.code
    }
}

pub struct Parser {
    pub prog: &'static str,
    pub description: &'static str,
    pub opts: &'static [Opt],
}

fn looks_negative_number(s: &str) -> bool {
    s.strip_prefix('-').is_some_and(|rest| {
        !rest.is_empty() && rest.parse::<f64>().is_ok() && !rest.starts_with('-')
    })
}

fn looks_like_option(s: &str) -> bool {
    s.starts_with('-') && s.len() > 1 && !looks_negative_number(s)
}

impl Parser {
    pub fn usage(&self) -> String {
        let mut line = format!("usage: {} [-h]", self.prog);
        for o in self.opts {
            match o.kind {
                Kind::Flag => line.push_str(&format!(" [--{}]", o.name)),
                Kind::Value => line.push_str(&format!(" [--{} {}]", o.name, o.metavar)),
                Kind::Optional => line.push_str(&format!(" [--{} [{}]]", o.name, o.metavar)),
            }
        }
        line.push('\n');
        line
    }

    fn help(&self) -> String {
        let mut text = self.usage();
        text.push('\n');
        text.push_str(self.description);
        text.push_str("\n\noptions:\n  -h, --help            show this help message and exit\n");
        for o in self.opts {
            let head = match o.kind {
                Kind::Flag => format!("--{}", o.name),
                Kind::Value => format!("--{} {}", o.name, o.metavar),
                Kind::Optional => format!("--{} [{}]", o.name, o.metavar),
            };
            text.push_str(&format!("  {head:<22}{}\n", o.help));
        }
        text
    }

    pub fn error(&self, msg: &str) -> Exit {
        Exit {
            code: 2,
            stdout: String::new(),
            stderr: format!("{}{}: error: {msg}\n", self.usage(), self.prog),
        }
    }

    pub fn parse(&self, args: &[String]) -> Result<Parsed, Exit> {
        let mut values = HashMap::new();
        let mut rest = args.iter().peekable();
        let mut unknown = Vec::new();
        while let Some(arg) = rest.next() {
            if arg == "-h" || arg == "--help" {
                return Err(Exit {
                    code: 0,
                    stdout: self.help(),
                    stderr: String::new(),
                });
            }
            let (name, inline) = match arg.strip_prefix("--") {
                Some(body) => match body.split_once('=') {
                    Some((n, v)) => (n, Some(v.to_owned())),
                    None => (body, None),
                },
                None => {
                    unknown.push(arg.clone());
                    continue;
                }
            };
            let Some(opt) = self.opts.iter().find(|o| o.name == name) else {
                unknown.push(arg.clone());
                continue;
            };
            let value = match (opt.kind, inline) {
                (Kind::Flag, Some(_)) => {
                    return Err(
                        self.error(&format!("argument --{name}: ignored explicit argument"))
                    );
                }
                (Kind::Flag, None) => None,
                (_, Some(v)) => Some(v),
                (Kind::Value, None) => match rest.next_if(|v| !looks_like_option(v)) {
                    Some(v) => Some(v.clone()),
                    None => {
                        return Err(
                            self.error(&format!("argument --{name}: expected one argument"))
                        );
                    }
                },
                (Kind::Optional, None) => rest.next_if(|v| !looks_like_option(v)).cloned(),
            };
            values.insert(opt.name, value);
        }
        if !unknown.is_empty() {
            return Err(self.error(&format!("unrecognized arguments: {}", unknown.join(" "))));
        }
        Ok(Parsed { values })
    }
}

impl Parsed {
    pub fn flag(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }

    /// The value of a `Value` option, if given.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(|v| v.as_deref())
    }

    /// An `Optional` option: `None` absent, `Some(None)` bare, `Some(Some(v))`.
    pub fn optional(&self, name: &str) -> Option<Option<&str>> {
        self.values.get(name).map(|v| v.as_deref())
    }
}

/// Python `int(text)`: optional sign, decimal digits with single underscores
/// between them, surrounding whitespace allowed.
pub fn py_int(text: &str) -> Option<i128> {
    py_int_radix(text.trim(), 10)
}

/// Python `int(text, 0)`: `0x`/`0o`/`0b` prefixes, or decimal without leading
/// zeros.
pub fn py_int_auto(text: &str) -> Option<i128> {
    let t = text.trim();
    let (neg, body) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let lower = body.to_ascii_lowercase();
    let (radix, digits) = if let Some(d) = lower.strip_prefix("0x") {
        (16, d)
    } else if let Some(d) = lower.strip_prefix("0o") {
        (8, d)
    } else if let Some(d) = lower.strip_prefix("0b") {
        (2, d)
    } else {
        if lower.len() > 1
            && lower.starts_with('0')
            && lower.bytes().any(|b| b != b'0' && b != b'_')
        {
            return None;
        }
        (10, lower.as_str())
    };
    // Python allows one underscore right after the prefix: 0x_ff.
    let digits = if radix != 10 {
        digits.strip_prefix('_').unwrap_or(digits)
    } else {
        digits
    };
    let v = py_int_radix(digits, radix)?;
    if digits.starts_with(['-', '+']) {
        return None;
    }
    Some(if neg { -v } else { v })
}

fn py_int_radix(t: &str, radix: u32) -> Option<i128> {
    let (neg, body) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    if body.is_empty() || body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return None;
    }
    let clean: String = body.chars().filter(|&c| c != '_').collect();
    if !clean.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    let v = i128::from_str_radix(&clean, radix).ok()?;
    Some(if neg { -v } else { v })
}

/// Python `float(text)` for the finite values a duration can take.
pub fn py_float(text: &str) -> Option<f64> {
    let t = text.trim();
    if t.contains('_') {
        let clean: String = t.chars().filter(|&c| c != '_').collect();
        return clean.parse().ok();
    }
    t.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPTS: &[Opt] = &[
        Opt {
            name: "seq",
            kind: Kind::Value,
            metavar: "SEQ",
            help: "",
        },
        Opt {
            name: "plain",
            kind: Kind::Flag,
            metavar: "",
            help: "",
        },
        Opt {
            name: "rec",
            kind: Kind::Optional,
            metavar: "R",
            help: "",
        },
    ];
    const P: Parser = Parser {
        prog: "t",
        description: "",
        opts: OPTS,
    };

    fn parse(args: &[&str]) -> Result<Parsed, Exit> {
        P.parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn argparse_shapes() {
        let p = parse(&["--seq", "1", "--seq=-5", "--plain", "--rec"])
            .ok()
            .unwrap();
        assert_eq!(p.value("seq"), Some("-5"));
        assert!(p.flag("plain"));
        assert_eq!(p.optional("rec"), Some(None));
        let p = parse(&["--rec", "/x", "--seq", "-3"]).ok().unwrap();
        assert_eq!(p.optional("rec"), Some(Some("/x")));
        assert_eq!(p.value("seq"), Some("-3"));
        let p = parse(&["--rec", "--plain"]).ok().unwrap();
        assert_eq!(p.optional("rec"), Some(None));
        assert!(p.flag("plain"));
        for bad in [
            &["--seq"][..],
            &["--seq", "--plain"],
            &["x"],
            &["--nope"],
            &["--plain=1"],
        ] {
            let e = parse(bad).err().unwrap();
            assert_eq!(e.code, 2, "{bad:?}");
            assert!(e.stderr.contains("t: error: "), "{}", e.stderr);
        }
        assert_eq!(parse(&["-h"]).err().unwrap().code, 0);
    }

    #[test]
    fn python_int_rules() {
        assert_eq!(py_int(" 12 "), Some(12));
        assert_eq!(py_int("-1_000"), Some(-1000));
        assert_eq!(py_int("1__0"), None);
        assert_eq!(py_int("0x10"), None);
        assert_eq!(py_int(""), None);
        assert_eq!(py_int_auto("0x05"), Some(5));
        assert_eq!(py_int_auto("0X7E"), Some(126));
        assert_eq!(py_int_auto("0b101"), Some(5));
        assert_eq!(py_int_auto("0o17"), Some(15));
        assert_eq!(py_int_auto("5"), Some(5));
        assert_eq!(py_int_auto("05"), None);
        assert_eq!(py_int_auto("00"), Some(0));
        assert_eq!(py_int_auto("0x"), None);
        assert_eq!(py_int_auto("0x-5"), None);
        assert_eq!(py_float("0.02"), Some(0.02));
        assert_eq!(py_float("1_0.5"), Some(10.5));
    }
}
