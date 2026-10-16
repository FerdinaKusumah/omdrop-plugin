//! Python's `repr()` and `str(float)`, for the log lines and commands the
//! Python sender printed. People read them and bash matches on parts of them,
//! so the Rust sender spells them the same way.

/// `repr(str)`: single quotes unless the text holds a single quote and no
/// double quote.
pub fn str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => {
                let n = c as u32;
                if n < 0x100 {
                    out.push_str(&format!("\\x{n:02x}"));
                } else {
                    out.push_str(&format!("\\u{n:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `repr(bytes)`: `b'...'` with printable ASCII kept and everything else
/// escaped.
pub fn bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::with_capacity(b.len() + 3);
    out.push('b');
    out.push(quote as char);
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c as char);
            }
            0x20..=0x7e => out.push(c as char),
            c => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    out.push(quote as char);
    out
}

/// `repr()` of an optional string: the repr, or `None`.
pub fn opt_str_repr(s: Option<&str>) -> String {
    s.map_or_else(|| "None".to_owned(), str_repr)
}

/// `repr(list_of_str)`.
pub fn list_repr<S: AsRef<str>>(items: &[S]) -> String {
    let inner: Vec<String> = items.iter().map(|s| str_repr(s.as_ref())).collect();
    format!("[{}]", inner.join(", "))
}

/// `str(float)`: `60.0`, `2.5`, `1e+16`, `inf`.
pub fn float_str(f: f64) -> String {
    if f.is_nan() {
        return "nan".to_owned();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    let a = f.abs();
    if a != 0.0 && !(1e-4..1e16).contains(&a) {
        // Rust writes `1e16` and `1.5e-5`; Python writes `1e+16` and `1.5e-05`.
        let s = format!("{f:e}");
        let (mantissa, exp) = s.split_once('e').unwrap_or((&s, "0"));
        let (sign, digits) = match exp.strip_prefix('-') {
            Some(d) => ('-', d),
            None => ('+', exp),
        };
        return format!("{mantissa}e{sign}{digits:0>2}");
    }
    if f == f.trunc() {
        format!("{f:.1}")
    } else {
        format!("{f}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reprs_match_python() {
        assert_eq!(str_repr("hume"), "'hume'");
        assert_eq!(str_repr("Beata's iMac"), "\"Beata's iMac\"");
        assert_eq!(str_repr("a'b\"c"), "'a\\'b\"c'");
        assert_eq!(str_repr("tab\there"), "'tab\\there'");
        assert_eq!(bytes_repr(b"bplist00\xd3\x01"), "b'bplist00\\xd3\\x01'");
        assert_eq!(bytes_repr(b""), "b''");
        assert_eq!(list_repr(&["a", "b"]), "['a', 'b']");
        assert_eq!(opt_str_repr(None), "None");
    }

    #[test]
    fn floats_match_python_str() {
        assert_eq!(float_str(60.0), "60.0");
        assert_eq!(float_str(8.0), "8.0");
        assert_eq!(float_str(2.5), "2.5");
        assert_eq!(float_str(0.1), "0.1");
        assert_eq!(float_str(1e16), "1e+16");
        assert_eq!(float_str(1.5e-5), "1.5e-05");
        assert_eq!(float_str(0.0), "0.0");
        assert_eq!(float_str(f64::INFINITY), "inf");
    }
}
