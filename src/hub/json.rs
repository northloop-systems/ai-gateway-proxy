//! JSON, in the small.
//!
//! The hub answers in JSON, so this binary has to read an answer and write
//! one request body. That is all it needs: no DOM, no schema, no
//! streaming, no round-trip fidelity beyond what the hub's own answers
//! carry.
//!
//! It is written by hand rather than pulled in as a crate because this
//! program ships with no dependencies at all. A JSON parser is a few
//! hundred readable lines, and it is the one piece of what a TLS stack
//! would have brought that would have been hardest to audit.
//!
//! The parser is strict where JSON is strict - a raw control character
//! inside a string is an error, not a shrug - and it never panics: every
//! malformed answer comes back as a message for the operator.

use std::fmt::Write as _;

/// A JSON value.
///
/// Objects keep their pairs in a list rather than a map, because the order
/// the hub sent them in is worth keeping: the request body this writes
/// has to look like the one the shell installer sent, and a reader can
/// see it.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// The value for a key, if this is an object that has one.
    ///
    /// A repeated key takes its LAST value, which is what Python's json
    /// module does and therefore what the hub means when it sends one.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs
                .iter()
                .rev()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// The text, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(text) => Some(text),
            _ => None,
        }
    }

    /// The whole number, if this is a number that is one.
    ///
    /// Part of the fixed JSON API: the rest of the program is allowed to
    /// ask for a number, and a method no caller has used yet is not a
    /// mistake to leave in.
    #[allow(dead_code)]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Num(value) => {
                let whole = value.fract() == 0.0 && value.is_finite();
                let in_range = *value >= i64::MIN as f64 && *value <= i64::MAX as f64;
                if whole && in_range {
                    Some(*value as i64)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// The true/false, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// Read JSON text. The error is a message for the operator.
    pub fn parse(text: &str) -> Result<Json, String> {
        let mut parser = Parser::new(text);
        let value = parser.value()?;
        parser.skip_whitespace();
        if parser.pos != parser.bytes.len() {
            return parser.error("there is more after the value");
        }
        Ok(value)
    }

    /// Compact JSON text, for a request body.
    pub fn write(&self) -> String {
        let mut out = String::new();
        self.write_into(&mut out);
        out
    }

    fn write_into(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Num(value) => out.push_str(&number_text(*value)),
            Json::Str(text) => write_string(text, out),
            Json::Arr(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write_into(out);
                }
                out.push(']');
            }
            Json::Obj(pairs) => {
                out.push('{');
                for (index, (key, value)) in pairs.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    value.write_into(out);
                }
                out.push('}');
            }
        }
    }
}

/// A JSON string.
pub fn s(value: &str) -> Json {
    Json::Str(value.to_string())
}

/// A JSON number.
pub fn n(value: i64) -> Json {
    Json::Num(value as f64)
}

/// A JSON object.
pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

/// A number as text, without a pointless fraction.
///
/// JSON has one number type, so 9050 and 9050.0 are the same value; the
/// whole number is written as a whole number because that is what the hub
/// expects to read back.
fn number_text(value: f64) -> String {
    if !value.is_finite() {
        // JSON cannot say NaN or infinity, and a value that is neither is
        // not one the hub could have sent. Writing null keeps the body
        // something a JSON reader can still read.
        return "null".to_string();
    }
    if value == value.trunc() && value.abs() < 1e15 {
        return format!("{}", value as i64);
    }
    format!("{value}")
}

/// A string as JSON text, with the escapes JSON requires.
fn write_string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A reader over the bytes of a JSON text.
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Parser<'a> {
        Parser {
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    /// An error that says where the text stopped making sense.
    fn error<T>(&self, message: &str) -> Result<T, String> {
        Err(format!("invalid JSON at byte {}: {message}", self.pos))
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.bytes.get(self.pos) {
            match byte {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_whitespace();
        match self.peek() {
            None => self.error("the text ended in the middle of a value"),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.word("true", Json::Bool(true)),
            Some(b'f') => self.word("false", Json::Bool(false)),
            Some(b'n') => self.word("null", Json::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            Some(other) => self.error(&format!("unexpected character '{}'", other as char)),
        }
    }

    /// A literal word, which must be there exactly.
    fn word(&mut self, text: &str, value: Json) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(text.as_bytes()) {
            self.pos += text.len();
            Ok(value)
        } else {
            self.error(&format!("expected '{text}'"))
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return self.error("expected a digit"),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.error("expected a digit after the decimal point");
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return self.error("expected a digit in the exponent");
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let text = match std::str::from_utf8(&self.bytes[start..self.pos]) {
            Ok(text) => text,
            Err(_) => return self.error("the number is not text"),
        };
        match text.parse::<f64>() {
            Ok(value) => Ok(Json::Num(value)),
            Err(_) => self.error("the number could not be read"),
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1; // the opening quote
        let mut out = String::new();
        loop {
            let byte = match self.peek() {
                None => return self.error("the string was not closed"),
                Some(byte) => byte,
            };
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let escape = match self.peek() {
                        None => return self.error("the text ended in the middle of an escape"),
                        Some(escape) => escape,
                    };
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        other => {
                            return self.error(&format!("unknown escape '\\{}'", other as char));
                        }
                    }
                }
                b if b < 0x20 => {
                    return self.error("a control character in a string has to be escaped");
                }
                _ => {
                    // A run of ordinary characters, copied whole. The slice
                    // is valid UTF-8 because it came out of a &str.
                    let start = self.pos;
                    while let Some(byte) = self.peek() {
                        if byte == b'"' || byte == b'\\' || byte < 0x20 {
                            break;
                        }
                        self.pos += 1;
                    }
                    match std::str::from_utf8(&self.bytes[start..self.pos]) {
                        Ok(text) => out.push_str(text),
                        Err(_) => return self.error("the string is not text"),
                    }
                }
            }
        }
    }

    /// A `\uXXXX` escape, which may be half of a surrogate pair.
    fn unicode_escape(&mut self) -> Result<char, String> {
        let first = self.hex4()?;
        if (0xD800..0xDC00).contains(&first) {
            // The high half of a pair. The low half has to be there: a
            // lone high half is not a character.
            if self.peek() != Some(b'\\') {
                return self.error("a high surrogate has to be followed by a low surrogate");
            }
            self.pos += 1;
            if self.peek() != Some(b'u') {
                return self.error("a high surrogate has to be followed by a low surrogate");
            }
            self.pos += 1;
            let second = self.hex4()?;
            if !(0xDC00..0xE000).contains(&second) {
                return self.error("the second half of a surrogate pair is not a low surrogate");
            }
            let code = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
            return match char::from_u32(code) {
                Some(ch) => Ok(ch),
                None => self.error("the surrogate pair is not a character"),
            };
        }
        if (0xDC00..0xE000).contains(&first) {
            return self.error("a low surrogate appeared on its own");
        }
        match char::from_u32(first) {
            Some(ch) => Ok(ch),
            None => self.error("the escape is not a character"),
        }
    }

    /// Four hex digits.
    fn hex4(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.bytes.len() {
            return self.error("a \\u escape needs four hex digits");
        }
        let text = match std::str::from_utf8(&self.bytes[self.pos..self.pos + 4]) {
            Ok(text) => text,
            Err(_) => return self.error("the escape is not text"),
        };
        match u32::from_str_radix(text, 16) {
            Ok(value) => {
                self.pos += 4;
                Ok(value)
            }
            Err(_) => self.error("a \\u escape needs four hex digits"),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.pos += 1; // the opening brace
        let mut pairs: Vec<(String, Json)> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return self.error("expected a quoted key");
            }
            let key = self.string()?;
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return self.error("expected ':' after the key");
            }
            self.pos += 1;
            let value = self.value()?;
            pairs.push((key, value));
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(pairs));
                }
                None => return self.error("the object was not closed"),
                Some(_) => return self.error("expected ',' or '}'"),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.pos += 1; // the opening bracket
        let mut items: Vec<Json> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            let value = self.value()?;
            items.push(value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                None => return self.error("the list was not closed"),
                Some(_) => return self.error("expected ',' or ']'"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_shapes_the_hub_answers_with() {
        let value = Json::parse(
            r#"{"status":"ok","node_id":"node-laptop","wireguard_ip":"10.200.0.2","ports":{"tor":9050}}"#,
        )
        .expect("a plain object should parse");
        assert_eq!(value.get("status").and_then(Json::as_str), Some("ok"));
        assert_eq!(
            value.get("node_id").and_then(Json::as_str),
            Some("node-laptop")
        );
        assert_eq!(
            value
                .get("ports")
                .and_then(|ports| ports.get("tor"))
                .and_then(Json::as_i64),
            Some(9050)
        );
    }

    #[test]
    fn a_missing_key_is_not_an_error() {
        let value = Json::parse(r#"{"status":"ok"}"#).expect("parse");
        assert_eq!(value.get("node_id"), None);
        assert_eq!(value.get("status").and_then(Json::as_str), Some("ok"));
    }

    #[test]
    fn a_repeated_key_takes_its_last_value() {
        let value = Json::parse(r#"{"a":1,"a":2}"#).expect("parse");
        assert_eq!(value.get("a").and_then(Json::as_i64), Some(2));
    }

    #[test]
    fn reads_nested_structures() {
        let value = Json::parse(
            r#"{"object":"list","data":[{"node_id":"node-a","ports":{"tor":9050,"warp":40000,"direct":1080}}]}"#,
        )
        .expect("parse");
        let data = value.get("data").expect("data");
        let items = match data {
            Json::Arr(items) => items,
            other => panic!("data should be a list, was {other:?}"),
        };
        assert_eq!(items.len(), 1);
        let ports = items[0].get("ports").expect("ports");
        assert_eq!(ports.get("warp").and_then(Json::as_i64), Some(40000));
        assert_eq!(ports.get("direct").and_then(Json::as_i64), Some(1080));
    }

    #[test]
    fn reads_every_kind_of_value() {
        let value = Json::parse(
            r#"{"n":null,"b":true,"f":false,"i":9050,"neg":-3,"d":1.5,"e":2e3,"s":"x"}"#,
        )
        .expect("parse");
        assert_eq!(value.get("n"), Some(&Json::Null));
        assert_eq!(value.get("b").and_then(Json::as_bool), Some(true));
        assert_eq!(value.get("f").and_then(Json::as_bool), Some(false));
        assert_eq!(value.get("i").and_then(Json::as_i64), Some(9050));
        assert_eq!(value.get("neg").and_then(Json::as_i64), Some(-3));
        assert_eq!(value.get("d"), Some(&Json::Num(1.5)));
        assert_eq!(value.get("e"), Some(&Json::Num(2000.0)));
        assert_eq!(value.get("s").and_then(Json::as_str), Some("x"));
    }

    #[test]
    fn a_fraction_is_not_a_whole_number() {
        let value = Json::parse(r#"{"d":1.5}"#).expect("parse");
        assert_eq!(value.get("d").and_then(Json::as_i64), None);
    }

    #[test]
    fn reads_escapes_including_surrogate_pairs() {
        let value = Json::parse(r#""a\"b\\c\/d\be\ff\ng\rh\ti\u00e9\u20ac""#).expect("parse");
        assert_eq!(
            value.as_str(),
            Some("a\"b\\c/d\u{0008}e\u{000c}f\ng\rh\ti\u{00e9}\u{20ac}")
        );
    }

    #[test]
    fn reads_a_surrogate_pair_as_one_character() {
        let value = Json::parse(r#""\ud83d\ude00""#).expect("parse");
        assert_eq!(value.as_str(), Some("\u{1F600}"));
    }

    #[test]
    fn refuses_a_lone_surrogate() {
        assert!(Json::parse(r#""\ud83d""#).is_err());
        assert!(Json::parse(r#""\ude00""#).is_err());
        assert!(Json::parse(r#""\ud83dA""#).is_err());
    }

    #[test]
    fn refuses_malformed_input_without_panicking() {
        let broken = [
            "",
            "{",
            "}",
            "[1,",
            "{\"a\"}",
            "{\"a\":}",
            "{\"a\":1,}",
            "{a:1}",
            "\"unterminated",
            "tru",
            "nul",
            "01",
            "-",
            "1.",
            "1e",
            "1e+",
            "{} {}",
            "[1] trailing",
            "\u{0001}",
        ];
        for text in broken {
            assert!(
                Json::parse(text).is_err(),
                "{text:?} should not have parsed"
            );
        }
    }

    #[test]
    fn a_control_character_in_a_string_is_an_error() {
        assert!(Json::parse("\"a\u{0001}b\"").is_err());
    }

    #[test]
    fn writes_a_value_back_as_text() {
        let value = Json::parse(r#"{"a":[1,2,{"b":"c"}],"d":null,"e":true}"#).expect("parse");
        assert_eq!(value.write(), r#"{"a":[1,2,{"b":"c"}],"d":null,"e":true}"#);
    }

    #[test]
    fn a_value_survives_being_written_and_read_again() {
        let original = r#"[{"a":1,"b":[true,false,null,"x"]},{"c":-1.5}]"#;
        let value = Json::parse(original).expect("parse");
        let again = Json::parse(&value.write()).expect("the written text should parse");
        assert_eq!(value, again);
    }

    #[test]
    fn writes_the_escapes_json_requires() {
        let value = Json::Str("a\"b\\c\nd\te\u{0001}f".to_string());
        assert_eq!(value.write(), r#""a\"b\\c\nd\te\u0001f""#);
    }

    #[test]
    fn writes_whole_numbers_without_a_fraction() {
        assert_eq!(Json::Num(9050.0).write(), "9050");
        assert_eq!(Json::Num(-3.0).write(), "-3");
        assert_eq!(Json::Num(1.5).write(), "1.5");
    }

    #[test]
    fn the_helpers_build_what_they_say() {
        assert_eq!(s("x"), Json::Str("x".to_string()));
        assert_eq!(n(9050), Json::Num(9050.0));
        assert_eq!(
            obj(vec![("a", s("b"))]),
            Json::Obj(vec![("a".to_string(), Json::Str("b".to_string()))])
        );
    }

    #[test]
    fn a_value_of_the_wrong_kind_reads_as_nothing() {
        let value = Json::parse(r#"{"a":"x","b":1,"c":true}"#).expect("parse");
        assert_eq!(value.get("a").and_then(Json::as_i64), None);
        assert_eq!(value.get("b").and_then(Json::as_str), None);
        assert_eq!(value.get("a").and_then(Json::as_bool), None);
        assert_eq!(value.get("b").and_then(Json::as_bool), None);
        assert_eq!(value.get("c").and_then(Json::as_bool), Some(true));
        assert_eq!(value.get("c").and_then(Json::as_str), None);
    }
}
