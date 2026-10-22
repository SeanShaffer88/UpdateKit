//! A minimal JSON parser — just enough to read update manifests.
//! Objects, arrays, strings (with \u escapes), numbers, booleans, null.
//! Strict about structure, permissive about whitespace; errors carry a
//! byte offset. Not a general JSON library: no serialization (the FFI
//! builds result JSON with json_escape), no duplicate-key policy
//! duplicate keys are rejected to avoid ambiguous security-sensitive fields.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(BTreeMap<String, Value>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Num(n) if *n >= 0.0 && n.fract() == 0.0 && *n < u64::MAX as f64 => {
                Some(*n as u64)
            }
            _ => None,
        }
    }
}

pub fn parse(input: &str) -> Result<Value, String> {
    if input.len() > 1024 * 1024 {
        return Err("JSON exceeds 1 MiB limit".into());
    }
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(format!("trailing characters at byte {}", p.pos));
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn value(&mut self) -> Result<Value, String> {
        if self.depth >= 64 {
            return Err("JSON nesting exceeds 64 levels".into());
        }
        self.depth += 1;
        let result = self.value_inner();
        self.depth -= 1;
        result
    }

    fn value_inner(&mut self) -> Result<Value, String> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(format!("unexpected character at byte {}", self.pos)),
        }
    }

    fn literal(&mut self, lit: &str, v: Value) -> Result<Value, String> {
        if self.bytes[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(v)
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.pos += 1; // {
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Obj(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected object key at byte {}", self.pos));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at byte {}", self.pos));
            }
            self.pos += 1;
            self.skip_ws();
            let val = self.value()?;
            if map.insert(key, val).is_some() {
                return Err(format!("duplicate object key at byte {}", self.pos));
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Obj(map));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.pos)),
            }
        }
    }

    fn array(&mut self) -> Result<Value, String> {
        self.pos += 1; // [
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Arr(items));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.pos)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        // Caller guarantees the opening quote.
        self.pos += 1;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.pos += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.peek().ok_or("unterminated escape")?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            if (0xD800..0xDC00).contains(&hi) {
                                // High surrogate: expect \uXXXX low half.
                                if self.peek() == Some(b'\\') {
                                    self.pos += 1;
                                    if self.peek() == Some(b'u') {
                                        self.pos += 1;
                                        let lo = self.hex4()?;
                                        let c = 0x10000
                                            + (((hi - 0xD800) as u32) << 10)
                                            + (lo as u32 - 0xDC00);
                                        out.push(
                                            char::from_u32(c).ok_or("invalid surrogate pair")?,
                                        );
                                        continue;
                                    }
                                    return Err("expected low surrogate".into());
                                }
                                return Err("lone high surrogate".into());
                            }
                            out.push(char::from_u32(hi as u32).ok_or("invalid \\u escape")?);
                        }
                        _ => return Err(format!("invalid escape at byte {}", self.pos)),
                    }
                }
                _ => {
                    // Consume the full UTF-8 sequence for this char.
                    let start = self.pos - 1;
                    let len = utf8_len(self.bytes[start]);
                    let end = (start + len).min(self.bytes.len());
                    out.push_str(
                        std::str::from_utf8(&self.bytes[start..end])
                            .map_err(|_| "invalid UTF-8 in string")?,
                    );
                    self.pos = end;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("truncated \\u escape".into());
        }
        let s = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
            .map_err(|_| "invalid \\u escape")?;
        self.pos += 4;
        u16::from_str_radix(s, 16).map_err(|_| "invalid \\u escape".to_string())
    }

    fn number(&mut self) -> Result<Value, String> {
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
            _ => return Err("invalid JSON integer".into()),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            let digits = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if digits == self.pos {
                return Err("missing fractional digits".into());
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let digits = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if digits == self.pos {
                return Err("missing exponent digits".into());
            }
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap_or("");
        let n = s
            .parse::<f64>()
            .map_err(|_| format!("invalid number at byte {start}"))?;
        if !n.is_finite() {
            return Err("non-finite JSON number".into());
        }
        Ok(Value::Num(n))
    }
}

fn utf8_len(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_manifest_shape() {
        let v = parse(
            r#"{"version":"1.4.0","mandatory":false,"size":12345,"notes":"hi \"there\"\n","tags":["a","b"],"nested":{"x":null}}"#,
        )
        .unwrap();
        assert_eq!(v.get("version").unwrap().as_str(), Some("1.4.0"));
        assert_eq!(v.get("mandatory").unwrap().as_bool(), Some(false));
        assert_eq!(v.get("size").unwrap().as_u64(), Some(12345));
        assert_eq!(v.get("notes").unwrap().as_str(), Some("hi \"there\"\n"));
        assert_eq!(v.get("nested").unwrap().get("x"), Some(&Value::Null));
    }

    #[test]
    fn unicode_escapes_and_surrogates() {
        let v = parse(r#""café 😀""#).unwrap();
        assert_eq!(v.as_str(), Some("café 😀"));
        let v = parse(r#""caf\u00e9 \ud83d\ude00""#).unwrap();
        assert_eq!(v.as_str(), Some("café 😀"));
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "{",
            "{\"a\":}",
            "[1,",
            "tru",
            "{\"a\":1} extra",
            "\"unterminated",
        ] {
            assert!(parse(bad).is_err(), "should reject: {bad}");
        }
    }
}
