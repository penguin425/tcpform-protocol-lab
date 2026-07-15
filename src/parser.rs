//! Hand-rolled lexer + recursive-descent parser for a block-oriented grammar.
//!
//! ```text
//! file       := block*
//! block      := IDENT (STRING)* "{" body "}"
//! body       := item*
//! item       := attribute | block
//! attribute  := IDENT "=" expr
//! expr       := STRING | NUMBER | BOOL | array | object
//! array      := "[" (expr ("," expr)*)? "]"
//! object     := "{" (attribute)* "}"
//! ```
//!
//! Not newline-sensitive: an `IDENT` followed by `=` is an attribute; an
//! `IDENT` followed by a string label or `{` is a block.

use crate::ast::Block;
use crate::value::Value;
use std::collections::HashMap;

/// Parse error with a 1-based line number.
#[derive(Debug, Clone)]
pub struct ParseError {
    pub source: Option<String>,
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(source) => write!(
                f,
                "{source}:{}:{}: parse error: {}",
                self.line, self.column, self.message
            ),
            None => write!(
                f,
                "parse error ({}:{}): {}",
                self.line, self.column, self.message
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a source string into a list of top-level blocks.
pub fn parse_file(src: &str) -> Result<Vec<Block>, ParseError> {
    parse_file_named(src, None)
}

pub fn parse_file_named(src: &str, source: Option<&str>) -> Result<Vec<Block>, ParseError> {
    let attach_source = |mut error: ParseError| {
        error.source = source.map(str::to_string);
        error
    };
    let tokens = Lexer::new(src).tokenize().map_err(&attach_source)?;
    let mut p = Parser { tokens, pos: 0 };
    let mut blocks = Vec::new();
    while !p.at_end() {
        blocks.push(p.parse_block().map_err(&attach_source)?);
    }
    set_source(&mut blocks, source);
    Ok(blocks)
}

fn set_source(blocks: &mut [Block], source: Option<&str>) {
    for block in blocks {
        block.source = source.map(str::to_string);
        set_source(&mut block.blocks, source);
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    String(String),
    Number(f64),
    Bool(bool),
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Equals,
    Comma,
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    kind: Tok,
    line: usize,
    column: usize,
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: usize,
    column: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Lexer {
            src: src.as_bytes(),
            pos: 0,
            line: 1,
            column: 1,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.src.get(self.pos).copied();
        if let Some(b) = c {
            self.pos += 1;
            if b == b'\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
        }
        c
    }
    fn skip_ws_and_comments(&mut self) {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => {
                    self.bump();
                }
                Some(b'#') => {
                    while let Some(c) = self.peek() {
                        if c == b'\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                Some(b'/') if self.src.get(self.pos + 1) == Some(&b'/') => {
                    while let Some(c) = self.peek() {
                        if c == b'\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                _ => break,
            }
        }
    }

    fn tokenize(mut self) -> Result<Vec<Token>, ParseError> {
        let mut out = Vec::new();
        loop {
            self.skip_ws_and_comments();
            let line = self.line;
            let column = self.column;
            let Some(c) = self.peek() else {
                out.push(Token {
                    kind: Tok::Eof,
                    line,
                    column,
                });
                break;
            };
            let tok = match c {
                b'{' => {
                    self.bump();
                    Tok::LBrace
                }
                b'}' => {
                    self.bump();
                    Tok::RBrace
                }
                b'[' => {
                    self.bump();
                    Tok::LBracket
                }
                b']' => {
                    self.bump();
                    Tok::RBracket
                }
                b'=' => {
                    self.bump();
                    Tok::Equals
                }
                b',' => {
                    self.bump();
                    Tok::Comma
                }
                b'"' => Tok::String(self.read_string(line, column)?),
                b'0'..=b'9' | b'-' => self.read_number(line, column)?,
                c if c.is_ascii_alphabetic() || c == b'_' => self.read_ident(),
                other => {
                    return Err(ParseError {
                        source: None,
                        line,
                        column,
                        message: format!("unexpected character {:#?}", other as char),
                    });
                }
            };
            out.push(Token {
                kind: tok,
                line,
                column,
            });
        }
        Ok(out)
    }

    fn read_string(&mut self, line: usize, column: usize) -> Result<String, ParseError> {
        self.bump(); // opening quote
        let mut s = String::new();
        loop {
            match self.bump() {
                None => {
                    return Err(ParseError {
                        source: None,
                        line,
                        column,
                        message: "unterminated string".into(),
                    });
                }
                Some(b'"') => break,
                Some(b'\\') => match self.bump() {
                    Some(b'n') => s.push('\n'),
                    Some(b't') => s.push('\t'),
                    Some(b'r') => s.push('\r'),
                    Some(b'"') => s.push('"'),
                    Some(b'\\') => s.push('\\'),
                    Some(other) => s.push(other as char),
                    None => {
                        return Err(ParseError {
                            source: None,
                            line,
                            column,
                            message: "unterminated escape".into(),
                        })
                    }
                },
                Some(b) => s.push(b as char),
            }
        }
        Ok(s)
    }
    fn read_number(&mut self, line: usize, column: usize) -> Result<Tok, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        let mut saw_digit = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                saw_digit = true;
                self.bump();
            } else {
                break;
            }
        }
        if self.peek() == Some(b'.') {
            self.bump();
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() {
                    saw_digit = true;
                    self.bump();
                } else {
                    break;
                }
            }
        }
        if !saw_digit {
            return Err(ParseError {
                source: None,
                line,
                column,
                message: "invalid number".into(),
            });
        }
        let text = std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("");
        let n: f64 = text.parse().map_err(|_| ParseError {
            source: None,
            line,
            column,
            message: format!("invalid number {text:?}"),
        })?;
        Ok(Tok::Number(n))
    }

    fn read_ident(&mut self) -> Tok {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
                self.bump();
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("");
        match text {
            "true" => Tok::Bool(true),
            "false" => Tok::Bool(false),
            "null" => Tok::Ident("null".into()),
            _ => Tok::Ident(text.into()),
        }
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn at_end(&self) -> bool {
        matches!(self.tokens[self.pos].kind, Tok::Eof)
    }

    fn peek(&self) -> &Tok {
        &self.tokens[self.pos].kind
    }

    fn peek_line(&self) -> usize {
        self.tokens[self.pos].line
    }

    fn peek_column(&self) -> usize {
        self.tokens[self.pos].column
    }

    fn bump(&mut self) -> &Tok {
        self.pos += 1;
        &self.tokens[self.pos - 1].kind
    }

    fn err(&self, line: usize, msg: impl Into<String>) -> ParseError {
        ParseError {
            source: None,
            line,
            column: self.peek_column(),
            message: msg.into(),
        }
    }

    fn parse_block(&mut self) -> Result<Block, ParseError> {
        let line = self.peek_line();
        let column = self.peek_column();
        let Tok::Ident(name) = self.bump().clone() else {
            return Err(self.err(line, "expected block name"));
        };
        let mut labels = Vec::new();
        while let Tok::String(s) = self.peek().clone() {
            self.bump();
            labels.push(s);
        }
        // Top-level import directives intentionally omit a body:
        // `import "relative/file.tcpf"`.
        if name == "import" && matches!(labels.len(), 1 | 2) && !matches!(self.peek(), Tok::LBrace)
        {
            return Ok(Block {
                name,
                labels,
                attributes: HashMap::new(),
                blocks: Vec::new(),
                source: None,
                line,
                column,
            });
        }
        if !matches!(self.peek(), Tok::LBrace) {
            return Err(self.err(line, format!("expected '{{' after block `{name}`")));
        }
        self.bump(); // {
        let mut block = Block {
            name,
            labels,
            attributes: HashMap::new(),
            blocks: Vec::new(),
            source: None,
            line,
            column,
        };
        self.parse_body(&mut block)?;
        Ok(block)
    }
    fn parse_body(&mut self, block: &mut Block) -> Result<(), ParseError> {
        loop {
            match self.peek() {
                Tok::RBrace => {
                    self.bump();
                    return Ok(());
                }
                Tok::Eof => {
                    return Err(self.err(self.peek_line(), "unexpected end of file, missing '}'"));
                }
                Tok::Ident(name) => {
                    let name = name.clone();
                    // attribute vs block: an `=` after the ident => attribute
                    if self.tokens.get(self.pos + 1).map(|t| &t.kind) == Some(&Tok::Equals) {
                        self.bump(); // ident
                        self.bump(); // =
                        let val = self.parse_expr()?;
                        if block.attributes.insert(name.clone(), val).is_some() {
                            return Err(
                                self.err(self.peek_line(), format!("duplicate attribute `{name}`"))
                            );
                        }
                    } else {
                        let child = self.parse_block()?;
                        block.blocks.push(child);
                    }
                }
                Tok::String(s) => {
                    // quoted key — always an attribute (strings can't start blocks)
                    let name = s.clone();
                    if !matches!(
                        self.tokens.get(self.pos + 1).map(|t| &t.kind),
                        Some(Tok::Equals)
                    ) {
                        return Err(self.err(self.peek_line(), "expected '=' after quoted key"));
                    }
                    self.bump(); // string
                    self.bump(); // =
                    let val = self.parse_expr()?;
                    if block.attributes.insert(name.clone(), val).is_some() {
                        return Err(
                            self.err(self.peek_line(), format!("duplicate attribute `{name}`"))
                        );
                    }
                }
                other => {
                    return Err(self.err(
                        self.peek_line(),
                        format!("expected identifier, got {other:?}"),
                    ));
                }
            }
        }
    }

    fn parse_expr(&mut self) -> Result<Value, ParseError> {
        let line = self.peek_line();
        match self.peek().clone() {
            Tok::String(s) => {
                self.bump();
                Ok(Value::String(s))
            }
            Tok::Number(n) => {
                self.bump();
                Ok(Value::Number(n))
            }
            Tok::Bool(b) => {
                self.bump();
                Ok(Value::Bool(b))
            }
            Tok::LBracket => self.parse_array(),
            Tok::LBrace => self.parse_object(),
            Tok::Ident(i) if i == "null" => {
                self.bump();
                Ok(Value::Null)
            }
            other => Err(self.err(line, format!("expected value, got {other:?}"))),
        }
    }

    fn parse_array(&mut self) -> Result<Value, ParseError> {
        self.bump(); // [
        let mut items = Vec::new();
        loop {
            if matches!(self.peek(), Tok::RBracket) {
                self.bump();
                break;
            }
            items.push(self.parse_expr()?);
            match self.peek() {
                Tok::Comma => {
                    self.bump();
                }
                Tok::RBracket => {
                    self.bump();
                    break;
                }
                other => {
                    return Err(self.err(
                        self.peek_line(),
                        format!("expected ',' or ']', got {other:?}"),
                    ));
                }
            }
        }
        Ok(Value::Array(items))
    }

    fn parse_object(&mut self) -> Result<Value, ParseError> {
        self.bump(); // {
        let mut obj = HashMap::new();
        loop {
            match self.peek() {
                Tok::RBrace => {
                    self.bump();
                    break;
                }
                Tok::Ident(name) | Tok::String(name) => {
                    let name = name.clone();
                    if !matches!(
                        self.tokens.get(self.pos + 1).map(|t| &t.kind),
                        Some(Tok::Equals)
                    ) {
                        return Err(self.err(self.peek_line(), "expected '=' in object"));
                    }
                    self.bump(); // key
                    self.bump(); // =
                    let val = self.parse_expr()?;
                    if obj.insert(name.clone(), val).is_some() {
                        return Err(
                            self.err(self.peek_line(), format!("duplicate object key `{name}`"))
                        );
                    }
                }
                other => {
                    return Err(self.err(
                        self.peek_line(),
                        format!("expected identifier in object, got {other:?}"),
                    ));
                }
            }
        }
        Ok(Value::Object(obj))
    }
}
