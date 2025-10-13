//! HTTP Language Example
//!
//! HTTP Semantics
//! <https://www.rfc-editor.org/rfc/rfc9110.html>
//!
//! HTTP/1.1
//! <https://www.rfc-editor.org/rfc/rfc9112.htm>

use std::{collections::BTreeMap, sync::Arc};

use pang::{
    DerivationTree, Grammar, exp, exp_dc, grammar, nt, nt_nom, symbol::DecodeError, t_bytes_val,
    t_dyn,
};

use crate::helper::find_symbol_with_offset;

pub fn http_grammar() -> Grammar {
    grammar! {
        "http-message" => [exp([
            nt("start-line"), nt_nom("field-line", 0),
            nt("CRLF"), nt("message-body")
        ])],
        "start-line" => [exp_dc([t_dyn()], find_crlf_decode_callback)],
        "message-body" => [exp([t_dyn()])],
        "field-line" => [exp([
            nt("field-name"), t_bytes_val(b":"), nt("field-value"), nt("CRLF")
        ])],
        "CRLF" => [exp([t_bytes_val(b"\r\n")])],
        "field-name" => [exp_dc([t_dyn()], find_colon_decode_callback)],
        "field-value" => [exp_dc([t_dyn()], find_crlf_offset_0_decode_callback)],
    }
}

fn find_crlf_decode_callback<'a>(
    input: &'a [u8],
    _context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    find_symbol_with_offset(input, b"\r\n", 2)
}

fn find_crlf_offset_0_decode_callback<'a>(
    input: &'a [u8],
    _context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    find_symbol_with_offset(input, b"\r\n", 0)
}

fn find_crlfx2_decode_callback<'a>(
    input: &'a [u8],
    _context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    find_symbol_with_offset(input, b"\r\n\r\n", 2)
}

fn find_colon_decode_callback<'a>(
    input: &'a [u8],
    _context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    find_symbol_with_offset(input, b":", 0)
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use super::*;

    static INIT: Once = Once::new();

    pub fn setup_logger() {
        INIT.call_once(|| {
            let _ = env_logger::try_init();
        });
    }

    #[test]
    fn test_http_grammar() {
        setup_logger();
        let mut http_message = b"POST /users HTTP/1.1\r\n".to_vec();
        http_message.extend_from_slice(b"Host: example.com\r\n");
        http_message.extend_from_slice(b"Content-Type: application/x-www-form-urlencoded\r\n");
        http_message.extend_from_slice(b"Content-Length: 49\r\n");
        http_message.extend_from_slice(b"\r\n");
        http_message.extend_from_slice(b"name=FirstName+LastName&email=bsmth%40example.com");
        let grammar = http_grammar();
        assert!(grammar.is_valid("http-message"));
        let tree = grammar
            .parse_combinator(&http_message, "http-message")
            .unwrap();
        assert_eq!(&tree.to_bytes(), &http_message);
    }
}
