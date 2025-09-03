//! IPv4 Language Example

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use pang::exp_cb;
use pang::parser::callback::big_endian_bytes_to_usize;
use pang::{
    DerivationTree, Grammar, Language, exp, grammar, nt, symbol::DecodeError, t_bytes, t_dyn,
};

pub fn ipv4_grammar() -> Grammar {
    grammar! {
        "ipv4_packet" => vec![exp(vec![nt("ipv4_seq")])],
        "ipv4_seq" => vec![
            exp(vec![
                nt("b1"),
                nt("b2"),
                nt("total_length"),
                nt("identification"),
                nt("b67"),
                nt("ttl"),
                nt("protocol"),
                nt("header_checksum"),
                nt("src_ip_addr"),
                nt("dst_ip_addr"),
                nt("options"),
                nt("ipv4_body"),
            ])
        ],
        "b1" => vec![exp(vec![t_bytes(1)])],
        "b2" => vec![exp(vec![t_bytes(1)])],
        "total_length" => vec![exp(vec![t_bytes(2)])],
        "identification" => vec![exp(vec![t_bytes(2)])],
        "b67" => vec![exp(vec![t_bytes(2)])],
        "ttl" => vec![exp(vec![t_bytes(1)])],
        "protocol" => vec![exp(vec![t_bytes(1)])],
        "header_checksum" => vec![exp(vec![t_bytes(2)])],
        "src_ip_addr" => vec![exp(vec![t_bytes(4)])],
        "dst_ip_addr" => vec![exp(vec![t_bytes(4)])],
        "options" => vec![exp_cb(vec![t_dyn()], Some(options_decode_callbackfn), None)],
        "ipv4_body" => vec![exp_cb(vec![t_dyn()], Some(body_decode_callbackfn), None)],
    }
}

pub fn options_decode_callbackfn<'a>(
    input: &'a [u8],
    context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    let b1_tree = context.get("b1").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation",
    ))?;
    let b1 = big_endian_bytes_to_usize(&b1_tree.to_bytes())?;

    let ihl = b1 & 0x0f;
    let ihl_bytes = ihl * 4;

    let (slice_to_parse, remaining_input) = input.split_at(ihl_bytes - 20);

    Ok((remaining_input, slice_to_parse.to_vec()))
}

pub fn body_decode_callbackfn<'a>(
    input: &'a [u8],
    context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    let total_length_tree = context.get("total_length").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation",
    ))?;
    let total_length = big_endian_bytes_to_usize(&total_length_tree.to_bytes())?;

    let b1_tree = context.get("b1").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation",
    ))?;
    let b1 = big_endian_bytes_to_usize(&b1_tree.to_bytes())?;

    let ihl = b1 & 0x0f;
    let ihl_bytes = ihl * 4;

    let (slice_to_parse, remaining_input) = input.split_at(total_length - ihl_bytes);

    Ok((remaining_input, slice_to_parse.to_vec()))
}

pub fn ipv4_options_grammar() -> Grammar {
    grammar! {
        "options" => vec![exp_cb(vec![nt("ipv4_options")], Some(options_decode_callbackfn), None)],
        "ipv4_options" => vec![
            exp(vec![nt("ipv4_option")]),
            exp(vec![nt("ipv4_option"), nt("ipv4_options")]),
            exp(vec![t_dyn()])
        ],
        "ipv4_option" => vec![
            exp(vec![t_bytes(1), nt("ipv4_option_len"), nt("ipv4_option_body")]),
        ],
        "ipv4_option_len" => vec![exp(vec![t_bytes(1)])],
        "ipv4_option_body" => vec![
            exp_cb(vec![t_dyn()], Some(ipv4_option_body_decode_callbackfn), None)
        ],
    }
}

pub fn ipv4_option_body_decode_callbackfn<'a>(
    input: &'a [u8],
    context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    let ipv4_option_len_tree = context.get("incl_len").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation",
    ))?;

    let ipv4_option_len = big_endian_bytes_to_usize(&ipv4_option_len_tree.to_bytes())?;

    let (slice_to_parse, remaining_input) = if ipv4_option_len > 2 {
        input.split_at(ipv4_option_len - 2)
    } else {
        input.split_at(0)
    };

    Ok((remaining_input, slice_to_parse.to_vec()))
}

/// Generate a IPv4 small language.
pub fn ipv4_lang_less() -> Language {
    let grammar = ipv4_grammar();

    assert!(grammar.is_valid("ipv4_packet"));

    Language::new(grammar, "ipv4_packet", HashSet::new())
}

/// Generate a IPv4 full language.
pub fn ipv4_lang_full() -> Language {
    let grammar = ipv4_grammar().extend_grammar(&ipv4_options_grammar());

    assert!(grammar.is_valid("ipv4_packet"));

    Language::new(grammar, "ipv4_packet", HashSet::new())
}

#[cfg(test)]
mod tests {
    use std::{env, fs, sync::Once};

    use super::*;

    static INIT: Once = Once::new();

    fn setup_logger() {
        INIT.call_once(|| {
            let _ = env_logger::try_init();
        });
    }

    #[test]
    fn test_ipv4_lang_less() {
        setup_logger();
        let ipv4_input_path = env::current_dir().unwrap().join("assets/ipv4.bin");

        let inp_data = match fs::read(ipv4_input_path) {
            Ok(data) => data,
            Err(e) => {
                println!("Failed to read input file: {}", e);
                return;
            }
        };

        let lang = ipv4_lang_less();
        let tree = lang.parse(&inp_data).unwrap();
        println!("Tree:\n{}", tree);
    }

    #[test]
    fn test_ipv4_lang_full() {
        setup_logger();
        let ipv4_input_path = env::current_dir().unwrap().join("assets/ipv4.bin");

        let inp_data = match fs::read(ipv4_input_path) {
            Ok(data) => data,
            Err(e) => {
                println!("Failed to read input file: {}", e);
                return;
            }
        };

        let lang = ipv4_lang_full();
        let tree = lang.parse(&inp_data).unwrap();
        println!("Tree:\n{}", tree);
    }
}
