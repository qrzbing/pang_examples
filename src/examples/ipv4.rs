//! IPv4 Language Example

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use pang::parser::callback::big_endian_bytes_to_usize;
use pang::{
    DerivationTree, ExpansionCallback, Grammar, Language, exp, exp_with_opts, grammar, nt, opts,
    symbol::DecodeError, t_bytes, t_dyn,
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
        "options" => vec![exp_with_opts(
            vec![t_dyn()], opts! {
                "length_calculator" => options_callback as ExpansionCallback,
            }
        )],
        "ipv4_body" => vec![exp_with_opts(vec![t_dyn()], opts!("length_calculator" => body_callback as ExpansionCallback))],
    }
}

fn options_callback(
    parent_context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<usize, DecodeError> {
    let b1_tree = parent_context.get("b1").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation",
    ))?;
    let b1 = big_endian_bytes_to_usize(&b1_tree.to_bytes())?;

    let ihl = b1 & 0x0f;
    let ihl_bytes = ihl * 4;
    Ok(ihl_bytes - 20)
}

fn body_callback(
    parent_context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<usize, DecodeError> {
    let total_length_tree = parent_context
        .get("total_length")
        .ok_or(DecodeError::Invalid(
            "Symbol not found in context for length calculation",
        ))?;
    let total_length = big_endian_bytes_to_usize(&total_length_tree.to_bytes())?;

    let b1_tree = parent_context.get("b1").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation",
    ))?;
    let b1 = big_endian_bytes_to_usize(&b1_tree.to_bytes())?;

    let ihl = b1 & 0x0f;
    let ihl_bytes = ihl * 4;
    Ok(total_length - ihl_bytes)
}

pub fn ipv4_options_grammar() -> Grammar {
    grammar! {
        "options" => vec![exp_with_opts(
            vec![nt("ipv4_options")], opts! {
                "length_calculator" => options_callback as ExpansionCallback,
            }
        )],
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
            exp_with_opts(vec![t_dyn()], opts! {
                "length_calculator" => ipv4_option_body_callback as ExpansionCallback
            })
        ],
    }
}

fn ipv4_option_body_callback(
    parent_context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<usize, DecodeError> {
    let ipv4_option_len_tree = parent_context.get("incl_len").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation",
    ))?;

    let ipv4_option_len = big_endian_bytes_to_usize(&ipv4_option_len_tree.to_bytes())?;

    if ipv4_option_len > 2 {
        Ok(ipv4_option_len - 2)
    } else {
        Ok(0)
    }
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
