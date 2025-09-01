//! Pcap Language Example

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use pang::{
    DerivationTree, ExpansionCallback, Grammar, Language, exp, exp_with_opts, grammar, nt, opts,
    parser::callback::little_endian_bytes_to_usize, symbol::DecodeError, t_bytes, t_bytes_val,
    t_dyn,
};

fn pcap_grammar() -> Grammar {
    grammar! {
        "pcap" => vec![exp(vec![nt("pcap_seq")])],
        "pcap_seq" => vec![
            exp(vec![
                nt("header"),
                nt("packets"),
            ])
        ],
        "header" => vec![exp(vec![
            t_bytes_val(&[0xd4, 0xc3, 0xb2, 0xa1]),
            nt("version_major"),
            nt("version_minor"),
            nt("thiszone"),
            nt("sigfigs"),
            nt("snaplen"),
            nt("network"),
        ])],
        "version_major" => vec![exp(vec![t_bytes_val(&[0x02, 0x00])])],
        "version_minor" => vec![exp(vec![t_bytes(2)])],
        "thiszone" => vec![exp(vec![t_bytes(4)])],
        "sigfigs" => vec![exp(vec![t_bytes(4)])],
        "snaplen" => vec![exp(vec![t_bytes(4)])],
        "network" => vec![exp(vec![t_bytes(4)])],
        "packets" => vec![
            exp(vec![nt("packet")]),
            exp(vec![nt("packet"), nt("packets")]),
            exp(vec![t_dyn()]),
        ],
        "packet" => vec![
            exp(
                vec![
                    nt("ts_sec"),
                    nt("ts_usec"),
                    nt("incl_len"),
                    nt("orig_len"),
                    nt("pcap_body"),
                ]
            )
        ],
        "ts_sec" => vec![exp(vec![t_bytes(4)])],
        "ts_usec" => vec![exp(vec![t_bytes(4)])],
        "incl_len" => vec![exp(vec![t_bytes(4)])],
        "orig_len" => vec![exp(vec![t_bytes(4)])],
        "pcap_body" => vec![exp_with_opts(vec![t_dyn()], opts!(
            "length_calculator" => body_callback as ExpansionCallback
        ))]
    }
}

fn body_callback(
    parent_context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<usize, DecodeError> {
    let incl_len_tree = parent_context.get("incl_len").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation",
    ))?;

    // debug!("incl_len_tree bytes: {:#?}", incl_len_tree.to_bytes());

    let incl_len = little_endian_bytes_to_usize(&incl_len_tree.to_bytes())?;

    Ok(incl_len as usize)
}

/// Generate a Pcap language.
pub fn pcap_lang() -> Language {
    let grammar = pcap_grammar();

    assert!(grammar.is_valid("pcap"));

    Language::new(grammar, "pcap", HashSet::new())
}

#[cfg(test)]
mod tests {
    use std::{env, fs, sync::Once};

    use crate::examples::{
        ethernet_frame::ethernet_frame_grammar,
        ipv4::{ipv4_grammar, ipv4_options_grammar},
    };

    use super::*;

    static INIT: Once = Once::new();

    fn setup_logger() {
        INIT.call_once(|| {
            let _ = env_logger::try_init();
        });
    }

    #[test]
    fn test_pcap_lang() {
        setup_logger();
        let pcap_input_path = env::current_dir()
            .unwrap()
            .join("assets/small_capture.pcap");

        let inp_data = match fs::read(pcap_input_path) {
            Ok(data) => data,
            Err(e) => {
                println!("Failed to read input file: {}", e);
                return;
            }
        };
        let lang = pcap_lang();
        let tree = lang.parse(&inp_data).unwrap();
        println!("Tree:\n{}", tree);
    }

    #[test]
    fn test_extend_with_ipv4_grammar() {
        setup_logger();
        let pcap_input_path = env::current_dir()
            .unwrap()
            .join("assets/small_capture.pcap");

        let inp_data = match fs::read(pcap_input_path) {
            Ok(data) => data,
            Err(e) => {
                println!("Failed to read input file: {}", e);
                return;
            }
        };

        let grammar = pcap_grammar()
            .extend_grammar(&grammar! {
                "pcap_body" => vec![
                    exp_with_opts(vec![nt("ethernet_frame")], opts!{
                        "length_calculator" => body_callback as ExpansionCallback
                    })
                ]
            })
            .extend_grammar(&ethernet_frame_grammar())
            .extend_grammar(&grammar! {
                "ethernet_body" => vec![
                    exp(vec![nt("ipv4_packet")])
                ]
            })
            .extend_grammar(&ipv4_grammar())
            .extend_grammar(&ipv4_options_grammar());

        assert!(grammar.is_valid("pcap"));
        let lang = Language::new(grammar, "pcap", HashSet::new());
        let tree = lang.parse(&inp_data).unwrap();
        println!("Tree:\n{}", tree);
    }
}
