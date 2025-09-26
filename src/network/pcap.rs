//! Pcap Language Example

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use pang::tl_bytes;
use pang::{
    DerivationTree, Grammar, Language, exp, exp_dc, grammar, nt,
    parser::callback::little_endian_bytes_to_usize, symbol::DecodeError, t_bytes_val, t_dyn,
    tl_bytes_val,
};

fn pcap_grammar() -> Grammar {
    grammar! {
        "pcap" => [exp([nt("pcap_seq")])],
        "pcap_seq" => [
            exp([
                nt("header"),
                nt("packets"),
            ])
        ],
        "header" => [exp([
            t_bytes_val(&[0xd4, 0xc3, 0xb2, 0xa1]),
            tl_bytes_val("version_major", &[0x02, 0x00]),
            tl_bytes("version_minor", 2),
            tl_bytes("thiszone", 4),
            tl_bytes("sigfigs", 4),
            tl_bytes("snaplen", 4),
            tl_bytes("network", 4),
        ])],
        "packets" => [
            exp([nt("packet")]),
            exp([nt("packet"), nt("packets")]),
            exp([t_dyn()]),
        ],
        "packet" => [
            exp(
                [
                    tl_bytes("ts_sec", 4),
                    tl_bytes("ts_usec", 4),
                    tl_bytes("incl_len", 4),
                    tl_bytes("orig_len", 4),
                    nt("pcap_body"),
                ]
            )
        ],
        "pcap_body" => [exp_dc([t_dyn()], body_decode_callbackfn)]
    }
}

pub fn body_decode_callbackfn<'a>(
    input: &'a [u8],
    context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    let incl_len_tree = context.get("incl_len").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation".into(),
    ))?;

    let incl_len = little_endian_bytes_to_usize(&incl_len_tree.to_bytes())?;

    let (slice_to_parse, remaining_input) = input.split_at(incl_len);

    Ok((remaining_input, slice_to_parse.to_vec()))
}

/// Generate a Pcap language.
pub fn pcap_lang() -> Language {
    let grammar = pcap_grammar();

    assert!(grammar.is_valid("pcap"));

    Language::new(&grammar, "pcap", HashSet::new())
}

#[cfg(test)]
mod tests {
    use std::{env, fs, sync::Once};

    use pang::exp_dc;

    use crate::network::{
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
                "pcap_body" => [
                    exp_dc([nt("ethernet_frame")], body_decode_callbackfn)
                ]
            })
            .extend_grammar(&ethernet_frame_grammar())
            .extend_grammar(&grammar! {
                "ethernet_body" => [
                    exp([nt("ipv4_packet")])
                ]
            })
            .extend_grammar(&ipv4_grammar())
            .extend_grammar(&ipv4_options_grammar());

        assert!(grammar.is_valid("pcap"));
        let lang = Language::new(&grammar, "pcap", HashSet::new());
        let tree = lang.parse(&inp_data).unwrap();
        println!("Tree:\n{}", tree);
    }
}
