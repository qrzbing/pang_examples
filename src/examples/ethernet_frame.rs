//! Ethernet Frame Language Example

use std::collections::BTreeMap;
use std::sync::Arc;

use pang::{
    DerivationTree, ExpansionCallback, Grammar, exp, exp_with_opts, grammar, nt, opts,
    parser::callback::big_endian_bytes_to_usize, symbol::DecodeError, t_bytes, t_dyn,
};

pub fn ethernet_frame_grammar() -> Grammar {
    grammar! {
        "ethernet_frame" => vec![exp(vec![nt("ethernet_frame_seq")])],
        "ethernet_frame_seq" => vec![
            exp(vec![
                nt("dst_mac"),
                nt("src_mac"),
                nt("ether_type_1"),
                nt("tci"),
                nt("ether_type_2"),
                nt("ethernet_body")
            ])
        ],
        "dst_mac" => vec![exp(vec![t_bytes(6)])],
        "src_mac" => vec![exp(vec![t_bytes(6)])],
        "ether_type_1" => vec![exp(vec![t_bytes(2)])],
        "tci" => vec![
            exp_with_opts(vec![t_dyn()], opts!{
                "length_calculator" => tci_callback as ExpansionCallback,
            })
        ],
        "ether_type_2" => vec![exp_with_opts(vec![t_dyn()], opts!{
            "length_calculator" => ether_type_2_callback as ExpansionCallback,
        })],
        "ethernet_body" => vec![exp(vec![t_dyn()])]
    }
}

fn tci_callback(
    parent_context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<usize, DecodeError> {
    let ether_type_1_tree = parent_context
        .get("ether_type_1")
        .ok_or(DecodeError::Invalid(
            "Symbol not found in context for length calculation",
        ))?;

    let ether_type_1_val = big_endian_bytes_to_usize(&ether_type_1_tree.to_bytes())?;

    // ether_type_1_val == ether_type_enum::ieee_802_1q_tpid
    if ether_type_1_val == 0x8100 {
        Ok(2)
    } else {
        Ok(0)
    }
}

fn ether_type_2_callback(
    parent_context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<usize, DecodeError> {
    let ether_type_1_tree = parent_context
        .get("ether_type_1")
        .ok_or(DecodeError::Invalid(
            "Symbol not found in context for length calculation",
        ))?;

    let ether_type_1_val = big_endian_bytes_to_usize(&ether_type_1_tree.to_bytes())?;

    // ether_type_1_val == ether_type_enum::ieee_802_1q_tpid
    if ether_type_1_val == 0x8100 {
        Ok(2)
    } else {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use pang::Language;

    use super::*;

    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup_logger() {
        INIT.call_once(|| {
            let _ = env_logger::try_init();
        });
    }

    #[test]
    fn test_ethernet_frame_grammar() {
        setup_logger();
        let lang = Language::new(ethernet_frame_grammar(), "ethernet_frame", HashSet::new());
        let input = &[
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // dst_mac
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // src_mac
            0x8, 0x0, // ether_type_1
            0xFF, 0xFF, // body
        ];
        let tree = lang.parse(input).unwrap();
        println!("Tree: {}", tree);
    }
}
