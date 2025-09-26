//! Ethernet Frame Language Example

use std::collections::BTreeMap;
use std::sync::Arc;

use pang::{
    DerivationTree, Grammar, exp, exp_dc, grammar, nt, parser::callback::big_endian_bytes_to_usize,
    symbol::DecodeError, t_dyn, tl_bytes,
};

pub fn ethernet_frame_grammar() -> Grammar {
    grammar! {
        "ethernet_frame" => [exp([nt("ethernet_frame_seq")])],
        "ethernet_frame_seq" => [
            exp([
                tl_bytes("dst_mac", 6),
                tl_bytes("src_mac", 6),
                tl_bytes("ether_type_1", 2),
                nt("tci"),
                nt("ether_type_2"),
                nt("ethernet_body")
            ])
        ],
        "tci" => [
            exp_dc([t_dyn()], tci_decode_callbackfn)
        ],
        "ether_type_2" => [exp_dc([t_dyn()], tci_decode_callbackfn)],
        "ethernet_body" => [exp([t_dyn()])]
    }
}

pub fn tci_decode_callbackfn<'a>(
    input: &'a [u8],
    context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    let ether_type_1_tree = context.get("ether_type_1").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation".into(),
    ))?;

    let ether_type_1_val = big_endian_bytes_to_usize(&ether_type_1_tree.to_bytes())?;

    // ether_type_1_val == ether_type_enum::ieee_802_1q_tpid
    let (slice_to_parse, remaining_input) = if ether_type_1_val == 0x8100 {
        input.split_at(2)
    } else {
        input.split_at(0)
    };

    Ok((remaining_input, slice_to_parse.to_vec()))
}

pub fn ether_type_2_decode_callbackfn<'a>(
    input: &'a [u8],
    context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    let ether_type_1_tree = context.get("ether_type_1").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation".into(),
    ))?;

    let ether_type_1_val = big_endian_bytes_to_usize(&ether_type_1_tree.to_bytes())?;

    // ether_type_1_val == ether_type_enum::ieee_802_1q_tpid
    let (slice_to_parse, remaining_input) = if ether_type_1_val == 0x8100 {
        input.split_at(2)
    } else {
        input.split_at(0)
    };

    Ok((remaining_input, slice_to_parse.to_vec()))
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
        let lang = Language::new(&ethernet_frame_grammar(), "ethernet_frame", HashSet::new());
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
