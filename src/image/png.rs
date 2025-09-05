//! PNG Language Example

use std::{collections::BTreeMap, sync::Arc};

use crc::{CRC_32_ISO_HDLC, Crc};

use pang::{
    DerivationTree, Grammar, exp, exp_dc, grammar, new_node, nt,
    parser::callback::big_endian_bytes_to_usize, symbol::DecodeError, t_bytes, t_dyn,
};
use pang::{exp_ec, t_bytes_val};

pub fn png_basic_grammar() -> Grammar {
    grammar! {
        "png" => vec![
            exp(vec![
                nt("magic"), nt("chunks")
            ])
        ],
        "magic" => vec![exp(vec![t_bytes_val(&[137, 80, 78, 71, 13, 10, 26, 10])])],
        "chunks" => vec![exp(vec![t_dyn()])],
    }
}

pub fn png_basic_chunks_grammar() -> Grammar {
    grammar! {
        "chunks" => vec![
            exp(vec![nt("chunk"), nt("chunks")]),
            exp(vec![nt("chunk")]),
        ],
        "chunk" => vec![
            exp_ec(vec![nt("chunk_len"), nt("chunk_type"), nt("chunk_data"), nt("chunk_crc")], chunk_encode_callback)
        ],
        "chunk_len" => vec![exp(vec![t_bytes(4)])],
        "chunk_type" => vec![exp(vec![t_bytes(4)])],
        "chunk_data" => vec![exp_dc(vec![t_dyn()], chunk_data_decode_callbackfn)],
        "chunk_crc" => vec![exp(vec![t_bytes(4)])],
    }
}

fn chunk_data_decode_callbackfn<'a>(
    input: &'a [u8],
    context: &BTreeMap<String, Arc<DerivationTree>>,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    let chunk_len_tree = context.get("chunk_len").ok_or(DecodeError::Invalid(
        "Symbol not found in context for length calculation",
    ))?;

    let chunk_len = big_endian_bytes_to_usize(&chunk_len_tree.to_bytes())?;

    let (slice_to_parse, remaining_input) = input.split_at(chunk_len);

    Ok((remaining_input, slice_to_parse.to_vec()))
}

pub fn chunk_encode_callback(node: Arc<DerivationTree>) -> Arc<DerivationTree> {
    // Calculate CRC
    let chunk_type_node = node.at(&[1]).unwrap();
    let chunk_data_node = node.at(&[2]).unwrap();
    let mut to_crc_bytes = vec![];
    to_crc_bytes.extend_from_slice(&chunk_type_node.to_bytes());
    to_crc_bytes.extend_from_slice(&chunk_data_node.to_bytes());

    pub const CRC_PNG: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let crc = CRC_PNG.checksum(&to_crc_bytes);

    // Rewrite CRC
    let crc_node = new_node(t_bytes_val(&crc.to_be_bytes()), Some(vec![]));
    let node = node.replace_by_path(&[3, 0], crc_node).unwrap();

    // Calculate length
    let chunk_len = chunk_data_node.to_bytes().len() as u32;

    // Rewrite length
    let chunk_len_node = new_node(t_bytes_val(&chunk_len.to_be_bytes()), Some(vec![]));
    let node = node.replace_by_path(&[0, 0], chunk_len_node).unwrap();

    node
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, env, path::PathBuf, sync::Once};

    use pang::Language;

    use crate::get_input_data;

    use super::*;

    static INIT: Once = Once::new();

    fn setup_logger() {
        INIT.call_once(|| {
            let _ = env_logger::try_init();
        });
    }

    fn testfile_path() -> PathBuf {
        env::current_dir()
            .unwrap()
            .join("assets/image/not_kitty.png")
    }

    #[test]
    fn test_png_basic_grammar() {
        setup_logger();
        let input = get_input_data(&testfile_path()).unwrap();
        let lang = Language::new(&png_basic_grammar(), "png", HashSet::new());
        let tree = lang.parse(&input).unwrap();
        assert_eq!(tree.to_bytes(), input);
        let tree = tree.fix(&png_basic_grammar());
        assert_eq!(tree.to_bytes(), input);
    }

    #[test]
    fn test_png_basic_chunks_grammar() {
        setup_logger();

        let grammar = png_basic_grammar().extend_grammar(&png_basic_chunks_grammar());

        let input = get_input_data(&testfile_path()).unwrap();
        let lang = Language::new(&grammar, "png", HashSet::new());
        let tree = lang.parse(&input).unwrap();
        assert_eq!(tree.to_bytes(), input);
        let tree: Arc<DerivationTree> = tree.fix(&grammar);
        assert_eq!(tree.to_bytes(), input);
    }
}
