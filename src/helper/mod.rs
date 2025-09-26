use std::{fs, path::PathBuf, sync::Once};

use pang::DecodeError;

static INIT: Once = Once::new();

pub fn setup_logger() {
    INIT.call_once(|| {
        let _ = env_logger::try_init();
    });
}

pub fn get_input_data(path: &PathBuf) -> Option<Vec<u8>> {
    let inp_data = match fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            println!("Failed to read input file: {}", e);
            return None;
        }
    };

    Some(inp_data)
}

pub fn find_symbol(input: &[u8], symbol: &[u8]) -> Option<usize> {
    input
        .windows(symbol.len())
        .position(|window| window == symbol)
}

pub fn find_symbol_with_offset<'a>(
    input: &'a [u8],
    symbol: &[u8],
    offset: usize,
) -> Result<(&'a [u8], Vec<u8>), DecodeError> {
    if let Some(pos) = find_symbol(input, symbol) {
        let request_line_slice = &input[..pos + offset];
        let remaining_input = &input[pos + offset..];

        Ok((remaining_input, request_line_slice.to_vec()))
    } else {
        Err(DecodeError::Invalid("Can not find symbol".into()))
    }
}
