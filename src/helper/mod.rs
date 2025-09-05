use std::{fs, path::PathBuf, sync::Once};

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
