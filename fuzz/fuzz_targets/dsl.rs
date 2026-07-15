#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data) {
        if let Ok(blocks) = tcpform::parse_file(source) {
            let _ = tcpform::model::interpret(&blocks);
            let _ = tcpform::model::interpret_cases(&blocks);
        }
    }
});
