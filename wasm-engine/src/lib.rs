//! Dependency-free browser execution core for the portable DSL subset.

#[no_mangle]
pub extern "C" fn alloc(length: usize) -> *mut u8 {
    let mut bytes = Vec::<u8>::with_capacity(length);
    let pointer = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    pointer
}

#[no_mangle]
/// Releases a buffer previously returned by [`alloc`].
///
/// # Safety
///
/// `pointer` must have been returned by [`alloc`] with the same `length`, and
/// the allocation must not have been released already.
pub unsafe extern "C" fn dealloc(pointer: *mut u8, length: usize) {
    if !pointer.is_null() {
        drop(Vec::from_raw_parts(pointer, 0, length));
    }
}

#[no_mangle]
/// Counts the steps in a UTF-8 DSL source buffer.
///
/// # Safety
///
/// `pointer` must reference at least `length` readable bytes for this call.
pub unsafe extern "C" fn step_count(pointer: *const u8, length: usize) -> usize {
    source(pointer, length)
        .map(|text| text.match_indices("step \"").count())
        .unwrap_or(0)
}

/// Writes one status byte per step: 1 is runnable, 0 is structurally invalid.
///
/// # Safety
///
/// `source_pointer` must reference at least `source_length` readable bytes and
/// `output_pointer` must reference at least `output_length` writable bytes.
/// The two buffers must not overlap.
#[no_mangle]
pub unsafe extern "C" fn simulate(
    source_pointer: *const u8,
    source_length: usize,
    output_pointer: *mut u8,
    output_length: usize,
) -> usize {
    let Some(text) = source(source_pointer, source_length) else {
        return 0;
    };
    if output_pointer.is_null() {
        return 0;
    }
    let starts = text
        .match_indices("step \"")
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let output = std::slice::from_raw_parts_mut(output_pointer, output_length);
    let mut written = 0;
    for (position, start) in starts.iter().enumerate().take(output.len()) {
        let end = starts.get(position + 1).copied().unwrap_or(text.len());
        let block = &text[*start..end];
        output[position] = u8::from(
            attribute(block, "role").is_some()
                && attribute(block, "action").is_some_and(supported_action),
        );
        written += 1;
    }
    written
}

unsafe fn source<'a>(pointer: *const u8, length: usize) -> Option<&'a str> {
    if pointer.is_null() || length > 16 * 1024 * 1024 {
        return None;
    }
    std::str::from_utf8(std::slice::from_raw_parts(pointer, length)).ok()
}

fn attribute<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let rest = block.split_once(name)?.1.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start().strip_prefix('"')?;
    rest.split_once('"').map(|(value, _)| value)
}

fn supported_action(value: &str) -> bool {
    matches!(
        value,
        "send" | "recv" | "send_raw" | "recv_raw" | "wait" | "assert" | "set"
            | "log" | "open" | "close" | "reset" | "drop" | "corrupt" | "duplicate"
            | "ack" | "nack"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_subset_classifies_steps() {
        let source = br#"protocol "p" {
          step "ok" { role = "client" action = "send" }
          step "bad" { role = "client" action = "plugin" }
        }"#;
        let mut output = [0u8; 2];
        unsafe {
            assert_eq!(step_count(source.as_ptr(), source.len()), 2);
            assert_eq!(simulate(source.as_ptr(), source.len(), output.as_mut_ptr(), output.len()), 2);
        }
        assert_eq!(output, [1, 0]);
    }
}
