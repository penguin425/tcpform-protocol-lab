//! Bidirectional codec for declarative, data-dependent message schemas.

use crate::model::{HeaderFieldSpec, HeaderSchema};
use crate::value::{bytes_to_hex, parse_hex, Value};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq)]
pub struct DecodedSchema {
    pub fields: HashMap<String, Value>,
    pub checksum_valid: HashMap<String, bool>,
    pub consumed: usize,
    pub unknown: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError(pub String);

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SchemaError {}

pub fn decode_schema(schema: &HeaderSchema, bytes: &[u8]) -> Result<DecodedSchema, SchemaError> {
    decode_schema_with_context(schema, bytes, &HashMap::new())
}

/// Decode with out-of-band values such as encryption keys and nonces. Context
/// entries can be referenced by schema expressions but are not returned.
pub fn decode_schema_with_context(
    schema: &HeaderSchema,
    bytes: &[u8],
    context: &HashMap<String, Value>,
) -> Result<DecodedSchema, SchemaError> {
    if schema.offset > bytes.len() {
        return Err(error(format!(
            "schema `{}` offset exceeds input",
            schema.name
        )));
    }
    let mut values = context.clone();
    let mut checksums = HashMap::new();
    let consumed = decode_fields(
        &schema.fields,
        bytes,
        schema.offset,
        schema.offset,
        &schema.endian,
        &mut values,
        &mut checksums,
    )?;
    for key in context.keys() {
        values.remove(key);
    }
    Ok(DecodedSchema {
        fields: values,
        checksum_valid: checksums,
        consumed,
        unknown: bytes.get(consumed..).unwrap_or_default().to_vec(),
    })
}

pub fn encode_schema(
    schema: &HeaderSchema,
    values: &HashMap<String, Value>,
) -> Result<Vec<u8>, SchemaError> {
    let mut out = vec![0; schema.offset];
    encode_fields(
        &schema.fields,
        values,
        &schema.endian,
        schema.offset,
        &mut out,
    )?;
    Ok(out)
}

fn decode_fields(
    fields: &[HeaderFieldSpec],
    input: &[u8],
    base: usize,
    mut cursor: usize,
    endian: &str,
    values: &mut HashMap<String, Value>,
    checksums: &mut HashMap<String, bool>,
) -> Result<usize, SchemaError> {
    for field in fields {
        if !predicate(field.when.as_deref(), values)? {
            continue;
        }
        let start = if field.offset_explicit {
            base.checked_add(field.offset)
        } else {
            Some(cursor)
        }
        .ok_or_else(|| error(format!("field `{}` offset overflow", field.name)))?;
        let count = resolve_count(field, values)?;
        let mut decoded = Vec::with_capacity(count);
        let mut item_cursor = start;
        for _ in 0..count {
            let length = resolve_length(field, values, input, item_cursor)?;
            let end = item_cursor
                .checked_add(length)
                .ok_or_else(|| error(format!("field `{}` length overflow", field.name)))?;
            let raw = input.get(item_cursor..end).ok_or_else(|| {
                error(format!(
                    "field `{}` is truncated at byte {item_cursor}",
                    field.name
                ))
            })?;
            let transformed = decode_transform(field, raw, values)?;
            let value = if !field.fields.is_empty() {
                let mut nested = HashMap::new();
                decode_fields(
                    &field.fields,
                    &transformed,
                    0,
                    0,
                    endian,
                    &mut nested,
                    checksums,
                )?;
                Value::Object(nested)
            } else if let Some(selector) = &field.switch_on {
                let key = scalar_key(values.get(selector).ok_or_else(|| {
                    error(format!(
                        "field `{}` switch references unknown `{selector}`",
                        field.name
                    ))
                })?);
                let selected = field
                    .cases
                    .get(&key)
                    .or_else(|| field.cases.get("default"))
                    .ok_or_else(|| {
                        error(format!("field `{}` has no case for `{key}`", field.name))
                    })?;
                let mut nested = HashMap::new();
                decode_fields(selected, &transformed, 0, 0, endian, &mut nested, checksums)?;
                Value::Object(nested)
            } else {
                decode_scalar(field, &transformed, endian)?
            };
            decoded.push(apply_enum(field, value));
            if let Some(algorithm) = &field.checksum {
                let covered = checksum_slice(field, input, base, item_cursor)?;
                let expected = integer_from_bytes(raw, endian, 0, raw.len() * 8)?;
                checksums.insert(
                    field.name.clone(),
                    checksum(algorithm, covered)? == expected,
                );
            }
            item_cursor = end;
        }
        let value = if count == 1 {
            decoded.pop().unwrap()
        } else {
            Value::Array(decoded)
        };
        values.insert(field.name.clone(), value);
        cursor = cursor.max(item_cursor);
    }
    Ok(cursor)
}

fn encode_fields(
    fields: &[HeaderFieldSpec],
    values: &HashMap<String, Value>,
    endian: &str,
    base: usize,
    out: &mut Vec<u8>,
) -> Result<usize, SchemaError> {
    let mut cursor = out.len().max(base);
    for field in fields {
        if !predicate(field.when.as_deref(), values)? {
            continue;
        }
        let start = if field.offset_explicit {
            base + field.offset
        } else {
            cursor
        };
        if out.len() < start {
            out.resize(start, 0);
        }
        let count = resolve_count(field, values)?;
        let supplied = values.get(&field.name);
        let items: Vec<Value> = if field.checksum.is_some() {
            vec![Value::Null; count]
        } else if count == 1 {
            vec![supplied
                .ok_or_else(|| error(format!("missing field `{}`", field.name)))?
                .clone()]
        } else {
            supplied
                .and_then(Value::as_array)
                .ok_or_else(|| error(format!("field `{}` must be an array", field.name)))?
                .to_vec()
        };
        if items.len() != count {
            return Err(error(format!(
                "field `{}` expected {count} items, got {}",
                field.name,
                items.len()
            )));
        }
        let mut item_cursor = start;
        for value in &items {
            let mut raw = if !field.fields.is_empty() {
                let nested = value
                    .as_object()
                    .ok_or_else(|| error(format!("field `{}` must be an object", field.name)))?;
                let mut bytes = Vec::new();
                encode_fields(&field.fields, nested, endian, 0, &mut bytes)?;
                bytes
            } else if let Some(selector) = &field.switch_on {
                let key = scalar_key(
                    values
                        .get(selector)
                        .ok_or_else(|| error(format!("unknown switch `{selector}`")))?,
                );
                let selected = field
                    .cases
                    .get(&key)
                    .or_else(|| field.cases.get("default"))
                    .ok_or_else(|| {
                        error(format!("field `{}` has no case for `{key}`", field.name))
                    })?;
                let nested = value
                    .as_object()
                    .ok_or_else(|| error(format!("field `{}` must be an object", field.name)))?;
                let mut bytes = Vec::new();
                encode_fields(selected, nested, endian, 0, &mut bytes)?;
                bytes
            } else if let Some(algorithm) = &field.checksum {
                let covered = checksum_slice(field, out, base, item_cursor)?;
                integer_bytes(checksum(algorithm, covered)?, field.length, endian)?
            } else {
                encode_scalar(field, value, endian)?
            };
            raw = encode_transform(field, &raw, values)?;
            let expected = resolve_length_for_encode(field, values, raw.len())?;
            if raw.len() != expected {
                return Err(error(format!(
                    "field `{}` encoded to {} bytes, expected {expected}",
                    field.name,
                    raw.len()
                )));
            }
            if out.len() < item_cursor {
                out.resize(item_cursor, 0);
            }
            if out.len() < item_cursor + raw.len() {
                out.resize(item_cursor + raw.len(), 0);
            }
            if (field.bits as usize) < field.length * 8 {
                for (target, value) in out[item_cursor..item_cursor + raw.len()]
                    .iter_mut()
                    .zip(&raw)
                {
                    *target |= *value;
                }
            } else {
                out[item_cursor..item_cursor + raw.len()].copy_from_slice(&raw);
            }
            item_cursor += raw.len();
        }
        cursor = cursor.max(item_cursor);
    }
    Ok(cursor)
}

fn resolve_count(
    field: &HeaderFieldSpec,
    values: &HashMap<String, Value>,
) -> Result<usize, SchemaError> {
    field.repeat_from.as_ref().map_or(Ok(field.repeat), |name| {
        reference_usize(values, name, "repeat_from")
    })
}

fn resolve_length(
    field: &HeaderFieldSpec,
    values: &HashMap<String, Value>,
    input: &[u8],
    start: usize,
) -> Result<usize, SchemaError> {
    if let Some(terminator) = &field.terminator {
        let tail = input
            .get(start..)
            .ok_or_else(|| error("terminator start exceeds input"))?;
        let position = tail
            .windows(terminator.len())
            .position(|window| window == terminator)
            .ok_or_else(|| error(format!("field `{}` terminator was not found", field.name)))?;
        return Ok(position + terminator.len());
    }
    resolve_declared_length(field, values)
}

fn resolve_length_for_encode(
    field: &HeaderFieldSpec,
    values: &HashMap<String, Value>,
    actual: usize,
) -> Result<usize, SchemaError> {
    if field.terminator.is_some() {
        Ok(actual)
    } else {
        resolve_declared_length(field, values)
    }
}

fn resolve_declared_length(
    field: &HeaderFieldSpec,
    values: &HashMap<String, Value>,
) -> Result<usize, SchemaError> {
    let base = field
        .length_from
        .as_ref()
        .map_or(Ok(field.length), |name| {
            reference_usize(values, name, "length_from")
        })?;
    usize::try_from((base as i128) + (field.length_adjust as i128)).map_err(|_| {
        error(format!(
            "field `{}` resolved to an invalid length",
            field.name
        ))
    })
}

fn reference_usize(
    values: &HashMap<String, Value>,
    name: &str,
    kind: &str,
) -> Result<usize, SchemaError> {
    values
        .get(name)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_object()?.get("value")?.as_u64())
        })
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            error(format!(
                "{kind} references missing or non-integer field `{name}`"
            ))
        })
}

fn predicate(
    expression: Option<&str>,
    values: &HashMap<String, Value>,
) -> Result<bool, SchemaError> {
    let Some(expression) = expression.map(str::trim) else {
        return Ok(true);
    };
    for (operator, equal) in [("!=", false), ("==", true)] {
        if let Some((left, right)) = expression.split_once(operator) {
            let actual = values
                .get(left.trim())
                .ok_or_else(|| error(format!("condition references unknown `{}`", left.trim())))?;
            let expected = literal(right.trim());
            return Ok((underlying_value(actual) == &expected) == equal);
        }
    }
    if let Some(name) = expression.strip_prefix('!') {
        return values
            .get(name.trim())
            .and_then(|value| underlying_value(value).as_bool())
            .map(|value| !value)
            .ok_or_else(|| error(format!("condition `{expression}` is not boolean")));
    }
    values
        .get(expression)
        .and_then(|value| underlying_value(value).as_bool())
        .ok_or_else(|| error(format!("condition `{expression}` is not boolean")))
}

fn literal(value: &str) -> Value {
    if value == "true" {
        Value::Bool(true)
    } else if value == "false" {
        Value::Bool(false)
    } else if let Ok(value) = value.parse::<f64>() {
        Value::Number(value)
    } else {
        Value::String(value.trim_matches('"').to_string())
    }
}

fn decode_scalar(
    field: &HeaderFieldSpec,
    bytes: &[u8],
    endian: &str,
) -> Result<Value, SchemaError> {
    let payload = if let Some(terminator) = &field.terminator {
        &bytes[..bytes.len() - terminator.len()]
    } else {
        bytes
    };
    match field.format.as_str() {
        "uint" => Ok(Value::Number(integer_from_bytes(
            payload,
            endian,
            field.bit_offset,
            field.bits as usize,
        )? as f64)),
        "int" => {
            let unsigned =
                integer_from_bytes(payload, endian, field.bit_offset, field.bits as usize)?;
            let bits = field.bits as usize;
            let signed = if bits < 64 && unsigned & (1 << (bits - 1)) != 0 {
                (unsigned as i128 - (1i128 << bits)) as i64
            } else {
                unsigned as i64
            };
            Ok(Value::Number(signed as f64))
        }
        "bool" => Ok(Value::Bool(
            integer_from_bytes(payload, endian, field.bit_offset, field.bits as usize)? != 0,
        )),
        "hex" => Ok(Value::String(bytes_to_hex(payload))),
        "bytes" => Ok(Value::Bytes(payload.to_vec())),
        "ascii" => {
            if !payload.is_ascii() {
                return Err(error(format!("field `{}` is not ASCII", field.name)));
            }
            Ok(Value::String(String::from_utf8(payload.to_vec()).unwrap()))
        }
        "utf8" => String::from_utf8(payload.to_vec())
            .map(Value::String)
            .map_err(|_| error(format!("field `{}` is not UTF-8", field.name))),
        "ipv4" if payload.len() == 4 => Ok(Value::String(format!(
            "{}.{}.{}.{}",
            payload[0], payload[1], payload[2], payload[3]
        ))),
        "ipv4" => Err(error(format!(
            "field `{}` IPv4 value must be 4 bytes",
            field.name
        ))),
        other => Err(error(format!("unsupported format `{other}`"))),
    }
}

fn encode_scalar(
    field: &HeaderFieldSpec,
    value: &Value,
    endian: &str,
) -> Result<Vec<u8>, SchemaError> {
    let value = reverse_enum(field, value);
    let mut bytes = match field.format.as_str() {
        "uint" => {
            let number = value.as_u64().ok_or_else(|| {
                error(format!(
                    "field `{}` must be a non-negative integer",
                    field.name
                ))
            })?;
            let limit = if field.bits == 64 {
                u64::MAX
            } else {
                (1u64 << field.bits) - 1
            };
            if number > limit {
                return Err(error(format!(
                    "field `{}` exceeds {} bits",
                    field.name, field.bits
                )));
            }
            integer_bytes(number << field.bit_offset, field.length, endian)?
        }
        "int" => {
            let number = value
                .as_i64()
                .ok_or_else(|| error(format!("field `{}` must be an integer", field.name)))?;
            let bits = field.bits as usize;
            let min = if bits == 64 {
                i64::MIN as i128
            } else {
                -(1i128 << (bits - 1))
            };
            let max = if bits == 64 {
                i64::MAX as i128
            } else {
                (1i128 << (bits - 1)) - 1
            };
            if (number as i128) < min || (number as i128) > max {
                return Err(error(format!(
                    "field `{}` exceeds signed {bits} bits",
                    field.name
                )));
            }
            let mask = if bits == 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            integer_bytes(
                ((number as u64) & mask) << field.bit_offset,
                field.length,
                endian,
            )?
        }
        "bool" => integer_bytes(
            u64::from(
                value
                    .as_bool()
                    .ok_or_else(|| error(format!("field `{}` must be boolean", field.name)))?,
            ) << field.bit_offset,
            field.length,
            endian,
        )?,
        "hex" => parse_hex(
            value
                .as_str()
                .ok_or_else(|| error(format!("field `{}` must be hex text", field.name)))?,
        )
        .map_err(error)?,
        "bytes" => match &value {
            Value::Bytes(bytes) => bytes.clone(),
            Value::String(hex) => parse_hex(hex).map_err(error)?,
            _ => {
                return Err(error(format!(
                    "field `{}` must be bytes or hex text",
                    field.name
                )))
            }
        },
        "ascii" => {
            let text = value
                .as_str()
                .ok_or_else(|| error(format!("field `{}` must be text", field.name)))?;
            if !text.is_ascii() {
                return Err(error(format!("field `{}` is not ASCII", field.name)));
            }
            text.as_bytes().to_vec()
        }
        "utf8" => value
            .as_str()
            .ok_or_else(|| error(format!("field `{}` must be text", field.name)))?
            .as_bytes()
            .to_vec(),
        "ipv4" => value
            .as_str()
            .ok_or_else(|| error(format!("field `{}` must be IPv4 text", field.name)))?
            .split('.')
            .map(|part| {
                part.parse::<u8>()
                    .map_err(|_| error("invalid IPv4 address"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        other => return Err(error(format!("unsupported format `{other}`"))),
    };
    if let Some(terminator) = &field.terminator {
        bytes.extend_from_slice(terminator);
    }
    Ok(bytes)
}

fn integer_from_bytes(
    bytes: &[u8],
    endian: &str,
    bit_offset: u8,
    bits: usize,
) -> Result<u64, SchemaError> {
    if bytes.len() > 8 || bits == 0 || bits > 64 {
        return Err(error("integer field exceeds 64 bits"));
    }
    let mut value = 0u64;
    if endian == "little" {
        for byte in bytes.iter().rev() {
            value = (value << 8) | u64::from(*byte);
        }
    } else {
        for byte in bytes {
            value = (value << 8) | u64::from(*byte);
        }
    }
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    Ok((value >> bit_offset) & mask)
}

fn integer_bytes(value: u64, length: usize, endian: &str) -> Result<Vec<u8>, SchemaError> {
    if length == 0 || length > 8 || (length < 8 && value >= (1u64 << (length * 8))) {
        return Err(error("integer does not fit field length"));
    }
    let full = if endian == "little" {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    Ok(if endian == "little" {
        full[..length].to_vec()
    } else {
        full[8 - length..].to_vec()
    })
}

fn apply_enum(field: &HeaderFieldSpec, value: Value) -> Value {
    field
        .enum_values
        .get(&scalar_key(&value))
        .map_or(value.clone(), |name| {
            Value::Object(HashMap::from([
                ("value".into(), value),
                ("name".into(), name.clone()),
            ]))
        })
}

fn reverse_enum(field: &HeaderFieldSpec, value: &Value) -> Value {
    field
        .enum_values
        .iter()
        .find_map(|(key, mapped)| (mapped == value).then(|| literal(key)))
        .unwrap_or_else(|| value.clone())
}

fn scalar_key(value: &Value) -> String {
    match value {
        Value::Object(value) if value.contains_key("value") => scalar_key(&value["value"]),
        Value::Number(number) if number.fract() == 0.0 => format!("{}", *number as i64),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        _ => value.to_display(),
    }
}

fn underlying_value(value: &Value) -> &Value {
    value
        .as_object()
        .and_then(|object| object.get("value"))
        .unwrap_or(value)
}

fn decode_transform(
    field: &HeaderFieldSpec,
    bytes: &[u8],
    values: &HashMap<String, Value>,
) -> Result<Vec<u8>, SchemaError> {
    match field.transform.as_deref() {
        None => Ok(bytes.to_vec()),
        Some("zlib") => {
            let mut decoder = ZlibDecoder::new(bytes);
            let mut output = Vec::new();
            decoder
                .read_to_end(&mut output)
                .map_err(|err| error(format!("field `{}` zlib: {err}", field.name)))?;
            Ok(output)
        }
        Some("aes-gcm") => {
            let (key, nonce) = encryption_material(field, values)?;
            Aes256Gcm::new_from_slice(&key)
                .map_err(|_| error("invalid AES-256 key"))?
                .decrypt(Nonce::from_slice(&nonce), bytes)
                .map_err(|_| {
                    error(format!(
                        "field `{}` AES-GCM authentication failed",
                        field.name
                    ))
                })
        }
        Some(plugin) => Err(error(format!(
            "field `{}` transform `{plugin}` requires runtime plugin dispatch",
            field.name
        ))),
    }
}

fn encode_transform(
    field: &HeaderFieldSpec,
    bytes: &[u8],
    values: &HashMap<String, Value>,
) -> Result<Vec<u8>, SchemaError> {
    match field.transform.as_deref() {
        None => Ok(bytes.to_vec()),
        Some("zlib") => {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(bytes)
                .and_then(|_| encoder.finish())
                .map_err(|err| error(format!("field `{}` zlib: {err}", field.name)))
        }
        Some("aes-gcm") => {
            let (key, nonce) = encryption_material(field, values)?;
            Aes256Gcm::new_from_slice(&key)
                .map_err(|_| error("invalid AES-256 key"))?
                .encrypt(Nonce::from_slice(&nonce), bytes)
                .map_err(|_| error(format!("field `{}` AES-GCM encryption failed", field.name)))
        }
        Some(plugin) => Err(error(format!(
            "field `{}` transform `{plugin}` requires runtime plugin dispatch",
            field.name
        ))),
    }
}

fn encryption_material(
    field: &HeaderFieldSpec,
    values: &HashMap<String, Value>,
) -> Result<(Vec<u8>, Vec<u8>), SchemaError> {
    let material =
        |reference: &Option<String>, size: usize, kind: &str| -> Result<Vec<u8>, SchemaError> {
            let name = reference
                .as_ref()
                .ok_or_else(|| error(format!("field `{}` lacks {kind}_from", field.name)))?;
            let value = values.get(name).ok_or_else(|| {
                error(format!(
                    "field `{}` references unknown {kind} `{name}`",
                    field.name
                ))
            })?;
            let bytes = match value {
                Value::Bytes(bytes) => bytes.clone(),
                Value::String(hex) => parse_hex(hex).map_err(error)?,
                _ => return Err(error(format!("{kind} `{name}` must be bytes or hex"))),
            };
            if bytes.len() != size {
                return Err(error(format!("{kind} `{name}` must contain {size} bytes")));
            }
            Ok(bytes)
        };
    Ok((
        material(&field.key_from, 32, "key")?,
        material(&field.nonce_from, 12, "nonce")?,
    ))
}

fn checksum_slice<'a>(
    field: &HeaderFieldSpec,
    bytes: &'a [u8],
    base: usize,
    current: usize,
) -> Result<&'a [u8], SchemaError> {
    match field.checksum_range.as_deref().unwrap_or("all_before") {
        "all_before" => bytes
            .get(base..current)
            .ok_or_else(|| error("invalid checksum range")),
        range => {
            let (start, end) = range
                .split_once("..")
                .ok_or_else(|| error("checksum_range must be all_before or start..end"))?;
            let start = base
                + start
                    .parse::<usize>()
                    .map_err(|_| error("invalid checksum range start"))?;
            let end = base
                + end
                    .parse::<usize>()
                    .map_err(|_| error("invalid checksum range end"))?;
            bytes
                .get(start..end)
                .ok_or_else(|| error("checksum range exceeds message"))
        }
    }
}

fn checksum(algorithm: &str, bytes: &[u8]) -> Result<u64, SchemaError> {
    match algorithm {
        "crc16" => {
            let mut crc = 0xffffu16;
            for byte in bytes {
                crc ^= u16::from(*byte) << 8;
                for _ in 0..8 {
                    crc = if crc & 0x8000 != 0 {
                        (crc << 1) ^ 0x1021
                    } else {
                        crc << 1
                    };
                }
            }
            Ok(u64::from(crc))
        }
        "crc32" => {
            let mut crc = 0xffff_ffffu32;
            for byte in bytes {
                crc ^= u32::from(*byte);
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xedb8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            Ok(u64::from(!crc))
        }
        "internet" => Ok(u64::from(crate::packet::internet_checksum(bytes))),
        other => Err(error(format!("unsupported checksum `{other}`"))),
    }
}

fn error(message: impl Into<String>) -> SchemaError {
    SchemaError(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::interpret;
    use crate::parse_file;

    fn schema(source: &str) -> HeaderSchema {
        let blocks = parse_file(&format!(
            "protocol \"dynamic\" {{ header_schema \"message\" {{ fields = {{ {source} }} }} step \"noop\" {{ role=\"client\" action=\"send\" }} }}"
        )).unwrap();
        interpret(&blocks)
            .unwrap()
            .remove(0)
            .header_schemas
            .remove(0)
    }

    #[test]
    fn length_repetition_conditions_enums_and_unknown_bytes_round_trip() {
        let schema = schema(
            r#"
            size={ order=1 length=1 format="uint" enum={ "3"="payload" } }
            enabled={ order=2 length=1 format="bool" }
            payload={ order=3 length_from="size" format="ascii" when="enabled == true" }
            count={ order=4 length=1 format="uint" }
            items={ order=5 length=1 format="uint" repeat_from="count" }
        "#,
        );
        let decoded = decode_schema(&schema, &[3, 1, b'a', b'b', b'c', 2, 7, 9, 0xff]).unwrap();
        assert_eq!(
            decoded.fields["size"].as_object().unwrap()["name"],
            Value::String("payload".into())
        );
        assert_eq!(decoded.fields["payload"], Value::String("abc".into()));
        assert_eq!(
            decoded.fields["items"],
            Value::Array(vec![Value::Number(7.0), Value::Number(9.0)])
        );
        assert_eq!(decoded.unknown, vec![0xff]);

        let encoded = encode_schema(
            &schema,
            &HashMap::from([
                ("size".into(), Value::Number(3.0)),
                ("enabled".into(), Value::Bool(true)),
                ("payload".into(), Value::String("abc".into())),
                ("count".into(), Value::Number(2.0)),
                (
                    "items".into(),
                    Value::Array(vec![Value::Number(7.0), Value::Number(9.0)]),
                ),
            ]),
        )
        .unwrap();
        assert_eq!(encoded, vec![3, 1, b'a', b'b', b'c', 2, 7, 9]);
    }

    #[test]
    fn overlapping_bit_fields_encode_bidirectionally() {
        let schema = schema(
            r#"
            high={ offset=0 length=1 bit_offset=4 bits=4 format="uint" }
            low={ offset=0 length=1 bit_offset=0 bits=4 format="uint" }
        "#,
        );
        let values = HashMap::from([
            ("high".into(), Value::Number(10.0)),
            ("low".into(), Value::Number(5.0)),
        ]);
        let wire = encode_schema(&schema, &values).unwrap();
        assert_eq!(wire, vec![0xa5]);
        let decoded = decode_schema(&schema, &wire).unwrap();
        assert_eq!(decoded.fields["high"], Value::Number(10.0));
        assert_eq!(decoded.fields["low"], Value::Number(5.0));
    }

    #[test]
    fn terminated_nested_and_switched_fields_decode() {
        let schema = schema(
            r#"
            tag={ order=1 length=1 format="uint" }
            name={ order=2 length=1 terminator="00" format="utf8" }
            body={ order=3 length=2 switch_on="tag" cases={
                "1"={ fields={ left={ order=1 length=1 format="uint" } right={ order=2 length=1 format="uint" } } }
                default={ fields={ raw={ length=2 format="hex" } } }
            } }
        "#,
        );
        let decoded = decode_schema(&schema, &[1, b'o', b'k', 0, 4, 5]).unwrap();
        assert_eq!(decoded.fields["name"], Value::String("ok".into()));
        assert_eq!(
            decoded.fields["body"].as_object().unwrap()["left"],
            Value::Number(4.0)
        );
    }

    #[test]
    fn checksums_are_generated_and_verified() {
        let schema = schema(
            r#"
            data={ order=1 length=3 format="ascii" }
            crc={ order=2 length=2 format="uint" checksum="crc16" checksum_range="all_before" }
        "#,
        );
        let encoded = encode_schema(
            &schema,
            &HashMap::from([("data".into(), Value::String("123".into()))]),
        )
        .unwrap();
        let decoded = decode_schema(&schema, &encoded).unwrap();
        assert!(decoded.checksum_valid["crc"]);
        let mut damaged = encoded;
        damaged[0] ^= 1;
        assert!(!decode_schema(&schema, &damaged).unwrap().checksum_valid["crc"]);
    }

    #[test]
    fn zlib_nested_region_round_trips() {
        let schema = schema(
            r#"
            compressed_size={ order=1 length=2 format="uint" }
            body={ order=2 length_from="compressed_size" transform="zlib" fields={ text={ order=1 length=5 format="ascii" } } }
        "#,
        );
        let mut body = ZlibEncoder::new(Vec::new(), Compression::default());
        body.write_all(b"hello").unwrap();
        let body = body.finish().unwrap();
        let mut wire = (body.len() as u16).to_be_bytes().to_vec();
        wire.extend_from_slice(&body);
        let decoded = decode_schema(&schema, &wire).unwrap();
        assert_eq!(
            decoded.fields["body"].as_object().unwrap()["text"],
            Value::String("hello".into())
        );
    }

    #[test]
    fn aes_gcm_region_uses_out_of_band_key_material() {
        let schema = schema(
            r#"
            body={ order=1 length=21 transform="aes-gcm" key_from="secret" nonce_from="nonce" fields={ text={ order=1 length=5 format="ascii" } } }
        "#,
        );
        let context = HashMap::from([
            ("secret".into(), Value::Bytes(vec![0x11; 32])),
            ("nonce".into(), Value::Bytes(vec![0x22; 12])),
        ]);
        let mut values = context.clone();
        values.insert(
            "body".into(),
            Value::Object(HashMap::from([(
                "text".into(),
                Value::String("hello".into()),
            )])),
        );
        let wire = encode_schema(&schema, &values).unwrap();
        assert_ne!(wire[..5], *b"hello");
        let decoded = decode_schema_with_context(&schema, &wire, &context).unwrap();
        assert_eq!(
            decoded.fields["body"].as_object().unwrap()["text"],
            Value::String("hello".into())
        );
        assert!(!decoded.fields.contains_key("secret"));
    }
}
