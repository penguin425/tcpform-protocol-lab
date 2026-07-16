//! Import the fixed-layout subset of Kaitai Struct `.ksy` schemas.

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KaitaiImport {
    pub dsl: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Document {
    #[serde(default)]
    meta: Meta,
    #[serde(default)]
    seq: Vec<SequenceField>,
}

#[derive(Debug, Default, Deserialize)]
struct Meta {
    id: Option<String>,
    endian: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SequenceField {
    id: String,
    #[serde(rename = "type")]
    kind: Option<String>,
    size: Option<yaml_serde::Value>,
    #[serde(rename = "if")]
    condition: Option<yaml_serde::Value>,
    repeat: Option<String>,
    contents: Option<yaml_serde::Value>,
}

#[derive(Debug)]
struct ImportedField {
    name: String,
    offset: usize,
    length: usize,
    bits: Option<u8>,
    format: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct FieldShape {
    length: usize,
    bits: Option<u8>,
    format: &'static str,
}

pub fn import_ksy(source: &str, protocol_override: Option<&str>) -> Result<KaitaiImport, String> {
    let document: Document = yaml_serde::from_str(source)
        .map_err(|error| format!("invalid Kaitai Struct YAML: {error}"))?;
    let raw_name = protocol_override
        .map(str::to_owned)
        .or(document.meta.id)
        .ok_or("Kaitai schema needs meta.id or --protocol")?;
    let protocol = identifier(&raw_name)?;
    let endian = match document.meta.endian.as_deref().unwrap_or("be") {
        "be" | "big" => "big",
        "le" | "little" => "little",
        value => return Err(format!("unsupported Kaitai endian `{value}`")),
    };
    if document.seq.is_empty() {
        return Err("Kaitai schema has no seq fields".into());
    }

    let mut fields = Vec::new();
    let mut warnings = Vec::new();
    let mut offset = 0usize;
    let mut layout_known = true;
    for field in document.seq {
        if !layout_known {
            warnings.push(format!(
                "skipped `{}` because a preceding dynamic field makes its offset unknown",
                field.id
            ));
            continue;
        }
        if field.condition.is_some() || field.repeat.is_some() {
            warnings.push(format!(
                "skipped conditional or repeated field `{}`; tcpform header schemas require a fixed offset",
                field.id
            ));
            layout_known = false;
            continue;
        }
        let name = field_identifier(&field.id);
        let inferred = infer_field(&field)?;
        let Some(FieldShape {
            length,
            bits,
            format,
        }) = inferred
        else {
            warnings.push(format!(
                "skipped dynamic or user-defined field `{}` of type `{}`",
                field.id,
                field.kind.as_deref().unwrap_or("bytes")
            ));
            layout_known = false;
            continue;
        };
        if length == 0 {
            return Err(format!("Kaitai field `{}` has zero length", field.id));
        }
        for (part, part_offset, part_length) in split_field(length) {
            fields.push(ImportedField {
                name: if length > 8 {
                    format!("{name}_part_{part}")
                } else {
                    name.clone()
                },
                offset: offset + part_offset,
                length: part_length,
                bits: if length <= 8 { bits } else { None },
                format,
            });
        }
        offset = offset
            .checked_add(length)
            .ok_or("Kaitai layout is too large")?;
    }
    if fields.is_empty() {
        return Err("Kaitai schema contains no fixed-layout fields that tcpform can import".into());
    }

    let mut dsl = format!(
        "tcpform {{ dsl_version = 2 }}\n\n# Imported from Kaitai Struct. Review skipped constructs and semantic field types.\nprotocol \"{protocol}\" {{\n  description = \"Imported from Kaitai Struct schema {raw_name}\"\n\n  header_schema \"{protocol}\" {{\n    offset = 0\n    endian = \"{endian}\"\n    fields = {{\n"
    );
    for field in &fields {
        dsl.push_str(&format!(
            "      {} = {{ offset = {} length = {}{} format = \"{}\" }}\n",
            field.name,
            field.offset,
            field.length,
            field
                .bits
                .filter(|bits| *bits < (field.length * 8) as u8)
                .map(|bits| format!(" bits = {bits}"))
                .unwrap_or_default(),
            field.format
        ));
    }
    dsl.push_str(&format!(
        "    }}\n  }}\n\n  step \"send_{protocol}\" {{\n    role = \"client\"\n    action = \"send\"\n    to = \"server\"\n    segment {{ hex = \"{}\" }}\n  }}\n  step \"recv_{protocol}\" {{\n    role = \"server\"\n    action = \"recv\"\n    depends_on = [\"send_{protocol}\"]\n    expect {{ from = \"client\" }}\n  }}\n}}\n\ncases \"{protocol}\" {{\n  case \"kaitai_import_smoke\" {{ expect = \"pass\" tags = [\"smoke\", \"kaitai-import\"] }}\n}}\n",
        "00".repeat(offset)
    ));
    Ok(KaitaiImport { dsl, warnings })
}

fn infer_field(field: &SequenceField) -> Result<Option<FieldShape>, String> {
    if let Some(contents) = &field.contents {
        let length = match contents {
            yaml_serde::Value::String(value) => value.len(),
            yaml_serde::Value::Sequence(values) => values.len(),
            _ => {
                return Err(format!(
                    "Kaitai field `{}` contents must be a string or byte list",
                    field.id
                ))
            }
        };
        return Ok(Some(FieldShape {
            length,
            bits: None,
            format: "hex",
        }));
    }
    let kind = field.kind.as_deref().unwrap_or("bytes");
    let primitive = kind.trim_end_matches("be").trim_end_matches("le");
    let value = match primitive {
        "u1" | "s1" => Some((1, None, "uint")),
        "u2" | "s2" => Some((2, None, "uint")),
        "u4" | "s4" => Some((4, None, "uint")),
        "u8" | "s8" => Some((8, None, "uint")),
        value
            if value.strip_prefix('b').is_some_and(|width| {
                !width.is_empty() && width.chars().all(|c| c.is_ascii_digit())
            }) =>
        {
            let bits = value[1..]
                .parse::<u8>()
                .map_err(|_| format!("invalid Kaitai bit type `{kind}`"))?;
            if bits == 0 || bits > 64 {
                return Err(format!("Kaitai bit type `{kind}` exceeds 1..=64 bits"));
            }
            Some((usize::from(bits).div_ceil(8), Some(bits), "uint"))
        }
        "str" => static_size(field).map(|length| (length, None, "ascii")),
        "bytes" => static_size(field).map(|length| (length, None, "hex")),
        _ => None,
    };
    Ok(value.map(|(length, bits, format)| FieldShape {
        length,
        bits,
        format,
    }))
}

fn static_size(field: &SequenceField) -> Option<usize> {
    match field.size.as_ref()? {
        yaml_serde::Value::Number(value) => value.as_u64().and_then(|value| value.try_into().ok()),
        _ => None,
    }
}

fn split_field(length: usize) -> Vec<(usize, usize, usize)> {
    (0..length)
        .step_by(8)
        .enumerate()
        .map(|(index, offset)| (index + 1, offset, (length - offset).min(8)))
        .collect()
}

fn identifier(value: &str) -> Result<String, String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        Err("protocol name may contain only ASCII letters, numbers, `_`, and `-`".into())
    } else {
        Ok(value.into())
    }
}

fn field_identifier(value: &str) -> String {
    let mut result = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if result.is_empty() || result.starts_with(|character: char| character.is_ascii_digit()) {
        result.insert_str(0, "field_");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_fixed_kaitai_layout_and_reports_dynamic_tail() {
        let source = r#"
meta:
  id: telemetry
  endian: be
seq:
  - id: magic
    contents: [0x54, 0x46]
  - id: version
    type: u1
  - id: sequence
    type: u4
  - id: label
    type: str
    size: 12
  - id: payload
    size-eos: true
"#;
        let imported = import_ksy(source, None).unwrap();
        assert!(imported.dsl.contains("protocol \"telemetry\""));
        assert!(imported.dsl.contains("sequence = { offset = 3 length = 4"));
        assert!(imported.dsl.contains("label_part_1"));
        assert!(imported.dsl.contains("label_part_2"));
        assert!(imported
            .warnings
            .iter()
            .any(|warning| warning.contains("payload")));
        let blocks = crate::parse_file(&imported.dsl).unwrap();
        let protocols = crate::model::interpret(&blocks).unwrap();
        let cases = crate::model::interpret_cases(&blocks).unwrap();
        let results = crate::Engine::new(protocols[0].clone())
            .unwrap()
            .run_cases(&cases[0].cases);
        assert!(results.iter().all(|result| result.passed), "{results:?}");
    }

    #[test]
    fn rejects_invalid_or_fully_dynamic_schemas() {
        assert!(import_ksy("meta: [", None).is_err());
        assert!(import_ksy(
            "meta: { id: dynamic }\nseq:\n  - { id: body, size-eos: true }",
            None
        )
        .is_err());
    }
}
