//! tcpform CLI.
//!
//! ```
//! tcpform validate <file>
//! tcpform list <file>
//! tcpform plan <file> <protocol>
//! tcpform run <file> <protocol>
//! ```

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, fs, process};

use tcpform::model::interpret;
use tcpform::{load_blocks, Engine, EngineError, Protocol};
mod orchestrate;
mod proxy;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        process::exit(2);
    }
    let cmd = args[1].as_str();
    let result = match cmd {
        "validate" => cmd_validate(&args[2..]),
        "list" => cmd_list(&args[2..]),
        "plan" => cmd_plan(&args[2..]),
        "visualize" => cmd_visualize(&args[2..]),
        "serve" => cmd_serve(&args[2..]),
        "fmt" => cmd_fmt(&args[2..]),
        "migrate" => cmd_migrate(&args[2..]),
        "init" => cmd_init(&args[2..]),
        "template" => cmd_template(&args[2..]),
        "schema" => cmd_schema(&args[2..]),
        "snapshot" => cmd_snapshot(&args[2..]),
        "ci-snapshot" => cmd_ci_snapshot(&args[2..]),
        "ci-report" => cmd_ci_report(&args[2..]),
        "doctor" => cmd_doctor(&args[2..]),
        "completion" => cmd_completion(&args[2..]),
        "import-pcap" => cmd_import_pcap(&args[2..]),
        "import-kaitai" => cmd_import_kaitai(&args[2..]),
        "packetdrill" => cmd_packetdrill(&args[2..]),
        "lsp" => cmd_lsp(),
        "gate" => cmd_gate(&args[2..]),
        "bundle" => cmd_bundle(&args[2..]),
        "replay-bundle" => cmd_replay_bundle(&args[2..]),
        "anonymize" => cmd_anonymize(&args[2..]),
        "orchestrate" => cmd_orchestrate(&args[2..]),
        "proxy" => cmd_proxy(&args[2..]),
        "explore" => cmd_explore(&args[2..]),
        "generate-faults" => cmd_generate_faults(&args[2..]),
        "fuzz-export" => cmd_fuzz_export(&args[2..]),
        "plugin" => cmd_plugin(&args[2..]),
        "tls-audit" => cmd_tls_audit(&args[2..]),
        "differential" => cmd_differential(&args[2..]),
        "conformance" => cmd_conformance(&args[2..]),
        "interop" => cmd_interop(&args[2..]),
        "platform" => cmd_platform(&args[2..]),
        "run" => cmd_run(&args[2..]),
        "test" => cmd_test(&args[2..]),
        "help" | "-h" | "--help" => {
            usage();
            Ok(())
        }
        other => Err(format!("unknown command `{other}`")),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn usage() {
    eprintln!(
        "tcpform — declaratively compose and simulate protocols\n\
         \n\
         usage:\n  \
         tcpform validate <file>\n  \
         tcpform list <file>\n  \
         tcpform plan [--json] [--json-file <file>] <file> <protocol>\n  \
         tcpform visualize [--output <directory>] [--no-run] <file> <protocol>\n  \
         tcpform serve [--bind 127.0.0.1:8080] [--db tcpform.sqlite] [--auth-config auth.json] [--workers 2] [--retention-days 30]\n  \
         tcpform fmt [--check|--write] [--stdin] [--config <file>] [--indent <n>] [--align] [--expand-inline] <file...>\n  \
         tcpform migrate [--check|--write] <file>\n  \
         tcpform init [directory] [--name <name>] [--template <name>] [--force]\n  \
         tcpform template <list|show <name>|search <query>|add <owner/name>> [--registry <file>]\n  \
         tcpform schema dsl [--output <file>]\n  \
         tcpform schema decode <source> <protocol> <schema> --hex <bytes>\n  \
         tcpform schema encode <source> <protocol> <schema> --values <values.json>\n  \
         tcpform snapshot [--check|--update] [--output <file>] [--latency-tolerance-us <n>] <source> [protocol]\n  \
         tcpform ci-snapshot --output <file> <source> [protocol]\n  \
         tcpform ci-report <baseline.json> <current.json> [--markdown <file>] [--json <file>] [--fail-on-regression]\n  \
         tcpform doctor [--json] [project-directory]\n  \
         tcpform completion <bash|zsh>\n  \
         tcpform import-pcap <capture.pcap|capture.pcapng> --protocol <name> --output <file> [--analysis <report.json>]\n  \
         tcpform import-kaitai <schema.ksy> --output <file> [--protocol <name>]\n  \
         tcpform packetdrill export <source> <protocol> --local-role <role> --output <file.pkt>\n  \
         tcpform packetdrill import <file.pkt> --protocol <name> --local-role <role> --peer-role <role> --output <file.tcpf>\n  \
         tcpform lsp\n  \
         tcpform gate <metrics.json> [--config <file>] [--profile <name>] [--baseline <file>] [--repeat <n>] [--markdown <file>] [--junit <file>] [--github]\n  \
         tcpform bundle --output <file> [--capture <file>] <source> <protocol>\n  \
         tcpform replay-bundle <bundle> [protocol]\n  \
         tcpform anonymize <input.json> <output.json>\n  \
         tcpform orchestrate <scenario.json> [--dry-run]\n  \
         tcpform proxy --listen <address> --upstream <address> [TLS options]\n  \
         tcpform explore <source> <protocol>\n  \
         tcpform generate-faults --output <directory> <source>\n  \
         tcpform fuzz-export <boofuzz|aflnet> <source> <protocol> --role <role> --output <path> [--host <host> --port <port>]\n  \
         tcpform plugin <manifest.json> <action|matcher|decoder|report> <name> <input.json>\n  \
         tcpform tls-audit (--cert <file> | --connect <address> --server-name <name>) [--ca <file>] [--alpn <protocol>] [--warn-days <days>]\n  \
         tcpform differential --left <address> --right <address> --role <role> [--framing <kind>] <file> <protocol>\n  \
         tcpform conformance --connect <address> --role <role> [--udp|--tls|--unix|--websocket|--quic] [--listen] [--framing <kind>] [--json <file>] [--markdown <file>] [--junit <file>] <file> <protocol>\n  \
         tcpform interop --targets <implementations.json> --role <role> [--framing <kind>] [--json <file>] [--markdown <file>] [--junit <file>] <file> <protocol>\n  \
         tcpform platform <openapi-import|protobuf-import|proto-export|wireshark|scapy|schema-check|k8s-job|html-report|sarif|netem> ...\n  \
         tcpform run [--json] [--json-file <file>] [--diagram] [--pcap <file>] [--pcapng <file>] [--allow-plugins] <file> <protocol>\n  \
         tcpform run --live [--udp] --bind <address> <file> <protocol>\n  \
         tcpform run --external --role <role> [--udp|--tls|--unix|--websocket|--quic] [--listen] [--framing <kind>] [--alpn <protocol>] [--require-client-cert] --connect <address> <file> <protocol>\n  \
         tcpform run --raw --interface <name> --role <role> [--snaplen <bytes>] [--promiscuous] [--receive-outgoing] [--allow-host-tcp] [--drop-uid <id> --drop-gid <id>] <file> <protocol>\n  \
         tcpform test [--json] [--junit <file>] [--jobs <n>] [--case <regex>] [--tag <tag>] [--shard <i/n>] <file> [protocol]"
    );
}

fn cmd_platform(args: &[String]) -> Result<(), String> {
    let command = args
        .first()
        .map(String::as_str)
        .ok_or("platform subcommand required")?;
    match command {
        "openapi-import" => {
            let path = args.get(1).ok_or("openapi-import <openapi.json>")?;
            let value: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            print!("{}", tcpform::platform::openapi_to_tcpform(&value)?);
            Ok(())
        }
        "protobuf-import" => {
            let path = args.get(1).ok_or("protobuf-import <schema.proto>")?;
            print!(
                "{}",
                tcpform::platform::protobuf_to_tcpform(
                    &fs::read_to_string(path).map_err(|e| e.to_string())?
                )?
            );
            Ok(())
        }
        "proto-export" | "wireshark" | "scapy" => {
            let path = args
                .get(1)
                .ok_or("proto-export|wireshark|scapy <source> <protocol> [tcp-port]")?;
            let name = args.get(2).ok_or("protocol name required")?;
            let protocols = interpret(&load_blocks(path)?).map_err(|e| e.to_string())?;
            let protocol = find(&protocols, name)?;
            if command == "proto-export" {
                print!("{}", tcpform::platform::tcpform_to_proto(protocol));
            } else {
                let port = args
                    .get(3)
                    .map(String::as_str)
                    .unwrap_or("0")
                    .parse()
                    .map_err(|_| "invalid TCP port")?;
                if command == "wireshark" {
                    print!("{}", tcpform::platform::wireshark_lua(protocol, port));
                } else {
                    print!("{}", tcpform::platform::scapy_python(protocol, port));
                }
            }
            Ok(())
        }
        "schema-check" => {
            let old = args.get(1).ok_or("schema-check <old.json> <new.json>")?;
            let new = args.get(2).ok_or("schema-check <old.json> <new.json>")?;
            let read = |path: &str| -> Result<serde_json::Value, String> {
                serde_json::from_str(&fs::read_to_string(path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())
            };
            tcpform::platform::json_schema_compatible(&read(old)?, &read(new)?)
                .map_err(|errors| errors.join("; "))?;
            println!("compatible");
            Ok(())
        }
        "k8s-job" => {
            if args.len() < 6 {
                return Err("k8s-job <name> <image> <shards> <source> <protocol>".into());
            }
            let shards = args[3].parse().map_err(|_| "invalid shards")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&tcpform::platform::kubernetes_job(
                    &args[1], &args[2], shards, &args[4], &args[5]
                ))
                .unwrap()
            );
            Ok(())
        }
        "html-report" => {
            if args.len() < 5 {
                return Err("html-report <source> <trace.json> <diagram> <output.html>".into());
            }
            let source = fs::read_to_string(&args[1]).map_err(|e| e.to_string())?;
            let trace: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&args[2]).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let diagram = fs::read_to_string(&args[3]).map_err(|e| e.to_string())?;
            fs::write(
                &args[4],
                tcpform::platform::single_html_report(&source, &trace, &diagram, None),
            )
            .map_err(|e| e.to_string())
        }
        "sarif" => {
            let input = args.get(1).ok_or("sarif <failures.json>")?;
            let values: Vec<(String, String, usize)> =
                serde_json::from_str(&fs::read_to_string(input).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&tcpform::platform::sarif_report(&values)).unwrap()
            );
            Ok(())
        }
        "netem" => {
            if args.len() < 5 {
                return Err("netem <interface> <delay-ms> <loss-rate> <reorder:true|false>".into());
            }
            let (apply, cleanup) = tcpform::platform::netem_commands(
                &args[1],
                args[2].parse().map_err(|_| "invalid delay")?,
                args[3].parse().map_err(|_| "invalid loss rate")?,
                args[4].parse().map_err(|_| "invalid reorder")?,
            )?;
            println!(
                "{}",
                serde_json::json!({"program":"tc","apply":apply,"cleanup":cleanup})
            );
            Ok(())
        }
        other => Err(format!("unknown platform subcommand `{other}`")),
    }
}

fn cmd_fuzz_export(args: &[String]) -> Result<(), String> {
    let target = args
        .first()
        .map(String::as_str)
        .ok_or("fuzz-export requires boofuzz or aflnet")?;
    if !matches!(target, "boofuzz" | "aflnet") {
        return Err("fuzz-export target must be boofuzz or aflnet".into());
    }
    let source = args.get(1).ok_or("fuzz-export requires a DSL source")?;
    let name = args.get(2).ok_or("fuzz-export requires a protocol name")?;
    let mut role = None;
    let mut output = None;
    let mut host = "127.0.0.1";
    let mut port = 0u16;
    let mut index = 3;
    while index < args.len() {
        let option = args[index].as_str();
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option {
            "--role" => role = Some(value.as_str()),
            "--output" => output = Some(value.as_str()),
            "--host" => host = value,
            "--port" => port = value.parse().map_err(|_| "invalid --port")?,
            _ => return Err(format!("unknown fuzz-export option `{option}`")),
        }
        index += 1;
    }
    let role = role.ok_or("fuzz-export requires --role <role>")?;
    let output = output.ok_or("fuzz-export requires --output <path>")?;
    let protocols = interpret(&load_blocks(source)?).map_err(|error| error.to_string())?;
    let protocol = find(&protocols, name)?;
    match target {
        "boofuzz" => {
            let script = tcpform::fuzz_export::boofuzz_script(protocol, role, host, port)?;
            fs::write(output, script)
                .map_err(|error| format!("cannot write `{output}`: {error}"))?;
        }
        "aflnet" => {
            let export = tcpform::fuzz_export::aflnet_seed(protocol, role)?;
            fs::create_dir_all(output)
                .map_err(|error| format!("cannot create `{output}`: {error}"))?;
            let directory = std::path::Path::new(output);
            fs::write(directory.join("seed_0001.raw"), export.seed)
                .map_err(|error| error.to_string())?;
            fs::write(directory.join("tcpform.dict"), export.dictionary)
                .map_err(|error| error.to_string())?;
            let manifest = serde_json::to_string_pretty(&export.manifest)
                .map_err(|error| error.to_string())?;
            fs::write(directory.join("manifest.json"), format!("{manifest}\n"))
                .map_err(|error| error.to_string())?;
        }
        _ => unreachable!(),
    }
    println!("generated {output}");
    Ok(())
}

fn cmd_plugin(args: &[String]) -> Result<(), String> {
    let manifest_path = args.first().ok_or(
        "usage: tcpform plugin <manifest.json> <action|matcher|decoder|report> <name> <input.json>",
    )?;
    let kind = args.get(1).ok_or("plugin requires a capability kind")?;
    let name = args.get(2).ok_or("plugin requires a capability name")?;
    let input_path = args.get(3).ok_or("plugin requires an input JSON file")?;
    if !matches!(kind.as_str(), "action" | "matcher" | "decoder" | "report") {
        return Err("plugin kind must be action, matcher, decoder or report".into());
    }
    let manifest: tcpform::PluginManifest = serde_json::from_str(
        &fs::read_to_string(manifest_path)
            .map_err(|error| format!("cannot read plugin manifest {manifest_path}: {error}"))?,
    )
    .map_err(|error| format!("invalid plugin manifest {manifest_path}: {error}"))?;
    let input: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(input_path)
            .map_err(|error| format!("cannot read plugin input {input_path}: {error}"))?,
    )
    .map_err(|error| format!("invalid plugin input {input_path}: {error}"))?;
    let result = tcpform::invoke_plugin(&manifest, kind, name, input)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn cmd_migrate(args: &[String]) -> Result<(), String> {
    let check = args.iter().any(|argument| argument == "--check");
    let write = args.iter().any(|argument| argument == "--write");
    if check && write {
        return Err("migrate accepts either --check or --write".into());
    }
    let path = args
        .iter()
        .find(|argument| !argument.starts_with("--"))
        .ok_or("usage: tcpform migrate [--check|--write] <file>")?;
    let source =
        fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let result = tcpform::tooling::migrate_dsl(&source)?;
    if check {
        if result.source != source {
            return Err(format!(
                "{path} requires migration from DSL v{} to v{}: {}",
                result.from_version,
                result.to_version,
                result.changes.join(", ")
            ));
        }
        return Ok(());
    }
    if write {
        fs::write(path, &result.source).map_err(|error| format!("cannot write {path}: {error}"))?;
    } else {
        print!("{}", result.source);
    }
    Ok(())
}

fn cmd_tls_audit(args: &[String]) -> Result<(), String> {
    let value = |flag: &str| {
        args.iter()
            .position(|argument| argument == flag)
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
    };
    let warn_days = value("--warn-days")
        .unwrap_or("30")
        .parse::<u64>()
        .map_err(|_| "--warn-days requires a non-negative integer")?;
    let report = if let Some(path) = value("--cert") {
        tcpform::audit_certificate_file(path, warn_days)?
    } else {
        let address = value("--connect").ok_or("tls-audit requires --cert or --connect")?;
        let server_name = value("--server-name").ok_or("--connect requires --server-name")?;
        let alpn = value("--alpn")
            .map(str::to_string)
            .into_iter()
            .collect::<Vec<_>>();
        tcpform::audit_tls_endpoint(address, server_name, value("--ca"), warn_days, &alpn)?
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
    );
    if report
        .certificates
        .iter()
        .any(|certificate| matches!(certificate.status.as_str(), "expired" | "not_yet_valid"))
    {
        return Err("TLS certificate validity audit failed".into());
    }
    Ok(())
}

fn cmd_differential(args: &[String]) -> Result<(), String> {
    let mut left = None;
    let mut right = None;
    let mut role = None;
    let mut framing = tcpform::Framing::Raw;
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let next = |index: &mut usize, flag: &str| -> Result<String, String> {
            *index += 1;
            args.get(*index)
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match args[index].as_str() {
            "--left" => left = Some(next(&mut index, "--left")?),
            "--right" => right = Some(next(&mut index, "--right")?),
            "--role" => role = Some(next(&mut index, "--role")?),
            "--framing" => framing = parse_framing(&next(&mut index, "--framing")?)?,
            option if option.starts_with('-') => {
                return Err(format!("unknown differential option `{option}`"));
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }
    if positional.len() != 2 {
        return Err("differential requires <file> <protocol>".into());
    }
    let protocols = load(&positional[0])?;
    let protocol = find(&protocols, &positional[1])?.clone();
    let role = role.ok_or("differential requires --role")?;
    let run = |address: &str| {
        Engine::new(protocol.clone())
            .map_err(|error| error.to_string())?
            .run_external_tcp_framed(&role, address, false, framing.clone())
            .map_err(|error| error.to_string())
    };
    let left_trace = run(&left.ok_or("differential requires --left")?)?;
    let right_trace = run(&right.ok_or("differential requires --right")?)?;
    let (report, equal) = tcpform::output::differential_trace_json(&left_trace, &right_trace);
    println!("{report}");
    if equal {
        Ok(())
    } else {
        Err("differential implementations diverged".into())
    }
}

fn cmd_interop(args: &[String]) -> Result<(), String> {
    let mut targets = None;
    let mut role = None;
    let mut json_output = None;
    let mut markdown_output = None;
    let mut junit_output = None;
    let mut framing = tcpform::Framing::Raw;
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let value = |index: &mut usize, flag: &str| -> Result<String, String> {
            *index += 1;
            args.get(*index)
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match args[index].as_str() {
            "--targets" => targets = Some(value(&mut index, "--targets")?),
            "--role" => role = Some(value(&mut index, "--role")?),
            "--framing" => framing = parse_framing(&value(&mut index, "--framing")?)?,
            "--json" => json_output = Some(value(&mut index, "--json")?),
            "--markdown" => markdown_output = Some(value(&mut index, "--markdown")?),
            "--junit" => junit_output = Some(value(&mut index, "--junit")?),
            option if option.starts_with('-') => {
                return Err(format!("unknown interop option `{option}`"));
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }
    if positional.len() != 2 {
        return Err("interop requires <file> <protocol>".into());
    }
    let role = role.ok_or("interop requires --role <role>")?;
    let targets = targets.ok_or("interop requires --targets <implementations.json>")?;
    let config: tcpform::interoperability::InteroperabilityConfig = serde_json::from_str(
        &fs::read_to_string(&targets)
            .map_err(|error| format!("cannot read `{targets}`: {error}"))?,
    )
    .map_err(|error| format!("invalid interoperability config `{targets}`: {error}"))?;
    tcpform::interoperability::validate_config(&config)?;
    let protocols = load(&positional[0])?;
    let protocol = find(&protocols, &positional[1])?.clone();
    let mut runs = Vec::with_capacity(config.implementations.len());
    for implementation in config.implementations {
        let result = Engine::new(protocol.clone())
            .map_err(|error| error.to_string())?
            .run_external_tcp_framed(&role, &implementation.address, false, framing.clone());
        let (trace, failure_kind, error) = match result {
            Ok(trace) => (trace, None, None),
            Err(EngineError::Runtime {
                kind,
                message,
                trace,
                ..
            }) => (trace, Some(kind.as_str().to_string()), Some(message)),
            Err(error) => return Err(error.to_string()),
        };
        runs.push(tcpform::interoperability::ImplementationRun {
            name: implementation.name,
            address: implementation.address,
            trace,
            failure_kind,
            error,
        });
    }
    let report = tcpform::interoperability::build_report(&protocol.name, &role, &runs);
    let json = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    if let Some(path) = json_output.as_deref() {
        fs::write(path, &json).map_err(|error| format!("cannot write `{path}`: {error}"))?;
    }
    if let Some(path) = markdown_output.as_deref() {
        fs::write(path, tcpform::interoperability::markdown(&report))
            .map_err(|error| format!("cannot write `{path}`: {error}"))?;
    }
    if let Some(path) = junit_output.as_deref() {
        fs::write(path, tcpform::interoperability::junit(&report))
            .map_err(|error| format!("cannot write `{path}`: {error}"))?;
    }
    if json_output.is_none() && markdown_output.is_none() && junit_output.is_none() {
        println!("{json}");
    }
    if report.status == "interoperable" {
        Ok(())
    } else {
        Err("implementations are not interoperable".into())
    }
}

fn cmd_conformance(args: &[String]) -> Result<(), String> {
    let mut address = None;
    let mut role = None;
    let mut json_output = None;
    let mut markdown_output = None;
    let mut junit_output = None;
    let mut framing = tcpform::Framing::Raw;
    let mut tls_options = tcpform::TlsOptions::default();
    let mut udp_options = tcpform::UdpOptions::default();
    let mut websocket_options = tcpform::WebSocketOptions::default();
    let mut udp = false;
    let mut tls = false;
    let mut unix = false;
    let mut websocket = false;
    let mut quic = false;
    let mut listen = false;
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let value = |index: &mut usize, flag: &str| -> Result<String, String> {
            *index += 1;
            args.get(*index)
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match args[index].as_str() {
            "--connect" | "--address" => address = Some(value(&mut index, "--connect")?),
            "--role" => role = Some(value(&mut index, "--role")?),
            "--json" => json_output = Some(value(&mut index, "--json")?),
            "--markdown" => markdown_output = Some(value(&mut index, "--markdown")?),
            "--junit" => junit_output = Some(value(&mut index, "--junit")?),
            "--framing" => framing = parse_framing(&value(&mut index, "--framing")?)?,
            "--listen" => listen = true,
            "--udp" => udp = true,
            "--tls" => tls = true,
            "--unix" => unix = true,
            "--websocket" => websocket = true,
            "--quic" => quic = true,
            "--server-name" => tls_options.server_name = Some(value(&mut index, "--server-name")?),
            "--ca" => tls_options.ca_file = Some(value(&mut index, "--ca")?),
            "--tls-cert" => tls_options.cert_file = Some(value(&mut index, "--tls-cert")?),
            "--tls-key" => tls_options.key_file = Some(value(&mut index, "--tls-key")?),
            "--alpn" => tls_options
                .alpn_protocols
                .push(value(&mut index, "--alpn")?),
            "--require-client-cert" => tls_options.require_client_auth = true,
            "--broadcast" => udp_options.broadcast = true,
            "--reuse-address" => udp_options.reuse_address = true,
            "--multicast" => udp_options.multicast_group = Some(value(&mut index, "--multicast")?),
            "--multicast-interface" => {
                udp_options.multicast_interface = Some(value(&mut index, "--multicast-interface")?)
            }
            "--multicast-ttl" => {
                udp_options.multicast_ttl = Some(
                    value(&mut index, "--multicast-ttl")?
                        .parse()
                        .map_err(|_| "--multicast-ttl requires an integer")?,
                )
            }
            "--websocket-text" => websocket_options.text = true,
            "--websocket-protocol" => websocket_options
                .subprotocols
                .push(value(&mut index, "--websocket-protocol")?),
            "--origin" => websocket_options.origin = Some(value(&mut index, "--origin")?),
            option if option.starts_with('-') => {
                return Err(format!("unknown conformance option `{option}`"));
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }
    if positional.len() != 2 {
        return Err("conformance requires <file> <protocol>".into());
    }
    if usize::from(udp)
        + usize::from(tls)
        + usize::from(unix)
        + usize::from(websocket)
        + usize::from(quic)
        > 1
    {
        return Err("--udp, --tls, --unix, --websocket, and --quic are mutually exclusive".into());
    }
    if udp && framing != tcpform::Framing::Raw {
        return Err("--framing is not used by UDP datagrams".into());
    }
    let address = address.ok_or("conformance requires --connect <address>")?;
    let role = role.ok_or("conformance requires --role <role>")?;
    let protocols = load(&positional[0])?;
    let protocol = find(&protocols, &positional[1])?.clone();
    let engine = Engine::new(protocol.clone()).map_err(|error| error.to_string())?;
    let result = if quic {
        engine.run_external_quic(&role, &address, listen, &tls_options)
    } else if websocket {
        engine.run_external_websocket(&role, &address, listen, &websocket_options)
    } else if unix {
        #[cfg(unix)]
        {
            engine.run_external_unix(&role, &address, listen, framing)
        }
        #[cfg(not(unix))]
        {
            return Err("--unix is only supported on Unix platforms".into());
        }
    } else if tls {
        engine.run_external_tls(&role, &address, listen, framing, &tls_options)
    } else if udp {
        engine.run_external_udp_with_options(&role, &address, listen, &udp_options)
    } else {
        engine.run_external_tcp_framed(&role, &address, listen, framing)
    };
    let (trace, failure) = match result {
        Ok(trace) => (trace, None),
        Err(EngineError::Runtime {
            kind,
            message,
            trace,
            ..
        }) => (trace, Some((kind.as_str().to_string(), message))),
        Err(error) => return Err(error.to_string()),
    };
    let report = tcpform::conformance::build_report(
        &protocol,
        &role,
        &address,
        &trace,
        failure
            .as_ref()
            .map(|(kind, message)| (kind.as_str(), message.as_str())),
    );
    let json = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    if let Some(path) = json_output.as_deref() {
        fs::write(path, &json).map_err(|error| format!("cannot write `{path}`: {error}"))?;
    }
    if let Some(path) = markdown_output.as_deref() {
        fs::write(path, tcpform::conformance::markdown(&report))
            .map_err(|error| format!("cannot write `{path}`: {error}"))?;
    }
    if let Some(path) = junit_output.as_deref() {
        fs::write(path, tcpform::conformance::junit(&report))
            .map_err(|error| format!("cannot write `{path}`: {error}"))?;
    }
    if json_output.is_none() && markdown_output.is_none() && junit_output.is_none() {
        println!("{json}");
    }
    if report.status == "conformant" {
        Ok(())
    } else {
        Err(format!(
            "target `{address}` is nonconformant ({} passed, {} failed, {} not run)",
            report.summary.passed, report.summary.failed, report.summary.not_run
        ))
    }
}

fn load(path: &str) -> Result<Vec<Protocol>, String> {
    let blocks = load_blocks(path)?;
    interpret(&blocks).map_err(|e| e.to_string())
}

/// Load protocols and case suites from a file.
fn load_with_cases(path: &str) -> Result<(Vec<Protocol>, Vec<tcpform::Cases>), String> {
    let blocks = load_blocks(path)?;
    let protocols = interpret(&blocks).map_err(|e| e.to_string())?;
    let cases = tcpform::model::interpret_cases(&blocks).map_err(|e| e.to_string())?;
    Ok((protocols, cases))
}

fn find<'a>(protocols: &'a [Protocol], name: &str) -> Result<&'a Protocol, String> {
    protocols
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| format!("protocol `{name}` not found in file"))
}

fn cmd_validate(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("usage: tcpform validate <file>")?;
    let source = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let blocks = tcpform::parse_file(&source).map_err(|error| error.to_string())?;
    let compatibility = tcpform::compat::inspect_dsl(&source, &blocks)?;
    for warning in compatibility.warnings {
        eprintln!("warning: {warning}");
    }
    let protocols = interpret(&blocks).map_err(|error| error.to_string())?;
    for p in &protocols {
        Engine::new(p.clone()).map_err(|e| e.to_string())?;
        println!("ok: protocol `{}` ({} steps)", p.name, p.steps.len());
    }
    if protocols.is_empty() {
        println!("ok: no protocols defined");
    }
    Ok(())
}

fn cmd_init(args: &[String]) -> Result<(), String> {
    let mut directory = ".";
    let mut name = None;
    let mut template = "tcp-handshake";
    let mut force = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--name" => {
                index += 1;
                name = Some(args.get(index).ok_or("--name requires a value")?.as_str());
            }
            "--template" => {
                index += 1;
                template = args.get(index).ok_or("--template requires a value")?;
            }
            "--force" => force = true,
            value if !value.starts_with('-') && directory == "." => directory = value,
            value => return Err(format!("unknown init argument `{value}`")),
        }
        index += 1;
    }
    let path = std::path::Path::new(directory);
    let inferred = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("tcpform-project");
    let project_name = name.unwrap_or(inferred);
    let written = if template.contains('/') {
        let root = env::current_dir().map_err(|error| error.to_string())?;
        let source = tcpform::template_registry::load_locked(&root, template)?;
        tcpform::templates::init_project_with_source(path, project_name, template, &source, force)?
    } else {
        tcpform::templates::init_project(path, project_name, template, force)?
    };
    for path in written {
        println!("created {}", path.display());
    }
    Ok(())
}

fn cmd_template(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("list") => {
            for template in tcpform::templates::list_templates() {
                println!("{:<14} {}", template.name, template.description);
            }
            Ok(())
        }
        Some("show") => {
            let name = args.get(1).ok_or("template show <name>")?;
            print!("{}", tcpform::templates::render_template(name, name)?);
            Ok(())
        }
        Some("search") => {
            let query = args.get(1).ok_or("template search <query> [--registry <file>]")?;
            let root = env::current_dir().map_err(|error| error.to_string())?;
            let registry_path = template_registry_path(args, &root)?;
            let registry = tcpform::template_registry::read_registry(&registry_path)?;
            for entry in tcpform::template_registry::search(&registry, query) {
                println!("{:<28} {:<12} {}", entry.name, entry.version, entry.revision);
            }
            Ok(())
        }
        Some("add") => {
            let name = args.get(1).ok_or("template add <owner/name> [--registry <file>]")?;
            let root = env::current_dir().map_err(|error| error.to_string())?;
            let registry_path = template_registry_path(args, &root)?;
            let locked = tcpform::template_registry::add(&root, &registry_path, name)?;
            println!(
                "locked {} {} at {} ({})",
                locked.entry.name, locked.entry.version, locked.entry.revision, locked.entry.sha256
            );
            Ok(())
        }
        _ => Err("usage: tcpform template <list|show <name>|search <query>|add <owner/name>> [--registry <file>]".into()),
    }
}

fn template_registry_path(
    args: &[String],
    root: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    let path = if let Some(index) = args.iter().position(|arg| arg == "--registry") {
        std::path::PathBuf::from(args.get(index + 1).ok_or("--registry requires a file")?)
    } else {
        std::path::PathBuf::from(tcpform::template_registry::DEFAULT_REGISTRY)
    };
    Ok(if path.is_absolute() {
        path
    } else {
        root.join(path)
    })
}

fn cmd_schema(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("dsl") => {
            let rendered = serde_json::to_string_pretty(&tcpform::compat::dsl_json_schema())
                .map_err(|error| error.to_string())?;
            if let Some(position) = args.iter().position(|arg| arg == "--output") {
                let path = args.get(position + 1).ok_or("--output requires a file")?;
                fs::write(path, format!("{rendered}\n")).map_err(|error| error.to_string())?;
            } else {
                println!("{rendered}");
            }
        }
        Some(command @ ("decode" | "encode")) => {
            let source = args
                .get(1)
                .ok_or("schema decode|encode requires a source")?;
            let protocol_name = args
                .get(2)
                .ok_or("schema decode|encode requires a protocol")?;
            let schema_name = args
                .get(3)
                .ok_or("schema decode|encode requires a schema")?;
            let protocols = interpret(&load_blocks(source)?).map_err(|error| error.to_string())?;
            let protocol = find(&protocols, protocol_name)?;
            let schema = protocol
                .header_schemas
                .iter()
                .find(|schema| schema.name == *schema_name)
                .ok_or_else(|| format!("unknown header schema `{schema_name}`"))?;
            if command == "decode" {
                let position = args
                    .iter()
                    .position(|arg| arg == "--hex")
                    .ok_or("schema decode requires --hex <bytes>")?;
                let bytes =
                    tcpform::parse_hex(args.get(position + 1).ok_or("--hex requires bytes")?)?;
                let decoded =
                    tcpform::decode_schema(schema, &bytes).map_err(|error| error.to_string())?;
                let document = serde_json::json!({
                    "fields":decoded.fields.iter().map(|(key,value)|(key.clone(),tcpform::plugin::dsl_value_to_json(value))).collect::<serde_json::Map<_,_>>(),
                    "checksum_valid":decoded.checksum_valid,
                    "consumed":decoded.consumed,
                    "unknown_hex":tcpform::bytes_to_hex(&decoded.unknown),
                });
                println!("{}", serde_json::to_string_pretty(&document).unwrap());
            } else {
                let position = args
                    .iter()
                    .position(|arg| arg == "--values")
                    .ok_or("schema encode requires --values <values.json>")?;
                let path = args.get(position + 1).ok_or("--values requires a file")?;
                let json: serde_json::Value = serde_json::from_str(
                    &fs::read_to_string(path).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                let values = json
                    .as_object()
                    .ok_or("values JSON must be an object")?
                    .iter()
                    .map(|(key, value)| (key.clone(), tcpform::plugin::json_to_dsl_value(value)))
                    .collect();
                println!(
                    "{}",
                    tcpform::bytes_to_hex(
                        &tcpform::encode_schema(schema, &values)
                            .map_err(|error| error.to_string())?
                    )
                );
            }
        }
        _ => return Err("usage: tcpform schema <dsl|decode|encode> ...".into()),
    }
    Ok(())
}

fn cmd_ci_snapshot(args: &[String]) -> Result<(), String> {
    let output_position = args
        .iter()
        .position(|arg| arg == "--output")
        .ok_or("ci-snapshot requires --output <file>")?;
    let output = args
        .get(output_position + 1)
        .ok_or("--output requires a file")?;
    let positional = args
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != output_position && *index != output_position + 1)
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    let source = positional
        .first()
        .ok_or("ci-snapshot requires a source file")?;
    let (protocols, suites) = load_with_cases(source)?;
    let snapshot = tcpform::ci_report::create_snapshot(
        &protocols,
        &suites,
        positional.get(1).map(|value| value.as_str()),
    )?;
    fs::write(
        output,
        format!("{}\n", serde_json::to_string_pretty(&snapshot).unwrap()),
    )
    .map_err(|error| error.to_string())
}

fn cmd_snapshot(args: &[String]) -> Result<(), String> {
    let check = args.iter().any(|arg| arg == "--check");
    let update = args.iter().any(|arg| arg == "--update");
    if check && update {
        return Err("--check and --update cannot be used together".into());
    }
    let value_after = |flag: &str| -> Result<Option<&String>, String> {
        args.iter()
            .position(|arg| arg == flag)
            .map(|index| {
                args.get(index + 1)
                    .ok_or_else(|| format!("{flag} requires a value"))
            })
            .transpose()
    };
    let output = value_after("--output")?;
    let tolerance = value_after("--latency-tolerance-us")?
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "--latency-tolerance-us must be an integer".to_string())
        })
        .transpose()?
        .unwrap_or(1_000);
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--check" | "--update" => index += 1,
            "--output" | "--latency-tolerance-us" => index += 2,
            value if value.starts_with('-') => {
                return Err(format!("unknown snapshot option `{value}`"))
            }
            _ => {
                positional.push(&args[index]);
                index += 1;
            }
        }
    }
    let source = positional
        .first()
        .ok_or("snapshot requires a source file")?;
    let snapshot_path = output
        .cloned()
        .unwrap_or_else(|| format!("{source}.snapshot.json"));
    let (protocols, suites) = load_with_cases(source)?;
    let current = tcpform::snapshot::create(
        &protocols,
        &suites,
        positional.get(1).map(|value| value.as_str()),
    )?;
    let path = std::path::Path::new(&snapshot_path);
    if check || (path.exists() && !update) {
        let baseline: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?,
        )
        .map_err(|error| format!("invalid snapshot {}: {error}", path.display()))?;
        tcpform::snapshot::check(&baseline, &current, tolerance)?;
        println!("snapshot matches {}", path.display());
        return Ok(());
    }
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(&current).unwrap()),
    )
    .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    println!("snapshot written to {}", path.display());
    Ok(())
}

fn cmd_ci_report(args: &[String]) -> Result<(), String> {
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--markdown" | "--json" => index += 2,
            "--fail-on-regression" => index += 1,
            value if value.starts_with('-') => {
                return Err(format!("unknown ci-report argument `{value}`"));
            }
            _ => {
                positional.push(&args[index]);
                index += 1;
            }
        }
    }
    let baseline_path = positional
        .first()
        .ok_or("ci-report requires baseline and current snapshots")?;
    let current_path = positional
        .get(1)
        .ok_or("ci-report requires baseline and current snapshots")?;
    let read = |path: &str| -> Result<serde_json::Value, String> {
        serde_json::from_str(&fs::read_to_string(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())
    };
    let report = tcpform::ci_report::compare_snapshots(&read(baseline_path)?, &read(current_path)?);
    let markdown = tcpform::ci_report::markdown_report(&report);
    if let Some(position) = args.iter().position(|arg| arg == "--markdown") {
        fs::write(
            args.get(position + 1).ok_or("--markdown requires a file")?,
            &markdown,
        )
        .map_err(|error| error.to_string())?;
    } else {
        print!("{markdown}");
    }
    if let Some(position) = args.iter().position(|arg| arg == "--json") {
        fs::write(
            args.get(position + 1).ok_or("--json requires a file")?,
            format!("{}\n", serde_json::to_string_pretty(&report).unwrap()),
        )
        .map_err(|error| error.to_string())?;
    }
    if args.iter().any(|arg| arg == "--fail-on-regression")
        && report["regression"].as_bool() == Some(true)
    {
        return Err("tcpform regression detected".into());
    }
    Ok(())
}

fn cmd_doctor(args: &[String]) -> Result<(), String> {
    let mut json = false;
    let mut project = None;
    for argument in args {
        match argument.as_str() {
            "--json" => json = true,
            value if value.starts_with('-') => {
                return Err(format!("unknown doctor option `{value}`"));
            }
            value if project.is_none() => project = Some(value),
            _ => return Err("doctor accepts at most one project directory".into()),
        }
    }
    let path = std::path::Path::new(project.unwrap_or("."));
    if !path.is_dir() {
        return Err(format!(
            "project directory does not exist: {}",
            path.display()
        ));
    }
    let report = tcpform::doctor::diagnose(path);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "tcpform doctor — tcpform {}, DSL v{}",
            report.tcpform_version, report.dsl_version
        );
        println!("project: {}", report.project);
        for check in &report.checks {
            let label = match check.status {
                tcpform::doctor::CheckStatus::Pass => "PASS",
                tcpform::doctor::CheckStatus::Warn => "WARN",
                tcpform::doctor::CheckStatus::Fail => "FAIL",
            };
            println!("{label:<4} {:<20} {}", check.name, check.message);
        }
    }
    if report.healthy() {
        Ok(())
    } else {
        Err("doctor found one or more fatal problems".into())
    }
}

fn cmd_completion(args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: tcpform completion <bash|zsh>".into());
    }
    print!("{}", tcpform::completion::generate(&args[0])?);
    Ok(())
}

fn cmd_import_pcap(args: &[String]) -> Result<(), String> {
    let mut input = None;
    let mut protocol = None;
    let mut output = None;
    let mut analysis = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--protocol" => {
                index += 1;
                protocol = Some(
                    args.get(index)
                        .ok_or("--protocol requires a name")?
                        .as_str(),
                );
            }
            "--output" => {
                index += 1;
                output = Some(args.get(index).ok_or("--output requires a file")?.as_str());
            }
            "--analysis" => {
                index += 1;
                analysis = Some(
                    args.get(index)
                        .ok_or("--analysis requires a JSON file")?
                        .as_str(),
                );
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown import-pcap option `{value}`"));
            }
            value if input.is_none() => input = Some(value),
            _ => return Err("import-pcap accepts one capture file".into()),
        }
        index += 1;
    }
    let input = input.ok_or("import-pcap requires a capture file")?;
    let protocol = protocol.ok_or("import-pcap requires --protocol <name>")?;
    let output = output.ok_or("import-pcap requires --output <file>")?;
    let bytes = fs::read(input).map_err(|error| format!("cannot read `{input}`: {error}"))?;
    let source = tcpform::pcap_import::import_capture(&bytes, protocol)?;
    fs::write(output, source).map_err(|error| format!("cannot write `{output}`: {error}"))?;
    if let Some(path) = analysis {
        let report = tcpform::pcap_import::analyze_capture(&bytes)?;
        let document = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
        fs::write(path, format!("{document}\n"))
            .map_err(|error| format!("cannot write `{path}`: {error}"))?;
        println!("generated {path}");
    }
    println!("generated {output}");
    Ok(())
}

fn cmd_import_kaitai(args: &[String]) -> Result<(), String> {
    let mut input = None;
    let mut output = None;
    let mut protocol = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                index += 1;
                output = Some(args.get(index).ok_or("--output requires a file")?.as_str());
            }
            "--protocol" => {
                index += 1;
                protocol = Some(
                    args.get(index)
                        .ok_or("--protocol requires a name")?
                        .as_str(),
                );
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown import-kaitai option `{value}`"));
            }
            value if input.is_none() => input = Some(value),
            _ => return Err("import-kaitai accepts one schema file".into()),
        }
        index += 1;
    }
    let input = input.ok_or("import-kaitai requires a .ksy schema")?;
    let output = output.ok_or("import-kaitai requires --output <file>")?;
    let source =
        fs::read_to_string(input).map_err(|error| format!("cannot read `{input}`: {error}"))?;
    let imported = tcpform::kaitai::import_ksy(&source, protocol)?;
    fs::write(output, imported.dsl).map_err(|error| format!("cannot write `{output}`: {error}"))?;
    for warning in imported.warnings {
        eprintln!("warning: {warning}");
    }
    println!("generated {output}");
    Ok(())
}

fn cmd_packetdrill(args: &[String]) -> Result<(), String> {
    let action = args
        .first()
        .map(String::as_str)
        .ok_or("packetdrill requires import or export")?;
    match action {
        "export" => {
            let source = args.get(1).ok_or("packetdrill export requires a source")?;
            let name = args
                .get(2)
                .ok_or("packetdrill export requires a protocol")?;
            let options = key_value_options(&args[3..])?;
            let role = options
                .get("--local-role")
                .ok_or("packetdrill export requires --local-role")?;
            let output = options
                .get("--output")
                .ok_or("packetdrill export requires --output")?;
            let protocols = interpret(&load_blocks(source)?).map_err(|error| error.to_string())?;
            let protocol = find(&protocols, name)?;
            fs::write(output, tcpform::packetdrill::export(protocol, role)?)
                .map_err(|error| format!("cannot write `{output}`: {error}"))?;
            println!("generated {output}");
            Ok(())
        }
        "import" => {
            let source = args
                .get(1)
                .ok_or("packetdrill import requires a .pkt file")?;
            let options = key_value_options(&args[2..])?;
            let protocol = options
                .get("--protocol")
                .ok_or("packetdrill import requires --protocol")?;
            let local = options
                .get("--local-role")
                .ok_or("packetdrill import requires --local-role")?;
            let peer = options
                .get("--peer-role")
                .ok_or("packetdrill import requires --peer-role")?;
            let output = options
                .get("--output")
                .ok_or("packetdrill import requires --output")?;
            let source = fs::read_to_string(source).map_err(|error| error.to_string())?;
            let imported = tcpform::packetdrill::import(&source, protocol, local, peer)?;
            fs::write(output, imported.dsl).map_err(|error| error.to_string())?;
            for warning in imported.warnings {
                eprintln!("warning: {warning}");
            }
            println!("generated {output}");
            Ok(())
        }
        value => Err(format!("unknown packetdrill action `{value}`")),
    }
}

fn key_value_options(args: &[String]) -> Result<HashMap<&str, &str>, String> {
    if !args.len().is_multiple_of(2) {
        return Err(format!("{} requires a value", args.last().unwrap()));
    }
    let mut options = HashMap::new();
    for pair in args.chunks_exact(2) {
        if !pair[0].starts_with("--") {
            return Err(format!("unexpected argument `{}`", pair[0]));
        }
        if options.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err(format!("duplicate option `{}`", pair[0]));
        }
    }
    Ok(options)
}

fn cmd_list(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("usage: tcpform list <file>")?;
    let protocols = load(path)?;
    if protocols.is_empty() {
        println!("(no protocols)");
        return Ok(());
    }
    for p in &protocols {
        let roles: Vec<&str> = {
            let mut r = Vec::new();
            for s in &p.steps {
                if !r.contains(&s.role.as_str()) {
                    r.push(s.role.as_str());
                }
            }
            r
        };
        println!(
            "{}  ({} steps, roles: {})",
            p.name,
            p.steps.len(),
            roles.join(", ")
        );
    }
    Ok(())
}

fn cmd_plan(args: &[String]) -> Result<(), String> {
    let mut json = false;
    let mut json_file = None;
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--json-file" => {
                index += 1;
                json_file = Some(
                    args.get(index)
                        .ok_or("--json-file requires a path")?
                        .clone(),
                );
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown plan option `{value}`"))
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }
    let path = positional
        .first()
        .ok_or("usage: tcpform plan <file> <protocol>")?;
    let name = positional
        .get(1)
        .ok_or("usage: tcpform plan <file> <protocol>")?;
    let (protocols, cases) = load_with_cases(path)?;
    let p = find(&protocols, name)?;
    if json || json_file.is_some() {
        let document = tcpform::output::visualization_manifest(p, &cases, &[]);
        if json {
            println!("{document}");
        }
        if let Some(output) = json_file {
            fs::write(&output, &document)
                .map_err(|e| format!("cannot write manifest `{output}`: {e}"))?;
        }
        return Ok(());
    }
    let engine = Engine::new(p.clone()).map_err(|e| e.to_string())?;
    let plan = engine.plan();
    println!(
        "plan: protocol `{}`  roles: [{}]",
        plan.protocol_name,
        plan.roles.join(", ")
    );
    println!(
        "{:<4} {:<14} {:<8} {:<9} depends_on",
        "#", "step", "role", "action"
    );
    for (i, ps) in plan.order.iter().enumerate() {
        let deps = if ps.deps.is_empty() {
            "-".to_string()
        } else {
            ps.deps.join(", ")
        };
        println!(
            "{:<4} {:<14} {:<8} {:<9} {}",
            i + 1,
            ps.step.name,
            ps.step.role,
            ps.step.action.as_str(),
            deps
        );
    }
    Ok(())
}

fn cmd_visualize(args: &[String]) -> Result<(), String> {
    let mut output = "tcpform-visualization".to_string();
    let mut run = true;
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                index += 1;
                output = args
                    .get(index)
                    .ok_or("--output requires a directory")?
                    .clone();
            }
            "--no-run" => run = false,
            value if value.starts_with('-') => {
                return Err(format!("unknown visualize option `{value}`"))
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }
    let path = positional
        .first()
        .ok_or("usage: tcpform visualize [--output <directory>] [--no-run] <file> <protocol>")?;
    let name = positional
        .get(1)
        .ok_or("usage: tcpform visualize [--output <directory>] [--no-run] <file> <protocol>")?;
    let (protocols, cases) = load_with_cases(path)?;
    let protocol = find(&protocols, name)?;
    Engine::new(protocol.clone()).map_err(|e| e.to_string())?;
    fs::create_dir_all(&output).map_err(|e| format!("cannot create `{output}`: {e}"))?;
    let trace_files = if run {
        vec!["trace.json".to_string()]
    } else {
        Vec::new()
    };
    let case_defs = cases
        .iter()
        .filter(|suite| suite.protocol == protocol.name)
        .flat_map(|suite| suite.cases.iter().cloned())
        .collect::<Vec<_>>();
    let case_trace_files = if run {
        let results = Engine::new(protocol.clone())
            .map_err(|e| e.to_string())?
            .run_cases(&case_defs);
        let mut files = Vec::new();
        for (index, result) in results.iter().enumerate() {
            let filename = format!("case-{index}.json");
            let status = result.actual.as_str();
            let fallback =
                (!result.assertion_failures.is_empty()).then_some("case assertions failed");
            let document = tcpform::output::trace_json_with_failure(
                status,
                result.failure_kind.map(|kind| kind.as_str()),
                result.error.as_deref().or(fallback),
                &result.trace,
            );
            fs::write(format!("{output}/{filename}"), document).map_err(|e| e.to_string())?;
            files.push(filename);
        }
        files
    } else {
        Vec::new()
    };
    fs::write(
        format!("{output}/manifest.json"),
        tcpform::output::visualization_manifest_with_case_traces(
            protocol,
            &cases,
            &trace_files,
            &case_trace_files,
        ),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        format!("{output}/index.html"),
        include_str!("../dashboard/index.html"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        format!("{output}/order.js"),
        include_str!("../dashboard/order.js"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        format!("{output}/flow.js"),
        include_str!("../dashboard/flow.js"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        format!("{output}/packet-view.js"),
        include_str!("../dashboard/packet-view.js"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        format!("{output}/analysis-tools.js"),
        include_str!("../dashboard/analysis-tools.js"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        format!("{output}/advanced-tools.js"),
        include_str!("../dashboard/advanced-tools.js"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        format!("{output}/workbench-tools.js"),
        include_str!("../dashboard/workbench-tools.js"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        format!("{output}/platform-ui.js"),
        include_str!("../dashboard/platform-ui.js"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        format!("{output}/workbench-worker.js"),
        include_str!("../dashboard/workbench-worker.js"),
    )
    .map_err(|e| e.to_string())?;
    if run {
        let result = Engine::new(protocol.clone())
            .map_err(|e| e.to_string())?
            .run();
        let document = match result {
            Ok(trace) => tcpform::output::trace_json("ok", None, &trace),
            Err(EngineError::Runtime {
                kind,
                message,
                trace,
                ..
            }) => tcpform::output::trace_json_with_failure(
                "fail",
                Some(kind.as_str()),
                Some(&message),
                &trace,
            ),
            Err(error) => return Err(error.to_string()),
        };
        fs::write(format!("{output}/trace.json"), document).map_err(|e| e.to_string())?;
    }
    println!("visualization written to {output}/index.html");
    Ok(())
}

#[derive(Clone, Deserialize)]
struct AuthEntry {
    name: String,
    token_sha256: String,
    role: String,
}

#[derive(Clone)]
struct ServerState {
    store: tcpform::Store,
    auth: Vec<AuthEntry>,
    rates: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
    max_request: usize,
}

impl ServerState {
    fn identity(&self, headers: &HashMap<String, String>) -> Result<(String, String), String> {
        if self.auth.is_empty() {
            return Ok(("anonymous".into(), "admin".into()));
        }
        let token = headers
            .get("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or("authentication required")?;
        let digest = tcpform::bytes_to_hex(&Sha256::digest(token.as_bytes()));
        self.auth
            .iter()
            .find(|entry| entry.token_sha256 == digest)
            .map(|entry| (entry.name.clone(), entry.role.clone()))
            .ok_or_else(|| "invalid bearer token".into())
    }

    fn authorize(
        &self,
        headers: &HashMap<String, String>,
        permission: &str,
        mutating: bool,
    ) -> Result<(String, String), String> {
        let identity = self.identity(headers)?;
        let allowed = match identity.1.as_str() {
            "admin" => true,
            "runner" => permission != "admin",
            "viewer" => permission == "view",
            _ => false,
        };
        if !allowed {
            return Err("permission denied".into());
        }
        if mutating
            && !self.auth.is_empty()
            && headers.get("x-tcpform-csrf").map(String::as_str) != Some("1")
        {
            return Err("missing X-Tcpform-CSRF: 1".into());
        }
        let mut rates = self.rates.lock().map_err(|_| "rate limiter poisoned")?;
        let entry = rates
            .entry(identity.0.clone())
            .or_insert((Instant::now(), 0));
        if entry.0.elapsed() >= Duration::from_secs(60) {
            *entry = (Instant::now(), 0);
        }
        if entry.1 >= 120 {
            return Err("rate limit exceeded".into());
        }
        entry.1 += 1;
        Ok(identity)
    }
}

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let mut bind = "127.0.0.1:8080".to_string();
    let mut database = "tcpform.sqlite".to_string();
    let mut auth_config = None;
    let mut workers = 2usize;
    let mut retention_days = 30u64;
    let mut max_request = 16 * 1024 * 1024usize;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bind" => {
                index += 1;
                bind = args.get(index).ok_or("--bind requires an address")?.clone();
            }
            "--db" => {
                index += 1;
                database = args.get(index).ok_or("--db requires a path")?.clone();
            }
            "--auth-config" => {
                index += 1;
                auth_config = Some(
                    args.get(index)
                        .ok_or("--auth-config requires a path")?
                        .clone(),
                );
            }
            "--workers" => {
                index += 1;
                workers = args
                    .get(index)
                    .ok_or("--workers requires a number")?
                    .parse()
                    .map_err(|_| "invalid --workers")?;
            }
            "--retention-days" => {
                index += 1;
                retention_days = args
                    .get(index)
                    .ok_or("--retention-days requires a number")?
                    .parse()
                    .map_err(|_| "invalid --retention-days")?;
            }
            "--max-request-bytes" => {
                index += 1;
                max_request = args
                    .get(index)
                    .ok_or("--max-request-bytes requires a number")?
                    .parse()
                    .map_err(|_| "invalid --max-request-bytes")?;
            }
            value => return Err(format!("unknown serve option `{value}`")),
        }
        index += 1;
    }
    let auth = auth_config
        .map(|path| {
            serde_json::from_str::<Vec<AuthEntry>>(
                &fs::read_to_string(&path).map_err(|e| format!("cannot read {path}: {e}"))?,
            )
            .map_err(|e| format!("invalid auth config: {e}"))
        })
        .transpose()?
        .unwrap_or_default();
    for entry in &auth {
        if !matches!(entry.role.as_str(), "viewer" | "runner" | "admin")
            || entry.token_sha256.len() != 64
        {
            return Err(format!("invalid auth entry for {}", entry.name));
        }
    }
    let store = tcpform::Store::open(&database)?;
    store.prune(retention_days)?;
    let state = Arc::new(ServerState {
        store,
        auth,
        rates: Arc::new(Mutex::new(HashMap::new())),
        max_request,
    });
    for _ in 0..workers.clamp(1, 32) {
        let worker_state = Arc::clone(&state);
        std::thread::spawn(move || job_worker(worker_state));
    }
    let listener = TcpListener::bind(&bind).map_err(|e| format!("cannot bind {bind}: {e}"))?;
    println!("tcpform visualizer: http://{bind}");
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(error) = serve_request(&mut stream, &state) {
                        let _ = http_response(
                            &mut stream,
                            "500 Internal Server Error",
                            "text/plain",
                            error.as_bytes(),
                        );
                    }
                });
            }
            Err(error) => eprintln!("visualizer connection error: {error}"),
        }
    }
    Ok(())
}

fn job_worker(state: Arc<ServerState>) {
    loop {
        match state.store.claim_job() {
            Ok(Some(job)) => {
                if job.cancel_requested {
                    let _ = state.store.cancel_job(&job.id);
                    continue;
                }
                let bytes = serde_json::to_vec(&job.payload).unwrap_or_default();
                let _ = state.store.update_job_progress(&job.id, 0.25);
                let result = uploaded_visualization(&bytes).and_then(|document| {
                    serde_json::from_str(&document).map_err(|e| e.to_string())
                });
                match &result {
                    Ok(value) => {
                        let _ = state.store.finish_job(&job.id, Ok(value));
                    }
                    Err(error) => {
                        let _ = state.store.finish_job(&job.id, Err(error));
                    }
                }
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => {
                eprintln!("job worker: {error}");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn serve_request(stream: &mut TcpStream, state: &ServerState) -> Result<(), String> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 8192];
    let header_end;
    loop {
        let count = stream.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("incomplete HTTP request".to_string());
        }
        request.extend_from_slice(&buffer[..count]);
        if request.len() > state.max_request {
            return http_response(
                stream,
                "413 Payload Too Large",
                "text/plain",
                b"request exceeds configured limit",
            );
        }
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = position + 4;
            break;
        }
    }
    let header = std::str::from_utf8(&request[..header_end])
        .map_err(|_| "invalid HTTP header".to_string())?;
    let first = header.lines().next().ok_or("missing request line")?;
    let mut request_line = first.split_whitespace();
    let method = request_line.next().ok_or("missing method")?.to_string();
    let path = request_line.next().ok_or("missing path")?.to_string();
    let headers = header
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect::<HashMap<_, _>>();
    let length = header
        .lines()
        .find_map(|line| {
            line.strip_prefix("Content-Length:")
                .or_else(|| line.strip_prefix("content-length:"))
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if length > state.max_request {
        return http_response(
            stream,
            "413 Payload Too Large",
            "text/plain",
            b"request exceeds configured limit",
        );
    }
    while request.len() < header_end + length {
        let count = stream.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..count]);
    }
    let route = path.split('?').next().unwrap_or(&path);
    let body = request
        .get(header_end..header_end + length)
        .ok_or("incomplete request body")?;
    match (method.as_str(), route) {
        ("GET", "/") | ("GET", "/index.html") => http_response(
            stream,
            "200 OK",
            "text/html; charset=utf-8",
            include_bytes!("../dashboard/index.html"),
        ),
        ("GET", "/order.js") => http_response(
            stream,
            "200 OK",
            "text/javascript",
            include_bytes!("../dashboard/order.js"),
        ),
        ("GET", "/flow.js") => http_response(
            stream,
            "200 OK",
            "text/javascript",
            include_bytes!("../dashboard/flow.js"),
        ),
        ("GET", "/packet-view.js") => http_response(
            stream,
            "200 OK",
            "text/javascript",
            include_bytes!("../dashboard/packet-view.js"),
        ),
        ("GET", "/analysis-tools.js") => http_response(
            stream,
            "200 OK",
            "text/javascript",
            include_bytes!("../dashboard/analysis-tools.js"),
        ),
        ("GET", "/advanced-tools.js") => http_response(
            stream,
            "200 OK",
            "text/javascript",
            include_bytes!("../dashboard/advanced-tools.js"),
        ),
        ("GET", "/workbench-tools.js") => http_response(
            stream,
            "200 OK",
            "text/javascript",
            include_bytes!("../dashboard/workbench-tools.js"),
        ),
        ("GET", "/platform-ui.js") => http_response(
            stream,
            "200 OK",
            "text/javascript",
            include_bytes!("../dashboard/platform-ui.js"),
        ),
        ("GET", "/workbench-worker.js") => http_response(
            stream,
            "200 OK",
            "text/javascript",
            include_bytes!("../dashboard/workbench-worker.js"),
        ),
        ("GET", "/api/openapi.json") => http_response(
            stream,
            "200 OK",
            "application/json",
            api_openapi().to_string().as_bytes(),
        ),
        ("GET", "/metrics") => {
            if let Err(error) = state.authorize(&headers, "admin", false) {
                return api_error(stream, "403 Forbidden", &error);
            }
            http_response(
                stream,
                "200 OK",
                "text/plain; version=0.0.4",
                tcpform::platform::prometheus_metrics().as_bytes(),
            )
        }
        ("GET", "/api/v1/jobs") => {
            if let Err(error) = state.authorize(&headers, "view", false) {
                return api_error(stream, "401 Unauthorized", &error);
            }
            json_response(
                stream,
                "200 OK",
                &serde_json::json!({"schema_version":"1.0","jobs":state.store.list_jobs(100)?}),
            )
        }
        ("POST", "/api/v1/jobs") => {
            let identity = match state.authorize(&headers, "run", true) {
                Ok(value) => value,
                Err(error) => return api_error(stream, "403 Forbidden", &error),
            };
            let payload: serde_json::Value =
                serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;
            let job = state.store.create_job(&payload)?;
            state
                .store
                .audit(&identity.0, "create", &job.id, "ok", "visualization job")?;
            json_response(
                stream,
                "202 Accepted",
                &serde_json::json!({"schema_version":"1.0","job":job}),
            )
        }
        ("GET", route) if route.starts_with("/api/v1/jobs/") => {
            if let Err(error) = state.authorize(&headers, "view", false) {
                return api_error(stream, "401 Unauthorized", &error);
            }
            let id = route.trim_start_matches("/api/v1/jobs/");
            match state.store.get_job(id)? {
                Some(job) => json_response(
                    stream,
                    "200 OK",
                    &serde_json::json!({"schema_version":"1.0","job":job}),
                ),
                None => api_error(stream, "404 Not Found", "job not found"),
            }
        }
        ("POST", route) if route.starts_with("/api/v1/jobs/") && route.ends_with("/cancel") => {
            let identity = match state.authorize(&headers, "run", true) {
                Ok(value) => value,
                Err(error) => return api_error(stream, "403 Forbidden", &error),
            };
            let id = route
                .trim_start_matches("/api/v1/jobs/")
                .trim_end_matches("/cancel")
                .trim_end_matches('/');
            let changed = state.store.cancel_job(id)?;
            state.store.audit(
                &identity.0,
                "cancel",
                id,
                if changed { "ok" } else { "ignored" },
                "",
            )?;
            json_response(
                stream,
                if changed { "200 OK" } else { "409 Conflict" },
                &serde_json::json!({"changed":changed}),
            )
        }
        ("POST", route) if route.starts_with("/api/v1/jobs/") && route.ends_with("/retry") => {
            let identity = match state.authorize(&headers, "run", true) {
                Ok(value) => value,
                Err(error) => return api_error(stream, "403 Forbidden", &error),
            };
            let id = route
                .trim_start_matches("/api/v1/jobs/")
                .trim_end_matches("/retry")
                .trim_end_matches('/');
            let changed = state.store.retry_job(id)?;
            state.store.audit(
                &identity.0,
                "retry",
                id,
                if changed { "ok" } else { "ignored" },
                "",
            )?;
            json_response(
                stream,
                if changed { "200 OK" } else { "409 Conflict" },
                &serde_json::json!({"changed":changed}),
            )
        }
        ("GET", "/api/v1/runs") => {
            if let Err(error) = state.authorize(&headers, "view", false) {
                return api_error(stream, "401 Unauthorized", &error);
            }
            json_response(
                stream,
                "200 OK",
                &serde_json::json!({"schema_version":"1.0","runs":state.store.list_runs(None, 100)?}),
            )
        }
        ("GET", "/api/v1/corpus") => {
            if let Err(error) = state.authorize(&headers, "view", false) {
                return api_error(stream, "401 Unauthorized", &error);
            }
            json_response(
                stream,
                "200 OK",
                &serde_json::json!({"schema_version":"1.0","corpus":state.store.list_corpus(100)?}),
            )
        }
        ("POST", "/api/v1/corpus/revalidate") => {
            let identity = match state.authorize(&headers, "run", true) {
                Ok(value) => value,
                Err(error) => return api_error(stream, "403 Forbidden", &error),
            };
            let mut jobs = Vec::new();
            for payload in state.store.corpus_revalidation_payloads()? {
                jobs.push(state.store.create_job(&payload)?);
            }
            state.store.audit(
                &identity.0,
                "revalidate",
                "corpus",
                "ok",
                &format!("{} jobs", jobs.len()),
            )?;
            json_response(stream, "202 Accepted", &serde_json::json!({"jobs":jobs}))
        }
        ("POST", route) if route.starts_with("/api/v1/corpus/") && route.ends_with("/promote") => {
            let identity = match state.authorize(&headers, "run", true) {
                Ok(value) => value,
                Err(error) => return api_error(stream, "403 Forbidden", &error),
            };
            let fingerprint = route
                .trim_start_matches("/api/v1/corpus/")
                .trim_end_matches("/promote")
                .trim_end_matches('/');
            let changed = state.store.promote_corpus(fingerprint)?;
            state.store.audit(
                &identity.0,
                "promote",
                fingerprint,
                if changed { "ok" } else { "missing" },
                "corpus",
            )?;
            json_response(
                stream,
                if changed { "200 OK" } else { "404 Not Found" },
                &serde_json::json!({"changed":changed}),
            )
        }
        ("POST", "/api/v1/shares") => {
            let identity = match state.authorize(&headers, "run", true) {
                Ok(value) => value,
                Err(error) => return api_error(stream, "403 Forbidden", &error),
            };
            let value: serde_json::Value =
                serde_json::from_slice(body).map_err(|e| e.to_string())?;
            let id = state.store.create_share(
                value.get("document").unwrap_or(&value),
                value.get("ttl_seconds").and_then(|v| v.as_u64()),
            )?;
            state
                .store
                .audit(&identity.0, "create", &id, "ok", "share")?;
            json_response(
                stream,
                "201 Created",
                &serde_json::json!({"id":id,"path":format!("/api/v1/shares/{id}")}),
            )
        }
        ("GET", route) if route.starts_with("/api/v1/shares/") => {
            let id = route.trim_start_matches("/api/v1/shares/");
            match state.store.get_share(id)? {
                Some(value) => json_response(stream, "200 OK", &value),
                None => api_error(stream, "404 Not Found", "share not found or expired"),
            }
        }
        ("POST", "/api/v1/baselines") => {
            let identity = match state.authorize(&headers, "run", true) {
                Ok(value) => value,
                Err(error) => return api_error(stream, "403 Forbidden", &error),
            };
            let value: serde_json::Value =
                serde_json::from_slice(body).map_err(|e| e.to_string())?;
            let id = state.store.save_baseline(
                value
                    .get("protocol")
                    .and_then(|v| v.as_str())
                    .ok_or("protocol required")?,
                value
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or("name required")?,
                value.get("document").unwrap_or(&serde_json::Value::Null),
            )?;
            state
                .store
                .audit(&identity.0, "create", &id, "ok", "baseline")?;
            json_response(stream, "201 Created", &serde_json::json!({"id":id}))
        }
        ("POST", "/api/v1/annotations") => {
            let identity = match state.authorize(&headers, "run", true) {
                Ok(value) => value,
                Err(error) => return api_error(stream, "403 Forbidden", &error),
            };
            let value: serde_json::Value =
                serde_json::from_slice(body).map_err(|e| e.to_string())?;
            let id = state.store.add_annotation(
                value
                    .get("protocol")
                    .and_then(|v| v.as_str())
                    .ok_or("protocol required")?,
                value
                    .get("event_index")
                    .and_then(|v| v.as_u64())
                    .ok_or("event_index required")? as usize,
                value.get("step").and_then(|v| v.as_str()).unwrap_or(""),
                value
                    .get("text")
                    .and_then(|v| v.as_str())
                    .ok_or("text required")?,
                &identity.0,
            )?;
            state
                .store
                .audit(&identity.0, "create", &id, "ok", "annotation")?;
            json_response(stream, "201 Created", &serde_json::json!({"id":id}))
        }
        ("POST", "/api/visualize") => {
            if let Err(error) = state.authorize(&headers, "run", true) {
                return api_error(stream, "403 Forbidden", &error);
            }
            match uploaded_visualization(body) {
                Ok(document) => {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&document) {
                        let protocol = value
                            .get("manifest")
                            .and_then(|v| v.get("protocol"))
                            .and_then(|v| v.get("name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let _ = state.store.save_run(protocol, "ok", &value);
                        let failed = value
                            .get("documents")
                            .and_then(|v| v.as_object())
                            .is_some_and(|documents| {
                                documents.values().any(|document| {
                                    document.get("status").and_then(|v| v.as_str()) == Some("fail")
                                })
                            });
                        if failed {
                            let _ = state.store.record_corpus(protocol, &value);
                        }
                    }
                    http_response(stream, "200 OK", "application/json", document.as_bytes())
                }
                Err(error) => http_response(
                    stream,
                    "400 Bad Request",
                    "application/json",
                    serde_json::json!({"error":error}).to_string().as_bytes(),
                ),
            }
        }
        ("POST", "/api/live") => {
            if let Err(error) = state.authorize(&headers, "run", true) {
                return api_error(stream, "403 Forbidden", &error);
            }
            stream_live_visualization(stream, body)
        }
        _ => http_response(stream, "404 Not Found", "text/plain", b"not found"),
    }
}

fn uploaded_protocol(body: &[u8]) -> Result<Protocol, String> {
    let input: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;
    let requested = input.get("protocol").and_then(|value| value.as_str());
    let blocks = if let Some(files) = input.get("files") {
        let files = files.as_object().ok_or("files must be an object")?;
        let sources = files
            .iter()
            .map(|(path, value)| {
                value
                    .as_str()
                    .map(|source| (path.clone(), source.to_string()))
                    .ok_or_else(|| format!("file `{path}` must contain text"))
            })
            .collect::<Result<std::collections::HashMap<_, _>, _>>()?;
        let root = input
            .get("root")
            .and_then(|value| value.as_str())
            .ok_or("root must name the entry file")?;
        tcpform::load_blocks_from_sources(root, &sources)?
    } else {
        let source = input
            .get("source")
            .and_then(|value| value.as_str())
            .ok_or("source must be a string")?;
        tcpform::parse_file_named(source, Some("uploaded.tcpf")).map_err(|e| e.to_string())?
    };
    let protocols = interpret(&blocks).map_err(|e| e.to_string())?;
    requested.map_or_else(
        || {
            protocols
                .first()
                .cloned()
                .ok_or_else(|| "no protocol in uploaded source".to_string())
        },
        |name| find(&protocols, name).cloned(),
    )
}

fn stream_live_visualization(stream: &mut TcpStream, body: &[u8]) -> Result<(), String> {
    let input: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;
    let mode = input
        .get("mode")
        .and_then(|value| value.as_str())
        .unwrap_or("simulation");
    let protocol = match uploaded_protocol(body) {
        Ok(protocol) => protocol,
        Err(error) => {
            return http_response(
                stream,
                "400 Bad Request",
                "application/json",
                serde_json::json!({"error":error}).to_string().as_bytes(),
            )
        }
    };
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nConnection: close\r\nX-Accel-Buffering: no\r\n\r\n").map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let output = std::sync::Arc::new(std::sync::Mutex::new(
        stream.try_clone().map_err(|e| e.to_string())?,
    ));
    let writer = std::sync::Arc::clone(&output);
    let observer = std::sync::Arc::new(move |event: &tcpform::TraceEvent| {
        let document = tcpform::output::trace_json("ok", None, std::slice::from_ref(event));
        let value = serde_json::from_str::<serde_json::Value>(&document)
            .ok()
            .and_then(|value| value.get("events")?.get(0).cloned());
        if let Some(value) = value {
            if let Ok(mut stream) = writer.lock() {
                let _ = writeln!(stream, "data: {value}\n");
                let _ = stream.flush();
            }
        }
    });
    let result = Engine::new(protocol).and_then(|engine| match mode {
        "simulation" => engine.run_with_observer(observer),
        "live" => {
            let bind = input
                .get("bind")
                .and_then(|value| value.as_str())
                .unwrap_or("127.0.0.1:0");
            let udp = input
                .get("udp")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            engine.run_live_with_observer(bind, udp, observer)
        }
        "raw" => {
            let role = input
                .get("role")
                .and_then(|value| value.as_str())
                .ok_or_else(|| EngineError::Plan("raw live stream requires role".to_string()))?;
            let interface = input
                .get("interface")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    EngineError::Plan("raw live stream requires interface".to_string())
                })?;
            let mut config = tcpform::RawSocketConfig::new(interface);
            config.receive_outgoing = input
                .get("receive_outgoing")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            config.promiscuous = input
                .get("promiscuous")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            config.allow_host_tcp = input
                .get("allow_host_tcp")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            engine.run_external_raw_with_observer(role, config, observer)
        }
        other => Err(EngineError::Plan(format!("unknown live mode `{other}`"))),
    });
    let mut stream = output.lock().map_err(|_| "live stream lock poisoned")?;
    match result {
        Ok(_) => writeln!(stream, "event: complete\ndata: {{\"status\":\"ok\"}}\n"),
        Err(error) => writeln!(
            stream,
            "event: complete\ndata: {}\n",
            serde_json::json!({"status":"fail","error":error.to_string()})
        ),
    }
    .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

fn uploaded_visualization(body: &[u8]) -> Result<String, String> {
    let _span = tcpform::platform::Span::start("visualize");
    let input: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))?;
    let source = input.get("source").and_then(|value| value.as_str());
    let requested = input.get("protocol").and_then(|value| value.as_str());
    let (blocks, root, sources) = if let Some(files) = input.get("files") {
        let files = files
            .as_object()
            .ok_or("files must be an object of path to source")?;
        if files.is_empty() {
            return Err("files must not be empty".into());
        }
        if files.len() > 128 {
            return Err("uploaded bundle exceeds 128 files".into());
        }
        let sources = files
            .iter()
            .map(|(path, value)| {
                let source = value
                    .as_str()
                    .ok_or_else(|| format!("file `{path}` must contain text"))?;
                Ok((path.clone(), source.to_string()))
            })
            .collect::<Result<std::collections::HashMap<_, _>, String>>()?;
        let root = input
            .get("root")
            .and_then(|value| value.as_str())
            .ok_or("root must name the entry file")?
            .to_string();
        let blocks = tcpform::load_blocks_from_sources(&root, &sources)?;
        (blocks, root, sources)
    } else {
        let source = source.ok_or("source must be a string when files is omitted")?;
        let root = "uploaded.tcpf".to_string();
        let sources = std::collections::HashMap::from([(root.clone(), source.to_string())]);
        let blocks = tcpform::parse_file_named(source, Some(&root)).map_err(|e| e.to_string())?;
        (blocks, root, sources)
    };
    let protocols = interpret(&blocks).map_err(|e| e.to_string())?;
    let suites = tcpform::model::interpret_cases(&blocks).map_err(|e| e.to_string())?;
    let protocol = if let Some(name) = requested {
        find(&protocols, name)?
    } else {
        protocols.first().ok_or("no protocol in uploaded source")?
    };
    let case_defs = suites
        .iter()
        .filter(|suite| suite.protocol == protocol.name)
        .flat_map(|suite| suite.cases.iter().cloned())
        .collect::<Vec<_>>();
    let case_files = (0..case_defs.len())
        .map(|index| format!("case-{index}.json"))
        .collect::<Vec<_>>();
    let manifest: serde_json::Value =
        serde_json::from_str(&tcpform::output::visualization_manifest_with_case_traces(
            protocol,
            &suites,
            &["trace.json".to_string()],
            &case_files,
        ))
        .map_err(|e| e.to_string())?;
    let mut documents = serde_json::Map::new();
    let engine = Engine::new(protocol.clone()).map_err(|e| e.to_string())?;
    let base = match engine.run() {
        Ok(trace) => tcpform::output::trace_json("ok", None, &trace),
        Err(EngineError::Runtime {
            kind,
            message,
            trace,
            ..
        }) => tcpform::output::trace_json_with_failure(
            "fail",
            Some(kind.as_str()),
            Some(&message),
            &trace,
        ),
        Err(error) => return Err(error.to_string()),
    };
    documents.insert(
        "trace.json".to_string(),
        serde_json::from_str(&base).map_err(|e| e.to_string())?,
    );
    for (index, result) in Engine::new(protocol.clone())
        .map_err(|e| e.to_string())?
        .run_cases(&case_defs)
        .iter()
        .enumerate()
    {
        let status = result.actual.as_str();
        let fallback = (!result.assertion_failures.is_empty()).then_some("case assertions failed");
        let trace = tcpform::output::trace_json_with_failure(
            status,
            result.failure_kind.map(|kind| kind.as_str()),
            result.error.as_deref().or(fallback),
            &result.trace,
        );
        documents.insert(
            format!("case-{index}.json"),
            serde_json::from_str(&trace).map_err(|e| e.to_string())?,
        );
    }
    let mut source_files = sources.keys().cloned().collect::<Vec<_>>();
    source_files.sort();
    Ok(serde_json::json!({
        "manifest":manifest,"documents":documents,"root":root,"sources":sources,
        "source_files":source_files,
        "protocols":protocols.iter().map(|protocol|protocol.name.as_str()).collect::<Vec<_>>()
    })
    .to_string())
}

fn http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n", body.len()).map_err(|e| e.to_string())?;
    stream.write_all(body).map_err(|e| e.to_string())
}

fn json_response(
    stream: &mut TcpStream,
    status: &str,
    value: &serde_json::Value,
) -> Result<(), String> {
    http_response(
        stream,
        status,
        "application/json",
        value.to_string().as_bytes(),
    )
}

fn api_error(stream: &mut TcpStream, status: &str, error: &str) -> Result<(), String> {
    json_response(
        stream,
        status,
        &serde_json::json!({"schema_version":"1.0","error":error}),
    )
}

fn api_openapi() -> serde_json::Value {
    serde_json::json!({
        "openapi":"3.1.0",
        "info":{"title":"tcpform visualizer API","version":"1.0.0"},
        "components":{
            "securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}},
            "schemas":{
                "Job":{"type":"object","required":["id","status","payload","created_at","updated_at","attempt","progress"],"properties":{"id":{"type":"string"},"status":{"enum":["queued","running","completed","failed","cancelled"]},"payload":{},"result":{},"error":{"type":["string","null"]},"attempt":{"type":"integer"},"progress":{"type":"number","minimum":0,"maximum":1}}},
                "VisualizationRequest":{"type":"object","oneOf":[{"required":["source"]},{"required":["files","root"]}]},
                "Error":{"type":"object","required":["schema_version","error"]}
            }
        },
        "paths":{
            "/api/visualize":{"post":{"summary":"Run synchronously","security":[{"bearer":[]}]}},
            "/api/v1/jobs":{"get":{"summary":"List jobs"},"post":{"summary":"Queue a run"}},
            "/api/v1/jobs/{id}":{"get":{"summary":"Get a job"}},
            "/api/v1/jobs/{id}/cancel":{"post":{"summary":"Cancel a job"}},
            "/api/v1/jobs/{id}/retry":{"post":{"summary":"Retry a job"}},
            "/api/v1/runs":{"get":{"summary":"List persisted runs"}},
            "/api/v1/corpus":{"get":{"summary":"List deduplicated failures"}},
            "/api/v1/corpus/revalidate":{"post":{"summary":"Queue regression corpus"}},
            "/api/v1/baselines":{"post":{"summary":"Create a baseline"}},
            "/api/v1/annotations":{"post":{"summary":"Create an annotation"}}
        }
    })
}

fn cmd_fmt(args: &[String]) -> Result<(), String> {
    let mut check = false;
    let mut stdin_mode = false;
    let mut config_path = None;
    let mut options = tcpform::tooling::FormatOptions::default();
    let mut files = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--check" => check = true,
            "--write" => check = false,
            "--stdin" | "-" => stdin_mode = true,
            "--align" => options.align_attributes = true,
            "--expand-inline" => options.preserve_inline_blocks = false,
            "--indent" => {
                index += 1;
                options.indent_width = args
                    .get(index)
                    .ok_or("--indent requires a number")?
                    .parse::<usize>()
                    .map_err(|_| "--indent requires a non-negative integer")?;
            }
            "--config" => {
                index += 1;
                config_path = Some(args.get(index).ok_or("--config requires a file")?.clone());
            }
            option if option.starts_with('-') => {
                return Err(format!("unknown fmt option `{option}`"));
            }
            path => files.push(path.to_string()),
        }
        index += 1;
    }
    let discovered = config_path.or_else(|| {
        std::path::Path::new(".tcpformfmt.json")
            .exists()
            .then(|| ".tcpformfmt.json".to_string())
    });
    if let Some(path) = discovered {
        options = serde_json::from_str(
            &fs::read_to_string(&path).map_err(|error| format!("cannot read `{path}`: {error}"))?,
        )
        .map_err(|error| format!("invalid formatter config `{path}`: {error}"))?;
        if args.iter().any(|argument| argument == "--align") {
            options.align_attributes = true;
        }
        if args.iter().any(|argument| argument == "--expand-inline") {
            options.preserve_inline_blocks = false;
        }
    }
    if stdin_mode {
        if !files.is_empty() {
            return Err("fmt --stdin does not accept file arguments".to_string());
        }
        let mut source = String::new();
        std::io::stdin()
            .read_to_string(&mut source)
            .map_err(|error| error.to_string())?;
        tcpform::parse_file(&source).map_err(|error| error.to_string())?;
        print!(
            "{}",
            tcpform::tooling::format_dsl_with_options(&source, &options)
        );
        return Ok(());
    }
    if files.is_empty() {
        return Err("usage: tcpform fmt [options] <file...>".to_string());
    }
    let mut changed = Vec::new();
    for path in &files {
        let source = fs::read_to_string(path).map_err(|e| format!("cannot read `{path}`: {e}"))?;
        tcpform::parse_file_named(&source, Some(path)).map_err(|e| e.to_string())?;
        let formatted = tcpform::tooling::format_dsl_with_options(&source, &options);
        tcpform::parse_file_named(&formatted, Some(path)).map_err(|e| e.to_string())?;
        if source != formatted {
            changed.push(path.clone());
            if !check {
                fs::write(path, formatted).map_err(|e| format!("cannot write `{path}`: {e}"))?;
            }
        }
    }
    if check && !changed.is_empty() {
        return Err(format!("files need formatting: {}", changed.join(", ")));
    }
    Ok(())
}

fn cmd_lsp() -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    tcpform::tooling::run_lsp(&mut stdin.lock(), &mut stdout.lock())
}

fn cmd_gate(args: &[String]) -> Result<(), String> {
    let path = args
        .first()
        .ok_or("usage: tcpform gate <metrics.json> [thresholds]")?;
    let metrics: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(path).map_err(|e| format!("cannot read `{path}`: {e}"))?,
    )
    .map_err(|e| format!("invalid metrics JSON: {e}"))?;
    let mut thresholds = serde_json::Map::new();
    let mut config_path = None;
    let mut profile = None;
    let mut baseline_path = None;
    let mut markdown_path = None;
    let mut junit_path = None;
    let mut github = false;
    let mut repeat = 1usize;
    let mut index = 1;
    while index < args.len() {
        let option = args[index].as_str();
        if option == "--github" {
            github = true;
            index += 1;
            continue;
        }
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option {
            "--config" => config_path = Some(value.clone()),
            "--profile" => profile = Some(value.clone()),
            "--baseline" => baseline_path = Some(value.clone()),
            "--markdown" => markdown_path = Some(value.clone()),
            "--junit" => junit_path = Some(value.clone()),
            "--repeat" => repeat = value.parse().map_err(|_| "--repeat requires an integer")?,
            "--min-success-rate" | "--max-p95-us" | "--min-coverage" | "--max-retries" => {
                let key = option.trim_start_matches("--").replace('-', "_");
                thresholds.insert(
                    key,
                    serde_json::json!(value
                        .parse::<f64>()
                        .map_err(|_| format!("invalid threshold `{value}`"))?),
                );
            }
            _ => return Err(format!("unknown gate option `{option}`")),
        }
        index += 1;
    }
    let discovered = config_path.or_else(|| {
        std::path::Path::new(".tcpform-gate.json")
            .exists()
            .then(|| ".tcpform-gate.json".into())
    });
    if let Some(path) = discovered {
        let config: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&path)
                .map_err(|e| format!("cannot read gate config `{path}`: {e}"))?,
        )
        .map_err(|e| format!("invalid gate config `{path}`: {e}"))?;
        let configured = if let Some(name) = profile.as_deref() {
            config
                .pointer(&format!("/profiles/{name}/thresholds"))
                .ok_or_else(|| format!("unknown gate profile `{name}`"))?
        } else {
            config.get("thresholds").unwrap_or(&config)
        };
        if let Some(map) = configured.as_object() {
            for (key, value) in map {
                thresholds
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
        }
    }
    let checks = [
        ("success_rate", "min_success_rate", true),
        ("p95_us", "max_p95_us", false),
        ("coverage", "min_coverage", true),
        ("retries", "max_retries", false),
    ];
    let mut failures = Vec::new();
    for (metric, threshold, minimum) in checks {
        if let Some(limit) = thresholds.get(threshold).and_then(|value| value.as_f64()) {
            let actual = metrics
                .get(metric)
                .and_then(|value| value.as_f64())
                .ok_or_else(|| format!("metrics JSON lacks numeric `{metric}`"))?;
            if (minimum && actual < limit) || (!minimum && actual > limit) {
                failures.push(format!("{metric}={actual} violates {threshold}={limit}"));
            }
        }
    }
    if repeat > 1 {
        let runs = metrics
            .get("runs")
            .and_then(|value| value.as_array())
            .ok_or("--repeat requires metrics.runs")?;
        if runs.len() < repeat {
            failures.push(format!(
                "only {} stability runs, expected {repeat}",
                runs.len()
            ));
        }
        let statuses = runs
            .iter()
            .take(repeat)
            .filter_map(|run| run.get("status").and_then(|value| value.as_str()))
            .collect::<std::collections::HashSet<_>>();
        if statuses.len() > 1 {
            failures.push(format!("flaky result across {repeat} runs"));
        }
    }
    if let Some(path) = baseline_path {
        let baseline: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&path)
                .map_err(|e| format!("cannot read baseline `{path}`: {e}"))?,
        )
        .map_err(|e| format!("invalid baseline `{path}`: {e}"))?;
        for key in ["packet_hash", "packet_count", "schema_hash"] {
            if baseline.get(key).is_some() && baseline.get(key) != metrics.get(key) {
                failures.push(format!(
                    "{key} changed from {} to {}",
                    baseline.get(key).unwrap(),
                    metrics.get(key).unwrap_or(&serde_json::Value::Null)
                ));
            }
        }
    }
    let passed = failures.is_empty();
    let report = serde_json::json!({"passed":passed,"failures":&failures,"thresholds":thresholds,"profile":profile,"repeat":repeat});
    println!("{report}");
    let details = if failures.is_empty() {
        "No regressions detected.".to_string()
    } else {
        failures
            .iter()
            .map(|failure| format!("- {failure}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    if let Some(path) = markdown_path {
        fs::write(
            path,
            format!(
                "# tcpform regression gate\n\n**{}**\n\n{details}\n",
                if passed { "PASS" } else { "FAIL" }
            ),
        )
        .map_err(|e| e.to_string())?;
    }
    if let Some(path) = junit_path {
        let failure = if passed {
            String::new()
        } else {
            format!(
                "<failure message=\"regression gate failed\">{}</failure>",
                xml_escape(&failures.join("\n"))
            )
        };
        fs::write(path, format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><testsuite name=\"tcpform gate\" tests=\"1\" failures=\"{}\"><testcase name=\"regression\">{failure}</testcase></testsuite>\n", usize::from(!passed))).map_err(|e| e.to_string())?;
    }
    if github {
        for failure in &failures {
            println!(
                "::error title=tcpform regression gate::{}",
                failure.replace('\n', "%0A")
            );
        }
    }
    if passed {
        Ok(())
    } else {
        Err("regression gate failed".to_string())
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn cmd_bundle(args: &[String]) -> Result<(), String> {
    let output_index = args
        .iter()
        .position(|arg| arg == "--output")
        .ok_or("bundle requires --output <file>")?;
    let output = args
        .get(output_index + 1)
        .ok_or("--output requires a file")?;
    let capture_index = args.iter().position(|arg| arg == "--capture");
    let capture = capture_index
        .map(|index| args.get(index + 1).ok_or("--capture requires a file"))
        .transpose()?;
    let positional = args
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            *index != output_index
                && *index != output_index + 1
                && capture_index.is_none_or(|capture| *index != capture && *index != capture + 1)
        })
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    let path = positional
        .first()
        .ok_or("bundle requires source and protocol")?;
    let name = positional
        .get(1)
        .ok_or("bundle requires source and protocol")?;
    let (protocols, suites) = load_with_cases(path)?;
    let mut protocol = find(&protocols, name)?.clone();
    let effective_seed = protocol
        .transport
        .as_mut()
        .map(|transport| {
            if transport.seed == 0 {
                transport.seed = reproduction_seed();
            }
            transport.seed
        })
        .unwrap_or(0);
    let result = Engine::new(protocol.clone())
        .map_err(|e| e.to_string())?
        .run();
    let trace = match result {
        Ok(trace) => tcpform::output::trace_json("ok", None, &trace),
        Err(EngineError::Runtime {
            kind,
            message,
            trace,
            ..
        }) => tcpform::output::trace_json_with_failure(
            "fail",
            Some(kind.as_str()),
            Some(&message),
            &trace,
        ),
        Err(error) => return Err(error.to_string()),
    };
    let case_defs = suites
        .iter()
        .filter(|suite| suite.protocol == protocol.name)
        .flat_map(|suite| suite.cases.iter().cloned())
        .collect::<Vec<_>>();
    let case_files = (0..case_defs.len())
        .map(|index| format!("case-{index}.json"))
        .collect::<Vec<_>>();
    let manifest: serde_json::Value =
        serde_json::from_str(&tcpform::output::visualization_manifest_with_case_traces(
            &protocol,
            &suites,
            &["trace.json".to_string()],
            &case_files,
        ))
        .map_err(|e| e.to_string())?;
    let mut documents = serde_json::Map::new();
    documents.insert(
        "trace.json".into(),
        serde_json::from_str(&trace).map_err(|e| e.to_string())?,
    );
    for (index, result) in Engine::new(protocol.clone())
        .map_err(|e| e.to_string())?
        .run_cases(&case_defs)
        .iter()
        .enumerate()
    {
        let fallback = (!result.assertion_failures.is_empty()).then_some("case assertions failed");
        let text = tcpform::output::trace_json_with_failure(
            result.actual.as_str(),
            result.failure_kind.map(|kind| kind.as_str()),
            result.error.as_deref().or(fallback),
            &result.trace,
        );
        documents.insert(
            format!("case-{index}.json"),
            serde_json::from_str(&text).map_err(|e| e.to_string())?,
        );
    }
    let sources = collect_bundle_sources(path)?;
    let capture_hex = capture
        .map(|path| {
            fs::read(path)
                .map(|bytes| hex_encode(&bytes))
                .map_err(|e| e.to_string())
        })
        .transpose()?;
    let mut hashes = serde_json::Map::new();
    for (name, value) in &sources {
        if let Some(text) = value.as_str() {
            hashes.insert(
                format!("sources/{name}"),
                sha256_hex(text.as_bytes()).into(),
            );
        }
    }
    hashes.insert(
        "manifest".into(),
        sha256_hex(&canonical_json_bytes(&manifest)).into(),
    );
    for (name, document) in &documents {
        hashes.insert(
            format!("documents/{name}"),
            sha256_hex(&canonical_json_bytes(document)).into(),
        );
    }
    if let Some(hex) = &capture_hex {
        hashes.insert("capture".into(), sha256_hex(&hex_decode(hex)?).into());
    }
    let invocation = serde_json::json!({
        "command":"bundle","protocol":name,"effective_seed":effective_seed,
        "arguments":{"capture":capture.is_some()}
    });
    let environment = serde_json::json!({
        "tcpform_version":env!("CARGO_PKG_VERSION"),"os":std::env::consts::OS,
        "arch":std::env::consts::ARCH,"family":std::env::consts::FAMILY
    });
    hashes.insert(
        "invocation".into(),
        sha256_hex(&canonical_json_bytes(&invocation)).into(),
    );
    hashes.insert(
        "environment".into(),
        sha256_hex(&canonical_json_bytes(&environment)).into(),
    );
    let bundle = serde_json::json!({
        "format":"tcpform-repro-bundle","version":3,"created_at":unix_timestamp(),"root":path,
        "sources":sources,"manifest":manifest,"documents":documents,
        "capture_hex":capture_hex,"integrity":{"algorithm":"sha256","files":hashes},
        "invocation":invocation,"environment":environment
    });
    fs::write(output, serde_json::to_string_pretty(&bundle).unwrap()).map_err(|e| e.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn canonical_json_bytes(value: &serde_json::Value) -> Vec<u8> {
    fn write(value: &serde_json::Value, output: &mut String) {
        match value {
            serde_json::Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    write(value, output);
                }
                output.push(']');
            }
            serde_json::Value::Object(values) => {
                output.push('{');
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(key).unwrap());
                    output.push(':');
                    write(&values[key], output);
                }
                output.push('}');
            }
            serde_json::Value::Number(number) => {
                if number.as_i64().is_none()
                    && number.as_u64().is_none()
                    && number.as_f64().is_some_and(|value| value.fract() == 0.0)
                {
                    output.push_str(&format!("{:.0}", number.as_f64().unwrap()));
                } else {
                    output.push_str(&number.to_string());
                }
            }
            _ => output.push_str(&serde_json::to_string(value).unwrap()),
        }
    }
    let mut output = String::new();
    write(value, &mut output);
    output.into_bytes()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("invalid hexadecimal capture".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn reproduction_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(1)
        .max(1)
}

fn cmd_replay_bundle(args: &[String]) -> Result<(), String> {
    let path = args
        .first()
        .ok_or("usage: tcpform replay-bundle <bundle> [protocol]")?;
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if value.get("format").and_then(|v| v.as_str()) != Some("tcpform-repro-bundle") {
        return Err("not a tcpform reproduction bundle".into());
    }
    verify_bundle_integrity(&value)?;
    let root = value
        .get("root")
        .and_then(|v| v.as_str())
        .ok_or("bundle has no root source")?;
    let sources = value
        .get("sources")
        .and_then(|v| v.as_object())
        .ok_or("bundle has no sources")?
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|text| (name.clone(), text.to_string()))
                .ok_or_else(|| format!("source {name} is not text"))
        })
        .collect::<Result<std::collections::HashMap<_, _>, _>>()?;
    let blocks = tcpform::load_blocks_from_sources(root, &sources)?;
    let protocols = interpret(&blocks).map_err(|e| e.to_string())?;
    let requested = args
        .get(1)
        .map(String::as_str)
        .or_else(|| {
            value
                .pointer("/invocation/protocol")
                .and_then(|v| v.as_str())
        })
        .ok_or("bundle has no protocol")?;
    let mut protocol = find(&protocols, requested)?.clone();
    if let Some(seed) = value
        .pointer("/invocation/effective_seed")
        .and_then(|value| value.as_u64())
    {
        if let Some(transport) = protocol.transport.as_mut() {
            transport.seed = seed;
        }
    }
    match Engine::new(protocol).map_err(|e| e.to_string())?.run() {
        Ok(trace) => {
            println!("{}", tcpform::output::trace_json("ok", None, &trace));
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

fn verify_bundle_integrity(bundle: &serde_json::Value) -> Result<(), String> {
    if bundle.get("version").and_then(|v| v.as_u64()).unwrap_or(1) < 2 {
        return Ok(());
    }
    let integrity = bundle
        .pointer("/integrity/files")
        .and_then(|v| v.as_object())
        .ok_or("bundle v2 has no integrity hashes")?;
    let verify = |name: &str, bytes: &[u8]| -> Result<(), String> {
        let expected = integrity
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("bundle integrity lacks `{name}`"))?;
        let actual = sha256_hex(bytes);
        if expected == actual {
            Ok(())
        } else {
            Err(format!("bundle integrity check failed for `{name}`"))
        }
    };
    let version = bundle
        .get("version")
        .and_then(|value| value.as_u64())
        .unwrap_or(1);
    let json_bytes = |value: &serde_json::Value| {
        if version >= 3 {
            canonical_json_bytes(value)
        } else {
            serde_json::to_vec(value).unwrap()
        }
    };
    let manifest = bundle.get("manifest").ok_or("bundle has no manifest")?;
    verify("manifest", &json_bytes(manifest))?;
    for (name, value) in bundle
        .get("sources")
        .and_then(|v| v.as_object())
        .ok_or("bundle has no sources")?
    {
        verify(
            &format!("sources/{name}"),
            value
                .as_str()
                .ok_or("bundle source is not text")?
                .as_bytes(),
        )?
    }
    for (name, value) in bundle
        .get("documents")
        .and_then(|v| v.as_object())
        .ok_or("bundle has no documents")?
    {
        verify(&format!("documents/{name}"), &json_bytes(value))?
    }
    if let Some(hex) = bundle.get("capture_hex").and_then(|v| v.as_str()) {
        verify("capture", &hex_decode(hex)?)?
    }
    if version >= 3 {
        verify(
            "invocation",
            &json_bytes(bundle.get("invocation").ok_or("bundle has no invocation")?),
        )?;
        verify(
            "environment",
            &json_bytes(
                bundle
                    .get("environment")
                    .ok_or("bundle has no environment")?,
            ),
        )?;
    }
    Ok(())
}

fn collect_bundle_sources(
    root: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let import = regex_lite::Regex::new(r#"(?m)^\s*import\s+\"([^\"]+)\""#)
        .map_err(|error| error.to_string())?;
    let mut sources = serde_json::Map::new();
    let mut pending = vec![std::path::PathBuf::from(root)];
    let mut visited = std::collections::HashSet::new();
    while let Some(path) = pending.pop() {
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("cannot resolve {}: {error}", path.display()))?;
        if !visited.insert(canonical) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        for capture in import.captures_iter(&source) {
            pending.push(parent.join(&capture[1]));
        }
        sources.insert(
            path.to_string_lossy().replace('\\', "/"),
            serde_json::Value::String(source),
        );
    }
    Ok(sources)
}

fn cmd_orchestrate(args: &[String]) -> Result<(), String> {
    let path = args
        .iter()
        .find(|value| !value.starts_with('-'))
        .ok_or("usage: tcpform orchestrate <scenario.json> [--dry-run]")?;
    for option in args.iter().filter(|value| value.starts_with('-')) {
        if option.as_str() != "--dry-run" {
            return Err(format!("unknown orchestrate option `{option}`"));
        }
    }
    let scenario: orchestrate::Scenario = serde_json::from_str(
        &fs::read_to_string(path).map_err(|e| format!("cannot read `{path}`: {e}"))?,
    )
    .map_err(|e| format!("invalid orchestration scenario `{path}`: {e}"))?;
    scenario.validate()?;
    let report = if args.iter().any(|value| value == "--dry-run") {
        scenario.plan()
    } else {
        orchestrate::run(&scenario)?
    };
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    Ok(())
}

fn cmd_proxy(args: &[String]) -> Result<(), String> {
    let mut listen = None;
    let mut upstream = None;
    let mut downstream_cert = None;
    let mut downstream_key = None;
    let mut upstream_tls = false;
    let mut upstream_ca = None;
    let mut server_name = None;
    let mut client_cert = None;
    let mut client_key = None;
    let mut alpn = Vec::new();
    let mut capture = None;
    let mut timeout_ms = 30_000u64;
    let mut index = 0;
    while index < args.len() {
        let option = args[index].as_str();
        if option == "--tls-upstream" {
            upstream_tls = true;
            index += 1;
            continue;
        }
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("{option} requires a value"))?
            .clone();
        match option {
            "--listen" => listen = Some(value),
            "--upstream" => upstream = Some(value),
            "--tls-cert" => downstream_cert = Some(value),
            "--tls-key" => downstream_key = Some(value),
            "--ca" => upstream_ca = Some(value),
            "--server-name" => server_name = Some(value),
            "--client-cert" => client_cert = Some(value),
            "--client-key" => client_key = Some(value),
            "--alpn" => alpn.push(value),
            "--capture" => capture = Some(value),
            "--timeout-ms" => {
                timeout_ms = value
                    .parse()
                    .map_err(|_| "--timeout-ms requires an integer")?
            }
            _ => return Err(format!("unknown proxy option `{option}`")),
        }
        index += 1
    }
    proxy::run(proxy::ProxyOptions {
        listen: listen.ok_or("proxy requires --listen")?,
        upstream: upstream.ok_or("proxy requires --upstream")?,
        downstream_cert,
        downstream_key,
        upstream_tls,
        upstream_ca,
        server_name,
        client_cert,
        client_key,
        alpn,
        capture,
        timeout_ms,
    })
}

fn cmd_anonymize(args: &[String]) -> Result<(), String> {
    let input = args
        .first()
        .ok_or("usage: tcpform anonymize <input.json> <output.json>")?;
    let output = args
        .get(1)
        .ok_or("usage: tcpform anonymize <input.json> <output.json>")?;
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(input).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let mut ips = std::collections::HashMap::new();
    let mut macs = std::collections::HashMap::new();
    anonymize_json(&mut value, "", &mut ips, &mut macs);
    fs::write(output, serde_json::to_string_pretty(&value).unwrap()).map_err(|e| e.to_string())
}

fn anonymize_json(
    value: &mut serde_json::Value,
    key: &str,
    ips: &mut std::collections::HashMap<String, String>,
    macs: &mut std::collections::HashMap<String, String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (name, value) in map {
                anonymize_json(value, name, ips, macs);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                anonymize_json(value, key, ips, macs);
            }
        }
        serde_json::Value::String(text) => {
            let lower = key.to_ascii_lowercase();
            if matches!(key, "wire_hex" | "hex")
                && text.len() % 2 == 0
                && text.chars().all(|character| character.is_ascii_hexdigit())
            {
                *text = "00".repeat(text.len() / 2);
            } else if key == "payload"
                || lower.contains("token")
                || lower.contains("password")
                || lower.contains("secret")
                || lower.contains("authorization")
            {
                *text = "[REDACTED]".to_string();
            } else if text.split('.').count() == 4
                && text.split('.').all(|part| part.parse::<u8>().is_ok())
            {
                let next = ips.len() + 1;
                *text = ips
                    .entry(text.clone())
                    .or_insert_with(|| format!("192.0.2.{next}"))
                    .clone();
            } else if text.split(':').count() == 6
                && text
                    .split(':')
                    .all(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok())
            {
                let next = macs.len() + 1;
                *text = macs
                    .entry(text.clone())
                    .or_insert_with(|| format!("02:00:00:00:00:{next:02x}"))
                    .clone();
            }
        }
        _ => {}
    }
}

fn cmd_explore(args: &[String]) -> Result<(), String> {
    let path = args
        .first()
        .ok_or("usage: tcpform explore <source> <protocol>")?;
    let name = args
        .get(1)
        .ok_or("usage: tcpform explore <source> <protocol>")?;
    let protocols = load(path)?;
    let base = find(&protocols, name)?.clone();
    let mut results = Vec::new();
    for loss_rate in [0.0, 0.1, 0.5, 1.0] {
        for delay_ms in [0, 10, 100, 500] {
            for seed in [1, 2, 3] {
                let mut protocol = base.clone();
                protocol.clock = tcpform::ClockMode::Virtual;
                protocol.transport = Some(tcpform::TransportConfig {
                    loss_rate,
                    delay_ms,
                    reorder: false,
                    seed,
                    ..tcpform::TransportConfig::default()
                });
                let result = Engine::new(protocol).map_err(|e| e.to_string())?.run();
                results.push(serde_json::json!({"loss_rate":loss_rate,"delay_ms":delay_ms,"seed":seed,"status":if result.is_ok(){"ok"}else{"fail"}}));
            }
        }
    }
    let minimal = results
        .iter()
        .filter(|result| result["status"] == "fail")
        .min_by(|a, b| {
            let score = |v: &serde_json::Value| {
                v["loss_rate"].as_f64().unwrap_or(0.0) * 1000.0
                    + v["delay_ms"].as_u64().unwrap_or(0) as f64
            };
            score(a).total_cmp(&score(b))
        })
        .cloned();
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"results":results,"minimal_failure":minimal})
        )
        .unwrap()
    );
    Ok(())
}

fn cmd_generate_faults(args: &[String]) -> Result<(), String> {
    let output_index = args
        .iter()
        .position(|arg| arg == "--output")
        .ok_or("generate-faults requires --output")?;
    let output = args
        .get(output_index + 1)
        .ok_or("--output requires directory")?;
    let source_path = args
        .iter()
        .enumerate()
        .find(|(index, _)| *index != output_index && *index != output_index + 1)
        .map(|(_, value)| value)
        .ok_or("generate-faults requires source")?;
    let source = fs::read_to_string(source_path).map_err(|e| e.to_string())?;
    fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let variants = [
        ("timeout", inject_transport(&source, "loss_rate = 1.0")?),
        ("latency", inject_transport(&source, "delay = \"500ms\"")?),
        (
            "reorder",
            inject_transport(&source, "reorder = true seed = 42")?,
        ),
        ("corrupt", replace_first_send(&source, "corrupt")?),
        ("duplicate", replace_first_send(&source, "duplicate")?),
    ];
    for (name, document) in variants {
        fs::write(format!("{output}/{name}.tcpf"), document).map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn inject_transport(source: &str, attributes: &str) -> Result<String, String> {
    if let Some(index) = source.find("transport {") {
        let at = index + "transport {".len();
        return Ok(format!("{} {attributes} {}", &source[..at], &source[at..]));
    }
    let protocol = source.find("protocol ").ok_or("protocol block not found")?;
    let brace = source[protocol..]
        .find('{')
        .ok_or("protocol opening brace not found")?
        + protocol
        + 1;
    Ok(format!(
        "{}\n  transport {{ {attributes} }}{}",
        &source[..brace],
        &source[brace..]
    ))
}
fn replace_first_send(source: &str, action: &str) -> Result<String, String> {
    for needle in [
        "action = \"send\"",
        "action=\"send\"",
        "action = \"send_raw\"",
        "action=\"send_raw\"",
    ] {
        if let Some(index) = source.find(needle) {
            return Ok(format!(
                "{}action = \"{action}\"{}",
                &source[..index],
                &source[index + needle.len()..]
            ));
        }
    }
    Err("no outbound action found".to_string())
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let mut json = false;
    let mut json_file: Option<String> = None;
    let mut diagram = false;
    let mut pcap: Option<String> = None;
    let mut pcapng: Option<String> = None;
    let mut live = false;
    let mut external = false;
    let mut raw = false;
    let mut udp = false;
    let mut tls = false;
    let mut unix = false;
    let mut websocket = false;
    let mut quic = false;
    let mut listen = false;
    let mut allow_plugins = false;
    let mut bind: Option<String> = None;
    let mut role: Option<String> = None;
    let mut interface: Option<String> = None;
    let mut snaplen = 65_535usize;
    let mut promiscuous = false;
    let mut receive_outgoing = false;
    let mut allow_host_tcp = false;
    let mut drop_uid: Option<u32> = None;
    let mut drop_gid: Option<u32> = None;
    let mut address: Option<String> = None;
    let mut framing = tcpform::Framing::Raw;
    let mut tls_options = tcpform::TlsOptions::default();
    let mut udp_options = tcpform::UdpOptions::default();
    let mut websocket_options = tcpform::WebSocketOptions::default();
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        let value = |index: &mut usize, name: &str| -> Result<String, String> {
            *index += 1;
            args.get(*index)
                .cloned()
                .ok_or_else(|| format!("{name} requires a value"))
        };
        match argument {
            "--json" => json = true,
            "--json-file" => json_file = Some(value(&mut index, "--json-file")?),
            "--diagram" => diagram = true,
            "--pcap" => pcap = Some(value(&mut index, "--pcap")?),
            "--pcapng" => pcapng = Some(value(&mut index, "--pcapng")?),
            "--live" => live = true,
            "--external" => external = true,
            "--raw" => raw = true,
            "--udp" => udp = true,
            "--tls" => tls = true,
            "--unix" => unix = true,
            "--websocket" => websocket = true,
            "--quic" => quic = true,
            "--websocket-text" => websocket_options.text = true,
            "--websocket-protocol" => websocket_options
                .subprotocols
                .push(value(&mut index, "--websocket-protocol")?),
            "--origin" => websocket_options.origin = Some(value(&mut index, "--origin")?),
            "--listen" => listen = true,
            "--allow-plugins" => allow_plugins = true,
            "--bind" => bind = Some(value(&mut index, "--bind")?),
            "--connect" | "--address" => address = Some(value(&mut index, argument)?),
            "--role" => role = Some(value(&mut index, "--role")?),
            "--interface" => interface = Some(value(&mut index, "--interface")?),
            "--snaplen" => {
                snaplen = value(&mut index, "--snaplen")?
                    .parse::<usize>()
                    .map_err(|_| "--snaplen must be a positive integer".to_string())?;
            }
            "--promiscuous" => promiscuous = true,
            "--receive-outgoing" => receive_outgoing = true,
            "--allow-host-tcp" => allow_host_tcp = true,
            "--drop-uid" => {
                drop_uid = Some(
                    value(&mut index, "--drop-uid")?
                        .parse::<u32>()
                        .map_err(|_| "--drop-uid must be a non-negative u32".to_string())?,
                );
            }
            "--drop-gid" => {
                drop_gid = Some(
                    value(&mut index, "--drop-gid")?
                        .parse::<u32>()
                        .map_err(|_| "--drop-gid must be a non-negative u32".to_string())?,
                );
            }
            "--server-name" => tls_options.server_name = Some(value(&mut index, "--server-name")?),
            "--ca" => tls_options.ca_file = Some(value(&mut index, "--ca")?),
            "--tls-cert" => tls_options.cert_file = Some(value(&mut index, "--tls-cert")?),
            "--tls-key" => tls_options.key_file = Some(value(&mut index, "--tls-key")?),
            "--alpn" => tls_options
                .alpn_protocols
                .push(value(&mut index, "--alpn")?),
            "--require-client-cert" => tls_options.require_client_auth = true,
            "--broadcast" => udp_options.broadcast = true,
            "--reuse-address" => udp_options.reuse_address = true,
            "--multicast" => udp_options.multicast_group = Some(value(&mut index, "--multicast")?),
            "--multicast-interface" => {
                udp_options.multicast_interface = Some(value(&mut index, "--multicast-interface")?)
            }
            "--multicast-ttl" => {
                udp_options.multicast_ttl = Some(
                    value(&mut index, "--multicast-ttl")?
                        .parse()
                        .map_err(|_| "--multicast-ttl requires an integer")?,
                )
            }
            "--framing" => {
                let specification = value(&mut index, "--framing")?;
                framing = parse_framing(&specification)?;
            }
            option if option.starts_with('-') => {
                return Err(format!("unknown run option `{option}`"))
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }
    if usize::from(live) + usize::from(external) + usize::from(raw) > 1 {
        return Err("--live, --external, and --raw are mutually exclusive".to_string());
    }
    if usize::from(udp)
        + usize::from(tls)
        + usize::from(unix)
        + usize::from(websocket)
        + usize::from(quic)
        > 1
    {
        return Err(
            "--udp, --tls, --unix, --websocket, and --quic are mutually exclusive".to_string(),
        );
    }
    if tls && !external {
        return Err("--tls requires --external".to_string());
    }
    if unix && !external {
        return Err("--unix requires --external".to_string());
    }
    if websocket && !external {
        return Err("--websocket requires --external".into());
    }
    if quic && !external {
        return Err("--quic requires --external".into());
    }
    if (!websocket_options.subprotocols.is_empty()
        || websocket_options.origin.is_some()
        || websocket_options.text)
        && !(external && websocket)
    {
        return Err("WebSocket options require --external --websocket".into());
    }
    if listen && !external {
        return Err("--listen requires --external".to_string());
    }
    if bind.is_some() && !live {
        return Err("--bind requires --live".to_string());
    }
    if role.is_some() && !external && !raw {
        return Err("--role requires --external or --raw".to_string());
    }
    if address.is_some() && !external {
        return Err("--connect requires --external".to_string());
    }
    if (interface.is_some()
        || promiscuous
        || receive_outgoing
        || allow_host_tcp
        || drop_uid.is_some()
        || drop_gid.is_some()
        || snaplen != 65_535)
        && !raw
    {
        return Err(
            "--interface/--snaplen/--promiscuous/--receive-outgoing/--allow-host-tcp/--drop-uid/--drop-gid require --raw"
                .to_string(),
        );
    }
    if drop_uid.is_some() != drop_gid.is_some() {
        return Err("--drop-uid and --drop-gid must be specified together".to_string());
    }
    if !external
        && (framing != tcpform::Framing::Raw
            || tls_options.server_name.is_some()
            || tls_options.ca_file.is_some()
            || tls_options.cert_file.is_some()
            || tls_options.key_file.is_some()
            || !tls_options.alpn_protocols.is_empty()
            || tls_options.require_client_auth)
    {
        return Err("TLS/framing options require --external".to_string());
    }
    if !live && !external && udp {
        return Err("--udp requires --live or --external".to_string());
    }
    if udp && framing != tcpform::Framing::Raw {
        return Err("--framing is not used by UDP datagrams".to_string());
    }
    if (udp_options.broadcast
        || udp_options.reuse_address
        || udp_options.multicast_group.is_some()
        || udp_options.multicast_interface.is_some()
        || udp_options.multicast_ttl.is_some())
        && !(external && udp)
    {
        return Err("UDP socket options require --external --udp".to_string());
    }
    if external && address.is_none() && positional.len() >= 3 {
        address = Some(positional.remove(0));
    }
    let path = positional
        .first()
        .ok_or("usage: tcpform run [options] <file> <protocol>")?;
    let name = positional
        .get(1)
        .ok_or("usage: tcpform run [options] <file> <protocol>")?;
    if positional.len() != 2 {
        return Err("run expects exactly <file> and <protocol> after options".to_string());
    }
    let protocols = load(path)?;
    let p = find(&protocols, name)?;
    let engine = Engine::new(p.clone())
        .map_err(|e| e.to_string())?
        .with_plugins_enabled(allow_plugins);
    let result = if live {
        engine.run_live(
            bind.as_deref().ok_or("--live requires --bind <address>")?,
            udp,
        )
    } else if raw {
        let role = role.as_deref().ok_or("--raw requires --role <role>")?;
        let interface = interface
            .as_deref()
            .ok_or("--raw requires --interface <name>")?;
        let mut config = tcpform::RawSocketConfig::new(interface);
        config.snaplen = snaplen;
        config.promiscuous = promiscuous;
        config.receive_outgoing = receive_outgoing;
        config.allow_host_tcp = allow_host_tcp;
        config.drop_privileges = drop_uid.zip(drop_gid);
        engine.run_external_raw(role, config)
    } else if external {
        let role = role.as_deref().ok_or("--external requires --role <role>")?;
        let address = address
            .as_deref()
            .ok_or("--external requires an address or --connect <address>")?;
        if quic {
            engine.run_external_quic(role, address, listen, &tls_options)
        } else if websocket {
            engine.run_external_websocket(role, address, listen, &websocket_options)
        } else if unix {
            #[cfg(unix)]
            {
                engine.run_external_unix(role, address, listen, framing)
            }
            #[cfg(not(unix))]
            {
                return Err("--unix is only supported on Unix platforms".into());
            }
        } else if tls {
            engine.run_external_tls(role, address, listen, framing, &tls_options)
        } else if udp {
            engine.run_external_udp_with_options(role, address, listen, &udp_options)
        } else {
            engine.run_external_tcp_framed(role, address, listen, framing)
        }
    } else {
        engine.run()
    };
    match result {
        Ok(trace) => {
            if !json && json_file.is_none() && !diagram && pcap.is_none() && pcapng.is_none() {
                print_trace(&trace);
                println!("\nresult: ok ({} events)", trace.len());
            }
            let json_document = tcpform::output::trace_json("ok", None, &trace);
            if json {
                println!("{json_document}");
            }
            if let Some(path) = json_file.as_deref() {
                fs::write(path, &json_document)
                    .map_err(|error| format!("cannot write JSON output `{path}`: {error}"))?;
            }
            if diagram {
                print!("{}", tcpform::output::sequence_diagram(&trace));
            }
            write_captures(&trace, pcap.as_deref(), pcapng.as_deref())?;
            Ok(())
        }
        Err(EngineError::Runtime {
            kind,
            message,
            trace,
            ..
        }) => {
            if !json && json_file.is_none() && !diagram && pcap.is_none() && pcapng.is_none() {
                print_trace(&trace);
                eprintln!("\nresult: FAIL — {message}");
            }
            let json_document = tcpform::output::trace_json_with_failure(
                "fail",
                Some(kind.as_str()),
                Some(&message),
                &trace,
            );
            if json {
                println!("{json_document}");
            }
            if let Some(path) = json_file.as_deref() {
                fs::write(path, &json_document)
                    .map_err(|error| format!("cannot write JSON output `{path}`: {error}"))?;
            }
            if diagram {
                print!("{}", tcpform::output::sequence_diagram(&trace));
            }
            write_captures(&trace, pcap.as_deref(), pcapng.as_deref())?;
            Err(message)
        }
        Err(e) => Err(e.to_string()),
    }
}

fn parse_framing(specification: &str) -> Result<tcpform::Framing, String> {
    match specification {
        "raw" => Ok(tcpform::Framing::Raw),
        "length" | "length-prefix" => Ok(tcpform::Framing::LengthPrefix),
        "line" => Ok(tcpform::Framing::Delimiter(b"\n".to_vec())),
        value if value.starts_with("delimiter:") => {
            let delimiter = &value["delimiter:".len()..];
            if delimiter.is_empty() {
                Err("framing delimiter must not be empty".to_string())
            } else {
                Ok(tcpform::Framing::Delimiter(delimiter.as_bytes().to_vec()))
            }
        }
        value if value.starts_with("fixed:") => {
            let size = value["fixed:".len()..]
                .parse::<usize>()
                .map_err(|_| format!("invalid fixed framing `{value}`"))?;
            if size == 0 {
                Err("fixed framing size must be positive".to_string())
            } else {
                Ok(tcpform::Framing::Fixed(size))
            }
        }
        value => Err(format!("unknown framing `{value}`")),
    }
}

fn write_captures(
    trace: &[tcpform::TraceEvent],
    pcap: Option<&str>,
    pcapng: Option<&str>,
) -> Result<(), String> {
    if let Some(output) = pcap {
        fs::write(output, tcpform::output::trace_pcap(trace))
            .map_err(|e| format!("cannot write {output}: {e}"))?;
    }
    if let Some(output) = pcapng {
        fs::write(output, tcpform::output::trace_pcapng(trace))
            .map_err(|e| format!("cannot write {output}: {e}"))?;
    }
    Ok(())
}

fn print_trace(trace: &[tcpform::TraceEvent]) {
    println!(
        "{:<4} {:<8} {:<14} {:<9} {:<4} detail",
        "#", "role", "step", "act", "ok"
    );
    for (i, e) in trace.iter().enumerate() {
        let ok = if e.ok { "ok" } else { "FAIL" };
        println!(
            "{:<4} {:<8} {:<14} {:<9} {:<4} {}",
            i + 1,
            e.role,
            e.step,
            e.action.as_str(),
            ok,
            e.detail
        );
    }
}

fn cmd_test(args: &[String]) -> Result<(), String> {
    let mut json = false;
    let mut junit: Option<String> = None;
    let mut jobs = 1usize;
    let mut case_pattern: Option<String> = None;
    let mut tags = Vec::new();
    let mut shard: Option<(usize, usize)> = None;
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        let value = |index: &mut usize, name: &str| -> Result<String, String> {
            *index += 1;
            args.get(*index)
                .cloned()
                .ok_or_else(|| format!("{name} requires a value"))
        };
        match argument {
            "--json" => json = true,
            "--junit" => junit = Some(value(&mut index, "--junit")?),
            "--jobs" => {
                let raw = value(&mut index, "--jobs")?;
                jobs = raw
                    .parse()
                    .map_err(|_| format!("--jobs must be a positive integer, got `{raw}`"))?;
                if jobs == 0 {
                    return Err("--jobs must be at least 1".to_string());
                }
            }
            "--case" => case_pattern = Some(value(&mut index, "--case")?),
            "--tag" => tags.push(value(&mut index, "--tag")?),
            "--shard" => shard = Some(parse_shard(&value(&mut index, "--shard")?)?),
            option if option.starts_with('-') => {
                return Err(format!("unknown test option `{option}`"))
            }
            value => positional.push(value.to_string()),
        }
        index += 1;
    }
    if positional.len() > 2 {
        return Err("test expects <file> and an optional [protocol]".to_string());
    }
    let path = positional
        .first()
        .ok_or("usage: tcpform test [--json] <file> [protocol]")?;
    let (protocols, all_cases) = load_with_cases(path)?;
    if all_cases.is_empty() {
        if json {
            println!("{}", tcpform::output::case_results_json(&[]));
        } else {
            println!("(no case suites defined)");
        }
        if let Some(path) = junit {
            fs::write(&path, tcpform::output::case_results_junit(&[]))
                .map_err(|error| format!("cannot write {path}: {error}"))?;
        }
        return Ok(());
    }
    // Optional protocol filter
    let filter = positional.get(1).map(String::as_str);
    if let Some(filter) = filter {
        if !all_cases.iter().any(|cases| cases.protocol == filter) {
            return Err(format!("no case suite found for protocol `{filter}`"));
        }
    }

    let mut total_pass = 0usize;
    let mut total_fail = 0usize;
    let mut json_results = Vec::new();
    let case_regex = case_pattern
        .as_deref()
        .map(regex_lite::Regex::new)
        .transpose()
        .map_err(|error| format!("invalid --case regex: {error}"))?;
    let mut candidate_index = 0usize;

    for cases in &all_cases {
        if let Some(f) = filter {
            if cases.protocol != f {
                continue;
            }
        }
        let selected: Vec<_> = cases
            .cases
            .iter()
            .filter(|case| {
                let matches_name = case_regex
                    .as_ref()
                    .is_none_or(|pattern| pattern.is_match(&case.name));
                let matches_tag = tags.is_empty()
                    || tags
                        .iter()
                        .any(|tag| case.tags.iter().any(|candidate| candidate == tag));
                if !matches_name || !matches_tag {
                    return false;
                }
                let current = candidate_index;
                candidate_index += 1;
                shard.is_none_or(|(index, total)| current % total == index)
            })
            .cloned()
            .collect();
        if selected.is_empty() {
            continue;
        }
        let proto = find(&protocols, &cases.protocol)?;
        let engine = Engine::new(proto.clone()).map_err(|e| e.to_string())?;

        if !json {
            println!(
                "Testing protocol `{}` — {} cases",
                cases.protocol,
                selected.len()
            );
            println!(
                "{:<4} {:<20} {:<8} {:<8} {:<6} detail",
                "#", "case", "expect", "actual", "result"
            );
        }

        for (i, result) in engine
            .run_cases_parallel(&selected, jobs)
            .into_iter()
            .enumerate()
        {
            let res = if result.passed { "PASS" } else { "FAIL" };
            let detail = if result.passed {
                String::new()
            } else {
                format!(
                    "expected {} but got {}",
                    result.expected.as_str(),
                    result.actual.as_str()
                )
            };
            if !json {
                println!(
                    "{:<4} {:<20} {:<8} {:<8} {:<6} {}",
                    i + 1,
                    result.name,
                    result.expected.as_str(),
                    result.actual.as_str(),
                    res,
                    detail
                );
            }
            if result.passed {
                total_pass += 1;
            } else {
                total_fail += 1;
            }
            json_results.push((cases.protocol.clone(), result));
        }
        if !json {
            println!();
        }
    }

    if json_results.is_empty() {
        return Err("no cases matched the requested protocol/filter/tag/shard".to_string());
    }

    if json {
        let borrowed: Vec<_> = json_results
            .iter()
            .map(|(protocol, result)| (protocol.as_str(), result))
            .collect();
        println!("{}", tcpform::output::case_results_json(&borrowed));
    } else {
        println!("{}/{} cases passed", total_pass, total_pass + total_fail);
    }
    if let Some(path) = junit {
        let borrowed: Vec<_> = json_results
            .iter()
            .map(|(protocol, result)| (protocol.as_str(), result))
            .collect();
        fs::write(&path, tcpform::output::case_results_junit(&borrowed))
            .map_err(|error| format!("cannot write {path}: {error}"))?;
    }
    if total_fail > 0 {
        return Err(format!("{total_fail} case(s) failed"));
    }
    Ok(())
}

fn parse_shard(value: &str) -> Result<(usize, usize), String> {
    let (index, total) = value
        .split_once('/')
        .ok_or_else(|| format!("--shard must use <index>/<total>, got `{value}`"))?;
    let index = index
        .parse::<usize>()
        .map_err(|_| format!("invalid shard index `{index}`"))?;
    let total = total
        .parse::<usize>()
        .map_err(|_| format!("invalid shard total `{total}`"))?;
    if total == 0 || index == 0 || index > total {
        return Err(format!(
            "--shard index is 1-based and must satisfy 1 <= index <= total, got `{value}`"
        ));
    }
    Ok((index - 1, total))
}

#[cfg(test)]
mod bundle_tests {
    use super::*;
    #[test]
    fn bundle_integrity_detects_tampering() {
        let manifest = serde_json::json!({"protocol":"p"});
        let document = serde_json::json!({"events":[]});
        let source = "protocol \"p\" {}";
        let mut bundle = serde_json::json!({"format":"tcpform-repro-bundle","version":2,"manifest":manifest,"sources":{"main.tcpf":source},"documents":{"trace.json":document},"integrity":{"files":{"manifest":sha256_hex(&serde_json::to_vec(&manifest).unwrap()),"sources/main.tcpf":sha256_hex(source.as_bytes()),"documents/trace.json":sha256_hex(&serde_json::to_vec(&document).unwrap())}}});
        verify_bundle_integrity(&bundle).unwrap();
        bundle["sources"]["main.tcpf"] = "tampered".into();
        assert!(verify_bundle_integrity(&bundle)
            .unwrap_err()
            .contains("main.tcpf"));
    }
}
