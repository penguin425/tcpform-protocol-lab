use std::time::{Duration, Instant};
use tcpform::model::{interpret, parse_duration_ms};
use tcpform::{bytes_to_hex, parse_file, parse_hex, Engine, Protocol, Value};

fn load_protocol(src: &str, name: &str) -> Protocol {
    let blocks = parse_file(src).unwrap();
    let protocols = interpret(&blocks).unwrap();
    protocols
        .into_iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("protocol `{name}` not found"))
}

#[test]
fn doctor_json_and_shell_completion_cli_are_available() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let project = std::env::temp_dir().join(format!("tcpform-doctor-cli-{unique}"));
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("protocol.tcpf"),
        "tcpform { dsl_version = 2 }\n",
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_tcpform");
    let output = std::process::Command::new(binary)
        .args(["doctor", "--json"])
        .arg(&project)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["dsl_version"], 2);
    assert!(report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["name"] == "imports"));
    for (shell, marker) in [("bash", "complete -F"), ("zsh", "#compdef tcpform")] {
        let output = std::process::Command::new(binary)
            .args(["completion", shell])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout).unwrap().contains(marker));
    }
    std::fs::remove_dir_all(project).unwrap();
}

#[test]
fn import_pcap_cli_generates_valid_dsl_and_smoke_case() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let capture = std::env::temp_dir().join(format!("tcpform-import-{unique}.pcapng"));
    let output = std::env::temp_dir().join(format!("tcpform-import-{unique}.tcpf"));
    let analysis = std::env::temp_dir().join(format!("tcpform-import-{unique}.json"));
    let protocol = load_protocol(
        include_str!("../examples/tcp_handshake.tcpf"),
        "tcp_handshake",
    );
    let trace = Engine::new(protocol).unwrap().run().unwrap();
    std::fs::write(&capture, tcpform::output::trace_pcapng(&trace)).unwrap();
    let command = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"))
        .arg("import-pcap")
        .arg(&capture)
        .args(["--protocol", "captured_handshake", "--output"])
        .arg(&output)
        .arg("--analysis")
        .arg(&analysis)
        .output()
        .unwrap();
    assert!(
        command.status.success(),
        "{}",
        String::from_utf8_lossy(&command.stderr)
    );
    let generated = std::fs::read_to_string(&output).unwrap();
    assert!(generated.contains("frame_0001_send"));
    assert!(generated.contains("capture_smoke"));
    let blocks = tcpform::load_blocks(&output).unwrap();
    assert_eq!(
        tcpform::model::interpret(&blocks).unwrap()[0].name,
        "captured_handshake"
    );
    let inference: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&analysis).unwrap()).unwrap();
    assert_eq!(inference["schema_version"], "1.0");
    assert_eq!(inference["sessions"][0]["transport"], "tcp");
    assert!(inference["sessions"][0]["states"]
        .as_array()
        .unwrap()
        .iter()
        .any(|state| state == "established"));
    std::fs::remove_file(capture).unwrap();
    std::fs::remove_file(output).unwrap();
    std::fs::remove_file(analysis).unwrap();
}

#[test]
fn import_kaitai_cli_generates_valid_header_schema_and_warns_on_dynamic_fields() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let schema = std::env::temp_dir().join(format!("tcpform-kaitai-{unique}.ksy"));
    let output = std::env::temp_dir().join(format!("tcpform-kaitai-{unique}.tcpf"));
    std::fs::write(
        &schema,
        "meta:\n  id: sensor_frame\n  endian: le\nseq:\n  - { id: version, type: u1 }\n  - { id: reading, type: u4 }\n  - { id: payload, size-eos: true }\n",
    )
    .unwrap();
    let command = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"))
        .arg("import-kaitai")
        .arg(&schema)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        command.status.success(),
        "{}",
        String::from_utf8_lossy(&command.stderr)
    );
    assert!(String::from_utf8_lossy(&command.stderr).contains("warning:"));
    let generated = std::fs::read_to_string(&output).unwrap();
    assert!(generated.contains("endian = \"little\""));
    assert!(generated.contains("reading = { offset = 1 length = 4"));
    let blocks = tcpform::load_blocks(&output).unwrap();
    assert_eq!(
        tcpform::model::interpret(&blocks).unwrap()[0].name,
        "sensor_frame"
    );
    std::fs::remove_file(schema).unwrap();
    std::fs::remove_file(output).unwrap();
}

#[test]
fn protocol_exporters_emit_field_aware_wireshark_and_scapy_code() {
    let binary = env!("CARGO_BIN_EXE_tcpform");
    let source = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/custom_header_schema.tcpf"
    );
    let run = |target: &str| {
        std::process::Command::new(binary)
            .args(["platform", target, source, "custom_header_demo", "19000"])
            .output()
            .unwrap()
    };
    let wireshark = run("wireshark");
    assert!(wireshark.status.success());
    let wireshark = String::from_utf8(wireshark.stdout).unwrap();
    assert!(wireshark.contains("ProtoField.uint8"));
    assert!(wireshark.contains("buffer(2, 2)"));
    assert!(wireshark.contains("add(19000"));

    let scapy = run("scapy");
    assert!(scapy.status.success());
    let scapy = String::from_utf8(scapy.stdout).unwrap();
    assert!(scapy.contains("class CustomHeaderDemoAcme(Packet):"));
    assert!(scapy.contains("BitField(\"version\""));
    assert!(scapy.contains("dport=19000"));
}

#[test]
fn fuzz_export_cli_writes_boofuzz_harness_and_aflnet_corpus() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("tcpform-fuzz-export-{unique}"));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("protocol.tcpf");
    let boofuzz = directory.join("fuzz.py");
    let corpus = directory.join("aflnet");
    std::fs::write(
        &source,
        r#"protocol "service" {
          step "hello" { role="client" action="send" to="server" segment { payload="HELLO" } }
          step "command" { role="client" action="send" to="server" segment { hex="010203" } }
        }"#,
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_tcpform");
    let status = std::process::Command::new(binary)
        .args(["fuzz-export", "boofuzz"])
        .arg(&source)
        .args(["service", "--role", "client", "--output"])
        .arg(&boofuzz)
        .args(["--port", "9000"])
        .status()
        .unwrap();
    assert!(status.success());
    let script = std::fs::read_to_string(&boofuzz).unwrap();
    assert!(script.contains("Session(target=Target"));
    assert!(script.contains("session.connect(s_get(\"hello\"), s_get(\"command\"))"));

    let status = std::process::Command::new(binary)
        .args(["fuzz-export", "aflnet"])
        .arg(&source)
        .args(["service", "--role", "client", "--output"])
        .arg(&corpus)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        std::fs::read(corpus.join("seed_0001.raw")).unwrap(),
        b"HELLO\x01\x02\x03"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(corpus.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["messages"][1]["offset"], 5);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn packetdrill_cli_imports_and_exports_supported_packet_events() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("tcpform-packetdrill-{unique}"));
    std::fs::create_dir_all(&directory).unwrap();
    let packetdrill = directory.join("input.pkt");
    let dsl = directory.join("output.tcpf");
    let roundtrip = directory.join("roundtrip.pkt");
    std::fs::write(
        &packetdrill,
        "0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3\n+0 < S 0:0(0)\n+0 > S. 0:0(0) ack 1\n+.005 < P. 1:4(3) ack 1\n",
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_tcpform");
    let imported = std::process::Command::new(binary)
        .args(["packetdrill", "import"])
        .arg(&packetdrill)
        .args([
            "--protocol",
            "converted",
            "--local-role",
            "server",
            "--peer-role",
            "client",
            "--output",
        ])
        .arg(&dsl)
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    assert!(String::from_utf8_lossy(&imported.stderr).contains("line 1"));
    assert!(tcpform::load_blocks(&dsl).is_ok());

    let exported = std::process::Command::new(binary)
        .args(["packetdrill", "export"])
        .arg(&dsl)
        .args(["converted", "--local-role", "server", "--output"])
        .arg(&roundtrip)
        .output()
        .unwrap();
    assert!(exported.status.success());
    let roundtrip = std::fs::read_to_string(roundtrip).unwrap();
    assert!(roundtrip.contains("< P. 1:4(3) ack 1"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn snapshot_cli_creates_checks_rejects_changes_and_updates() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("tcpform-snapshot-{unique}"));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("protocol.tcpf");
    let snapshot = dir.join("expected.json");
    let write_protocol = |payload: &str| {
        std::fs::write(
            &source,
            format!("tcpform {{ dsl_version=2 }}\nprotocol \"snap\" {{ step \"send\" {{ role=\"client\" action=\"send\" segment {{ payload=\"{payload}\" }} }} }}\n"),
        )
        .unwrap();
    };
    let run = |mode: Option<&str>| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"));
        command.arg("snapshot");
        if let Some(mode) = mode {
            command.arg(mode);
        }
        command
            .arg("--output")
            .arg(&snapshot)
            .arg(&source)
            .output()
            .unwrap()
    };
    write_protocol("hello");
    assert!(run(None).status.success());
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&snapshot).unwrap()).unwrap();
    assert_eq!(document["snapshot_version"], "1.0");
    assert!(document["visualizer"][0]["steps"].is_array());
    assert!(run(Some("--check")).status.success());
    write_protocol("changed");
    assert!(!run(Some("--check")).status.success());
    assert!(run(Some("--update")).status.success());
    assert!(run(Some("--check")).status.success());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn template_search_cli_reads_the_configured_registry() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("tcpform-template-search-{unique}"));
    std::fs::create_dir_all(dir.join(".tcpform")).unwrap();
    std::fs::write(
        dir.join(".tcpform/template-registry.json"),
        r#"{"schema_version":"1.0","trusted_owners":["owner"],"templates":[{"name":"owner/mqtt","version":"1.0.0","repository":"https://example.invalid/repo.git","revision":"0123456789abcdef0123456789abcdef01234567","path":"template.tcpf","sha256":"0000000000000000000000000000000000000000000000000000000000000000","signature_hex":"","public_key_hex":""}]}"#,
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"))
        .args(["template", "search", "mqtt"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("owner/mqtt"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn handshake_runs_to_completion() {
    let src = include_str!("../examples/tcp_handshake.tcpf");
    let p = load_protocol(src, "tcp_handshake");
    let engine = Engine::new(p).unwrap();
    let trace = engine.run().unwrap();
    assert!(
        trace.iter().all(|e| e.ok),
        "all steps should succeed; trace = {trace:?}"
    );
    let steps: Vec<&str> = trace.iter().map(|e| e.step.as_str()).collect();
    for expected in [
        "syn",
        "recv_syn",
        "syn_ack",
        "recv_syn_ack",
        "ack",
        "recv_ack",
    ] {
        assert!(
            steps.contains(&expected),
            "missing step `{expected}`: {steps:?}"
        );
    }
}

#[test]
fn teardown_runs_to_completion() {
    let src = include_str!("../examples/tcp_teardown.tcpf");
    let p = load_protocol(src, "tcp_teardown");
    let engine = Engine::new(p).unwrap();
    let trace = engine.run().unwrap();
    assert!(trace.iter().all(|e| e.ok), "trace = {trace:?}");
    // the ack actions should auto-compute ack numbers from received FINs
    let ack1 = trace
        .iter()
        .find(|e| e.step == "ack_fin1")
        .expect("ack_fin1 event");
    assert_eq!(
        ack1.ack_num,
        Some(2001),
        "ack_fin1 should ack the FIN seq 2000"
    );
    let ack2 = trace
        .iter()
        .find(|e| e.step == "ack_fin2")
        .expect("ack_fin2 event");
    assert_eq!(
        ack2.ack_num,
        Some(5002),
        "ack_fin2 should ack the FIN seq 5001"
    );
}

#[test]
fn ping_pong_runs() {
    let src = include_str!("../examples/custom.tcpf");
    let p = load_protocol(src, "ping_pong");
    let engine = Engine::new(p).unwrap();
    let trace = engine.run().unwrap();
    assert!(trace.iter().all(|e| e.ok), "trace = {trace:?}");
    let recv_pong = trace
        .iter()
        .find(|e| e.step == "recv_pong")
        .expect("recv_pong event");
    assert!(recv_pong.detail.contains("PONG"));
}

#[test]
fn cycle_is_detected() {
    let src = r#"
    protocol "cyc" {
      step "a" { role = "r1" action = "send" depends_on = ["b"] segment { flags = ["X"] } }
      step "b" { role = "r2" action = "recv" depends_on = ["a"] expect { flags = ["X"] } }
    }
    "#;
    let p = load_protocol(src, "cyc");
    let err = Engine::new(p).unwrap_err();
    assert!(err.to_string().contains("cycle"), "got: {err}");
}

#[test]
fn unknown_dependency_is_rejected() {
    let src = r#"
    protocol "u" {
      step "a" { role = "r1" action = "send" depends_on = ["nope"] segment { flags = ["X"] } }
      step "b" { role = "r2" action = "recv" expect { flags = ["X"] } }
    }
    "#;
    let p = load_protocol(src, "u");
    let err = Engine::new(p).unwrap_err();
    assert!(err.to_string().contains("unknown step"), "got: {err}");
}

#[test]
fn missing_segment_times_out() {
    let src = r#"
    protocol "miss" {
      step "a" { role = "r1" action = "send" segment { flags = ["X"] } }
      step "b" { role = "r2" action = "recv" expect { flags = ["Y"] } timer { timeout = "50ms" } }
    }
    "#;
    let p = load_protocol(src, "miss");
    let engine = Engine::new(p).unwrap();
    let res = engine.run();
    assert!(res.is_err(), "should time out waiting for Y");
}

#[test]
fn duration_parsing() {
    assert_eq!(parse_duration_ms("100ms").unwrap(), 100);
    assert_eq!(parse_duration_ms("2s").unwrap(), 2000);
    assert_eq!(parse_duration_ms("500").unwrap(), 500);
    assert!(parse_duration_ms("2x").is_err());
    assert!(parse_duration_ms("").is_err());
}

#[test]
fn parser_handles_comments_and_objects() {
    let src = r#"
    # a comment
    protocol "p" {
      description = "d" // trailing comment
      step "s" {
        role   = "r1"
        action = "send"
        segment = { flags = ["A", "B"] seq = 10 }
      }
      step "r" {
        role   = "r2"
        action = "recv"
        expect { flags = ["A"] }
      }
    }
    "#;
    let p = load_protocol(src, "p");
    assert_eq!(p.steps.len(), 2);
    assert_eq!(p.steps[0].segment.as_ref().unwrap().flags, vec!["A", "B"]);
    assert_eq!(p.steps[0].segment.as_ref().unwrap().seq, Some(10));
}

// ---- Tests for the expanded primitive set ----

fn run_ok(src: &str, name: &str) -> Vec<tcpform::TraceEvent> {
    let p = load_protocol(src, name);
    Engine::new(p).unwrap().run().unwrap()
}

#[test]
fn drop_removes_segment() {
    let src = r#"
    protocol "drop_test" {
      step "data" { role = "r1" action = "send" segment { flags = ["DATA"] } }
      step "drop" { role = "r2" action = "drop" expect { flags = ["DATA"] } }
      step "ack"  { role = "r2" action = "ack" depends_on = ["drop"] segment { flags = ["ACK"] } }
      step "rack" { role = "r1" action = "recv" expect { flags = ["ACK"] } }
    }
    "#;
    let trace = run_ok(src, "drop_test");
    let drop_ev = trace
        .iter()
        .find(|e| e.action == tcpform::Action::Drop)
        .unwrap();
    assert!(drop_ev.detail.contains("dropped"), "{}", drop_ev.detail);
    assert_eq!(drop_ev.flags, vec!["DATA"]);
}

#[test]
fn drop_with_no_match_is_benign() {
    let src = r#"
    protocol "drop_nomatch" {
      step "drop" { role = "r1" action = "drop" expect { flags = ["X"] } timer { timeout = "30ms" } }
      step "fin"  { role = "r2" action = "send" segment { flags = ["FIN"] } }
      step "rf"   { role = "r1" action = "recv" expect { flags = ["FIN"] } }
    }
    "#;
    let trace = run_ok(src, "drop_nomatch");
    let drop_ev = trace
        .iter()
        .find(|e| e.action == tcpform::Action::Drop)
        .unwrap();
    assert!(drop_ev.detail.contains("no matching"), "{}", drop_ev.detail);
}

#[test]
fn duplicate_emits_two_segments() {
    let src = r#"
    protocol "dup_test" {
      step "dup" { role = "r1" action = "duplicate" segment { flags = ["P"] } }
      step "r1"  { role = "r2" action = "recv" expect { flags = ["P"] } }
      step "r2"  { role = "r2" action = "recv" depends_on = ["r1"] expect { flags = ["P"] } }
    }
    "#;
    let trace = run_ok(src, "dup_test");
    let sends = trace
        .iter()
        .filter(|e| e.action == tcpform::Action::Duplicate)
        .count();
    assert_eq!(sends, 2, "duplicate should emit two trace events");
    let recvs = trace
        .iter()
        .filter(|e| e.action == tcpform::Action::Recv && e.ok)
        .count();
    assert_eq!(recvs, 2, "both duplicates should be received");
}

#[test]
fn reset_sets_aborted_and_sends_rst() {
    let src = r#"
    protocol "rst_test" {
      step "rst"   { role = "r1" action = "reset" to = "r2" }
      step "rrst"  { role = "r2" action = "recv" expect { flags = ["RST"] } }
      step "check" { role = "r1" action = "assert" depends_on = ["rst"] assert { aborted = true } }
    }
    "#;
    let trace = run_ok(src, "rst_test");
    let rst = trace
        .iter()
        .find(|e| e.action == tcpform::Action::Reset)
        .unwrap();
    assert!(rst.flags.contains(&"RST".to_string()));
}

#[test]
fn assert_failure_fails_the_run() {
    let src = r#"
    protocol "bad_assert" {
      step "s" { role = "r1" action = "send" segment { flags = ["A"] } }
      step "r" { role = "r2" action = "recv" expect { flags = ["A"] } }
      step "c" { role = "r1" action = "assert" depends_on = ["s"] assert { send_count = 99 } }
    }
    "#;
    let p = load_protocol(src, "bad_assert");
    let err = Engine::new(p).unwrap().run().unwrap_err();
    assert!(err.to_string().contains("assert failed"), "{}", err);
    assert!(err.to_string().contains("send_count"), "{}", err);
}
#[test]
fn set_and_assert_user_variable() {
    let src = r#"
    protocol "setvar" {
      step "s" { role = "r1" action = "set" set { phase = "half" n = 3 } }
      step "c" { role = "r1" action = "assert" depends_on = ["s"] assert { phase = "half" n = 3 } }
    }
    "#;
    let trace = run_ok(src, "setvar");
    let set_ev = trace
        .iter()
        .find(|e| e.action == tcpform::Action::Set)
        .unwrap();
    assert!(set_ev.detail.contains("phase="), "{}", set_ev.detail);
}

#[test]
fn window_is_advertised_and_matched() {
    let src = r#"
    protocol "win_test" {
      step "s" { role = "r1" action = "send" segment { flags = ["A"] window = 4096 } }
      step "r" { role = "r2" action = "recv" expect { flags = ["A"] window = 4096 } }
    }
    "#;
    let trace = run_ok(src, "win_test");
    let recv = trace
        .iter()
        .find(|e| e.action == tcpform::Action::Recv)
        .unwrap();
    assert!(recv.detail.contains("win=4096"), "{}", recv.detail);
}

#[test]
fn stream_is_advertised_and_matched() {
    let src = r#"
    protocol "str_test" {
      step "s" { role = "r1" action = "send" segment { flags = ["A"] stream = 7 } }
      step "r" { role = "r2" action = "recv" expect { flags = ["A"] stream = 7 } }
    }
    "#;
    run_ok(src, "str_test");
}

#[test]
fn recv_window_mismatch_times_out() {
    let src = r#"
    protocol "win_mismatch" {
      step "s" { role = "r1" action = "send" segment { flags = ["A"] window = 100 } }
      step "r" { role = "r2" action = "recv" expect { flags = ["A"] window = 999 } timer { timeout = "60ms" } }
    }
    "#;
    let p = load_protocol(src, "win_mismatch");
    assert!(
        Engine::new(p).unwrap().run().is_err(),
        "window mismatch should time out"
    );
}

#[test]
fn open_and_listen_modes_are_recorded() {
    let src = r#"
    protocol "open_test" {
      step "c" { role = "r1" action = "open" mode = "active" }
      step "l" { role = "r2" action = "listen" }
      step "s" { role = "r1" action = "send" depends_on = ["c"] segment { flags = ["A"] } }
      step "r" { role = "r2" action = "recv" depends_on = ["l"] expect { flags = ["A"] } }
    }
    "#;
    let trace = run_ok(src, "open_test");
    let open = trace.iter().find(|e| e.step == "c").unwrap();
    assert!(open.detail.contains("mode=active"), "{}", open.detail);
    let listen = trace.iter().find(|e| e.step == "l").unwrap();
    assert!(listen.detail.contains("mode=passive"), "{}", listen.detail);
}

#[test]
fn log_emits_message() {
    let src = r#"
    protocol "log_test" {
      step "m" { role = "r1" action = "log" message = "checkpoint reached" }
      step "s" { role = "r1" action = "send" depends_on = ["m"] segment { flags = ["A"] } }
      step "r" { role = "r2" action = "recv" expect { flags = ["A"] } }
    }
    "#;
    let trace = run_ok(src, "log_test");
    let log = trace
        .iter()
        .find(|e| e.action == tcpform::Action::Log)
        .unwrap();
    assert!(log.detail.contains("checkpoint reached"), "{}", log.detail);
}

#[test]
fn nack_sends_negative_acknowledgement() {
    let src = r#"
    protocol "nack_test" {
      step "data" { role = "r1" action = "send" segment { flags = ["DATA"] seq = 500 } }
      step "rd"   { role = "r2" action = "recv" expect { flags = ["DATA"] } }
      step "nack" { role = "r2" action = "nack" depends_on = ["rd"] segment { ack = 500 } }
      step "rn"   { role = "r1" action = "recv" expect { flags = ["NACK"] } }
    }
    "#;
    let trace = run_ok(src, "nack_test");
    let nack = trace
        .iter()
        .find(|e| e.action == tcpform::Action::Nack)
        .unwrap();
    assert!(nack.flags.contains(&"NACK".to_string()));
    assert_eq!(nack.ack_num, Some(500));
}

#[test]
fn rich_example_runs_to_completion() {
    let src = include_str!("../examples/rich.tcpf");
    let trace = run_ok(src, "rich_primitives");
    assert!(trace.iter().all(|e| e.ok), "trace = {trace:?}");
    let actions: Vec<tcpform::Action> = trace.iter().map(|e| e.action).collect();
    use tcpform::Action::*;
    for a in [
        Open, Send, Drop, Nack, Duplicate, Recv, Set, Assert, Log, Reset,
    ] {
        assert!(actions.contains(&a), "missing action {a:?} in trace");
    }
}

/// Regression guard: every protocol in every `examples/*.tcpf` file must
/// parse, plan, and run to completion successfully. Files that define
/// `cases` blocks (data-driven tests) are skipped here — their protocols
/// use `${var}` interpolation and require case variables to run; they are
/// verified by `all_case_suites_pass` instead.
#[test]
fn all_examples_run_to_completion() {
    use std::fs;
    let entries: Vec<_> = fs::read_dir("examples")
        .expect("examples/ directory should exist relative to crate root")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("tcpf"))
        .collect();
    assert!(
        !entries.is_empty(),
        "expected at least one .tcpf example file"
    );
    let mut ran = 0usize;
    for entry in entries {
        let path = entry.path();
        let blocks =
            tcpform::load_blocks(&path).unwrap_or_else(|e| panic!("load {}: {e}", path.display()));
        // Skip files that define `cases` blocks (data-driven protocols)
        let has_cases = blocks.iter().any(|b| b.name == "cases");
        let protocols =
            interpret(&blocks).unwrap_or_else(|e| panic!("interpret {}: {e}", path.display()));
        if has_cases {
            // Still verify it parses and plans, just don't run without vars
            for p in &protocols {
                Engine::new(p.clone()).unwrap_or_else(|e| panic!("plan {}: {e}", path.display()));
            }
            continue;
        }
        assert!(
            !protocols.is_empty(),
            "{} defines no protocols",
            path.display()
        );
        for p in protocols {
            let engine =
                Engine::new(p.clone()).unwrap_or_else(|e| panic!("plan {}: {e}", path.display()));
            let trace = engine
                .run()
                .unwrap_or_else(|e| panic!("run {} / {}: {e}", path.display(), p.name));
            assert!(
                trace.iter().all(|e| e.ok),
                "{} / {} produced a failing event: {trace:?}",
                path.display(),
                p.name
            );
            ran += 1;
        }
    }
    assert!(ran >= 30, "expected to run >=30 protocols, ran {ran}");
}

/// Regression guard: every `cases` suite in `examples/*.tcpf` must have all
/// its cases pass when run via `Engine::run_cases`.
#[test]
fn all_case_suites_pass() {
    use std::fs;
    use tcpform::model::interpret_cases;
    let entries: Vec<_> = fs::read_dir("examples")
        .expect("examples/ directory should exist relative to crate root")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("tcpf"))
        .collect();
    let mut suites_run = 0usize;
    for entry in entries {
        let path = entry.path();
        let blocks =
            tcpform::load_blocks(&path).unwrap_or_else(|e| panic!("load {}: {e}", path.display()));
        let protocols =
            interpret(&blocks).unwrap_or_else(|e| panic!("interpret {}: {e}", path.display()));
        let case_suites = interpret_cases(&blocks)
            .unwrap_or_else(|e| panic!("interpret_cases {}: {e}", path.display()));
        for suite in &case_suites {
            let proto = protocols
                .iter()
                .find(|p| p.name == suite.protocol)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: cases target unknown protocol `{}`",
                        path.display(),
                        suite.protocol
                    )
                });
            let engine = Engine::new(proto.clone())
                .unwrap_or_else(|e| panic!("plan {}: {e}", path.display()));
            let results = engine.run_cases(&suite.cases);
            for r in &results {
                assert!(
                    r.passed,
                    "{}: case `{}` failed (expected {}, got {})",
                    path.display(),
                    r.name,
                    r.expected.as_str(),
                    r.actual.as_str()
                );
            }
            suites_run += 1;
        }
    }
    assert!(
        suites_run >= 1,
        "expected at least 1 case suite, ran {suites_run}"
    );
}

// ---- Tests for structured messages (fields, capture, interpolation, operators) ----

#[test]
fn structured_fields_send_and_match() {
    let src = r#"
    protocol "sf" {
      step "s" { role = "r1" action = "send" segment { flags = ["X"] fields = { id = 42 name = "hi" } } }
      step "r" { role = "r2" action = "recv" expect { flags = ["X"] fields = { id = 42 } } }
    }
    "#;
    let trace = run_ok(src, "sf");
    assert!(trace.iter().all(|e| e.ok), "{trace:?}");
}

#[test]
fn field_match_contains_operator() {
    let src = r#"
    protocol "fc" {
      step "s" { role = "r1" action = "send" segment { flags = ["X"] fields = { msg = "hello world" } } }
      step "r" { role = "r2" action = "recv" expect { flags = ["X"] fields = { msg = { contains = "world" } } } }
    }
    "#;
    run_ok(src, "fc");
}

#[test]
fn field_match_range_operator() {
    let src = r#"
    protocol "fr" {
      step "s" { role = "r1" action = "send" segment { flags = ["X"] fields = { code = 200 } } }
      step "r" { role = "r2" action = "recv" expect { flags = ["X"] fields = { code = { min = 100 max = 299 } } } }
    }
    "#;
    run_ok(src, "fr");
}

#[test]
fn field_match_range_rejects_out_of_range() {
    let src = r#"
    protocol "fr_bad" {
      step "s" { role = "r1" action = "send" segment { flags = ["X"] fields = { code = 404 } } }
      step "r" { role = "r2" action = "recv" expect { flags = ["X"] fields = { code = { min = 100 max = 299 } } } timer { timeout = "50ms" } }
    }
    "#;
    let p = load_protocol(src, "fr_bad");
    assert!(
        Engine::new(p).unwrap().run().is_err(),
        "out-of-range should fail"
    );
}

#[test]
fn capture_and_interpolation_echo() {
    // Server captures the client's id, echoes it back via ${var}
    let src = r#"
    protocol "echo" {
      step "req" {
        role = "client" action = "send"
        segment { flags = ["X"] fields = { id = 99 } }
      }
      step "rreq" {
        role = "server" action = "recv"
        expect { flags = ["X"] capture { id = "txn" } }
      }
      step "resp" {
        role = "server" action = "send" depends_on = ["rreq"]
        segment { flags = ["Y"] fields = { id = "${txn}" } }
      }
      step "rresp" {
        role = "client" action = "recv" depends_on = ["req"]
        expect { flags = ["Y"] fields = { id = 99 } }
      }
      step "verify" {
        role = "server" action = "assert" depends_on = ["resp"]
        assert { txn = 99 }
      }
    }
    "#;
    let trace = run_ok(src, "echo");
    assert!(trace.iter().all(|e| e.ok), "{trace:?}");
}

#[test]
fn interpolation_preserves_type_for_exact_ref() {
    // ${var} alone preserves Number type; "id=${var}" stringifies
    let src = r#"
    protocol "types" {
      step "set" { role = "r1" action = "set" set { n = 42 } }
      step "exact" {
        role = "r1" action = "send" depends_on = ["set"]
        segment { flags = ["X"] fields = { a = "${n}" b = "val=${n}" } }
      }
      step "r" {
        role = "r2" action = "recv"
        expect { flags = ["X"] fields = { a = 42 b = "val=42" } }
      }
    }
    "#;
    run_ok(src, "types");
}

#[test]
fn assert_recv_field_direct_access() {
    let src = r#"
    protocol "rf" {
      step "s" { role = "r1" action = "send" segment { flags = ["X"] fields = { status = "ok" n = 5 } } }
      step "r" { role = "r2" action = "recv" expect { flags = ["X"] } }
      step "c" {
        role = "r2" action = "assert" depends_on = ["r"]
        assert { "recv_field:status" = "ok" "recv_field:n" = 5 }
      }
    }
    "#;
    run_ok(src, "rf");
}

#[test]
fn quoted_keys_in_assert_and_object() {
    let src = r#"
    protocol "qk" {
      step "s" {
        role = "r1" action = "send"
        segment = { flags = ["X"] fields = { "my-key" = 1 } }
      }
      step "r" {
        role = "r2" action = "recv"
        expect = { flags = ["X"] fields = { "my-key" = 1 } }
      }
      step "c" {
        role = "r2" action = "assert" depends_on = ["r"]
        assert { "recv_field:my-key" = 1 }
      }
    }
    "#;
    run_ok(src, "qk");
}

#[test]
fn structured_example_runs_to_completion() {
    let src = include_str!("../examples/structured_messages.tcpf");
    let trace = run_ok(src, "structured_messages");
    assert!(trace.iter().all(|e| e.ok), "{trace:?}");
}

// ---- Tests for binary hex messages ----

#[test]
fn parse_hex_basic() {
    assert_eq!(parse_hex("4500003c").unwrap(), vec![0x45, 0x00, 0x00, 0x3c]);
    assert_eq!(
        parse_hex("0x4500003c").unwrap(),
        vec![0x45, 0x00, 0x00, 0x3c]
    );
    assert_eq!(
        parse_hex("45 00 00 3c").unwrap(),
        vec![0x45, 0x00, 0x00, 0x3c]
    );
    assert_eq!(parse_hex("DEADbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn parse_hex_odd_digits_fail() {
    assert!(parse_hex("123").is_err());
}

#[test]
fn parse_hex_invalid_char_fails() {
    assert!(parse_hex("12gg").is_err());
}

#[test]
fn bytes_to_hex_roundtrip() {
    let bytes = vec![0x12, 0x34, 0xff, 0x00];
    assert_eq!(bytes_to_hex(&bytes), "1234ff00");
    assert_eq!(parse_hex(&bytes_to_hex(&bytes)).unwrap(), bytes);
}

#[test]
fn hex_payload_send_and_exact_match() {
    let src = r#"
    protocol "hex_exact" {
      step "s" { role = "r1" action = "send" segment { flags = ["X"] hex = "deadbeef" } }
      step "r" { role = "r2" action = "recv" expect { flags = ["X"] hex = "deadbeef" } }
    }
    "#;
    let trace = run_ok(src, "hex_exact");
    assert!(trace.iter().all(|e| e.ok), "{trace:?}");
}

#[test]
fn hex_payload_mismatch_fails() {
    let src = r#"
    protocol "hex_mismatch" {
      step "s" { role = "r1" action = "send" segment { flags = ["X"] hex = "deadbeef" } }
      step "r" { role = "r2" action = "recv" expect { flags = ["X"] hex = "cafebabe" } timer { timeout = "50ms" } }
    }
    "#;
    let p = load_protocol(src, "hex_mismatch");
    assert!(
        Engine::new(p).unwrap().run().is_err(),
        "hex mismatch should fail"
    );
}

#[test]
fn hex_contains_matching() {
    let src = r#"
    protocol "hex_contains" {
      step "s" { role = "r1" action = "send" segment { flags = ["X"] hex = "deadbeefcafe" } }
      step "r" { role = "r2" action = "recv" expect { flags = ["X"] hex_contains = "beefcafe" } }
    }
    "#;
    run_ok(src, "hex_contains");
}

#[test]
fn hex_contains_not_found_fails() {
    let src = r#"
    protocol "hex_contains_fail" {
      step "s" { role = "r1" action = "send" segment { flags = ["X"] hex = "deadbeef" } }
      step "r" { role = "r2" action = "recv" expect { flags = ["X"] hex_contains = "cafe" } timer { timeout = "50ms" } }
    }
    "#;
    let p = load_protocol(src, "hex_contains_fail");
    assert!(
        Engine::new(p).unwrap().run().is_err(),
        "hex_contains not found should fail"
    );
}

#[test]
fn hex_field_value_send_and_match() {
    let src = r#"
    protocol "hex_field" {
      step "s" {
        role = "r1" action = "send"
        segment { flags = ["X"] fields = { id = { hex = "1234" } data = { hex = "aabbcc" } } }
      }
      step "r" {
        role = "r2" action = "recv"
        expect { flags = ["X"] fields = { id = { hex = "1234" } } }
      }
      step "v" {
        role = "r2" action = "assert" depends_on = ["r"]
        assert { "recv_field:data" = { hex = "aabbcc" } }
      }
    }
    "#;
    let trace = run_ok(src, "hex_field");
    assert!(trace.iter().all(|e| e.ok), "{trace:?}");
}

#[test]
fn hex_field_hex_contains_operator() {
    let src = r#"
    protocol "hex_fc" {
      step "s" {
        role = "r1" action = "send"
        segment { flags = ["X"] fields = { data = { hex = "deadbeefcafe" } } }
      }
      step "r" {
        role = "r2" action = "recv"
        expect { flags = ["X"] fields = { data = { hex_contains = "beef" } } }
      }
    }
    "#;
    run_ok(src, "hex_fc");
}

#[test]
fn hex_capture_and_interpolation() {
    // Capture a binary field, interpolate it into a hex payload
    let src = r#"
    protocol "hex_cap" {
      step "req" {
        role = "client" action = "send"
        segment { flags = ["X"] fields = { id = { hex = "abcd" } } }
      }
      step "rreq" {
        role = "server" action = "recv"
        expect { flags = ["X"] capture { id = "txn" } }
      }
      step "resp" {
        role = "server" action = "send" depends_on = ["rreq"]
        segment { flags = ["Y"] hex = "${txn}0102" }
      }
      step "rresp" {
        role = "client" action = "recv" depends_on = ["req"]
        expect { flags = ["Y"] hex = "abcd0102" }
      }
    }
    "#;
    let trace = run_ok(src, "hex_cap");
    assert!(trace.iter().all(|e| e.ok), "{trace:?}");
}

#[test]
fn binary_example_runs_to_completion() {
    let src = include_str!("../examples/binary_hex.tcpf");
    let trace = run_ok(src, "binary_hex");
    assert!(trace.iter().all(|e| e.ok), "{trace:?}");
}

#[test]
fn value_bytes_display() {
    let v = Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(v.to_display(), "hex:\"deadbeef\"");
}

#[test]
fn hex_with_whitespace_and_prefix() {
    let src = r#"
    protocol "hex_ws" {
      step "s" { role = "r1" action = "send" segment { flags = ["X"] hex = "0x 45 00 00 3c" } }
      step "r" { role = "r2" action = "recv" expect { flags = ["X"] hex = "4500003c" } }
    }
    "#;
    run_ok(src, "hex_ws");
}

// ---- Tests for data-driven test cases ----

use tcpform::model::interpret_cases;
use tcpform::{Case, CaseOutcome};

fn load_cases(src: &str, proto_name: &str) -> (Protocol, Vec<Case>) {
    let blocks = parse_file(src).unwrap();
    let protocols = interpret(&blocks).unwrap();
    let proto = protocols
        .into_iter()
        .find(|p| p.name == proto_name)
        .unwrap_or_else(|| panic!("protocol `{proto_name}` not found"));
    let suites = interpret_cases(&blocks).unwrap();
    let cases: Vec<Case> = suites
        .into_iter()
        .filter(|c| c.protocol == proto_name)
        .flat_map(|c| c.cases)
        .collect();
    (proto, cases)
}

#[test]
fn cases_pass_with_matching_vars() {
    let src = r#"
    protocol "echo" {
      step "s" { role = "r1" action = "send" segment { flags = ["X"] fields = { msg = "${msg}" } } }
      step "r" { role = "r2" action = "recv" expect { flags = ["X"] fields = { msg = "${msg}" } } }
    }
    cases "echo" {
      case "hello" { vars { msg = "hello" } }
      case "world" { vars { msg = "world" } }
    }
    "#;
    let (proto, cases) = load_cases(src, "echo");
    let engine = Engine::new(proto).unwrap();
    let results = engine.run_cases(&cases);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.passed), "{results:?}");
}

#[test]
fn case_tags_and_parallel_execution_preserve_declaration_order() {
    let src = r#"
    protocol "tagged" {
      clock = "virtual"
      step "s" { role="a" action="send" segment { fields={ value="${value}" } } }
      step "r" { role="b" action="recv" expect { fields={ value="${value}" } } }
    }
    cases "tagged" {
      case "one"   { tags=["smoke", "fast"] vars { value=1 } }
      case "two"   { tags=["fast"] vars { value=2 } }
      case "three" { tags=["slow"] vars { value=3 } }
      case "four"  { tags=["slow"] vars { value=4 } }
    }
    "#;
    let (protocol, cases) = load_cases(src, "tagged");
    assert_eq!(cases[0].tags, ["smoke", "fast"]);
    let engine = Engine::new(protocol).unwrap();
    let sequential = engine.run_cases(&cases);
    let parallel = engine.run_cases_parallel(&cases, 8);
    assert_eq!(engine.run_cases_parallel(&cases, 0).len(), cases.len());
    assert_eq!(
        parallel
            .iter()
            .map(|result| &result.name)
            .collect::<Vec<_>>(),
        sequential
            .iter()
            .map(|result| &result.name)
            .collect::<Vec<_>>()
    );
    assert!(parallel.iter().all(|result| result.passed));

    let duplicate = parse_file(
        r#"
        protocol "p" { step "s" { role="a" action="log" } }
        cases "p" { case "bad" { tags=["same", "same"] } }
        "#,
    )
    .unwrap();
    assert!(interpret_cases(&duplicate)
        .unwrap_err()
        .to_string()
        .contains("duplicate tag"));
}

#[test]
fn cases_negative_test_expects_fail() {
    let src = r#"
    protocol "mismatch" {
      step "s"  { role = "r1" action = "send" segment { flags = ["X"] fields = { v = "${send_v}" } } }
      step "r"  { role = "r2" action = "recv" expect { flags = ["X"] fields = { v = "${expect_v}" } } }
    }
    cases "mismatch" {
      case "matching"    { vars { send_v = 1 expect_v = 1 } }
      case "mismatched"  { vars { send_v = 1 expect_v = 2 } expect = "fail" }
    }
    "#;
    let (proto, cases) = load_cases(src, "mismatch");
    let engine = Engine::new(proto).unwrap();
    let results = engine.run_cases(&cases);
    assert_eq!(results.len(), 2);
    assert!(
        results[0].passed,
        "matching case should pass: {:?}",
        results[0]
    );
    assert!(
        results[1].passed,
        "mismatched case (expect=fail) should pass: {:?}",
        results[1]
    );
}

#[test]
fn cases_per_role_post_run_asserts() {
    let src = r#"
    protocol "count" {
      step "s1" { role = "r1" action = "send" segment { flags = ["X"] } }
      step "s2" { role = "r1" action = "send" depends_on = ["s1"] segment { flags = ["X"] } }
      step "r1" { role = "r2" action = "recv" expect { flags = ["X"] } }
      step "r2" { role = "r2" action = "recv" depends_on = ["r1"] expect { flags = ["X"] } }
    }
    cases "count" {
      case "two_sends" {
        vars {}
        assert_r1 { send_count = 2 }
        assert_r2 { recv_count = 2 }
      }
    }
    "#;
    let (proto, cases) = load_cases(src, "count");
    let engine = Engine::new(proto).unwrap();
    let results = engine.run_cases(&cases);
    assert_eq!(results.len(), 1);
    assert!(
        results[0].passed,
        "post-run asserts should pass: {:?}",
        results[0]
    );
}

#[test]
fn cases_post_run_assert_failure_detected() {
    let src = r#"
    protocol "count" {
      step "s1" { role = "r1" action = "send" segment { flags = ["X"] } }
      step "r1" { role = "r2" action = "recv" expect { flags = ["X"] } }
    }
    cases "count" {
      case "wrong_count" {
        vars {}
        assert_r1 { send_count = 99 }
      }
    }
    "#;
    let (proto, cases) = load_cases(src, "count");
    let engine = Engine::new(proto).unwrap();
    let results = engine.run_cases(&cases);
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].passed,
        "wrong count should fail: {:?}",
        results[0]
    );
    assert_eq!(results[0].actual, CaseOutcome::Fail);
}

#[test]
fn dns_cases_example_all_pass() {
    let src = include_str!("../examples/dns_cases.tcpf");
    let (proto, cases) = load_cases(src, "dns_lookup");
    let engine = Engine::new(proto).unwrap();
    let results = engine.run_cases(&cases);
    assert_eq!(
        results.len(),
        5,
        "should have 5 cases (4 positive + 1 negative)"
    );
    assert!(results.iter().all(|r| r.passed), "{results:?}");
}

// ---- Tests for retransmission and simulated transport faults ----

#[test]
fn recv_timeout_retransmits_the_same_automatic_sequence() {
    let src = r#"
    protocol "retransmit" {
      step "syn" {
        role = "client"
        action = "send"
        segment { flags = ["SYN"] }
      }
      step "recv_ack" {
        role = "client"
        action = "recv"
        retransmit = 1
        expect { flags = ["ACK"] }
        timer { timeout = "300ms" }
      }

      step "drop_first" {
        role = "server"
        action = "drop"
        expect { flags = ["SYN"] }
        timer { timeout = "1s" }
      }
      step "recv_retry" {
        role = "server"
        action = "recv"
        expect { flags = ["SYN"] }
        timer { timeout = "1s" }
      }
      step "ack" {
        role = "server"
        action = "ack"
        segment { flags = ["ACK"] }
      }
    }
    "#;

    let trace = run_ok(src, "retransmit");
    assert!(trace.iter().all(|e| e.ok), "trace = {trace:?}");
    let sends: Vec<_> = trace.iter().filter(|e| e.step == "syn").collect();
    assert_eq!(sends.len(), 2, "the SYN should be sent once and retried");
    assert_eq!(
        sends[0].seq_num, sends[1].seq_num,
        "a retransmission must reuse the original automatic sequence number"
    );
    assert!(trace
        .iter()
        .any(|e| e.detail.contains("timed out, retransmitting syn")));
}

#[test]
fn timer_retransmit_is_parsed() {
    let src = r#"
    protocol "timer_retry" {
      step "send" { role = "a" action = "send" segment { flags = ["X"] } }
      step "recv" {
        role = "a"
        action = "recv"
        timer { timeout = "10ms" retransmit = 3 }
      }
      step "peer" { role = "b" action = "recv" expect { flags = ["X"] } }
    }
    "#;
    let protocol = load_protocol(src, "timer_retry");
    assert_eq!(protocol.steps[1].timer.as_ref().unwrap().retransmit, 3);
}

#[test]
fn transport_and_segment_delays_are_added() {
    use std::time::{Duration, Instant};

    let src = r#"
    protocol "delayed" {
      transport { delay = "20ms" }
      step "send" {
        role = "a"
        action = "send"
        segment { flags = ["X"] delay = "20ms" }
      }
      step "recv" {
        role = "b"
        action = "recv"
        expect { flags = ["X"] }
        timer { timeout = "500ms" }
      }
    }
    "#;
    let protocol = load_protocol(src, "delayed");
    assert_eq!(protocol.transport.as_ref().unwrap().delay_ms, 20);
    assert_eq!(protocol.steps[0].segment.as_ref().unwrap().delay_ms, 20);

    let started = Instant::now();
    Engine::new(protocol).unwrap().run().unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(35),
        "transport and segment delay should both affect delivery"
    );
}

#[test]
fn total_transport_loss_causes_a_receive_timeout() {
    let src = r#"
    protocol "loss" {
      transport { loss_rate = 1.0 seed = 7 }
      step "send" { role = "a" action = "send" segment { flags = ["X"] } }
      step "recv" {
        role = "b"
        action = "recv"
        expect { flags = ["X"] }
        timer { timeout = "20ms" }
      }
    }
    "#;
    let result = Engine::new(load_protocol(src, "loss")).unwrap().run();
    assert!(result.is_err(), "loss_rate=1 must drop every segment");
}

fn wire_message(seq: i64) -> tcpform::primitives::Message {
    tcpform::primitives::Message {
        from: "sender".to_string(),
        flags: vec!["DATA".to_string()],
        seq,
        ack: 0,
        payload: String::new(),
        raw: Vec::new(),
        window: 0,
        stream: None,
        fields: std::collections::HashMap::new(),
    }
}

fn queued_sequences(transport: &tcpform::transport::Transport, role: &str) -> Vec<i64> {
    let inbox = transport.inbox(role).unwrap();
    let (lock, _) = &*inbox;
    let queue = lock.lock().unwrap();
    queue.iter().map(|message| message.seq).collect()
}

#[test]
fn seeded_loss_and_reorder_are_reproducible() {
    let roles = vec!["receiver".to_string()];
    let config = tcpform::TransportConfig {
        loss_rate: 0.35,
        delay_ms: 0,
        reorder: true,
        seed: 42,
        ..tcpform::TransportConfig::default()
    };
    let first = tcpform::transport::Transport::with_config(&roles, &config);
    let second = tcpform::transport::Transport::with_config(&roles, &config);

    for seq in 0..20 {
        first.send("receiver", wire_message(seq), 0).unwrap();
        second.send("receiver", wire_message(seq), 0).unwrap();
    }

    let first_order = queued_sequences(&first, "receiver");
    let second_order = queued_sequences(&second, "receiver");
    assert_eq!(
        first_order, second_order,
        "the same seed must replay faults"
    );
    assert!(
        !first_order.is_empty() && first_order.len() < 20,
        "the selected seed should deliver some messages and lose others"
    );
    let mut sorted = first_order.clone();
    sorted.sort_unstable();
    assert_ne!(
        first_order, sorted,
        "reorder=true should change queue order"
    );
}

#[test]
fn transport_jitter_bandwidth_and_mtu_are_enforced() {
    let roles = vec!["receiver".to_string()];
    let config = tcpform::TransportConfig {
        delay_ms: 10,
        jitter_ms: 5,
        bandwidth_bps: 8_000,
        mtu: 8,
        seed: 7,
        ..tcpform::TransportConfig::default()
    };
    let first = tcpform::transport::Transport::with_config(&roles, &config);
    let second = tcpform::transport::Transport::with_config(&roles, &config);
    let report_a = first.send("receiver", wire_message(1), 0).unwrap();
    let report_b = second.send("receiver", wire_message(1), 0).unwrap();
    assert_eq!(report_a.delay_ms, report_b.delay_ms);
    assert!((5..=16).contains(&report_a.delay_ms));

    let mut oversized = wire_message(2);
    oversized.raw = vec![0; 9];
    assert!(first
        .send("receiver", oversized, 0)
        .unwrap_err()
        .to_string()
        .contains("transport mtu 8"));

    let source = r#"
protocol "network_shape" {
  transport { delay = "10ms" jitter = "5ms" bandwidth_bps = 8000 mtu = 1200 seed = 7 }
  step "log" { role = "client" action = "log" message = "ok" }
}
"#;
    let protocol = load_protocol(source, "network_shape");
    let transport = protocol.transport.unwrap();
    assert_eq!(transport.jitter_ms, 5);
    assert_eq!(transport.bandwidth_bps, 8_000);
    assert_eq!(transport.mtu, 1_200);
}

#[test]
fn transport_faults_support_nth_step_flag_burst_duplicate_and_corrupt() {
    let roles = vec!["receiver".to_string()];
    let nth = tcpform::TransportConfig {
        drop_nth: 2,
        fault_steps: vec!["target".to_string()],
        fault_flag: Some("DATA".to_string()),
        ..tcpform::TransportConfig::default()
    };
    let transport = tcpform::transport::Transport::with_config(&roles, &nth);
    assert!(
        !transport
            .send_scoped("receiver", wire_message(1), 0, Some("other"))
            .unwrap()
            .dropped
    );
    assert!(
        !transport
            .send_scoped("receiver", wire_message(2), 0, Some("target"))
            .unwrap()
            .dropped
    );
    assert!(
        transport
            .send_scoped("receiver", wire_message(3), 0, Some("target"))
            .unwrap()
            .dropped
    );

    let predicate = tcpform::TransportConfig {
        drop_nth: 1,
        fault_when: Some(tcpform::model::FaultPredicate {
            field: "seq".to_string(),
            equals: Value::Number(20.0),
        }),
        ..tcpform::TransportConfig::default()
    };
    let transport = tcpform::transport::Transport::with_config(&roles, &predicate);
    assert!(
        !transport
            .send("receiver", wire_message(10), 0)
            .unwrap()
            .dropped
    );
    assert!(
        transport
            .send("receiver", wire_message(20), 0)
            .unwrap()
            .dropped
    );

    let shaped = tcpform::TransportConfig {
        duplicate_rate: 1.0,
        corrupt_rate: 1.0,
        ..tcpform::TransportConfig::default()
    };
    let transport = tcpform::transport::Transport::with_config(&roles, &shaped);
    let mut message = wire_message(4);
    message.raw = vec![0x01, 0x02];
    let report = transport.send("receiver", message, 0).unwrap();
    assert!(report.duplicated && report.corrupted);
    let inbox = transport.inbox("receiver").unwrap();
    let queue = inbox.0.lock().unwrap();
    assert_eq!(queue.len(), 2);
    assert!(queue.iter().all(|message| message.raw == [0x81, 0x02]));

    let source = r#"
protocol "scoped_fault" {
  transport {
    loss_rate = 0.25 burst_loss = 3 duplicate_rate = 0.2 corrupt_rate = 0.1
    drop_nth = 4 fault_steps = ["request"] fault_flag = "DATA" seed = 9
    fault_when { field = "fields.kind" equals = "request" }
  }
  step "request" { role = "client" action = "log" message = "configured" }
}
"#;
    let config = load_protocol(source, "scoped_fault").transport.unwrap();
    assert_eq!(config.burst_loss, 3);
    assert_eq!(config.drop_nth, 4);
    assert_eq!(config.fault_steps, ["request"]);
    assert_eq!(config.fault_when.unwrap().field, "fields.kind");
}
#[test]
fn invalid_transport_loss_rate_is_rejected() {
    let src = r#"
    protocol "invalid_loss" {
      transport { loss_rate = 1.1 }
      step "send" { role = "a" action = "send" }
    }
    "#;
    let blocks = parse_file(src).unwrap();
    let error = tcpform::model::interpret(&blocks).unwrap_err();
    assert!(error.to_string().contains("0.0–1.0"));
}

// ---- Conditional flow, extended matching, corruption, retry and loops ----

#[test]
fn when_guard_works_with_cases() {
    let src = r#"
    protocol "conditional_drop" {
      step "send" { role = "client" action = "send" segment { flags = ["DATA"] } }
      step "maybe_drop" {
        role = "server" action = "drop" when = "${drop_first}"
        expect { flags = ["DATA"] }
        timer { timeout = "20ms" }
      }
      step "recv" {
        role = "server" action = "recv"
        expect { flags = ["DATA"] }
        timer { timeout = "20ms" }
      }
    }
    cases "conditional_drop" {
      case "keep" { vars { drop_first = false } expect = "pass" }
      case "lose" { vars { drop_first = true } expect = "fail" }
    }
    "#;
    let (protocol, cases) = load_cases(src, "conditional_drop");
    let results = Engine::new(protocol).unwrap().run_cases(&cases);
    assert!(results.iter().all(|result| result.passed), "{results:?}");
}

#[test]
fn when_guard_requires_a_boolean() {
    let src = r#"
    protocol "bad_when" {
      step "send" { role = "a" action = "send" when = "not-a-bool" }
    }
    "#;
    let error = Engine::new(load_protocol(src, "bad_when"))
        .unwrap()
        .run()
        .unwrap_err();
    assert!(error.to_string().contains("when must resolve to bool"));
}

#[test]
fn extended_field_match_operators_work() {
    let src = r#"
    protocol "operators" {
      step "send" {
        role = "a" action = "send"
        segment { fields = { code = 201 path = "/api/users.json" email = "dev@example.com" } }
      }
      step "recv" {
        role = "b" action = "recv"
        expect { fields = {
          code = { not_equal = 0 }
          path = { prefix = "/api" }
          email = { regex = ".*@example\\.com$" }
        } }
      }
      step "send_suffix" {
        role = "a" action = "send"
        segment { fields = { path = "/api/users.json" } }
      }
      step "recv_suffix" {
        role = "b" action = "recv"
        expect { fields = { path = { suffix = ".json" } } }
      }
    }
    "#;
    let trace = run_ok(src, "operators");
    assert!(trace.iter().all(|event| event.ok), "{trace:?}");
}

#[test]
fn invalid_field_regex_is_rejected() {
    let src = r#"
    protocol "bad_regex" {
      step "recv" { role = "a" action = "recv" expect { fields = { x = { regex = "[" } } } }
    }
    "#;
    let blocks = parse_file(src).unwrap();
    assert!(tcpform::model::interpret(&blocks).is_err());
}

#[test]
fn corrupt_flips_the_requested_msb_first_bit() {
    let src = r#"
    protocol "corruption" {
      step "damage" {
        role = "a" action = "corrupt"
        segment { flags = ["DATA"] hex = "deadbeef" flip = 3 }
      }
      step "recv" {
        role = "b" action = "recv"
        expect { flags = ["DATA"] hex = "ceadbeef" }
      }
    }
    "#;
    let trace = run_ok(src, "corruption");
    let event = trace.iter().find(|event| event.step == "damage").unwrap();
    assert_eq!(event.action, tcpform::Action::Corrupt);
    assert!(event.detail.contains("hex=ceadbeef"), "{}", event.detail);
}

#[test]
fn corrupt_rejects_an_out_of_range_bit() {
    let src = r#"
    protocol "bad_corruption" {
      step "damage" { role = "a" action = "corrupt" segment { hex = "00" flip = 8 } }
    }
    "#;
    assert!(Engine::new(load_protocol(src, "bad_corruption"))
        .unwrap()
        .run()
        .is_err());
}

#[test]
fn timeout_retry_can_recover_and_loop_repeats_successful_steps() {
    let src = r#"
    protocol "retry_loop" {
      step "send" {
        role = "a" action = "send" loop = 3
        segment { flags = ["X"] delay = "500ms" }
      }
      step "recv" {
        role = "b" action = "recv" loop = 3 retry = 10 on_timeout = true
        expect { flags = ["X"] }
        timer { timeout = "50ms" }
      }
    }
    "#;
    let trace = run_ok(src, "retry_loop");
    assert_eq!(trace.iter().filter(|event| event.step == "send").count(), 3);
    assert_eq!(
        trace
            .iter()
            .filter(|event| event.step == "recv" && event.detail.starts_with("recv <-"))
            .count(),
        3
    );
    assert!(trace
        .iter()
        .any(|event| event.detail.contains("retry after failure")));
}

// ---- Imports, modules and output formats ----

#[test]
fn import_loads_relative_protocols_and_detects_cycles() {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("tcpform-import-{}-{unique}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("base.tcpf"),
        r#"protocol "base" { step "send" { role = "a" action = "send" } }"#,
    )
    .unwrap();
    fs::write(dir.join("main.tcpf"), "import \"base.tcpf\"\n").unwrap();
    let blocks = tcpform::load_blocks(dir.join("main.tcpf")).unwrap();
    let protocols = tcpform::model::interpret(&blocks).unwrap();
    assert_eq!(protocols[0].name, "base");

    fs::write(dir.join("a.tcpf"), "import \"b.tcpf\"\n").unwrap();
    fs::write(dir.join("b.tcpf"), "import \"a.tcpf\"\n").unwrap();
    let error = tcpform::load_blocks(dir.join("a.tcpf")).unwrap_err();
    assert!(error.contains("import cycle"), "{error}");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn module_namespaces_protocols_and_cases() {
    let src = r#"
    module "tcp" {
      module "v1" {
        protocol "ping" { step "send" { role = "a" action = "send" } }
        cases "ping" { case "ok" { vars {} expect = "pass" } }
      }
    }
    "#;
    let blocks = parse_file(src).unwrap();
    let protocols = tcpform::model::interpret(&blocks).unwrap();
    let cases = tcpform::model::interpret_cases(&blocks).unwrap();
    assert_eq!(protocols[0].name, "tcp.v1.ping");
    assert_eq!(cases[0].protocol, "tcp.v1.ping");
}

#[test]
fn json_diagram_and_pcap_outputs_are_well_formed() {
    let trace = run_ok(
        r#"
        protocol "output" {
          step "send" { role = "a" action = "send" to = "b" segment { flags = ["X"] } }
          step "recv" { role = "b" action = "recv" expect { flags = ["X"] } }
        }
        "#,
        "output",
    );
    let json = tcpform::output::trace_json("ok", None, &trace);
    assert!(json.starts_with("{\"status\":\"ok\""));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap()["schema_version"],
        "1.0"
    );
    assert!(json.contains("\"events\":["));
    let json_value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json_value["events"][0]["pcap_frame"], 1);
    assert!(json_value["events"][1]["pcap_frame"].is_null());

    let diagram = tcpform::output::sequence_diagram(&trace);
    assert!(diagram.starts_with("sequenceDiagram\n"));
    assert!(diagram.contains("a->>b"));

    let pcap = tcpform::output::trace_pcap(&trace);
    assert_eq!(&pcap[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    assert!(pcap.len() > 24);
}

#[test]
fn live_tcp_and_udp_preserve_structured_and_binary_messages() {
    let src = r#"
    protocol "live_wire" {
      step "request" {
        role = "client" action = "send"
        segment {
          flags = ["DATA"] hex = "deadbeef" stream = 7
          fields = { id = 42 nested = { enabled = true values = [1, 2, 3] } }
        }
      }
      step "receive" {
        role = "server" action = "recv"
        expect {
          flags = ["DATA"] hex = "deadbeef" stream = 7
          fields = { id = 42 }
        }
        timer { timeout = "500ms" }
      }
      step "response" {
        role = "server" action = "send"
        segment { flags = ["ACK"] fields = { ok = true } }
      }
      step "receive_response" {
        role = "client" action = "recv"
        expect { flags = ["ACK"] fields = { ok = true } }
        timer { timeout = "500ms" }
      }
    }
    "#;
    let protocol = load_protocol(src, "live_wire");
    for udp in [false, true] {
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&observed);
        let trace = Engine::new(protocol.clone())
            .unwrap()
            .run_live_with_observer(
                "127.0.0.1:0",
                udp,
                std::sync::Arc::new(move |_| {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }),
            )
            .unwrap_or_else(|error| {
                panic!("live {} failed: {error}", if udp { "UDP" } else { "TCP" })
            });
        assert_eq!(
            observed.load(std::sync::atomic::Ordering::SeqCst),
            trace.len()
        );
        assert!(trace.iter().all(|event| event.ok), "{trace:?}");
        assert_eq!(
            trace
                .iter()
                .filter(|event| event.action == tcpform::Action::Recv)
                .count(),
            2
        );
    }
}

#[test]
fn live_transport_rejects_protocols_without_two_roles() {
    let protocol = load_protocol(
        r#"protocol "one" { step "log" { role = "only" action = "log" } }"#,
        "one",
    );
    let error = Engine::new(protocol)
        .unwrap()
        .run_live("127.0.0.1:0", false)
        .unwrap_err();
    assert!(error.to_string().contains("exactly 2 roles"));
}

#[test]
fn cli_json_diagram_and_pcap_modes_work() {
    use std::process::Command;

    let binary = env!("CARGO_BIN_EXE_tcpform");
    let json = Command::new(binary)
        .args(["run", "--json", "examples/custom.tcpf", "ping_pong"])
        .output()
        .unwrap();
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let stdout = String::from_utf8(json.stdout).unwrap();
    assert!(stdout.starts_with("{\"status\":\"ok\""), "{stdout}");

    let json_path = std::env::temp_dir().join(format!("tcpform-{}-trace.json", std::process::id()));
    let json_file = Command::new(binary)
        .arg("run")
        .arg("--json-file")
        .arg(&json_path)
        .args(["examples/custom.tcpf", "ping_pong"])
        .output()
        .unwrap();
    assert!(json_file.status.success());
    assert!(json_file.stdout.is_empty());
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&json_path).unwrap()).unwrap();
    assert_eq!(document["status"], "ok");
    assert!(document["events"]
        .as_array()
        .is_some_and(|events| !events.is_empty()));
    std::fs::remove_file(json_path).unwrap();

    let cases = Command::new(binary)
        .args(["test", "--json", "examples/dns_cases.tcpf"])
        .output()
        .unwrap();
    assert!(cases.status.success());
    let stdout = String::from_utf8(cases.stdout).unwrap();
    assert!(stdout.starts_with("{\"passed\":"), "{stdout}");

    let diagram = Command::new(binary)
        .args(["run", "--diagram", "examples/custom.tcpf", "ping_pong"])
        .output()
        .unwrap();
    assert!(diagram.status.success());
    assert!(String::from_utf8(diagram.stdout)
        .unwrap()
        .starts_with("sequenceDiagram\n"));

    let pcap = std::env::temp_dir().join(format!("tcpform-{}.pcap", std::process::id()));
    let capture = Command::new(binary)
        .arg("run")
        .arg("--pcap")
        .arg(&pcap)
        .args(["examples/custom.tcpf", "ping_pong"])
        .output()
        .unwrap();
    assert!(capture.status.success());
    let bytes = std::fs::read(&pcap).unwrap();
    assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    std::fs::remove_file(pcap).unwrap();
}

#[test]
fn empty_binary_contains_and_empty_payload_are_strict() {
    let empty_contains = r#"
    protocol "bad" {
      step "recv" { role = "a" action = "recv" expect { fields = { data = { hex_contains = "" } } } }
    }
    "#;
    let blocks = parse_file(empty_contains).unwrap();
    assert!(interpret(&blocks).is_err());

    let exact_empty = r#"
    protocol "exact_empty" {
      step "send" { role = "a" action = "send" segment { payload = "not-empty" } }
      step "recv" {
        role = "b" action = "recv" expect { payload = "" }
        timer { timeout = "10ms" }
      }
    }
    "#;
    assert!(Engine::new(load_protocol(exact_empty, "exact_empty"))
        .unwrap()
        .run()
        .is_err());
}

#[test]
fn retransmit_uses_the_original_message_snapshot() {
    let src = r#"
    protocol "snapshot" {
      step "set_old" { role = "a" action = "set" set { value = "old" } }
      step "send" {
        role = "a" action = "send"
        segment { payload = "${value}" }
      }
      step "set_new" { role = "a" action = "set" set { value = "new" } }
      step "wait_ack" {
        role = "a" action = "recv" retransmit = 1
        expect { flags = ["ACK"] }
        timer { timeout = "300ms" }
      }
      step "lose_first" {
        role = "b" action = "drop" expect { payload = "old" }
        timer { timeout = "1s" }
      }
      step "receive_again" {
        role = "b" action = "recv" expect { payload = "old" }
        timer { timeout = "1s" }
      }
      step "ack" {
        role = "b" action = "ack" depends_on = ["receive_again"]
        segment { flags = ["ACK"] }
      }
    }
    "#;
    let trace = Engine::new(load_protocol(src, "snapshot"))
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(trace.iter().filter(|event| event.step == "send").count(), 2);
}

#[test]
fn invalid_dsl_types_duplicates_and_duration_overflow_are_rejected() {
    assert!(
        parse_file(r#"protocol "p" { step "s" { role="a" role="b" action="send" } }"#).is_err()
    );
    assert!(parse_file(
        r#"protocol "p" { step "s" { role="a" action="send" segment={ fields={x=1 x=2} } } }"#
    )
    .is_err());

    for source in [
        r#"protocol "p" { step "s" { role="a" action="send" retry="3" } }"#,
        r#"protocol "p" { step "s" { role="a" action="send" loop=1.5 } }"#,
        r#"protocol "p" { transport { reorder="true" } step "s" { role="a" action="send" } }"#,
        r#"protocol "p" { step "s" { role="a" action="send" timer { retransmit=2.5 } } }"#,
    ] {
        let blocks = parse_file(source).unwrap();
        assert!(interpret(&blocks).is_err(), "source should fail: {source}");
    }
    assert!(parse_duration_ms("18446744073709552s").is_err());

    let cases = parse_file(
        r#"
        protocol "p" { step "s" { role="a" action="send" } }
        cases "p" { case "bad" { expect="maybe" } }
        "#,
    )
    .unwrap();
    assert!(tcpform::model::interpret_cases(&cases).is_err());
}

#[test]
fn modules_and_imports_reject_ambiguity_and_preserve_namespace() {
    let unlabeled =
        parse_file(r#"module { protocol "p" { step "s" { role="a" action="send" } } }"#).unwrap();
    assert!(interpret(&unlabeled).is_err());

    let duplicate = parse_file(
        r#"
        protocol "p" { step "a" { role="a" action="send" } }
        protocol "p" { step "b" { role="b" action="send" } }
        "#,
    )
    .unwrap();
    assert!(interpret(&duplicate).is_err());

    let dir = std::env::temp_dir().join(format!("tcpform-module-import-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("child.tcpf"),
        r#"protocol "ping" { step "send" { role="a" action="send" } }"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.tcpf"),
        "module \"net\" { import \"child.tcpf\" }",
    )
    .unwrap();
    let blocks = tcpform::load_blocks(dir.join("main.tcpf")).unwrap();
    let protocols = interpret(&blocks).unwrap();
    assert_eq!(protocols[0].name, "net.ping");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn pcap_contains_ethernet_ipv4_tcp_and_wire_payload() {
    let trace = run_ok(
        r#"
        protocol "pcap" {
          step "send" { role="a" action="send" to="b" segment { flags=["PSH", "ACK"] payload="hello" } }
          step "recv" { role="b" action="recv" expect { payload="hello" } }
        }
        "#,
        "pcap",
    );
    let pcap = tcpform::output::trace_pcap(&trace);
    assert_eq!(&pcap[20..24], &1u32.to_le_bytes());
    assert_eq!(&pcap[52..54], &0x0800u16.to_be_bytes());
    assert!(pcap.windows(5).any(|window| window == b"hello"));
}

#[test]
fn cli_unknown_case_filter_fails() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"))
        .args(["test", "examples/dns_cases.tcpf", "does-not-exist"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no case suite found"));
}

#[test]
fn live_external_tcp_exchanges_raw_payloads() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").unwrap();
    });
    let protocol = load_protocol(
        r#"
        protocol "external" {
          step "send" { role="client" action="send" to="server" segment { payload="ping" } }
          step "recv" {
            role="client" action="recv" expect { from="server" payload="pong" }
            timer { timeout="500ms" }
          }
          step "peer" { role="server" action="log" }
        }
        "#,
        "external",
    );
    let trace = Engine::new(protocol)
        .unwrap()
        .run_external_tcp("client", &address.to_string(), false)
        .unwrap();
    server.join().unwrap();
    assert!(trace.iter().any(|event| event.step == "recv" && event.ok));
}

#[cfg(unix)]
#[test]
fn live_external_unix_socket_exchanges_framed_payloads() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    let path = std::env::temp_dir().join(format!("tcpform-{}-external.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).unwrap();
        let mut request = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(request, b"ping");
        stream.write_all(&4u32.to_be_bytes()).unwrap();
        stream.write_all(b"pong").unwrap();
    });
    let protocol = load_protocol(
        r#"protocol "external_unix" {
      step "send" { role="client" action="send" to="server" segment { payload="ping" } }
      step "recv" { role="client" action="recv" expect { from="server" payload="pong" } timer { timeout="500ms" } }
      step "peer" { role="server" action="log" }
    }"#,
        "external_unix",
    );
    let trace = Engine::new(protocol)
        .unwrap()
        .run_external_unix(
            "client",
            path.to_str().unwrap(),
            false,
            tcpform::Framing::LengthPrefix,
        )
        .unwrap();
    server.join().unwrap();
    let _ = std::fs::remove_file(path);
    assert!(trace.iter().any(|event| event.step == "recv" && event.ok));
}

#[test]
fn live_external_websocket_exchanges_binary_frames() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut socket = tungstenite::accept(stream).unwrap();
        assert_eq!(socket.read().unwrap().into_data().as_ref(), b"ping");
        socket
            .send(tungstenite::Message::Binary(b"pong".to_vec().into()))
            .unwrap();
        socket.close(None).unwrap();
    });
    let protocol = load_protocol(
        r#"protocol "external_ws" {
      step "send" { role="client" action="send" to="server" segment { payload="ping" } }
      step "recv" { role="client" action="recv" expect { from="server" payload="pong" } timer { timeout="1s" } }
      step "peer" { role="server" action="log" }
    }"#,
        "external_ws",
    );
    let trace = Engine::new(protocol)
        .unwrap()
        .run_external_websocket(
            "client",
            &format!("ws://{address}/protocol"),
            false,
            &tcpform::WebSocketOptions::default(),
        )
        .unwrap();
    server.join().unwrap();
    assert!(trace.iter().any(|event| event.step == "recv" && event.ok));
}

#[test]
fn live_external_quic_exchanges_messages_with_alpn_and_ca_validation() {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let directory = std::env::temp_dir().join(format!("tcpform-quic-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let cert = directory.join("cert.pem");
    let private = directory.join("key.pem");
    std::fs::write(&cert, certificate.pem()).unwrap();
    std::fs::write(&private, key.serialize_pem()).unwrap();
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    let protocol = load_protocol(
        r#"protocol "external_quic" {
      step "c_send" { role="client" action="send" to="server" segment { payload="ping" } }
      step "s_recv" { role="server" action="recv" expect { from="client" payload="ping" } timer { timeout="2s" } }
      step "s_send" { role="server" action="send" to="client" depends_on=["s_recv"] segment { payload="pong" } }
      step "c_recv" { role="client" action="recv" expect { from="server" payload="pong" } timer { timeout="2s" } }
    }"#,
        "external_quic",
    );
    let server_protocol = protocol.clone();
    let server_options = tcpform::TlsOptions {
        cert_file: Some(cert.display().to_string()),
        key_file: Some(private.display().to_string()),
        alpn_protocols: vec!["tcpform-test".into()],
        ..Default::default()
    };
    let server = std::thread::spawn(move || {
        Engine::new(server_protocol).unwrap().run_external_quic(
            "server",
            &address.to_string(),
            true,
            &server_options,
        )
    });
    std::thread::sleep(Duration::from_millis(40));
    let client_options = tcpform::TlsOptions {
        server_name: Some("localhost".into()),
        ca_file: Some(cert.display().to_string()),
        alpn_protocols: vec!["tcpform-test".into()],
        ..Default::default()
    };
    let client_result = Engine::new(protocol).unwrap().run_external_quic(
        "client",
        &address.to_string(),
        false,
        &client_options,
    );
    let server_result = server.join().unwrap();
    if client_result.is_err() || server_result.is_err() {
        panic!("client={client_result:?} server={server_result:?}");
    }
    let trace = client_result.unwrap();
    let server_trace = server_result.unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(trace.iter().any(|event| event.step == "c_recv" && event.ok));
    assert!(server_trace
        .iter()
        .any(|event| event.step == "s_recv" && event.ok));
}

#[test]
fn typed_failures_virtual_time_limits_and_retry_policy_work() {
    let timeout = Engine::new(load_protocol(
        r#"protocol "p" { step "r" { role="a" action="recv" timer { timeout="1ms" } } }"#,
        "p",
    ))
    .unwrap()
    .run()
    .unwrap_err();
    assert!(matches!(
        timeout,
        tcpform::EngineError::Runtime {
            kind: tcpform::FailureKind::Timeout,
            ..
        }
    ));

    let virtual_protocol = load_protocol(
        r#"
        protocol "virtual" {
          clock = "virtual"
          step "wait" { role="a" action="wait" timer { timeout="5s" } }
          step "log" { role="a" action="log" message="done" }
        }
        "#,
        "virtual",
    );
    let started = Instant::now();
    let trace = Engine::new(virtual_protocol.clone())
        .unwrap()
        .run()
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(100));
    assert!(trace.last().unwrap().timestamp_us >= 5_000_000);
    let baseline: Vec<_> = trace
        .iter()
        .map(|event| (event.step.clone(), event.timestamp_us))
        .collect();
    for _ in 0..5 {
        let repeated = Engine::new(virtual_protocol.clone())
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            repeated
                .iter()
                .map(|event| (event.step.clone(), event.timestamp_us))
                .collect::<Vec<_>>(),
            baseline
        );
    }

    let retry = load_protocol(
        r#"
        protocol "retry" {
          clock = "virtual"
          step "recv" {
            role="a" action="recv" retry=2 retry_on=["timeout"]
            retry_delay="10ms" retry_backoff=2 retry_max_delay="100ms" retry_jitter=0
            timer { timeout="1ms" }
          }
        }
        "#,
        "retry",
    );
    let error = Engine::new(retry).unwrap().run().unwrap_err();
    let tcpform::EngineError::Runtime { trace, .. } = error else {
        panic!("expected runtime error")
    };
    assert_eq!(
        trace
            .iter()
            .filter(|event| event.detail.contains("retry after failure"))
            .count(),
        2
    );

    let limited = parse_file(
        r#"
        protocol "limited" {
          limits { max_loop=2 max_retry=1 max_inbox=1 max_trace=2 max_payload=4 connect_timeout="1ms" }
          step "send" { role="a" action="send" loop=3 }
        }
        "#,
    )
    .unwrap();
    assert!(interpret(&limited)
        .unwrap_err()
        .to_string()
        .contains("max_loop"));

    let payload_limit = load_protocol(
        r#"
        protocol "payload_limit" {
          limits { max_payload=1 }
          step "send" { role="a" action="send" segment { payload="too large" } }
          step "peer" { role="b" action="log" }
        }
        "#,
        "payload_limit",
    );
    assert!(matches!(
        Engine::new(payload_limit).unwrap().run().unwrap_err(),
        tcpform::EngineError::Runtime {
            kind: tcpform::FailureKind::ResourceLimit,
            ..
        }
    ));

    let transport = tcpform::transport::Transport::new(&["known".to_string()]);
    let error = transport
        .send(
            "missing",
            tcpform::primitives::Message {
                from: "known".to_string(),
                flags: Vec::new(),
                seq: 0,
                ack: 0,
                payload: String::new(),
                raw: Vec::new(),
                window: 0,
                stream: None,
                fields: Default::default(),
            },
            0,
        )
        .unwrap_err();
    assert_eq!(error.kind, tcpform::TransportErrorKind::Transport);
}

#[test]
fn raw_ipv4_tcp_headers_can_be_built_matched_captured_and_fragmented() {
    let source = r#"
    protocol "raw_headers" {
      clock = "virtual"
      step "packet" {
        role="client" action="send_raw" to="server" mtu=68
        ethernet { source="02:00:00:00:00:01" destination="02:00:00:00:00:02" vlan_id=7 }
        ipv4 {
          source="192.0.2.10" destination="198.51.100.20"
          ttl="${ttl}" id=1234 options="8204aabb0204ccdd"
        }
        tcp {
          source_port=40000 destination_port=443 seq=1000 ack=77
          flags=["SYN", "ACK", "ECE"] window=32000
          options=[{mss=1460}, "nop", {window_scale=7}, "sack_permitted", {timestamp={value=10 echo=5}}]
        }
        segment { payload="hello raw headers and fragmentation" }
      }
      step "receive" {
        role="server" action="recv_raw"
        expect {
          payload="hello raw headers and fragmentation"
          flags=["SYN", "ACK"]
          fields={
            "ethernet.vlan_id"=7
            "ipv4.source"="192.0.2.10"
            "ipv4.ttl"=32
            "tcp.source_port"=40000
            "tcp.destination_port"=443
            "transport.checksum_valid"=true
          }
          capture { "tcp.seq"="captured_seq" }
        }
      }
      step "verify" {
        role="server" action="assert"
        assert { captured_seq=1000 }
      }
    }
    cases "raw_headers" { case "custom" { vars { ttl=32 } } }
    "#;
    let (protocol, cases) = load_cases(source, "raw_headers");
    let results = Engine::new(protocol).unwrap().run_cases(&cases);
    assert!(results[0].passed, "{:?}", results[0]);
    let sends: Vec<_> = results[0]
        .trace
        .iter()
        .filter(|event| event.action == tcpform::Action::SendRaw)
        .collect();
    assert!(sends.len() >= 2, "MTU should create fragments: {sends:?}");
    assert!(sends
        .iter()
        .all(|event| event.network == tcpform::NetworkProtocol::Raw));
    let decoded = tcpform::packet::decode_ethernet(&sends[0].wire_data).unwrap();
    assert_eq!(decoded.ipv4_checksum_valid, Some(true));

    let pcap = tcpform::output::trace_pcap(&results[0].trace);
    assert_eq!(&pcap[40..40 + sends[0].wire_data.len()], sends[0].wire_data);
}

#[test]
fn raw_header_schema_rejects_ambiguous_or_misplaced_sections() {
    for source in [
        r#"protocol "p" { step "s" { role="a" action="send_raw" ipv4 { source="1.1.1.1" destination="2.2.2.2" } ipv6 { source="::1" destination="::2" } } }"#,
        r#"protocol "p" { step "s" { role="a" action="send" ipv4 { source="1.1.1.1" destination="2.2.2.2" } } }"#,
        r#"protocol "p" { step "s" { role="a" action="send_raw" ipv4 { source="1.1.1.1" destination="2.2.2.2" typo=1 } } }"#,
    ] {
        let blocks = parse_file(source).unwrap();
        assert!(interpret(&blocks).is_err(), "source should fail: {source}");
    }
}

#[test]
fn raw_tcp_stateful_validates_handshake_and_rejects_invalid_start() {
    let protocol = load_protocol(
        r#"
        protocol "raw_state" {
          raw_tcp_stateful = true
          step "syn" {
            role="client" action="send_raw" to="server"
            ipv4 { source="192.0.2.1" destination="192.0.2.2" }
            tcp { source_port=1000 destination_port=80 seq=10 flags=["SYN"] }
          }
          step "recv_syn" {
            role="server" action="recv_raw" depends_on=["syn"]
            expect { from="client" flags=["SYN"] }
          }
          step "syn_ack" {
            role="server" action="send_raw" to="client" depends_on=["recv_syn"]
            ipv4 { source="192.0.2.2" destination="192.0.2.1" }
            tcp { source_port=80 destination_port=1000 seq=20 ack=11 flags=["SYN","ACK"] }
          }
          step "recv_syn_ack" {
            role="client" action="recv_raw" depends_on=["syn_ack"]
            expect { from="server" flags=["SYN","ACK"] }
          }
          step "ack" {
            role="client" action="send_raw" to="server" depends_on=["recv_syn_ack"]
            ipv4 { source="192.0.2.1" destination="192.0.2.2" }
            tcp { source_port=1000 destination_port=80 seq=11 ack=21 flags=["ACK"] }
          }
          step "recv_ack" {
            role="server" action="recv_raw" depends_on=["ack"]
            expect { from="client" flags=["ACK"] }
          }
        }
        "#,
        "raw_state",
    );
    let (_, states) = Engine::new(protocol)
        .unwrap()
        .run_with_vars(&Default::default())
        .unwrap();
    assert_eq!(
        states["client"].raw_tcp_state,
        tcpform::packet::TcpState::Established
    );
    assert_eq!(
        states["server"].raw_tcp_state,
        tcpform::packet::TcpState::Established
    );

    let invalid = load_protocol(
        r#"
        protocol "bad" {
          raw_tcp_stateful=true
          step "bad_ack" {
            role="a" action="send_raw" to="b"
            ipv4 { source="192.0.2.1" destination="192.0.2.2" }
            tcp { source_port=1 destination_port=2 flags=["ACK"] }
          }
          step "peer" { role="b" action="log" }
        }
        "#,
        "bad",
    );
    assert!(Engine::new(invalid).unwrap().run().is_err());
}

#[test]
fn raw_validation_is_static_and_unmatched_frames_remain_queued() {
    for source in [
        r#"protocol "bad" { step "s" { role="a" action="send_raw" mtu=0 ipv4 { source="1.1.1.1" destination="2.2.2.2" } } }"#,
        r#"protocol "bad" { step "s" { role="a" action="send_raw" ipv4 { source="1.1.1.1" destination="2.2.2.2" dscp=64 } } }"#,
    ] {
        let blocks = tcpform::parse_file(source).unwrap();
        let invalid = match tcpform::model::interpret(&blocks) {
            Err(_) => true,
            Ok(protocols) => Engine::new(protocols[0].clone()).is_err(),
        };
        assert!(invalid, "source should fail validation: {source}");
    }

    let protocol = load_protocol(
        r#"
        protocol "queue" {
          step "one" {
            role="a" action="send_raw" to="b"
            ipv4 { source="192.0.2.1" destination="192.0.2.2" }
            udp { source_port=1001 destination_port=9 }
          }
          step "two" {
            role="a" action="send_raw" to="b"
            ipv4 { source="192.0.2.1" destination="192.0.2.2" }
            udp { source_port=1002 destination_port=9 }
          }
          step "recv_two" {
            role="b" action="recv_raw" depends_on=["two"]
            expect { fields={ "udp.source_port"=1002 } }
          }
          step "recv_one" {
            role="b" action="recv_raw"
            expect { fields={ "udp.source_port"=1001 } }
          }
        }
        "#,
        "queue",
    );
    let trace = Engine::new(protocol).unwrap().run().unwrap();
    let pcap = tcpform::output::trace_pcap(&trace);
    assert_eq!(u32::from_le_bytes(pcap[20..24].try_into().unwrap()), 101);
}

#[test]
fn raw_retransmit_replays_every_fragment() {
    let protocol = load_protocol(
        r#"
        protocol "raw_retry" {
          clock="virtual"
          step "large" {
            role="client" action="send_raw" to="server" mtu=1280
            ipv6 { source="2001:db8::1" destination="2001:db8::2" }
            udp { source_port=1000 destination_port=1001 }
            segment { payload="abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz" }
          }
          step "wait_reply" {
            role="client" action="recv_raw" retransmit=1
            timer { timeout="1ms" }
            expect { from="server" }
          }
          step "peer" { role="server" action="log" }
        }
        "#,
        "raw_retry",
    );
    let error = Engine::new(protocol).unwrap().run().unwrap_err();
    let tcpform::EngineError::Runtime { trace, .. } = error else {
        panic!("expected runtime timeout")
    };
    let sends = trace
        .iter()
        .filter(|event| event.action == tcpform::Action::SendRaw)
        .count();
    assert!(
        sends >= 4 && sends % 2 == 0,
        "fragments were not replayed: {sends}"
    );
}

#[test]
fn docker_raw_lab_scenario_runs_and_container_policy_is_hardened() {
    for transport in ["udp", "tcp"] {
        let path = format!("examples/docker/raw_docker_{transport}.tcpf");
        let name = format!("docker_raw_{transport}");
        let blocks = tcpform::load_blocks(path).unwrap();
        let protocol = tcpform::model::interpret(&blocks)
            .unwrap()
            .into_iter()
            .find(|protocol| protocol.name == name)
            .unwrap();
        let trace = Engine::new(protocol).unwrap().run().unwrap();
        let request_step = if transport == "udp" {
            "receive_request"
        } else {
            "recv_request"
        };
        let response_step = if transport == "udp" {
            "receive_response"
        } else {
            "recv_response"
        };
        assert!(trace.iter().any(|event| {
            event.step == request_step && event.action == tcpform::Action::RecvRaw && event.ok
        }));
        assert!(trace.iter().any(|event| {
            event.step == response_step && event.action == tcpform::Action::RecvRaw && event.ok
        }));
    }

    let compose = std::fs::read_to_string("compose.raw-test.yml").unwrap();
    for required in [
        "internal: true",
        "cap_drop:",
        "- ALL",
        "cap_add:",
        "- NET_RAW",
        "- SETUID",
        "- SETGID",
        "read_only: true",
        "no-new-privileges:true",
        "TCPFORM_SCENARIO",
        "--allow-host-tcp",
        "--drop-uid",
        "--drop-gid",
        "--json-file",
        "target: dashboard",
        "user: \"0:0\"",
    ] {
        assert!(
            compose.contains(required),
            "missing Compose policy: {required}"
        );
    }
    assert!(!compose.contains("privileged:"));
    assert!(!compose.contains("network_mode: host"));

    let published = std::fs::read_to_string("compose.published.yml").unwrap();
    for required in [
        "ghcr.io/penguin425/tcpform:latest",
        "ghcr.io/penguin425/tcpform-dashboard:latest",
        "user: \"0:0\"",
        "cap_drop: [ALL]",
        "cap_add: [NET_RAW, SETUID, SETGID]",
        "internal: true",
    ] {
        assert!(
            published.contains(required),
            "missing published Compose policy: {required}"
        );
    }

    let container_release =
        std::fs::read_to_string(".github/workflows/container-release.yml").unwrap();
    for required in [
        "target: runtime",
        "target: dashboard",
        "platforms: linux/amd64,linux/arm64",
        "sbom: true",
        "provenance: mode=max",
        "cosign sign --yes",
        "DOCKERHUB_ENABLED",
    ] {
        assert!(
            container_release.contains(required),
            "missing container release policy: {required}"
        );
    }

    let dockerfile = std::fs::read_to_string("Dockerfile").unwrap();
    assert!(dockerfile.contains("--uid 10001"));
    assert!(dockerfile.contains("USER tcpform:tcpform"));
    assert!(dockerfile.contains("cargo build --locked --release"));
    for asset in [
        "order.js",
        "flow.js",
        "packet-view.js",
        "analysis-tools.js",
        "advanced-tools.js",
        "workbench-tools.js",
        "workbench-worker.js",
        "platform-ui.js",
    ] {
        assert!(
            dockerfile.contains(&format!(
                "COPY dashboard/{asset} /usr/share/nginx/html/{asset}"
            )),
            "dashboard image is missing {asset}"
        );
    }
    assert!(dockerfile.contains(
        "FROM nginx:1.31.2-alpine3.23-slim@sha256:dd722b8ee8794f3c273bfaf8b5351b0652a68ccd73c17e5f0d029857a58f25ef AS dashboard"
    ));
    let dependabot = std::fs::read_to_string(".github/dependabot.yml").unwrap();
    assert!(dependabot.contains("package-ecosystem: docker"));
    let dashboard = std::fs::read_to_string("dashboard/index.html").unwrap();
    assert!(dashboard.contains("tcpform Visualizer"));
    assert!(dashboard.contains("manifest.json"));
    assert!(dashboard.contains("depends_on"));

    let error_blocks = tcpform::load_blocks("examples/docker/error_flow.tcpf").unwrap();
    let error_protocol = tcpform::model::interpret(&error_blocks)
        .unwrap()
        .into_iter()
        .find(|protocol| protocol.name == "docker_error_flow")
        .unwrap();
    let error = Engine::new(error_protocol).unwrap().run().unwrap_err();
    assert!(matches!(
        error,
        tcpform::EngineError::Runtime {
            kind: tcpform::FailureKind::Timeout,
            ..
        }
    ));
    let lab_script = std::fs::read_to_string("scripts/docker-raw-test.sh").unwrap();
    assert!(lab_script.contains("Error: recv timeout"));
    assert!(lab_script.contains("error-trace.json"));
    assert!(lab_script.contains("Error: unknown dependency"));
    let invalid = tcpform::load_blocks("examples/docker/error_dependency.tcpf").unwrap();
    let invalid_protocol = tcpform::model::interpret(&invalid).unwrap().remove(0);
    assert!(Engine::new(invalid_protocol)
        .unwrap_err()
        .to_string()
        .contains("missing_handshake"));
}

#[test]
fn generic_visualizer_emits_plan_cases_headers_and_trace() {
    let binary = env!("CARGO_BIN_EXE_tcpform");
    let output = std::env::temp_dir().join(format!("tcpform-visualizer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&output);
    let result = std::process::Command::new(binary)
        .args(["visualize", "--output"])
        .arg(&output)
        .args(["examples/conditional_cases.tcpf", "conditional_delivery"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["roles"].as_array().unwrap().len(), 2);
    assert!(manifest["steps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|step| step["action"] == "drop" && !step["when"].is_null()));
    assert_eq!(manifest["cases"].as_array().unwrap().len(), 2);
    assert_eq!(manifest["cases"][0]["trace_file"], "case-0.json");
    assert_eq!(manifest["cases"][1]["trace_file"], "case-1.json");
    assert_eq!(manifest["trace_files"][0], "trace.json");
    assert!(output.join("index.html").is_file());
    let html = std::fs::read_to_string(output.join("index.html")).unwrap();
    assert!(html.contains("Role interaction flow"));
    assert!(html.contains("renderSequence"));
    assert!(html.contains("data-exchange-step"));
    assert!(output.join("flow.js").is_file());
    assert!(output.join("analysis-tools.js").is_file());
    assert!(output.join("advanced-tools.js").is_file());
    assert!(output.join("trace.json").is_file());
    assert!(output.join("case-0.json").is_file());
    assert!(output.join("case-1.json").is_file());

    let raw = std::process::Command::new(binary)
        .args(["plan", "--json", "examples/raw_headers.tcpf", "raw_udp"])
        .output()
        .unwrap();
    assert!(raw.status.success());
    let raw_manifest: serde_json::Value = serde_json::from_slice(&raw.stdout).unwrap();
    assert_eq!(
        raw_manifest["steps"][0]["headers"]["ipv6"]["hop_limit"],
        32.0
    );
    assert_eq!(
        raw_manifest["steps"][0]["headers"]["udp"]["destination_port"],
        53.0
    );
    let _ = std::fs::remove_dir_all(output);
}

#[test]
fn visualizer_server_accepts_tcpf_and_returns_cases() {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::process::{Command, Stdio};
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut child = Command::new(env!("CARGO_BIN_EXE_tcpform"))
        .args(["serve", "--bind", &address.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut socket = (0..100)
        .find_map(|_| {
            TcpStream::connect(address).ok().or_else(|| {
                std::thread::sleep(Duration::from_millis(10));
                None
            })
        })
        .expect("visualizer server should listen");
    let source = std::fs::read_to_string("examples/conditional_cases.tcpf").unwrap();
    let body = serde_json::json!({"source":source,"protocol":"conditional_delivery"}).to_string();
    write!(socket, "POST /api/visualize HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    socket.shutdown(Shutdown::Write).unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    let payload = response.split("\r\n\r\n").nth(1).unwrap();
    let document: serde_json::Value = serde_json::from_str(payload).unwrap();
    assert_eq!(
        document["manifest"]["protocol"]["name"],
        "conditional_delivery"
    );
    assert!(document["documents"]["case-0.json"].is_object());
    assert_eq!(document["documents"]["case-1.json"]["status"], "fail");

    let mut live = TcpStream::connect(address).unwrap();
    let live_body =
        serde_json::json!({"source":source,"protocol":"conditional_delivery","mode":"simulation"})
            .to_string();
    write!(live, "POST /api/live HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{live_body}", live_body.len()).unwrap();
    live.shutdown(Shutdown::Write).unwrap();
    let mut live_response = String::new();
    live.read_to_string(&mut live_response).unwrap();
    assert!(live_response.contains("Content-Type: text/event-stream"));
    assert!(live_response.contains("\"step\":\"send\""));
    assert!(live_response.contains("event: complete"));
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn engine_observer_receives_events_as_they_are_recorded() {
    let protocol = load_protocol(
        r#"protocol "observed" {
          step "send" { role="a" action="send" to="b" segment { hex="01" } }
          step "recv" { role="b" action="recv" depends_on=["send"] expect { hex="01" from="a" } }
        }"#,
        "observed",
    );
    let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&observed);
    let trace = Engine::new(protocol)
        .unwrap()
        .run_with_observer(std::sync::Arc::new(move |event| {
            sink.lock().unwrap().push((event.seq, event.step.clone()));
        }))
        .unwrap();
    let mut received = observed.lock().unwrap().clone();
    received.sort_by_key(|event| event.0);
    assert_eq!(received.len(), trace.len());
    assert_eq!(received[0].1, "send");
    assert_eq!(received[1].1, "recv");
}

#[test]
fn uploaded_source_bundle_resolves_imports_without_filesystem_writes() {
    let sources = std::collections::HashMap::from([
        (
            "main.tcpf".to_string(),
            "import \"lib/echo.tcpf\"".to_string(),
        ),
        (
            "lib/echo.tcpf".to_string(),
            r#"protocol "uploaded_echo" {
              step "send" { role="a" action="send" to="b" segment { hex="01" } }
              step "recv" { role="b" action="recv" depends_on=["send"] expect { hex="01" from="a" } }
            }"#
            .to_string(),
        ),
    ]);
    let blocks = tcpform::load_blocks_from_sources("main.tcpf", &sources).unwrap();
    let protocol = interpret(&blocks).unwrap().remove(0);
    assert_eq!(protocol.name, "uploaded_echo");
    assert!(Engine::new(protocol).unwrap().run().is_ok());
    assert!(tcpform::load_blocks_from_sources("../main.tcpf", &sources)
        .unwrap_err()
        .contains("escapes bundle"));
}

#[test]
fn custom_header_schema_is_validated_and_emitted_in_manifest() {
    let blocks = tcpform::load_blocks("examples/custom_header_schema.tcpf").unwrap();
    let protocol = interpret(&blocks).unwrap().remove(0);
    assert_eq!(protocol.header_schemas[0].name, "acme");
    assert_eq!(protocol.header_schemas[0].fields[0].name, "kind");
    let manifest: serde_json::Value = serde_json::from_str(
        &tcpform::output::visualization_manifest(&protocol, &[], &[]),
    )
    .unwrap();
    assert_eq!(
        manifest["header_schemas"][0]["fields"][1]["name"],
        "version"
    );
    assert!(Engine::new(protocol).unwrap().run().is_ok());

    let invalid = parse_file(
        r#"protocol "bad" {
          header_schema "x" { fields={ bad={ length=1 bit_offset=7 bits=2 } } }
          step "s" { role="a" action="send" }
        }"#,
    )
    .unwrap();
    assert!(interpret(&invalid)
        .unwrap_err()
        .to_string()
        .contains("bit range"));
}

#[test]
fn schema_source_import_alias_and_selection_are_enforced() {
    let unknown =
        parse_file(r#"protocol "p" { step "s" { role="a" action="send" typo=true } }"#).unwrap();
    assert!(interpret(&unknown)
        .unwrap_err()
        .to_string()
        .contains("unknown attribute"));

    let dir = std::env::temp_dir().join(format!("tcpform-alias-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("library.tcpf"),
        r#"
        protocol "keep" { step "s" { role="a" action="send" } }
        protocol "skip" { step "s" { role="a" action="send" } }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.tcpf"),
        r#"import "library.tcpf" { as="lib" only=["keep"] }"#,
    )
    .unwrap();
    let protocols = interpret(&tcpform::load_blocks(dir.join("main.tcpf")).unwrap()).unwrap();
    assert_eq!(protocols.len(), 1);
    assert_eq!(protocols[0].name, "lib.keep");

    std::fs::write(
        dir.join("twice.tcpf"),
        r#"
        import "library.tcpf" { as="first" only=["keep"] }
        import "library.tcpf" { as="second" only=["keep"] }
        "#,
    )
    .unwrap();
    let protocols = interpret(&tcpform::load_blocks(dir.join("twice.tcpf")).unwrap()).unwrap();
    let names: Vec<_> = protocols
        .iter()
        .map(|protocol| protocol.name.as_str())
        .collect();
    assert_eq!(names, ["first.keep", "second.keep"]);

    std::fs::write(
        dir.join("bad.tcpf"),
        "protocol \"bad\" { step \"s\" { role=\"a\" action=\"send\" unknown=1 } }",
    )
    .unwrap();
    let blocks = tcpform::load_blocks(dir.join("bad.tcpf")).unwrap();
    let error = interpret(&blocks).unwrap_err().to_string();
    assert!(error.contains("bad.tcpf:1:1"), "{error}");

    std::fs::write(dir.join("syntax.tcpf"), "protocol \"bad\" { step ").unwrap();
    let error = tcpform::load_blocks(dir.join("syntax.tcpf"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("syntax.tcpf:1:"), "{error}");

    std::fs::write(
        dir.join("graph.tcpf"),
        "protocol \"p\" { step \"s\" { role=\"a\" action=\"send\" depends_on=[\"missing\"] } }",
    )
    .unwrap();
    let protocols = interpret(&tcpform::load_blocks(dir.join("graph.tcpf")).unwrap()).unwrap();
    let error = Engine::new(protocols[0].clone()).unwrap_err().to_string();
    assert!(error.contains("graph.tcpf:1:"), "{error}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn detailed_case_json_fault_trace_and_pcapng_are_emitted() {
    let source = r#"
    protocol "case_detail" {
      transport { loss_rate=1 seed=1 }
      step "send" { role="a" action="send" segment { payload="x" } }
      step "peer" { role="b" action="log" }
    }
    cases "case_detail" { case "bad" { expect="pass" assert_a { send_count=2 } } }
    "#;
    let (protocol, cases) = load_cases(source, "case_detail");
    let results = Engine::new(protocol).unwrap().run_cases(&cases);
    assert!(!results[0].passed);
    assert_eq!(
        results[0].failure_kind,
        Some(tcpform::FailureKind::Assertion)
    );
    assert!(!results[0].assertion_failures.is_empty());
    assert!(results[0]
        .trace
        .iter()
        .any(|event| event.detail.contains("transport=dropped")));
    let json = tcpform::output::case_results_json(&[("case_detail", &results[0])]);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["schema_version"], "1.0");
    assert_eq!(parsed["results"][0]["failure_kind"], "assertion");
    assert!(parsed["results"][0]["trace"].is_array());

    let capture = tcpform::output::trace_pcapng(&results[0].trace);
    assert_eq!(&capture[..4], &0x0a0d0d0au32.to_le_bytes());
}

#[test]
fn junit_output_and_ci_case_selection_are_well_formed() {
    let source = r#"
    protocol "xml<&" {
      step "assert" { role="a" action="assert" assert { send_count=1 } }
    }
    cases "xml<&" { case "bad<&\"" { tags=["ci"] expect="pass" } }
    "#;
    let (protocol, cases) = load_cases(source, "xml<&");
    let results = Engine::new(protocol).unwrap().run_cases(&cases);
    let junit = tcpform::output::case_results_junit(&[("xml<&", &results[0])]);
    assert!(junit.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(junit.contains("tests=\"1\" failures=\"1\" errors=\"0\""));
    assert!(junit.contains("classname=\"xml&lt;&amp;\""));
    assert!(junit.contains("name=\"bad&lt;&amp;&quot;�\""));
    assert!(junit.contains("<property name=\"tcpform.tag\" value=\"ci\"/>"));
    assert!(junit.contains("<failure type=\"assertion\""));
    assert!(!junit.contains("bad<&"));
    let mut reader = quick_xml::Reader::from_str(&junit);
    loop {
        if reader.read_event().unwrap() == quick_xml::events::Event::Eof {
            break;
        }
    }

    let report = std::env::temp_dir().join(format!("tcpform-{}.xml", std::process::id()));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"))
        .args([
            "test",
            "--json",
            "--junit",
            report.to_str().unwrap(),
            "--jobs",
            "4",
            "--tag",
            "smoke",
            "--case",
            "valid|nxdomain",
            "--shard",
            "1/2",
            "examples/dns_cases.tcpf",
            "dns_lookup",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["results"].as_array().unwrap().len(), 1);
    assert_eq!(document["results"][0]["case"], "valid_a_record");
    assert_eq!(document["results"][0]["tags"][0], "smoke");
    let junit = std::fs::read_to_string(&report).unwrap();
    assert!(junit.contains("tests=\"1\" failures=\"0\""));
    std::fs::remove_file(report).unwrap();

    let second = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"))
        .args([
            "test",
            "--json",
            "--tag",
            "smoke",
            "--case",
            "valid|nxdomain",
            "--shard",
            "2/2",
            "examples/dns_cases.tcpf",
            "dns_lookup",
        ])
        .output()
        .unwrap();
    assert!(second.status.success());
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second["results"].as_array().unwrap().len(), 1);
    assert_eq!(second["results"][0]["case"], "nxdomain");

    let invalid = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"))
        .args(["test", "--shard", "0/2", "examples/dns_cases.tcpf"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("1-based"));
}

#[test]
fn cli_combines_json_diagram_and_capture_options() {
    let capture =
        std::env::temp_dir().join(format!("tcpform-combined-{}.pcap", std::process::id()));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"))
        .args(["run", "--json", "--diagram", "--pcap"])
        .arg(&capture)
        .args(["examples/custom.tcpf", "ping_pong"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"status\":\"ok\""));
    assert!(stdout.contains("sequenceDiagram"));
    assert!(std::fs::metadata(&capture).unwrap().len() > 24);
    std::fs::remove_file(capture).unwrap();
}

#[test]
fn live_external_length_framing_and_udp_exchange_datagrams() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};

    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_address = tcp.local_addr().unwrap();
    let tcp_server = std::thread::spawn(move || {
        let (mut stream, _) = tcp.accept().unwrap();
        let mut length = [0; 4];
        stream.read_exact(&mut length).unwrap();
        let mut request = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(request, b"ping");
        stream.write_all(&4u32.to_be_bytes()).unwrap();
        stream.write_all(b"pong").unwrap();
    });
    let protocol = load_protocol(
        r#"
        protocol "external" {
          step "send" { role="client" action="send" segment { payload="ping" } }
          step "recv" { role="client" action="recv" expect { payload="pong" } timer { timeout="1s" } }
          step "peer" { role="server" action="log" }
        }
        "#,
        "external",
    );
    Engine::new(protocol.clone())
        .unwrap()
        .run_external_tcp_framed(
            "client",
            &tcp_address.to_string(),
            false,
            tcpform::Framing::LengthPrefix,
        )
        .unwrap();
    tcp_server.join().unwrap();

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_address = udp.local_addr().unwrap();
    let udp_server = std::thread::spawn(move || {
        let mut request = [0; 16];
        let (length, peer) = udp.recv_from(&mut request).unwrap();
        assert_eq!(&request[..length], b"ping");
        udp.send_to(b"pong", peer).unwrap();
    });
    let trace = Engine::new(protocol)
        .unwrap()
        .run_external_udp("client", &udp_address.to_string(), false)
        .unwrap();
    udp_server.join().unwrap();
    assert!(trace
        .iter()
        .all(|event| event.network == tcpform::NetworkProtocol::Udp));
    let pcap = tcpform::output::trace_pcap(&trace);
    assert_eq!(pcap[63], 17, "IPv4 protocol must be UDP");
}

#[test]
fn live_external_tls_verifies_ca_and_exchanges_payloads() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let directory = std::env::temp_dir().join(format!("tcpform-tls-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let cert_path = directory.join("cert.pem");
    let key_path = directory.join("key.pem");
    std::fs::write(&cert_path, certificate.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let cert_der = certificate.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    let server = std::thread::spawn(move || {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut request = [0; 4];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").unwrap();
    });
    let protocol = load_protocol(
        r#"
        protocol "tls_external" {
          step "send" { role="client" action="send" segment { payload="ping" } }
          step "recv" { role="client" action="recv" expect { payload="pong" } timer { timeout="2s" } }
          step "peer" { role="server" action="log" }
        }
        "#,
        "tls_external",
    );
    let options = tcpform::TlsOptions {
        server_name: Some("localhost".to_string()),
        ca_file: Some(cert_path.display().to_string()),
        cert_file: None,
        key_file: None,
        ..tcpform::TlsOptions::default()
    };
    Engine::new(protocol)
        .unwrap()
        .run_external_tls(
            "client",
            &address.to_string(),
            false,
            tcpform::Framing::Raw,
            &options,
        )
        .unwrap();
    server.join().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn live_external_tls_listener_accepts_and_uses_configured_identity() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;

    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let directory = std::env::temp_dir().join(format!("tcpform-tls-listen-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let cert_path = directory.join("cert.pem");
    let key_path = directory.join("key.pem");
    std::fs::write(&cert_path, certificate.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let protocol = load_protocol(
        r#"
        protocol "tls_listener" {
          step "peer" { role="client" action="log" }
          step "recv" { role="server" action="recv" expect { payload="ping" } timer { timeout="2s" } }
          step "send" { role="server" action="send" segment { payload="pong" } }
        }
        "#,
        "tls_listener",
    );
    let options = tcpform::TlsOptions {
        server_name: None,
        ca_file: None,
        cert_file: Some(cert_path.display().to_string()),
        key_file: Some(key_path.display().to_string()),
        ..tcpform::TlsOptions::default()
    };
    let server = std::thread::spawn(move || {
        Engine::new(protocol).unwrap().run_external_tls(
            "server",
            &address.to_string(),
            true,
            tcpform::Framing::Raw,
            &options,
        )
    });

    let socket = (0..100)
        .find_map(|_| match TcpStream::connect(address) {
            Ok(socket) => Some(socket),
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
                None
            }
        })
        .expect("TLS listener did not start");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connection = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut stream = rustls::StreamOwned::new(connection, socket);
    stream.write_all(b"ping").unwrap();
    let mut response = [0; 4];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"pong");
    server.join().unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn explicit_protocol_states_are_enforced_and_exposed() {
    let protocol = load_protocol(
        r#"
        protocol "states" {
          step "connect" { role="client" action="log" from_state="initial" to_state="ready" }
          step "request" { role="client" action="log" from_state="ready" to_state="waiting" }
        }
        "#,
        "states",
    );
    let (_, states) = Engine::new(protocol)
        .unwrap()
        .run_with_vars(&Default::default())
        .unwrap();
    assert_eq!(states["client"].protocol_state, "waiting");

    let invalid = load_protocol(
        r#"
        protocol "invalid_state" {
          step "request" { role="client" action="log" from_state="ready" }
        }
        "#,
        "invalid_state",
    );
    let error = Engine::new(invalid).unwrap().run().unwrap_err();
    match error {
        tcpform::EngineError::Runtime { kind, message, .. } => {
            assert_eq!(kind, tcpform::FailureKind::Validation);
            assert!(message.contains("requires `ready`"), "{message}");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn deterministic_disconnect_and_delay_spike_faults_work() {
    let disconnected = load_protocol(
        r#"
        protocol "disconnect" {
          transport { disconnect_nth=1 }
          step "send" { role="client" action="send" to="server" segment { payload="x" } }
          step "server" { role="server" action="log" }
        }
        "#,
        "disconnect",
    );
    let error = Engine::new(disconnected).unwrap().run().unwrap_err();
    assert!(
        error.to_string().contains("simulated link disconnect"),
        "{error:?}"
    );

    let delayed = load_protocol(
        r#"
        protocol "spike" {
          clock = "virtual"
          transport { delay_spike_nth=1 delay_spike="25ms" }
          step "send" { role="client" action="send" to="server" segment { payload="x" } }
          step "recv" { role="server" action="recv" depends_on=["send"] expect { payload="x" } }
        }
        "#,
        "spike",
    );
    let trace = Engine::new(delayed).unwrap().run().unwrap();
    assert!(
        trace.iter().any(|event| event.timestamp_us >= 25_000),
        "{trace:?}"
    );
}

#[test]
fn maximum_runtime_limit_stops_virtual_executions() {
    let protocol = load_protocol(
        r#"
        protocol "runtime_limit" {
          clock = "virtual"
          limits { max_runtime="10ms" }
          step "wait" { role="client" action="wait" timer { timeout="11ms" } }
          step "after" { role="client" action="log" }
        }
        "#,
        "runtime_limit",
    );
    let error = Engine::new(protocol).unwrap().run().unwrap_err();
    match error {
        tcpform::EngineError::Runtime {
            kind,
            message,
            trace,
            ..
        } => {
            assert_eq!(kind, tcpform::FailureKind::ResourceLimit);
            assert!(message.contains("max_runtime"), "{message}");
            assert!(!trace.iter().any(|event| event.step == "after"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn nat_mtu_blackhole_and_port_exhaustion_faults_are_enforced() {
    let nat = load_protocol(
        r#"
        protocol "nat" {
          transport { nat_source_ip="203.0.113.10" nat_source_port=40000 }
          step "send" { role="inside" action="send" to="outside" segment { fields={ "ipv4.source"="10.0.0.2" "tcp.source_port"=1234 } } }
          step "recv" { role="outside" action="recv" depends_on=["send"] expect { fields={ "ipv4.source"="203.0.113.10" "tcp.source_port"=40000 "nat.original_role"="inside" } } }
        }
        "#,
        "nat",
    );
    assert!(Engine::new(nat).unwrap().run().is_ok());

    let blackhole = load_protocol(
        r#"
        protocol "blackhole" {
          clock="virtual"
          transport { mtu=2 mtu_blackhole=true }
          step "send" { role="a" action="send" to="b" segment { payload="oversized" } }
          step "recv" { role="b" action="recv" depends_on=["send"] expect { payload="oversized" } timer { timeout="1ms" } }
        }
        "#,
        "blackhole",
    );
    let error = Engine::new(blackhole).unwrap().run().unwrap_err();
    assert!(matches!(
        error,
        tcpform::EngineError::Runtime {
            kind: tcpform::FailureKind::Timeout,
            ..
        }
    ));

    let exhausted = load_protocol(
        r#"
        protocol "ports" {
          transport { port_capacity=1 }
          step "one" { role="a" action="send" to="b" segment { payload="1" } }
          step "two" { role="a" action="send" to="b" segment { payload="2" } }
          step "peer" { role="b" action="log" }
        }
        "#,
        "ports",
    );
    let error = Engine::new(exhausted).unwrap().run().unwrap_err();
    assert!(error.to_string().contains("port capacity"), "{error:?}");
}

#[cfg(unix)]
#[test]
fn dsl_plugin_actions_matchers_decoders_and_reports_execute_in_process_isolation() {
    let directory = std::env::temp_dir().join(format!("tcpform-plugin-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let manifest_path = directory.join("plugin.json");
    let manifest = serde_json::json!({
        "id":"fixture","version":"1.0.0","protocol_version":"1.0",
        "command":"/bin/sh",
        "args":["-c","read request; printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"matched\":true,\"detail\":\"fixture\",\"vars\":{\"answer\":42},\"fields\":{\"decoded.kind\":\"demo\"}}}'"],
        "capabilities":{"actions":["custom"],"matchers":["custom"],"decoders":["custom"],"reports":["custom"]},
        "timeout_ms":1000,"max_output_bytes":4096
    });
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let path = manifest_path.display().to_string().replace('\\', "\\\\");
    let source = format!(
        r#"
        protocol "plugins" {{
          step "action" {{ role="client" action="plugin" plugin {{ manifest="{path}" kind="action" name="custom" input={{ value=1 }} }} }}
          step "match" {{ role="client" action="plugin" plugin {{ manifest="{path}" kind="matcher" name="custom" input={{ actual="${{answer}}" }} }} }}
          step "decode" {{ role="client" action="plugin" plugin {{ manifest="{path}" kind="decoder" name="custom" }} }}
          step "report" {{ role="client" action="plugin" plugin {{ manifest="{path}" kind="report" name="custom" }} }}
        }}
        "#
    );
    let protocol = load_protocol(&source, "plugins");
    let disabled = Engine::new(protocol.clone()).unwrap().run().unwrap_err();
    assert!(disabled
        .to_string()
        .contains("plugin execution is disabled"));
    let (trace, states) = Engine::new(protocol)
        .unwrap()
        .with_plugins_enabled(true)
        .run_with_vars(&Default::default())
        .unwrap();
    assert_eq!(
        trace
            .iter()
            .filter(|event| event.action == tcpform::Action::Plugin)
            .count(),
        4
    );
    assert_eq!(states["client"].vars["answer"], Value::Number(42.0));
    assert_eq!(
        states["client"].last_recv_fields["decoded.kind"],
        Value::String("demo".into())
    );
    assert!(states["client"].vars.contains_key("plugin.report"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn connection_setup_failures_are_deterministic_and_typed() {
    for (failure, expected) in [
        ("dns", "DNS resolution"),
        ("refused", "connection refused"),
        ("tls_handshake", "TLS handshake"),
    ] {
        let source = format!(
            r#"protocol "failure" {{
              transport {{ connect_failure="{failure}" }}
              step "open" {{ role="client" action="open" }}
            }}"#
        );
        let error = Engine::new(load_protocol(&source, "failure"))
            .unwrap()
            .run()
            .unwrap_err();
        match error {
            tcpform::EngineError::Runtime { kind, message, .. } => {
                assert_eq!(kind, tcpform::FailureKind::Transport);
                assert!(message.contains(expected), "{message}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}

#[test]
fn bandwidth_can_change_at_a_deterministic_send_ordinal() {
    let protocol = load_protocol(
        r#"
        protocol "dynamic_bandwidth" {
          clock="virtual"
          transport { bandwidth_bps=8000 bandwidth_after_nth=2 bandwidth_after_bps=8 }
          step "one" { role="a" action="send" to="b" segment { payload="x" } }
          step "recv_one" { role="b" action="recv" depends_on=["one"] expect { payload="x" } }
          step "two" { role="a" action="send" to="b" segment { payload="y" } }
          step "recv_two" { role="b" action="recv" depends_on=["two"] expect { payload="y" } }
        }
        "#,
        "dynamic_bandwidth",
    );
    let trace = Engine::new(protocol).unwrap().run().unwrap();
    let second = trace.iter().find(|event| event.step == "two").unwrap();
    assert!(second.timestamp_us >= 1_001_000, "{trace:?}");
}

#[test]
fn differential_report_detects_observable_implementation_divergence() {
    let protocol = load_protocol(include_str!("../examples/http1_0.tcpf"), "http1_0");
    let left = Engine::new(protocol).unwrap().run().unwrap();
    let (same, equal) = tcpform::output::differential_trace_json(&left, &left);
    assert!(equal);
    assert!(same.contains("\"equal\": true"));
    let mut right = left.clone();
    let event = right
        .iter_mut()
        .find(|event| !event.wire_data.is_empty())
        .unwrap();
    event.wire_data[0] ^= 0x20;
    let (different, equal) = tcpform::output::differential_trace_json(&left, &right);
    assert!(!equal);
    assert!(different.contains("\"differences\""));
}

#[test]
fn differential_cli_drives_two_external_implementations_with_the_same_protocol() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn server(response: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(response).unwrap();
        });
        (address, handle)
    }

    let directory = std::env::temp_dir().join(format!("tcpform-diff-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("protocol.tcpf");
    std::fs::write(
        &source,
        r#"protocol "diff" {
          step "send" { role="client" action="send" to="server" segment { payload="ping" } }
          step "recv" { role="client" action="recv" depends_on=["send"] expect { from="server" } timer { timeout="2s" } }
          step "peer" { role="server" action="log" }
        }"#,
    )
    .unwrap();
    let (left, left_server) = server(b"pong");
    let (right, right_server) = server(b"pang");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"))
        .args([
            "differential",
            "--left",
            &left,
            "--right",
            &right,
            "--role",
            "client",
            source.to_str().unwrap(),
            "diff",
        ])
        .output()
        .unwrap();
    left_server.join().unwrap();
    right_server.join().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("\"equal\": false"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn conformance_cli_writes_reports_for_conformant_and_nonconformant_targets() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn server(response: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(response).unwrap();
        });
        (address, handle)
    }

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("tcpform-conformance-{unique}"));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("protocol.tcpf");
    std::fs::write(
        &source,
        r#"protocol "service" {
          step "send" { role="client" action="send" to="server" segment { payload="ping" } }
          step "recv" { role="client" action="recv" depends_on=["send"] timer { timeout="2s" } expect { from="server" payload="pong" } }
          step "peer" { role="server" action="log" }
        }"#,
    )
    .unwrap();

    for (response, conformant) in [(b"pong" as &'static [u8], true), (b"pang", false)] {
        let (address, handle) = server(response);
        let suffix = if conformant { "pass" } else { "fail" };
        let json = directory.join(format!("{suffix}.json"));
        let markdown = directory.join(format!("{suffix}.md"));
        let junit = directory.join(format!("{suffix}.xml"));
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"))
            .args(["conformance", "--connect", &address, "--role", "client"])
            .arg("--json")
            .arg(&json)
            .arg("--markdown")
            .arg(&markdown)
            .arg("--junit")
            .arg(&junit)
            .arg(&source)
            .arg("service")
            .output()
            .unwrap();
        handle.join().unwrap();
        assert_eq!(
            output.status.success(),
            conformant,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
        assert_eq!(
            report["status"],
            if conformant {
                "conformant"
            } else {
                "nonconformant"
            }
        );
        assert_eq!(report["summary"]["total"], 2);
        assert!(std::fs::read_to_string(&markdown)
            .unwrap()
            .contains("protocol conformance report"));
        assert!(std::fs::read_to_string(&junit)
            .unwrap()
            .contains("<testsuite"));
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn interoperability_cli_builds_a_matrix_for_three_external_implementations() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn server(response: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(response).unwrap();
        });
        (address, handle)
    }

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("tcpform-interop-{unique}"));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("protocol.tcpf");
    std::fs::write(
        &source,
        r#"protocol "interop" {
          step "send" { role="client" action="send" to="server" segment { payload="ping" } }
          step "recv" { role="client" action="recv" depends_on=["send"] expect { from="server" } timer { timeout="2s" } }
          step "peer" { role="server" action="log" }
        }"#,
    )
    .unwrap();

    for (responses, interoperable) in [
        ([b"pong" as &'static [u8], b"pong", b"pong"], true),
        ([b"pong" as &'static [u8], b"pong", b"pang"], false),
    ] {
        let servers = responses.map(server);
        let config = directory.join(if interoperable {
            "same-targets.json"
        } else {
            "different-targets.json"
        });
        let implementations = servers
            .iter()
            .enumerate()
            .map(|(index, (address, _))| {
                serde_json::json!({"name": format!("implementation-{}", index + 1), "address": address})
            })
            .collect::<Vec<_>>();
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({"implementations": implementations})).unwrap(),
        )
        .unwrap();
        let suffix = if interoperable { "same" } else { "different" };
        let json = directory.join(format!("{suffix}.json"));
        let markdown = directory.join(format!("{suffix}.md"));
        let junit = directory.join(format!("{suffix}.xml"));
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_tcpform"))
            .arg("interop")
            .arg("--targets")
            .arg(&config)
            .args(["--role", "client"])
            .arg("--json")
            .arg(&json)
            .arg("--markdown")
            .arg(&markdown)
            .arg("--junit")
            .arg(&junit)
            .arg(&source)
            .arg("interop")
            .output()
            .unwrap();
        for (_, handle) in servers {
            handle.join().unwrap();
        }
        assert_eq!(
            output.status.success(),
            interoperable,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
        assert_eq!(report["implementations"].as_array().unwrap().len(), 3);
        assert_eq!(report["comparisons"].as_array().unwrap().len(), 3);
        assert_eq!(report["compatibility_matrix"].as_array().unwrap().len(), 3);
        assert_eq!(
            report["status"],
            if interoperable {
                "interoperable"
            } else {
                "not_interoperable"
            }
        );
        assert!(std::fs::read_to_string(&markdown)
            .unwrap()
            .contains("Compatibility matrix"));
        assert!(std::fs::read_to_string(&junit)
            .unwrap()
            .contains("tests=\"3\""));
    }
    std::fs::remove_dir_all(directory).unwrap();
}
