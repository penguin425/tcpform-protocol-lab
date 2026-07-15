use proptest::prelude::*;

proptest! {
    #[test]
    fn arbitrary_bytes_round_trip_hex(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = tcpform::bytes_to_hex(&bytes);
        prop_assert_eq!(tcpform::parse_hex(&encoded).unwrap(), bytes);
    }

    #[test]
    fn parser_never_panics_on_arbitrary_utf8(source in ".{0,2048}") {
        let result = std::panic::catch_unwind(|| tcpform::parse_file(&source));
        prop_assert!(result.is_ok());
    }

    #[test]
    fn packet_decoders_never_panic_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let ip = std::panic::catch_unwind(|| tcpform::packet::decode_ip(&bytes));
        let ethernet = std::panic::catch_unwind(|| tcpform::packet::decode_ethernet(&bytes));
        prop_assert!(ip.is_ok());
        prop_assert!(ethernet.is_ok());
    }

    #[test]
    fn millisecond_durations_preserve_values(value in 0u64..=u32::MAX as u64) {
        let source = format!("{value}ms");
        prop_assert_eq!(tcpform::model::parse_duration_ms(&source).unwrap(), value);
    }
}

#[test]
fn concurrent_transport_stress_preserves_every_message() {
    use std::sync::Arc;

    let roles = vec!["receiver".to_string()];
    let transport = Arc::new(tcpform::transport::Transport::new(&roles));
    let mut workers = Vec::new();
    for worker_id in 0..8 {
        let transport = Arc::clone(&transport);
        workers.push(std::thread::spawn(move || {
            for sequence in 0..250 {
                transport
                    .send(
                        "receiver",
                        tcpform::primitives::Message {
                            from: format!("sender-{worker_id}"),
                            flags: Vec::new(),
                            seq: worker_id * 250 + sequence,
                            ack: 0,
                            payload: "x".to_string(),
                            raw: Vec::new(),
                            window: 0,
                            stream: None,
                            fields: Default::default(),
                        },
                        0,
                    )
                    .unwrap();
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    let inbox = transport.inbox("receiver").unwrap();
    assert_eq!(inbox.0.lock().unwrap().len(), 2000);
}
