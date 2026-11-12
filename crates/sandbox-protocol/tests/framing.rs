use sandbox_protocol::{
    SANDBOX_RELAY_PROTOCOL_VERSION, StreamBinaryMetadata, StreamKind, encode_binary_frame,
    parse_binary_frame,
};

#[test]
fn binary_frame_round_trip() {
    let metadata = StreamBinaryMetadata {
        r#type: StreamKind::Chunk,
        stream_id: "str-1".into(),
        operation_id: "op-1".into(),
        generation: 1,
        attempt: 1,
        offset: None,
        gap_start: None,
        sequence: 42,
        flags: None,
        final_chunk: Some(true),
    };
    let body = b"hello sandbox";
    let frame = encode_binary_frame(&metadata, body).expect("encode");
    let (decoded_meta, decoded_body) = parse_binary_frame(&frame).expect("decode");
    assert_eq!(decoded_meta, metadata);
    assert_eq!(decoded_body, body);
}

#[test]
fn protocol_version_is_stable() {
    assert_eq!(SANDBOX_RELAY_PROTOCOL_VERSION, "1.0");
}
