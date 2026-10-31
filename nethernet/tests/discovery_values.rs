use nethernet::error::SignalErrorCode;
use nethernet::protocol::{
    codec::{NetherCodec, write_varint32},
    packet::discovery::{MessagePacket, ServerData},
};

#[test]
fn lan_message_retains_non_utf8_bytes() {
    let wire = [
        &2u64.to_le_bytes()[..],
        &3u32.to_le_bytes(),
        &[0xff, 0xfe, b'!'],
    ]
    .concat();
    let message = MessagePacket::deserialize(&mut wire.as_slice()).unwrap();
    let mut encoded = Vec::new();
    message.serialize(&mut encoded).unwrap();
    assert_eq!(encoded, wire);
}

#[test]
fn server_data_retains_signed_numeric_fields() {
    let mut wire = vec![7, 0, 0, 0, 0, 0, 0];
    write_varint32(&mut wire, 300).unwrap();
    wire.extend_from_slice(&[0, 0, 1, 1, 0]);
    write_varint32(&mut wire, -1).unwrap();
    let data = ServerData::decode(&wire).unwrap();
    assert_eq!(i64::from(data.game_type), 300);
    assert_eq!(i64::from(data.connection_type), -1);
    assert_eq!(data.encode().unwrap(), wire);
    assert_eq!(
        ServerData::from_json(&data.to_json()).unwrap().game_type,
        data.game_type
    );
}

#[test]
fn signaling_error_codes_retain_every_supported_value() {
    for code in 0..=37 {
        assert_eq!(u32::from(SignalErrorCode::from(code)), code);
    }
    assert_eq!(
        SignalErrorCode::from(38),
        SignalErrorCode::SignalingUnknownError
    );
}
