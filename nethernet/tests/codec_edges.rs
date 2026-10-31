use bytes::Bytes;
use nethernet::protocol::{codec::read_varuint32, message::Message};

#[test]
fn varuint32_refuses_overflow_without_requiring_canonical_encoding() {
    for last in 0x10..=0x7f {
        assert!(
            read_varuint32(&mut &[0x80, 0x80, 0x80, 0x80, last][..]).is_err(),
            "{last}"
        );
    }
    assert_eq!(
        read_varuint32(&mut &[0xff, 0xff, 0xff, 0xff, 0x0f][..]).unwrap(),
        u32::MAX
    );
    assert_eq!(
        read_varuint32(&mut &[0x80, 0x80, 0x80, 0x80, 0][..]).unwrap(),
        0
    );
}

#[test]
fn empty_application_bodies_are_refused_before_encoding() {
    assert!(Message::encode_segments(b"", 0).is_err());
    assert!(Message::encode_unreliable(Bytes::new(), 0).is_err());
}
