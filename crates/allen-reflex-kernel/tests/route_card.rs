//! Route card parser (aienos#399): what the image accepts, and that the card cannot carry
//! capabilities or expected answers.
use allen_reflex_kernel::card::{self, Kind};

fn card(lines: &str) -> Vec<u8> {
    format!("AIENALR1 QUALIF-ALLEN-ROUTE\n{lines}").into_bytes()
}

#[test]
fn accepts_owner_guest_flags_and_escapes() {
    let b = card("R1|owner:7|C|<u> what can you do?\nR2|guest:9|-|<u> tell me my notes\nR3|owner:1|PC|<u> approve it%2C please\n");
    assert_eq!(card::kind(&b), Some(Kind::Route));
    let r = card::parse_route(&b).unwrap();
    assert_eq!(r.len(), 3);
    assert!(r[0].owner && r[0].consent && !r[0].pending && r[0].session == 7);
    assert!(!r[1].owner && !r[1].consent && !r[1].pending);
    assert!(r[2].consent && r[2].pending);
}

#[test]
fn refuses_malformed_lines() {
    for bad in [
        "R1|admin:1|-|<u> hi\n",                      // unknown speaker
        "R1|owner:0|-|<u> hi\n",                      // session 0
        "R1|owner:1234567890|-|<u> hi\n",             // session too long
        "R1|owner:1|X|<u> hi\n",                      // unknown flag (e.g. a capability claim)
        "R1|owner:1|CC|<u> hi\n",                     // repeated flag
        "R1|owner:1||<u> hi\n",                       // empty flags
        "R1|owner:1|-|\n",                            // empty turns
        "R1|owner:1|<u> hi\n",                        // missing field
        "R1|owner:1|-|<u> hi\nR1|guest:1|-|<u> hi\n", // duplicate id
    ] {
        assert!(card::parse_route(&card(bad)).is_err(), "accepted: {bad}");
    }
}

#[test]
fn kinds_do_not_mix() {
    let exam = b"AIENALX1 QUALIF-ALLEN-EXAM\nX1|<u> hi\n".to_vec();
    assert_eq!(card::kind(&exam), Some(Kind::Exam));
    assert!(card::parse_route(&exam).is_err());
    assert!(card::parse(&card("R1|owner:1|-|<u> hi\n")).is_err());
    assert_eq!(card::kind(b"AIENALR1 QUALIF-ALLEN-ROUTEX\n"), None);
}
