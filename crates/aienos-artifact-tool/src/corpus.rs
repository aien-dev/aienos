//! P2-7 negative-test corpus: deterministic Binary Artifact v0 cases that the
//! kernel must refuse at a stable stage with a stable reason, or admit and
//! then contain. Every case starts from one valid, TEST-ONLY-signed baseline
//! and changes exactly one thing. Debug builds with `seed0b-test-signing`
//! only; never part of the kernel or release tooling.

use std::error::Error;
use std::fs;
use std::path::Path;

use aienos_artifact::signature::{artifact_signature_message, signer_fingerprint};
use aienos_artifact::verify::parse_and_identify;
use ed25519_dalek::{Signer, SigningKey};

use crate::{pack_bytes, CapabilityManifest, Manifest, ResourceManifest};

/// Expected kernel outcome for one case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expect {
    /// Refused before execution: kernel stage name, reason name, §7.3 code.
    Rejected {
        stage: &'static str,
        reason: &'static str,
        code: u16,
    },
    /// Admitted; `exec` is the kernel report's `exec=` value.
    Admitted { exec: &'static str, caps: usize },
}

pub struct Case {
    pub name: &'static str,
    pub what: &'static str,
    pub bytes: Vec<u8>,
    pub expect: Expect,
}

/// RFC 8032 TEST 3 seed: a well-formed Ed25519 key no anchor set trusts.
const UNTRUSTED_SEED: [u8; 32] = [
    0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
    0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
];

// AArch64 instruction words (checked against GNU as).
const MOV_X0_0: u32 = 0xd280_0000;
const MOV_X8_2: u32 = 0xd280_0048;
const MOV_X8_6: u32 = 0xd280_00c8;
const MOV_X8_99: u32 = 0xd280_0c68;
const SVC_0: u32 = 0xd400_0001;
const B_SELF: u32 = 0x1400_0000;
const BR_X2: u32 = 0xd61f_0040;
// SUB X9, SP, #16. SP starts at the stack top (the guard page) when no caps
// are granted, so the target must be below it to land on a mapped stack page.
const SUB_X9_SP_16: u32 = 0xd100_43e9;
const BR_X9: u32 = 0xd61f_0120;

// Canonical offsets (ADR 0014 §2).
const SECTION_CODE: usize = 128;
const SECTION_DATA: usize = 160;
const CAPS: usize = 192;
const CAP_SIZE: usize = 48;

fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn exit0() -> Vec<u8> {
    words(&[MOV_X0_0, MOV_X8_2, SVC_0, B_SELF])
}

fn seed_read(rights: u32) -> CapabilityManifest {
    CapabilityManifest {
        resource_kind: 3,
        resource_id: 1,
        rights,
        bounds_kind: 1,
        max_operations: 4,
        max_bytes: 32,
        byte_offset: 0,
        byte_length: 32,
    }
}

fn resources(code: u32, data: u32, stack: u32, caps: u16, syscalls: u32) -> ResourceManifest {
    ResourceManifest {
        code_pages: code,
        data_pages: data,
        stack_pages: stack,
        max_capabilities: caps,
        ipc_messages: 0,
        ipc_bytes: 0,
        cpu_ticks: 100_000_000,
        elapsed_ticks: 100_000_000,
        syscall_count: syscalls,
    }
}

fn manifest(caps: Vec<CapabilityManifest>, res: ResourceManifest) -> Manifest {
    Manifest {
        entry_offset: 0,
        capabilities: caps,
        resources: res,
    }
}

/// Sign packed bytes in place with `seed` (valid Ed25519, any key).
fn sign_with(bytes: &mut [u8], seed: &[u8; 32]) -> Result<(), Box<dyn Error>> {
    let id = parse_and_identify(bytes)
        .map_err(|e| format!("baseline does not parse: {e:?}"))?
        .artifact_id;
    let key = SigningKey::from_bytes(seed);
    let start = bytes.len() - 100;
    bytes[start + 4..start + 36]
        .copy_from_slice(&signer_fingerprint(&key.verifying_key().to_bytes()));
    bytes[start + 36..].copy_from_slice(&key.sign(&artifact_signature_message(&id)).to_bytes());
    Ok(())
}

fn signed(m: &Manifest, code: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = pack_bytes(m, code, data)?;
    sign_with(&mut bytes, &crate::test_only_seed())?;
    Ok(bytes)
}

fn baseline() -> Result<Vec<u8>, Box<dyn Error>> {
    signed(
        &manifest(vec![seed_read(1)], resources(1, 1, 1, 1, 8)),
        &exit0(),
        b"BASELINE",
    )
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn rejected(stage: &'static str, reason: &'static str, code: u16) -> Expect {
    Expect::Rejected {
        stage,
        reason,
        code,
    }
}

fn verified(reason: &'static str, code: u16) -> Expect {
    rejected("verified", reason, code)
}

/// The whole corpus, in a fixed order with fixed names.
pub fn corpus() -> Result<Vec<Case>, Box<dyn Error>> {
    let base = baseline()?;
    let payload = get32(&base, 56) as usize;
    let resource = CAPS + CAP_SIZE;
    let sig = base.len() - 100;
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = base.clone();
        f(&mut b);
        b
    };
    let v = vec![
        Case {
            name: "H01-BAD-MAGIC.AIEN",
            what: "magic is not AIENART\\0",
            bytes: with(&|b| b[0] = b'X'),
            expect: verified("BadMagic", 1),
        },
        Case {
            name: "H02-VERSION.AIEN",
            what: "format_version 1 (unsupported)",
            bytes: with(&|b| put16(b, 8, 1)),
            expect: verified("UnsupportedVersion", 2),
        },
        Case {
            name: "H03-TARGET.AIEN",
            what: "target_arch 2 (not AArch64 LE)",
            bytes: with(&|b| put16(b, 12, 2)),
            expect: verified("WrongTarget", 3),
        },
        Case {
            name: "H04-ABI.AIEN",
            what: "abi_version 2 (not ABI v1)",
            bytes: with(&|b| put16(b, 14, 2)),
            expect: verified("WrongAbi", 4),
        },
        Case {
            name: "H05-TRUNCATED.AIEN",
            what: "last 10 bytes cut off",
            bytes: with(&|b| b.truncate(b.len() - 10)),
            expect: verified("WrongLength", 7),
        },
        Case {
            name: "H06-TRAILING.AIEN",
            what: "one byte appended after the signature block",
            bytes: with(&|b| b.push(0)),
            expect: verified("WrongLength", 7),
        },
        Case {
            name: "H07-TOTAL-LENGTH.AIEN",
            what: "total_length field one larger than the file",
            bytes: with(&|b| {
                let t = get32(b, 20);
                put32(b, 20, t + 1)
            }),
            expect: verified("WrongLength", 7),
        },
        Case {
            name: "H08-OFFSET-OVERFLOW.AIEN",
            what: "payload_length 0xffffffff (offset + length overflows)",
            bytes: with(&|b| put32(b, 60, u32::MAX)),
            expect: verified("ResourceLimit", 14),
        },
        Case {
            name: "H09-SECTION-OVERLAP.AIEN",
            what: "data section starts inside the code section",
            bytes: with(&|b| put32(b, SECTION_DATA + 8, 4)),
            expect: verified("BadSection", 11),
        },
        Case {
            name: "H10-ENTRY-OUTSIDE.AIEN",
            what: "entry_offset beyond the code bytes",
            bytes: with(&|b| put32(b, 36, 0x1000)),
            expect: verified("BadEntryPoint", 12),
        },
        Case {
            name: "H11-PAYLOAD-MUTATED.AIEN",
            what: "one code byte changed after signing",
            bytes: with(&|b| b[payload] ^= 0x01),
            expect: verified("BadSignature", 18),
        },
        Case {
            name: "H12-CAPS-MUTATED.AIEN",
            what: "requested rights READ -> READ|WRITE after signing",
            bytes: with(&|b| put32(b, CAPS + 8, 3)),
            expect: verified("BadSignature", 18),
        },
        Case {
            name: "H13-ENVELOPE-MUTATED.AIEN",
            what: "stack_pages 1 -> 2 after signing",
            bytes: with(&|b| put32(b, resource + 8, 2)),
            expect: verified("BadSignature", 18),
        },
        Case {
            name: "H14-SIGNATURE-MUTATED.AIEN",
            what: "one signature byte changed",
            bytes: with(&|b| b[sig + 40] ^= 0x01),
            expect: verified("BadSignature", 18),
        },
        Case {
            name: "H15-UNKNOWN-SIGNER.AIEN",
            what: "valid Ed25519 signature by a key no anchor trusts",
            bytes: {
                let mut b = base.clone();
                sign_with(&mut b, &UNTRUSTED_SEED)?;
                b
            },
            expect: verified("UntrustedSigner", 17),
        },
        Case {
            name: "H16-SIG-FORMAT.AIEN",
            what: "signature block algorithm 2",
            bytes: with(&|b| put16(b, sig, 2)),
            expect: verified("BadSignatureFormat", 15),
        },
        Case {
            name: "H17-RESERVED-HEADER.AIEN",
            what: "reserved header byte 100 nonzero",
            bytes: with(&|b| b[100] = 1),
            expect: verified("ReservedNonZero", 8),
        },
        Case {
            name: "H18-RIGHTS-UNKNOWN.AIEN",
            what: "requested rights bit 6 (undefined)",
            bytes: with(&|b| put32(b, CAPS + 8, 1 | (1 << 6))),
            expect: verified("MalformedCapability", 13),
        },
        Case {
            name: "H19-CAP-COUNT.AIEN",
            what: "capability_count 17 (> 16)",
            bytes: with(&|b| put16(b, 44, 17)),
            expect: verified("ResourceLimit", 14),
        },
        Case {
            name: "H20-ENVELOPE-LIMIT.AIEN",
            what: "code_pages 65 (> 64); refused while parsing, before signature checks",
            bytes: {
                let mut b = base.clone();
                put32(&mut b, resource, 65);
                b
            },
            expect: verified("ResourceLimit", 14),
        },
        Case {
            name: "H21-LARGEST-ENVELOPE.AIEN",
            what: "largest valid envelope: 64 code, 64 data, 16 stack pages",
            bytes: signed(
                &manifest(vec![], resources(64, 64, 16, 0, 4)),
                &exit0(),
                b"LARGEST!",
            )?,
            expect: Expect::Admitted {
                exec: "exited:0x0",
                caps: 0,
            },
        },
        Case {
            name: "H22-WX-SECTION.AIEN",
            what: "code section permissions R|W|X",
            bytes: with(&|b| put16(b, SECTION_CODE + 2, 0b111)),
            expect: verified("BadSection", 11),
        },
        Case {
            name: "H23-EXEC-DATA.AIEN",
            what: "branches into its own data page (mapped RW+NX)",
            bytes: signed(
                &manifest(vec![], resources(1, 1, 1, 0, 4)),
                &words(&[BR_X2]),
                b"DATAPAGE",
            )?,
            expect: Expect::Admitted {
                exec: "fault:exec-nx",
                caps: 0,
            },
        },
        Case {
            name: "H24-EXEC-STACK.AIEN",
            what: "branches onto its own stack (mapped RW+NX)",
            bytes: signed(
                &manifest(vec![], resources(1, 1, 1, 0, 4)),
                &words(&[SUB_X9_SP_16, BR_X9]),
                b"STACKPAG",
            )?,
            expect: Expect::Admitted {
                exec: "fault:exec-nx",
                caps: 0,
            },
        },
        Case {
            name: "H25-BAD-SYSCALL.AIEN",
            what: "invokes undefined syscall 99",
            bytes: signed(
                &manifest(vec![], resources(1, 1, 1, 0, 4)),
                &words(&[MOV_X8_99, SVC_0, B_SELF]),
                b"BADSYSCL",
            )?,
            expect: Expect::Admitted {
                exec: "bad-syscall:99",
                caps: 0,
            },
        },
        Case {
            name: "H26-SYSCALL-BUDGET.AIEN",
            what: "third syscall exceeds syscall_count 2",
            bytes: signed(
                &manifest(vec![], resources(1, 1, 1, 0, 2)),
                &words(&[
                    MOV_X0_0, MOV_X8_6, SVC_0, SVC_0, SVC_0, MOV_X8_2, SVC_0, B_SELF,
                ]),
                b"OVERRUN!",
            )?,
            expect: Expect::Admitted {
                exec: "resource-overrun",
                caps: 0,
            },
        },
        Case {
            name: "H27-POLICY-IPC.AIEN",
            what: "requests 1 IPC message; local policy allows none",
            bytes: {
                let mut r = resources(1, 1, 1, 1, 8);
                r.ipc_messages = 1;
                r.ipc_bytes = 64;
                signed(&manifest(vec![seed_read(1)], r), &exit0(), b"IPCWANTS")?
            },
            expect: rejected("authorized", "ResourceLimit", 14),
        },
        Case {
            name: "H28-WRITE-ONLY-REQUEST.AIEN",
            what: "requests only WRITE on the SEED object; policy grants READ at most",
            bytes: signed(
                &manifest(vec![seed_read(2)], resources(1, 1, 1, 1, 8)),
                &exit0(),
                b"WRITEREQ",
            )?,
            expect: Expect::Admitted {
                exec: "exited:0x0",
                caps: 0,
            },
        },
        Case {
            name: "H29-READ-WRITE-REQUEST.AIEN",
            what: "requests READ|WRITE; granted READ only",
            bytes: signed(
                &manifest(vec![seed_read(3)], resources(1, 1, 1, 1, 8)),
                &exit0(),
                b"RWREQUST",
            )?,
            expect: Expect::Admitted {
                exec: "exited:0x0",
                caps: 1,
            },
        },
    ];
    Ok(v)
}

/// `negative-corpus OUT_DIR`: write every case and `expected.txt`.
pub fn write_corpus(out: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(out)?;
    let mut expected = String::new();
    for case in corpus()? {
        fs::write(out.join(case.name), &case.bytes)?;
        match &case.expect {
            Expect::Rejected {
                stage,
                reason,
                code,
            } => expected.push_str(&format!(
                "{} rejected {stage} {reason} {code:#x} # {}\n",
                case.name, case.what
            )),
            Expect::Admitted { exec, caps } => expected.push_str(&format!(
                "{} admitted {exec} {caps} # {}\n",
                case.name, case.what
            )),
        }
    }
    fs::write(out.join("expected.txt"), expected)?;
    println!("NEGATIVE_CORPUS: TEST ONLY SEED-0B qualification inputs written");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aienos_artifact::signature::seed0b_test_anchor::Seed0bTestAnchorSet;
    use aienos_artifact::signature::{
        ArtifactVerifier, ConfiguredArtifactVerifier, Ed25519Verifier,
    };

    #[test]
    fn corpus_is_deterministic_and_names_are_unique_and_sorted() {
        let a = corpus().unwrap();
        let b = corpus().unwrap();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(&b) {
            assert_eq!(x.name, y.name);
            assert_eq!(x.bytes, y.bytes, "{}", x.name);
        }
        let names: Vec<_> = a.iter().map(|c| c.name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(names, sorted);
        assert!(a
            .iter()
            .all(|c| c.name.len() <= 32 && c.name.ends_with(".AIEN")));
    }

    /// Every "verified"-stage expectation is exactly what the shared
    /// parser/verifier returns; every other case authenticates.
    #[test]
    fn verifier_stage_expectations_match_the_shared_verifier() {
        let anchors = Seed0bTestAnchorSet;
        let verifier = ConfiguredArtifactVerifier::new(&anchors, Ed25519Verifier);
        for case in corpus().unwrap() {
            let result = verifier.verify(&case.bytes);
            match case.expect {
                Expect::Rejected {
                    stage: "verified",
                    reason,
                    code,
                } => {
                    let error = result.expect_err(case.name);
                    assert_eq!(format!("{error:?}"), reason, "{}", case.name);
                    assert_eq!(error as u16, code, "{}", case.name);
                }
                _ => assert!(result.is_ok(), "{} must authenticate", case.name),
            }
        }
    }

    #[test]
    fn baseline_is_valid_and_each_case_differs_from_it() {
        let base = baseline().unwrap();
        let anchors = Seed0bTestAnchorSet;
        let verifier = ConfiguredArtifactVerifier::new(&anchors, Ed25519Verifier);
        assert!(verifier.verify(&base).is_ok());
        for case in corpus().unwrap() {
            assert_ne!(case.bytes, base, "{}", case.name);
        }
    }
}
