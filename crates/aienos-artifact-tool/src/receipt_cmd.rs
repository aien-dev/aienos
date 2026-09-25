//! `receipt` subcommands: inspect, cross-check against the artifact the
//! host supplied, TEST-ONLY signing, and verification (ADR 0014 §7).

use std::error::Error;
use std::fs;

use aienos_artifact::canonical::{requested_capability_digest, resource_envelope_digest};
use aienos_artifact::receipt::{
    decode, is_unsigned, receipt_digest, verify, Receipt, ReceiptDecision, RECEIPT_SIZE,
};
use aienos_artifact::signature::Ed25519Verifier;
use aienos_artifact::verify::parse_and_identify;

use crate::hex;

pub const USAGE: &str = "receipt inspect FILE.bin | receipt check EMITTED.bin ARTIFACT.aien | receipt from-hex HEX OUT.bin | receipt sign-test IN.bin OUT.bin | receipt verify FILE.bin";

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match (args.first().map(String::as_str), args.len()) {
        (Some("inspect"), 2) => inspect(&read(&args[1])?),
        (Some("check"), 3) => check(&read(&args[1])?, &fs::read(&args[2])?),
        (Some("from-hex"), 3) => from_hex(&args[1], &args[2]),
        (Some("sign-test"), 3) => sign_test(&read(&args[1])?, &args[2]),
        (Some("verify"), 2) => verify_file(&read(&args[1])?),
        _ => Err(USAGE.into()),
    }
}

fn read(path: &str) -> Result<[u8; RECEIPT_SIZE], Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let record: [u8; RECEIPT_SIZE] = bytes.as_slice().try_into().map_err(|_| {
        format!(
            "receipt must be exactly {RECEIPT_SIZE} bytes, got {}",
            bytes.len()
        )
    })?;
    Ok(record)
}

fn decoded(record: &[u8; RECEIPT_SIZE]) -> Result<Receipt, Box<dyn Error>> {
    decode(record).map_err(|e| format!("receipt rejected: {e:?}").into())
}

fn inspect(record: &[u8; RECEIPT_SIZE]) -> Result<(), Box<dyn Error>> {
    let r = decoded(record)?;
    println!("RECEIPT_DIGEST: {}", hex(&receipt_digest(record)));
    println!("SIGNED: {}", if is_unsigned(record) { "no" } else { "yes" });
    println!("DECISION: {:?}", r.decision);
    println!("TIER: {}", r.tier.label());
    println!("SEQUENCE: {}", r.sequence);
    println!(
        "REJECTION: stage={} reason={:#x}",
        r.rejection_stage, r.rejection_reason
    );
    println!(
        "EXECUTION: status={:?} exit={} syscalls={} reads_ok={} denials={}",
        r.execution_status, r.exit_status, r.syscalls, r.object_reads_ok, r.denials
    );
    println!("RESULT_FLAGS: {:#04x}", r.result_flags);
    println!("FRAMES_RESERVED: {}", r.frames_reserved);
    for (name, digest) in [
        ("ARTIFACT_ID", &r.artifact_id),
        ("PAYLOAD_SHA256", &r.payload_digest),
        ("ARTIFACT_SIGNER", &r.artifact_signer_fingerprint),
        ("POLICY_DIGEST", &r.policy_digest),
        ("REQUESTED_CAPS_DIGEST", &r.requested_capability_digest),
        ("GRANTED_CAPS_DIGEST", &r.granted_capability_digest),
        ("RESOURCE_ENVELOPE_DIGEST", &r.resource_envelope_digest),
        ("VERIFIER_IDENTITY", &r.verifier_identity),
    ] {
        println!("{name}: {}", hex(digest));
    }
    Ok(())
}

/// A kernel-emitted record must be unsigned and must bind exactly the
/// artifact the host supplied. Fields the failing stage had not computed may
/// be zero; any nonzero identity field must match.
fn check(record: &[u8; RECEIPT_SIZE], artifact: &[u8]) -> Result<(), Box<dyn Error>> {
    if !is_unsigned(record) {
        return Err("kernel-emitted receipts must be unsigned".into());
    }
    let r = decoded(record)?;
    let admitted = r.decision == ReceiptDecision::Admitted;
    let expected = match parse_and_identify(artifact) {
        Ok(identified) => Some((
            *identified.artifact_id.as_bytes(),
            identified.payload_digest,
            *identified.artifact.signer_fingerprint,
            requested_capability_digest(identified.artifact.capability_request_bytes),
            resource_envelope_digest(identified.artifact.resource_envelope_bytes),
        )),
        Err(_) => None,
    };
    let fields = [
        ("artifact_id", r.artifact_id),
        ("payload_digest", r.payload_digest),
        ("artifact_signer_fingerprint", r.artifact_signer_fingerprint),
        ("requested_capability_digest", r.requested_capability_digest),
        ("resource_envelope_digest", r.resource_envelope_digest),
    ];
    match expected {
        None => {
            if admitted {
                return Err("admitted receipt for an artifact the host cannot parse".into());
            }
            for (name, value) in fields {
                if value != [0; 32] {
                    return Err(format!("{name} must be zero for an unparseable artifact").into());
                }
            }
        }
        Some((id, payload, signer, requested, resources)) => {
            for ((name, value), want) in fields
                .into_iter()
                .zip([id, payload, signer, requested, resources])
            {
                let zero_allowed = !admitted;
                if value != want && !(zero_allowed && value == [0; 32]) {
                    return Err(format!("{name} does not bind the supplied artifact").into());
                }
            }
            if admitted && r.granted_capability_digest == [0; 32] {
                return Err("admitted receipt without a granted-capability digest".into());
            }
        }
    }
    println!(
        "RECEIPT_CHECK: PASS digest={} decision={:?} tier={} stage={} reason={:#x} status={:?} exit={} syscalls={} reads_ok={} denials={} flags={:#04x}",
        hex(&receipt_digest(record)),
        r.decision,
        r.tier.label(),
        r.rejection_stage,
        r.rejection_reason,
        r.execution_status,
        r.exit_status,
        r.syscalls,
        r.object_reads_ok,
        r.denials,
        r.result_flags
    );
    Ok(())
}

fn from_hex(text: &str, out: &str) -> Result<(), Box<dyn Error>> {
    let text = text.trim();
    if text.len() != RECEIPT_SIZE * 2
        || !text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("expected {} lowercase hex characters", RECEIPT_SIZE * 2).into());
    }
    let bytes: Vec<u8> = (0..RECEIPT_SIZE)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16))
        .collect::<Result<_, _>>()?;
    fs::write(out, bytes)?;
    println!("FROM_HEX: PASS");
    Ok(())
}

fn sign_test(record: &[u8; RECEIPT_SIZE], out: &str) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "seed0b-test-signing")]
    {
        use aienos_artifact::receipt::{sign, signature_message};
        use aienos_artifact::signature::ReceiptSigner;
        use aienos_crypto::sha256::{hash, Digest};
        use ed25519_dalek::{Signer, SigningKey};

        struct TestReceiptKey(SigningKey);
        impl ReceiptSigner for TestReceiptKey {
            fn signer_fingerprint(&self) -> Digest {
                hash(&self.0.verifying_key().to_bytes())
            }
            fn sign_receipt_digest(
                &self,
                digest: &Digest,
            ) -> Result<[u8; 64], aienos_artifact::ArtifactError> {
                Ok(self.0.sign(&signature_message(digest)).to_bytes())
            }
        }

        let key = TestReceiptKey(SigningKey::from_bytes(&test_only_receipt_seed()));
        let mut signed = *record;
        sign(&mut signed, &key).map_err(|e| format!("cannot sign receipt: {e:?}"))?;
        fs::write(out, signed)?;
        println!("RECEIPT_SIGN: TEST ONLY SEED-0B QUALIFICATION RECEIPT KEY");
        println!(
            "RECEIPT_SIGNER_FINGERPRINT: {}",
            hex(&key.signer_fingerprint())
        );
        Ok(())
    }
    #[cfg(not(feature = "seed0b-test-signing"))]
    {
        let _ = (record, out);
        Err("receipt signing requires explicit feature seed0b-test-signing; production receipt keys are not available".into())
    }
}

fn verify_file(record: &[u8; RECEIPT_SIZE]) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "seed0b-test-signing")]
    {
        use aienos_artifact::receipt::seed0b_test_receipt_anchor::Seed0bTestReceiptAnchorSet;
        let r = verify(record, &Seed0bTestReceiptAnchorSet, &Ed25519Verifier)
            .map_err(|e| format!("receipt verification failed: {e:?}"))?;
        println!(
            "RECEIPT_VERIFY: PASS digest={} decision={:?} tier={} trust=SEED-0B-TEST-ONLY",
            hex(&receipt_digest(record)),
            r.decision,
            r.tier.label()
        );
        Ok(())
    }
    #[cfg(not(feature = "seed0b-test-signing"))]
    {
        verify(
            record,
            &aienos_artifact::receipt::EmptyReceiptAnchorSet,
            &Ed25519Verifier,
        )
        .map_err(|e| {
            format!("receipt verification failed: {e:?} (no production receipt anchors before M5)")
        })?;
        Ok(())
    }
}

#[cfg(feature = "seed0b-test-signing")]
fn test_only_receipt_seed() -> [u8; 32] {
    // RFC 8032 TEST 2 seed. TEST-ONLY SEED-0B receipt key; never a secret.
    [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use aienos_artifact::receipt::{
        encode, receipt_nonce, ExecutionStatusCode, QualificationTier, RESULT_RECLAIMED,
    };

    fn artifact() -> Vec<u8> {
        let manifest: crate::Manifest = serde_json::from_str(
            r#"{"entry_offset":0,"capabilities":[{"resource_kind":3,"resource_id":1,"rights":1,"bounds_kind":1,"max_operations":4,"max_bytes":32,"byte_offset":0,"byte_length":32}],"resources":{"code_pages":1,"data_pages":1,"stack_pages":1,"max_capabilities":1,"ipc_messages":0,"ipc_bytes":0,"cpu_ticks":1000,"elapsed_ticks":1000,"syscall_count":8}}"#,
        )
        .unwrap();
        crate::pack_bytes(&manifest, &[0xc0, 0x03, 0x5f, 0xd6], b"DATA").unwrap()
    }

    fn binding(bytes: &[u8], decision: ReceiptDecision) -> Receipt {
        let identified = parse_and_identify(bytes).unwrap();
        let verifier_identity = [7u8; 32];
        let admitted = decision == ReceiptDecision::Admitted;
        Receipt {
            flags: 0,
            decision,
            tier: QualificationTier::Seed0bQemu,
            sequence: 1,
            nonce: receipt_nonce(&verifier_identity, 1),
            observed_time_ns: 0,
            execution_status: if admitted {
                ExecutionStatusCode::Exited
            } else {
                ExecutionStatusCode::NotRun
            },
            exit_status: 0,
            result_flags: RESULT_RECLAIMED,
            rejection_stage: if admitted { 0 } else { 3 },
            rejection_reason: if admitted { 0 } else { 17 },
            syscalls: 0,
            object_reads_ok: 0,
            denials: 0,
            frames_reserved: 0,
            artifact_id: *identified.artifact_id.as_bytes(),
            payload_digest: identified.payload_digest,
            artifact_signer_fingerprint: *identified.artifact.signer_fingerprint,
            policy_digest: [1; 32],
            requested_capability_digest: requested_capability_digest(
                identified.artifact.capability_request_bytes,
            ),
            granted_capability_digest: if admitted { [2; 32] } else { [0; 32] },
            resource_envelope_digest: resource_envelope_digest(
                identified.artifact.resource_envelope_bytes,
            ),
            verifier_identity,
            machine_id_digest: [0; 32],
            generation: 0,
            context_id: 0,
        }
    }

    #[test]
    fn check_accepts_only_receipts_that_bind_the_supplied_artifact() {
        let bytes = artifact();
        let admitted = binding(&bytes, ReceiptDecision::Admitted);
        assert!(check(&encode(&admitted), &bytes).is_ok());
        let rejected = Receipt {
            artifact_signer_fingerprint: [0; 32],
            ..binding(&bytes, ReceiptDecision::Rejected)
        };
        assert!(check(&encode(&rejected), &bytes).is_ok());
        let wrong_id = Receipt {
            artifact_id: [9; 32],
            ..admitted
        };
        assert!(check(&encode(&wrong_id), &bytes).is_err());
        let zero_in_admitted = Receipt {
            payload_digest: [0; 32],
            ..admitted
        };
        assert!(check(&encode(&zero_in_admitted), &bytes).is_err());
        let no_grants = Receipt {
            granted_capability_digest: [0; 32],
            ..admitted
        };
        assert!(check(&encode(&no_grants), &bytes).is_err());
        let mut signed_bytes = encode(&admitted);
        signed_bytes[400] = 1;
        assert!(check(&signed_bytes, &bytes).is_err());
        let mut other = bytes.clone();
        let last = other.len() - 101;
        other[last] ^= 1;
        assert!(check(&encode(&admitted), &other).is_err());
    }
}
