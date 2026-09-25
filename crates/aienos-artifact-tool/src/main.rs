use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

use aienos_artifact::canonical::payload_digest;
use aienos_artifact::capability::CAPABILITY_RECORD_SIZE;
use aienos_artifact::format::{
    Artifact, ABI_V1, CAPABILITY_TABLE_OFFSET, HEADER_SIZE, MAX_ARTIFACT_SIZE, MAX_PAYLOAD_SIZE,
    SECTION_RECORD_SIZE, SECTION_TABLE_OFFSET, SIGNATURE_ALGORITHM_ED25519, SIGNATURE_BLOCK_SIZE,
    TARGET_AARCH64_LE,
};
use aienos_artifact::resource::RESOURCE_ENVELOPE_SIZE;
#[cfg(not(feature = "seed0b-test-signing"))]
use aienos_artifact::signature::ProductionTrustAnchorSet;
#[cfg(feature = "seed0b-test-signing")]
use aienos_artifact::signature::{artifact_signature_message, signer_fingerprint};
use aienos_artifact::signature::{
    ArtifactVerifier, ConfiguredArtifactVerifier, Ed25519Verifier,
    SIGNATURE_BLOCK_SIZE as SIG_BLOCK,
};
use aienos_artifact::verify::parse_and_identify;
#[cfg(feature = "seed0b-test-signing")]
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;

#[cfg(all(feature = "seed0b-test-signing", not(debug_assertions)))]
compile_error!("the SEED-0B test signing identity is unavailable to release builds");

#[cfg(feature = "seed0b-test-signing")]
mod corpus;
mod receipt_cmd;

const PAGE_SIZE: u32 = 4096;
const SIGNATURE_OFFSET_HEADER: usize = 64;
const SIGNATURE_LENGTH_HEADER: usize = 68;
const SIGNATURE_ALGORITHM_HEADER: usize = 70;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    entry_offset: u32,
    capabilities: Vec<CapabilityManifest>,
    resources: ResourceManifest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityManifest {
    resource_kind: u16,
    resource_id: u32,
    rights: u32,
    bounds_kind: u32,
    max_operations: u32,
    max_bytes: u64,
    byte_offset: u64,
    byte_length: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceManifest {
    code_pages: u32,
    data_pages: u32,
    stack_pages: u32,
    max_capabilities: u16,
    ipc_messages: u32,
    ipc_bytes: u32,
    cpu_ticks: u64,
    elapsed_ticks: u64,
    syscall_count: u32,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("aienos-artifact-tool: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("pack") if args.len() == 6 => {
            let manifest: Manifest = serde_json::from_slice(&fs::read(&args[2])?)?;
            let code = fs::read(&args[3])?;
            let data = fs::read(&args[4])?;
            let bytes = pack_bytes(&manifest, &code, &data)?;
            fs::write(&args[5], bytes)?;
            println!("PACK: PASS");
        }
        Some("inspect") if args.len() == 3 => inspect(&fs::read(&args[2])?)?,
        Some("id") if args.len() == 3 => {
            let bytes = fs::read(&args[2])?;
            let identified = tool_artifact(parse_and_identify(&bytes))?;
            println!("{}", hex(identified.artifact_id.as_bytes()));
        }
        Some("sign") if args.len() == 4 => sign_file(Path::new(&args[2]), Path::new(&args[3]))?,
        Some("verify") if args.len() == 3 => verify_file(&fs::read(&args[2])?)?,
        Some("receipt") => receipt_cmd::run(&args[2..])?,
        #[cfg(feature = "seed0b-test-signing")]
        Some("negative-corpus") if args.len() == 3 => corpus::write_corpus(Path::new(&args[2]))?,
        _ => return Err(usage().into()),
    }
    Ok(())
}

fn usage() -> String {
    format!(
        "usage: aienos-artifact-tool pack MANIFEST.json CODE.bin DATA.bin OUTPUT.aien | inspect FILE.aien | id FILE.aien | sign INPUT.aien OUTPUT.aien | verify FILE.aien | {}",
        receipt_cmd::USAGE
    )
}

fn pack_bytes(manifest: &Manifest, code: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if code.is_empty() || data.is_empty() || manifest.capabilities.len() > 16 {
        return Err("code, data, and capability count are outside v0 bounds".into());
    }
    let capability_bytes = manifest
        .capabilities
        .len()
        .checked_mul(CAPABILITY_RECORD_SIZE)
        .ok_or("capability length overflow")?;
    let resource_offset = CAPABILITY_TABLE_OFFSET
        .checked_add(capability_bytes)
        .ok_or("resource offset overflow")?;
    let payload_offset = align_up_16(
        resource_offset
            .checked_add(RESOURCE_ENVELOPE_SIZE)
            .ok_or("payload offset overflow")?,
    )?;
    let payload_length = code
        .len()
        .checked_add(data.len())
        .ok_or("payload overflow")?;
    let signature_offset = payload_offset
        .checked_add(payload_length)
        .ok_or("signature offset overflow")?;
    let total_length = signature_offset
        .checked_add(SIG_BLOCK)
        .ok_or("artifact length overflow")?;
    if total_length > MAX_ARTIFACT_SIZE || payload_length > MAX_PAYLOAD_SIZE {
        return Err("artifact exceeds v0 maximum size".into());
    }

    let code_length = u32::try_from(code.len())?;
    let data_length = u32::try_from(data.len())?;
    let payload_length_u32 = u32::try_from(payload_length)?;
    let resource_offset_u32 = u32::try_from(resource_offset)?;
    let payload_offset_u32 = u32::try_from(payload_offset)?;
    let signature_offset_u32 = u32::try_from(signature_offset)?;
    let total_length_u32 = u32::try_from(total_length)?;

    let mut bytes = vec![0u8; total_length];
    bytes[0..8].copy_from_slice(b"AIENART\0");
    put_u16(&mut bytes, 8, 0);
    put_u16(&mut bytes, 10, HEADER_SIZE as u16);
    put_u16(&mut bytes, 12, TARGET_AARCH64_LE);
    put_u16(&mut bytes, 14, ABI_V1);
    put_u32(&mut bytes, 20, total_length_u32);
    put_u32(&mut bytes, 24, SECTION_TABLE_OFFSET as u32);
    put_u16(&mut bytes, 28, 2);
    put_u16(&mut bytes, 30, SECTION_RECORD_SIZE as u16);
    put_u16(&mut bytes, 32, 0);
    put_u32(&mut bytes, 36, manifest.entry_offset);
    put_u32(&mut bytes, 40, CAPABILITY_TABLE_OFFSET as u32);
    put_u16(&mut bytes, 44, u16::try_from(manifest.capabilities.len())?);
    put_u16(&mut bytes, 46, CAPABILITY_RECORD_SIZE as u16);
    put_u32(&mut bytes, 48, resource_offset_u32);
    put_u16(&mut bytes, 52, RESOURCE_ENVELOPE_SIZE as u16);
    put_u32(&mut bytes, 56, payload_offset_u32);
    put_u32(&mut bytes, 60, payload_length_u32);
    put_u32(&mut bytes, SIGNATURE_OFFSET_HEADER, signature_offset_u32);
    put_u16(
        &mut bytes,
        SIGNATURE_LENGTH_HEADER,
        SIGNATURE_BLOCK_SIZE as u16,
    );
    put_u16(
        &mut bytes,
        SIGNATURE_ALGORITHM_HEADER,
        SIGNATURE_ALGORITHM_ED25519,
    );

    encode_section(
        &mut bytes,
        SECTION_TABLE_OFFSET,
        1,
        5,
        0,
        code_length,
        code_length,
    );
    encode_section(
        &mut bytes,
        SECTION_TABLE_OFFSET + SECTION_RECORD_SIZE,
        2,
        3,
        code_length,
        data_length,
        manifest
            .resources
            .data_pages
            .checked_mul(PAGE_SIZE)
            .ok_or("data page overflow")?,
    );

    for (index, cap) in manifest.capabilities.iter().enumerate() {
        let offset = CAPABILITY_TABLE_OFFSET + index * CAPABILITY_RECORD_SIZE;
        put_u16(&mut bytes, offset, cap.resource_kind);
        put_u32(&mut bytes, offset + 4, cap.resource_id);
        put_u32(&mut bytes, offset + 8, cap.rights);
        put_u32(&mut bytes, offset + 12, cap.bounds_kind);
        put_u32(&mut bytes, offset + 16, cap.max_operations);
        put_u64(&mut bytes, offset + 24, cap.max_bytes);
        put_u64(&mut bytes, offset + 32, cap.byte_offset);
        put_u64(&mut bytes, offset + 40, cap.byte_length);
    }
    encode_resources(&mut bytes, resource_offset, &manifest.resources);
    bytes[payload_offset..payload_offset + code.len()].copy_from_slice(code);
    bytes[payload_offset + code.len()..signature_offset].copy_from_slice(data);
    put_u16(&mut bytes, signature_offset, SIGNATURE_ALGORITHM_ED25519);

    let parsed = tool_artifact(Artifact::parse(&bytes))?;
    for request in parsed.capabilities.as_slice() {
        tool_artifact(request.validate())?;
    }
    tool_artifact(parsed.resources.validate(parsed.capabilities.len()))?;
    Ok(bytes)
}

fn encode_section(
    bytes: &mut [u8],
    offset: usize,
    kind: u16,
    permissions: u16,
    payload_offset: u32,
    file_length: u32,
    memory_length: u32,
) {
    put_u16(bytes, offset, kind);
    put_u16(bytes, offset + 2, permissions);
    put_u32(bytes, offset + 8, payload_offset);
    put_u32(bytes, offset + 12, file_length);
    put_u32(bytes, offset + 16, memory_length);
    put_u32(bytes, offset + 20, PAGE_SIZE);
}

fn encode_resources(bytes: &mut [u8], offset: usize, value: &ResourceManifest) {
    put_u32(bytes, offset, value.code_pages);
    put_u32(bytes, offset + 4, value.data_pages);
    put_u32(bytes, offset + 8, value.stack_pages);
    put_u16(bytes, offset + 12, value.max_capabilities);
    put_u32(bytes, offset + 16, value.ipc_messages);
    put_u32(bytes, offset + 20, value.ipc_bytes);
    put_u64(bytes, offset + 24, value.cpu_ticks);
    put_u64(bytes, offset + 32, value.elapsed_ticks);
    put_u32(bytes, offset + 40, value.syscall_count);
}

fn sign_file(input: &Path, output: &Path) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "seed0b-test-signing")]
    {
        let mut bytes = fs::read(input)?;
        let artifact = tool_artifact(Artifact::parse(&bytes))?;
        let id = tool_artifact(parse_and_identify(&bytes))?.artifact_id;
        let signing_key = SigningKey::from_bytes(&test_only_seed());
        let fingerprint = signer_fingerprint(&signing_key.verifying_key().to_bytes());
        let signature = signing_key.sign(&artifact_signature_message(&id));
        let start = artifact.unsigned_bytes.len();
        bytes[start + 4..start + 36].copy_from_slice(&fingerprint);
        bytes[start + 36..start + 100].copy_from_slice(&signature.to_bytes());
        tool_artifact(Artifact::parse(&bytes))?;
        fs::write(output, bytes)?;
        println!("SIGN: TEST ONLY SEED-0B QUALIFICATION IDENTITY");
        println!("SIGNER_FINGERPRINT: {}", hex(&fingerprint));
        Ok(())
    }
    #[cfg(not(feature = "seed0b-test-signing"))]
    {
        let _ = (input, output);
        Err("signing requires explicit feature seed0b-test-signing; production signing is not available".into())
    }
}

fn verify_file(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "seed0b-test-signing")]
    {
        use aienos_artifact::signature::seed0b_test_anchor::Seed0bTestAnchorSet;
        let anchors = Seed0bTestAnchorSet;
        let verifier = ConfiguredArtifactVerifier::new(&anchors, Ed25519Verifier);
        let verified = tool_artifact(verifier.verify(bytes))?;
        println!("VERIFY: PASS");
        println!(
            "ARTIFACT_ID: {}",
            hex(verified.identified().artifact_id.as_bytes())
        );
        println!(
            "PAYLOAD_SHA256: {}",
            hex(&verified.identified().payload_digest)
        );
        println!("SIGNER_FINGERPRINT: {}", hex(verified.signer_fingerprint()));
        println!("TRUST_TIER: SEED-0B-QUALIFICATION-TEST-ONLY");
        Ok(())
    }
    #[cfg(not(feature = "seed0b-test-signing"))]
    {
        let anchors = ProductionTrustAnchorSet::default();
        let verifier = ConfiguredArtifactVerifier::new(&anchors, Ed25519Verifier);
        let _ = tool_artifact(verifier.verify(bytes))?;
        Ok(())
    }
}

fn inspect(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let identified = tool_artifact(parse_and_identify(bytes))?;
    let artifact = identified.artifact;
    println!("magic: AIENART\\0");
    println!("format_version: {}", read_u16(bytes, 8));
    println!("header_size: {}", read_u16(bytes, 10));
    println!(
        "target_arch: {} (AArch64 little-endian)",
        read_u16(bytes, 12)
    );
    println!("abi_version: {}", read_u16(bytes, 14));
    println!("flags: {:#x}", read_u32(bytes, 16));
    println!("total_length: {}", read_u32(bytes, 20));
    println!("section_table_offset: {}", read_u32(bytes, 24));
    println!("section_count: {}", read_u16(bytes, 28));
    println!("section_entry_size: {}", read_u16(bytes, 30));
    println!("entry_section_index: {}", read_u16(bytes, 32));
    println!("header_reserved_34: {}", read_u16(bytes, 34));
    println!("entry_offset: {}", read_u32(bytes, 36));
    println!("capability_table_offset: {}", read_u32(bytes, 40));
    println!("capability_count: {}", read_u16(bytes, 44));
    println!("capability_entry_size: {}", read_u16(bytes, 46));
    println!("resource_envelope_offset: {}", read_u32(bytes, 48));
    println!("resource_envelope_size: {}", read_u16(bytes, 52));
    println!("header_reserved_54: {}", read_u16(bytes, 54));
    println!("payload_offset: {}", read_u32(bytes, 56));
    println!("payload_length: {}", read_u32(bytes, 60));
    println!("signature_offset: {}", read_u32(bytes, 64));
    println!("signature_length: {}", read_u16(bytes, 68));
    println!("signature_algorithm: {}", read_u16(bytes, 70));
    println!("header_reserved_72_127: {}", hex(&bytes[72..128]));
    println!("artifact_id: {}", hex(identified.artifact_id.as_bytes()));
    println!("payload_sha256: {}", hex(&payload_digest(&artifact)));
    for index in 0..2 {
        let offset = SECTION_TABLE_OFFSET + index * SECTION_RECORD_SIZE;
        println!("section[{index}]: kind={} permissions={} reserved_4={} payload_relative_offset={} file_length={} memory_length={} alignment={} reserved_24={}", read_u16(bytes, offset), read_u16(bytes, offset + 2), read_u32(bytes, offset + 4), read_u32(bytes, offset + 8), read_u32(bytes, offset + 12), read_u32(bytes, offset + 16), read_u32(bytes, offset + 20), read_u64(bytes, offset + 24));
    }
    for (index, cap) in artifact.capabilities.as_slice().iter().enumerate() {
        let offset = CAPABILITY_TABLE_OFFSET + index * CAPABILITY_RECORD_SIZE;
        println!("capability[{index}]: kind={} flags={} resource={} rights={:#x} bounds={} ops={} reserved_20={} bytes={} offset={} length={}", cap.resource_kind, read_u16(bytes, offset + 2), cap.resource_id, cap.rights, cap.bounds_kind, cap.max_operations, read_u32(bytes, offset + 20), cap.max_bytes, cap.byte_offset, cap.byte_length);
    }
    let resources = artifact.resources;
    println!("resource_envelope: code_pages={} data_pages={} stack_pages={} max_capabilities={} reserved_14={} ipc_messages={} ipc_bytes={} cpu_ticks={} elapsed_ticks={} syscall_count={} reserved_44={}", resources.code_pages, resources.data_pages, resources.stack_pages, resources.max_capabilities, read_u16(bytes, read_u32(bytes, 48) as usize + 14), resources.ipc_messages, resources.ipc_bytes, resources.cpu_ticks, resources.elapsed_ticks, resources.syscall_count, read_u32(bytes, read_u32(bytes, 48) as usize + 44));
    println!(
        "signature_block_algorithm: {}",
        u16::from_le_bytes([
            bytes[artifact.unsigned_bytes.len()],
            bytes[artifact.unsigned_bytes.len() + 1]
        ])
    );
    println!(
        "signature_block_reserved: {}",
        u16::from_le_bytes([
            bytes[artifact.unsigned_bytes.len() + 2],
            bytes[artifact.unsigned_bytes.len() + 3]
        ])
    );
    println!("signer_fingerprint: {}", hex(artifact.signer_fingerprint));
    println!("signature: {}", hex(artifact.signature));
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("parsed field bounds"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("parsed field bounds"),
    )
}

fn align_up_16(value: usize) -> Result<usize, Box<dyn Error>> {
    Ok(value.checked_add(15).ok_or("alignment overflow")? & !15)
}

fn tool_artifact<T>(
    result: Result<T, aienos_artifact::ArtifactError>,
) -> Result<T, Box<dyn Error>> {
    result.map_err(|error| format!("artifact rejected: {error:?}").into())
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[cfg(feature = "seed0b-test-signing")]
fn test_only_seed() -> [u8; 32] {
    // RFC 8032 test-vector seed. Test fixture only; never use as a secret.
    [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_pack_uses_the_shared_parser_and_id() {
        let manifest: Manifest = serde_json::from_str(
            r#"{
                "entry_offset": 0,
                "capabilities": [{
                    "resource_kind": 3, "resource_id": 7, "rights": 1,
                    "bounds_kind": 1, "max_operations": 4, "max_bytes": 4,
                    "byte_offset": 0, "byte_length": 4
                }],
                "resources": {
                    "code_pages": 1, "data_pages": 1, "stack_pages": 1,
                    "max_capabilities": 1, "ipc_messages": 2, "ipc_bytes": 16,
                    "cpu_ticks": 1000, "elapsed_ticks": 2000, "syscall_count": 16
                }
            }"#,
        )
        .unwrap();
        let code = [0xc0, 0x03, 0x5f, 0xd6];
        let data = *b"DATA";
        let first = pack_bytes(&manifest, &code, &data).unwrap();
        let second = pack_bytes(&manifest, &code, &data).unwrap();
        assert_eq!(first, second);
        let id = parse_and_identify(&first).unwrap().artifact_id;
        assert_eq!(
            hex(id.as_bytes()),
            "71976b5c38ec15f2307565ed3eea51fde4a5375970cd49338d6e16166238cf4b"
        );
    }

    #[cfg(feature = "seed0b-test-signing")]
    #[test]
    fn test_signer_roundtrips_through_shared_verifier() {
        use aienos_artifact::signature::seed0b_test_anchor::Seed0bTestAnchorSet;

        let manifest: Manifest = serde_json::from_str(
            r#"{"entry_offset":0,"capabilities":[],"resources":{"code_pages":1,"data_pages":1,"stack_pages":1,"max_capabilities":0,"ipc_messages":0,"ipc_bytes":0,"cpu_ticks":1,"elapsed_ticks":1,"syscall_count":1}}"#,
        )
        .unwrap();
        let bytes = pack_bytes(&manifest, &[0xc0, 0x03, 0x5f, 0xd6], b"DATA").unwrap();
        let id = parse_and_identify(&bytes).unwrap().artifact_id;
        let key = SigningKey::from_bytes(&test_only_seed());
        let signature = key.sign(&artifact_signature_message(&id));
        let mut signed = bytes;
        let start = signed.len() - SIGNATURE_BLOCK_SIZE;
        let fingerprint = signer_fingerprint(&key.verifying_key().to_bytes());
        signed[start + 4..start + 36].copy_from_slice(&fingerprint);
        signed[start + 36..].copy_from_slice(&signature.to_bytes());

        let anchors = Seed0bTestAnchorSet;
        let verifier = ConfiguredArtifactVerifier::new(&anchors, Ed25519Verifier);
        assert!(verifier.verify(&signed).is_ok());
    }
}
