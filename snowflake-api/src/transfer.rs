//! `PUT` and `GET`: move files between the local disk and a stage.
//!
//! Snowflake hands back the cloud location and short-lived credentials in
//! the response to the `PUT` / `GET` statement; the client does the actual
//! transfer. Files in internal stages are client-side encrypted the way
//! every official driver does it:
//!
//! ```text
//! master key  = base64(queryStageMasterKey)            (16 or 32 bytes)
//! file key    = random, same length as the master key
//! data        = AES-CBC(file key, random 16-byte IV) + PKCS#7
//! x-amz-key   = base64(AES-ECB(master key, PKCS#7(file key)))
//! x-amz-iv    = base64(IV)
//! x-amz-matdesc = {"smkId": "..", "queryId": "..", "keySize": "128|256"}
//! ```
//!
//! With `AUTO_COMPRESS` (the default) uncompressed files are gzipped first
//! and land as `<name>.gz`. Only S3 stages are supported today.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use base64::Engine;
use object_store::aws::AmazonS3Builder;
use object_store::limit::LimitStore;
use object_store::{Attribute, Attributes, ObjectStore, ObjectStoreExt, PutOptions, PutPayload};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::task;

use crate::responses::{
    CommandType, EncryptionMaterialVariant, PutGetEncryptionMaterial, PutGetExecResponse,
    PutGetStageInfo, SnowflakeType,
};
use crate::{FieldSchema, JsonResult, SnowflakeApiError};

const META_KEY: &str = "x-amz-key";
const META_IV: &str = "x-amz-iv";
const META_MATDESC: &str = "x-amz-matdesc";
const META_DIGEST: &str = "sfc-digest";
const AES_BLOCK: usize = 16;
const COMPRESSED_EXTENSIONS: [&str; 8] = ["gz", "bz2", "br", "zst", "lz4", "xz", "z", "deflate"];

#[derive(Error, Debug)]
pub enum TransferError {
    #[error("stage master key must be 16 or 32 bytes, got {0}")]
    KeySize(usize),

    #[error("encryption metadata is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("encrypted file has a {0}-byte IV; expected {AES_BLOCK}")]
    IvSize(usize),

    #[error("ciphertext is not a whole number of blocks or has bad padding")]
    Padding,

    #[error(
        "file `{0}` on the stage is encrypted but Snowflake sent no encryption material for it"
    )]
    MissingMaterial(String),

    #[error("local path `{0}` has no file name")]
    NoFileName(String),

    #[error("PUT / GET to {0} stages is not implemented")]
    UnsupportedStage(&'static str),

    #[error("stage location `{0}` is not `bucket/prefix`")]
    InvalidLocation(String),
}

/// Encryption metadata stored next to the object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptMetadata {
    pub key: String,
    pub iv: String,
    pub matdesc: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MaterialDescriptor<'a> {
    smk_id: String,
    query_id: &'a str,
    key_size: String,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

enum Aes {
    K128,
    K256,
}

fn key_kind(key: &[u8]) -> Result<Aes, TransferError> {
    match key.len() {
        16 => Ok(Aes::K128),
        32 => Ok(Aes::K256),
        n => Err(TransferError::KeySize(n)),
    }
}

fn ecb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, TransferError> {
    use aes::cipher::block_padding::Pkcs7;
    Ok(match key_kind(key)? {
        Aes::K128 => ecb::Encryptor::<aes::Aes128>::new_from_slice(key)
            .map_err(|_| TransferError::KeySize(key.len()))?
            .encrypt_padded_vec_mut::<Pkcs7>(data),
        Aes::K256 => ecb::Encryptor::<aes::Aes256>::new_from_slice(key)
            .map_err(|_| TransferError::KeySize(key.len()))?
            .encrypt_padded_vec_mut::<Pkcs7>(data),
    })
}

fn ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, TransferError> {
    use aes::cipher::block_padding::Pkcs7;
    match key_kind(key)? {
        Aes::K128 => ecb::Decryptor::<aes::Aes128>::new_from_slice(key)
            .map_err(|_| TransferError::KeySize(key.len()))?
            .decrypt_padded_vec_mut::<Pkcs7>(data),
        Aes::K256 => ecb::Decryptor::<aes::Aes256>::new_from_slice(key)
            .map_err(|_| TransferError::KeySize(key.len()))?
            .decrypt_padded_vec_mut::<Pkcs7>(data),
    }
    .map_err(|_| TransferError::Padding)
}

fn cbc_encrypt(key: &[u8], iv: &[u8; AES_BLOCK], data: &[u8]) -> Result<Vec<u8>, TransferError> {
    use aes::cipher::block_padding::Pkcs7;
    Ok(match key_kind(key)? {
        Aes::K128 => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
            .map_err(|_| TransferError::KeySize(key.len()))?
            .encrypt_padded_vec_mut::<Pkcs7>(data),
        Aes::K256 => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(|_| TransferError::KeySize(key.len()))?
            .encrypt_padded_vec_mut::<Pkcs7>(data),
    })
}

fn cbc_decrypt(key: &[u8], iv: &[u8; AES_BLOCK], data: &[u8]) -> Result<Vec<u8>, TransferError> {
    use aes::cipher::block_padding::Pkcs7;
    match key_kind(key)? {
        Aes::K128 => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
            .map_err(|_| TransferError::KeySize(key.len()))?
            .decrypt_padded_vec_mut::<Pkcs7>(data),
        Aes::K256 => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(|_| TransferError::KeySize(key.len()))?
            .decrypt_padded_vec_mut::<Pkcs7>(data),
    }
    .map_err(|_| TransferError::Padding)
}

/// Encrypt one file's bytes for the stage. Returns the ciphertext and the
/// metadata to store with it.
pub fn encrypt_file(
    material: &PutGetEncryptionMaterial,
    plaintext: &[u8],
) -> Result<(Vec<u8>, EncryptMetadata), TransferError> {
    let master = b64().decode(&material.query_stage_master_key)?;
    key_kind(&master)?;
    let mut file_key = vec![0u8; master.len()];
    getrandom::fill(&mut file_key).expect("os randomness");
    let mut iv = [0u8; AES_BLOCK];
    getrandom::fill(&mut iv).expect("os randomness");

    let ciphertext = cbc_encrypt(&file_key, &iv, plaintext)?;
    let wrapped_key = ecb_encrypt(&master, &file_key)?;
    let matdesc = serde_json::to_string(&MaterialDescriptor {
        smk_id: material.smk_id.to_string(),
        query_id: &material.query_id,
        key_size: (master.len() * 8).to_string(),
    })
    .unwrap_or_default();
    Ok((
        ciphertext,
        EncryptMetadata {
            key: b64().encode(wrapped_key),
            iv: b64().encode(iv),
            matdesc,
        },
    ))
}

/// Undo [`encrypt_file`] given the metadata stored with the object.
pub fn decrypt_file(
    material: &PutGetEncryptionMaterial,
    metadata: &EncryptMetadata,
    ciphertext: &[u8],
) -> Result<Vec<u8>, TransferError> {
    let master = b64().decode(&material.query_stage_master_key)?;
    let wrapped_key = b64().decode(&metadata.key)?;
    let iv_bytes = b64().decode(&metadata.iv)?;
    let iv: [u8; AES_BLOCK] = iv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TransferError::IvSize(iv_bytes.len()))?;
    let file_key = ecb_decrypt(&master, &wrapped_key)?;
    cbc_decrypt(&file_key, &iv, ciphertext)
}

fn attributes_for(meta: &EncryptMetadata, digest: &str) -> Attributes {
    let mut attrs = Attributes::new();
    attrs.insert(
        Attribute::Metadata(META_KEY.into()),
        meta.key.clone().into(),
    );
    attrs.insert(Attribute::Metadata(META_IV.into()), meta.iv.clone().into());
    attrs.insert(
        Attribute::Metadata(META_MATDESC.into()),
        meta.matdesc.clone().into(),
    );
    attrs.insert(
        Attribute::Metadata(META_DIGEST.into()),
        digest.to_owned().into(),
    );
    attrs
}

fn metadata_from(attrs: &Attributes) -> Option<EncryptMetadata> {
    let get = |k: &'static str| {
        attrs
            .get(&Attribute::Metadata(k.into()))
            .map(|v| v.to_string())
    };
    Some(EncryptMetadata {
        key: get(META_KEY)?,
        iv: get(META_IV)?,
        matdesc: get(META_MATDESC).unwrap_or_default(),
    })
}

fn is_compressed(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| COMPRESSED_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
}

fn gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data)?;
    enc.finish()
}

fn file_name(path: &str) -> Result<String, TransferError> {
    Path::new(path)
        .file_name()
        .and_then(|f| f.to_str())
        .map(str::to_owned)
        .ok_or_else(|| TransferError::NoFileName(path.to_owned()))
}

/// What a single `PUT` did with one file; one row of the result set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadRow {
    pub source: String,
    pub target: String,
    pub source_size: u64,
    pub target_size: u64,
    pub source_compression: &'static str,
    pub target_compression: &'static str,
    pub status: &'static str,
    pub message: String,
}

/// What a single `GET` did with one file; one row of the result set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadRow {
    pub file: String,
    pub size: u64,
    pub status: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct UploadOptions {
    pub auto_compress: bool,
    pub overwrite: bool,
    pub encryption: Option<PutGetEncryptionMaterial>,
}

/// Upload one local file. `prefix` is the stage's key prefix inside the bucket.
pub async fn upload_file(
    store: &dyn ObjectStore,
    prefix: &str,
    local_path: &str,
    opts: &UploadOptions,
) -> Result<UploadRow, SnowflakeApiError> {
    let name = file_name(local_path)?;
    let source = tokio::fs::read(local_path).await?;
    let source_size = source.len() as u64;

    let (data, target, source_compression, target_compression) = if is_compressed(&name) {
        (source, name.clone(), "GZIP", "GZIP")
    } else if opts.auto_compress {
        (gzip(&source)?, format!("{name}.gz"), "NONE", "GZIP")
    } else {
        (source, name.clone(), "NONE", "NONE")
    };

    let dest = object_store::path::Path::parse(format!("{prefix}{target}"))?;
    if !opts.overwrite && store.head(&dest).await.is_ok() {
        return Ok(UploadRow {
            source: name,
            target,
            source_size,
            target_size: 0,
            source_compression,
            target_compression,
            status: "SKIPPED",
            message: "File with same destination name and checksum already exists".into(),
        });
    }

    let digest = b64().encode(Sha256::digest(&data));
    let (payload, attributes) = if let Some(material) = &opts.encryption {
        let (ciphertext, meta) = encrypt_file(material, &data)?;
        (ciphertext, attributes_for(&meta, &digest))
    } else {
        let mut attrs = Attributes::new();
        attrs.insert(Attribute::Metadata(META_DIGEST.into()), digest.into());
        (data, attrs)
    };
    let target_size = payload.len() as u64;
    store
        .put_opts(
            &dest,
            PutPayload::from(payload),
            PutOptions {
                attributes,
                ..PutOptions::default()
            },
        )
        .await?;
    Ok(UploadRow {
        source: name,
        target,
        source_size,
        target_size,
        source_compression,
        target_compression,
        status: "UPLOADED",
        message: String::new(),
    })
}

/// Download one stage file into `local_dir`, decrypting it when the object
/// carries encryption metadata.
pub async fn download_file(
    store: &dyn ObjectStore,
    prefix: &str,
    stage_path: &str,
    material: Option<&PutGetEncryptionMaterial>,
    local_dir: &Path,
) -> Result<DownloadRow, SnowflakeApiError> {
    let key = object_store::path::Path::parse(format!("{prefix}{stage_path}"))?;
    let result = store.get(&key).await?;
    let attributes = result.attributes.clone();
    let bytes = result.bytes().await?;

    let data = match metadata_from(&attributes) {
        Some(meta) => {
            let material =
                material.ok_or_else(|| TransferError::MissingMaterial(stage_path.to_owned()))?;
            decrypt_file(material, &meta, &bytes)?
        }
        None => bytes.to_vec(),
    };

    let file = file_name(stage_path)?;
    tokio::fs::create_dir_all(local_dir).await?;
    tokio::fs::write(local_dir.join(&file), &data).await?;
    Ok(DownloadRow {
        file,
        size: data.len() as u64,
        status: "DOWNLOADED",
        message: String::new(),
    })
}

fn s3_store(
    info: crate::responses::AwsPutGetStageInfo,
) -> Result<(Arc<dyn ObjectStore>, String), SnowflakeApiError> {
    let (bucket, prefix) = info
        .location
        .split_once('/')
        .ok_or_else(|| TransferError::InvalidLocation(info.location.clone()))?;
    let mut builder = AmazonS3Builder::new()
        .with_region(info.region)
        .with_bucket_name(bucket)
        .with_access_key_id(info.creds.aws_key_id)
        .with_secret_access_key(info.creds.aws_secret_key)
        .with_token(info.creds.aws_token);
    if let Some(endpoint) = info.end_point.filter(|e| !e.is_empty()) {
        builder = builder.with_endpoint(format!("https://{endpoint}"));
    }
    Ok((Arc::new(builder.build()?), prefix.to_owned()))
}

fn store_for(
    stage_info: PutGetStageInfo,
    parallel: usize,
) -> Result<(Arc<dyn ObjectStore>, String), SnowflakeApiError> {
    let (store, prefix) = match stage_info {
        PutGetStageInfo::Aws(info) => s3_store(info)?,
        PutGetStageInfo::Azure(_) => return Err(TransferError::UnsupportedStage("Azure").into()),
        PutGetStageInfo::Gcs(_) => return Err(TransferError::UnsupportedStage("GCS").into()),
    };
    Ok((Arc::new(LimitStore::new(store, parallel.max(1))), prefix))
}

fn expand_globs(globs: &[String]) -> Result<Vec<String>, SnowflakeApiError> {
    let mut out = Vec::new();
    for g in globs {
        for path in glob::glob(g)? {
            if let Some(p) = path?.to_str() {
                out.push(p.to_owned());
            }
        }
    }
    Ok(out)
}

fn expand_user(path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => dirs_home().join(rest),
        None if path == "~" => dirs_home(),
        None => PathBuf::from(path),
    }
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from)
}

/// Run the client side of a `PUT` response.
pub async fn put(resp: PutGetExecResponse) -> Result<JsonResult, SnowflakeApiError> {
    let data = resp.data;
    let (store, prefix) = store_for(data.stage_info, data.parallel)?;
    let material = match data.encryption_material {
        EncryptionMaterialVariant::Single(m) => Some(m),
        EncryptionMaterialVariant::Multiple(list) => list.into_iter().flatten().next(),
    };
    let opts = UploadOptions {
        auto_compress: data.auto_compress,
        overwrite: data.overwrite,
        encryption: material,
    };

    let paths = task::spawn_blocking({
        let globs = data.src_locations.clone();
        move || expand_globs(&globs)
    })
    .await??;
    let mut tasks = task::JoinSet::new();
    for path in paths {
        let store = Arc::clone(&store);
        let prefix = prefix.clone();
        let opts = opts.clone();
        tasks.spawn(async move { upload_file(store.as_ref(), &prefix, &path, &opts).await });
    }
    let mut rows = Vec::new();
    while let Some(r) = tasks.join_next().await {
        rows.push(r??);
    }
    rows.sort_by(|a, b| a.source.cmp(&b.source));
    Ok(upload_rows_to_json(&rows))
}

/// Run the client side of a `GET` response.
pub async fn get(resp: PutGetExecResponse) -> Result<JsonResult, SnowflakeApiError> {
    let data = resp.data;
    debug_assert!(matches!(data.command, CommandType::Download));
    let (store, prefix) = store_for(data.stage_info, data.parallel)?;
    let local_dir = expand_user(data.local_location.as_deref().unwrap_or("."));
    let materials: Vec<Option<PutGetEncryptionMaterial>> = match data.encryption_material {
        EncryptionMaterialVariant::Single(m) => vec![Some(m)],
        EncryptionMaterialVariant::Multiple(list) => list,
    };

    let mut tasks = task::JoinSet::new();
    for (i, stage_path) in data.src_locations.into_iter().enumerate() {
        let store = Arc::clone(&store);
        let prefix = prefix.clone();
        let local_dir = local_dir.clone();
        let material = materials.get(i).cloned().flatten();
        tasks.spawn(async move {
            download_file(
                store.as_ref(),
                &prefix,
                &stage_path,
                material.as_ref(),
                &local_dir,
            )
            .await
        });
    }
    let mut rows = Vec::new();
    while let Some(r) = tasks.join_next().await {
        rows.push(r??);
    }
    rows.sort_by(|a, b| a.file.cmp(&b.file));
    Ok(download_rows_to_json(&rows))
}

fn field(name: &str, type_: SnowflakeType) -> FieldSchema {
    FieldSchema {
        name: name.to_owned(),
        type_,
        byte_length: None,
        length: None,
        scale: None,
        precision: None,
        nullable: false,
        ext_type_name: None,
        vector_dimension: None,
        fields: Vec::new(),
    }
}

/// Same columns Snowflake's own `PUT` result carries.
pub fn upload_rows_to_json(rows: &[UploadRow]) -> JsonResult {
    JsonResult {
        value: serde_json::Value::Array(
            rows.iter()
                .map(|r| {
                    serde_json::json!([
                        r.source,
                        r.target,
                        r.source_size.to_string(),
                        r.target_size.to_string(),
                        r.source_compression,
                        r.target_compression,
                        r.status,
                        r.message
                    ])
                })
                .collect(),
        ),
        schema: vec![
            field("source", SnowflakeType::Text),
            field("target", SnowflakeType::Text),
            field("source_size", SnowflakeType::Fixed),
            field("target_size", SnowflakeType::Fixed),
            field("source_compression", SnowflakeType::Text),
            field("target_compression", SnowflakeType::Text),
            field("status", SnowflakeType::Text),
            field("message", SnowflakeType::Text),
        ],
    }
}

/// Same columns Snowflake's own `GET` result carries.
pub fn download_rows_to_json(rows: &[DownloadRow]) -> JsonResult {
    JsonResult {
        value: serde_json::Value::Array(
            rows.iter()
                .map(|r| serde_json::json!([r.file, r.size.to_string(), r.status, r.message]))
                .collect(),
        ),
        schema: vec![
            field("file", SnowflakeType::Text),
            field("size", SnowflakeType::Fixed),
            field("status", SnowflakeType::Text),
            field("message", SnowflakeType::Text),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use std::io::Read as _;

    fn material(key_len: usize) -> PutGetEncryptionMaterial {
        PutGetEncryptionMaterial {
            query_stage_master_key: b64().encode(vec![7u8; key_len]),
            query_id: "01b0-qid".into(),
            smk_id: 42,
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip_for_both_key_sizes() {
        for key_len in [16, 32] {
            let m = material(key_len);
            let plaintext = b"hello stage, this is longer than one block of sixteen bytes";
            let (ciphertext, meta) = encrypt_file(&m, plaintext).unwrap();
            assert_ne!(ciphertext, plaintext);
            assert_eq!(ciphertext.len() % AES_BLOCK, 0);
            assert_eq!(b64().decode(&meta.iv).unwrap().len(), AES_BLOCK);
            let wrapped = b64().decode(&meta.key).unwrap();
            assert_eq!(
                wrapped.len(),
                key_len + AES_BLOCK,
                "PKCS#7 adds a full block"
            );
            let desc: serde_json::Value = serde_json::from_str(&meta.matdesc).unwrap();
            assert_eq!(desc["smkId"], "42");
            assert_eq!(desc["queryId"], "01b0-qid");
            assert_eq!(desc["keySize"], (key_len * 8).to_string());
            assert_eq!(decrypt_file(&m, &meta, &ciphertext).unwrap(), plaintext);
        }
    }

    #[test]
    fn empty_file_encrypts_to_one_padding_block() {
        let m = material(16);
        let (ct, meta) = encrypt_file(&m, b"").unwrap();
        assert_eq!(ct.len(), AES_BLOCK);
        assert_eq!(decrypt_file(&m, &meta, &ct).unwrap(), b"");
    }

    #[test]
    fn bad_key_size_and_bad_ciphertext_are_errors() {
        assert!(matches!(
            encrypt_file(&material(24), b"x"),
            Err(TransferError::KeySize(24))
        ));
        let m = material(16);
        let (ct, meta) = encrypt_file(&m, b"payload").unwrap();
        assert!(matches!(
            decrypt_file(&m, &meta, &ct[..ct.len() - 1]),
            Err(TransferError::Padding)
        ));
        let other = material(32);
        assert!(decrypt_file(&other, &meta, &ct).is_err());
    }

    #[test]
    fn compressed_extensions_are_recognised() {
        assert!(is_compressed("data.csv.GZ"));
        assert!(is_compressed("x.zst"));
        assert!(!is_compressed("data.csv"));
        assert!(!is_compressed("noext"));
    }

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("firn-transfer-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn put_then_get_round_trips_through_an_object_store() {
        let dir = tempdir();
        let src = dir.join("rows.csv");
        let content = b"a,b\n1,2\n".repeat(100);
        std::fs::write(&src, &content).unwrap();
        let store = InMemory::new();
        let m = material(32);

        let row = upload_file(
            &store,
            "stages/abc/",
            src.to_str().unwrap(),
            &UploadOptions {
                auto_compress: true,
                overwrite: false,
                encryption: Some(m.clone()),
            },
        )
        .await
        .unwrap();
        assert_eq!(row.source, "rows.csv");
        assert_eq!(row.target, "rows.csv.gz");
        assert_eq!(row.source_size, content.len() as u64);
        assert_eq!(row.status, "UPLOADED");
        assert_eq!(
            (row.source_compression, row.target_compression),
            ("NONE", "GZIP")
        );

        let key = object_store::path::Path::parse("stages/abc/rows.csv.gz").unwrap();
        let obj = store.get(&key).await.unwrap();
        let meta = metadata_from(&obj.attributes).expect("encryption metadata stored");
        let ct = obj.bytes().await.unwrap();
        let gz = decrypt_file(&m, &meta, &ct).unwrap();
        let mut plain = Vec::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_end(&mut plain)
            .unwrap();
        assert_eq!(plain, content);

        // Second PUT without OVERWRITE is skipped.
        let again = upload_file(
            &store,
            "stages/abc/",
            src.to_str().unwrap(),
            &UploadOptions {
                auto_compress: true,
                overwrite: false,
                encryption: Some(m.clone()),
            },
        )
        .await
        .unwrap();
        assert_eq!(again.status, "SKIPPED");

        let out = dir.join("out");
        let got = download_file(&store, "stages/abc/", "rows.csv.gz", Some(&m), &out)
            .await
            .unwrap();
        assert_eq!(got.file, "rows.csv.gz");
        assert_eq!(got.status, "DOWNLOADED");
        assert_eq!(got.size, gz.len() as u64);
        assert_eq!(std::fs::read(out.join("rows.csv.gz")).unwrap(), gz);

        // Encrypted object with no material is an error, not garbage.
        let err = download_file(&store, "stages/abc/", "rows.csv.gz", None, &out)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no encryption material"), "{err}");

        // Plain objects download as-is.
        store
            .put(
                &object_store::path::Path::parse("stages/abc/plain.txt").unwrap(),
                PutPayload::from_static(b"plain"),
            )
            .await
            .unwrap();
        let got = download_file(&store, "stages/abc/", "plain.txt", None, &out)
            .await
            .unwrap();
        assert_eq!(got.size, 5);
        assert_eq!(std::fs::read(out.join("plain.txt")).unwrap(), b"plain");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn get_and_put_responses_deserialize() {
        let get = serde_json::json!({
            "data": {
                "clientShowEncryptionParameter": true,
                "command": "DOWNLOAD",
                "encryptionMaterial": [
                    {"queryId": "01c7-qid", "queryStageMasterKey": "AAAA", "smkId": 11_624_616_794_387_406_i64},
                    null
                ],
                "kind": null,
                "localLocation": "/tmp/firn_get/",
                "operation": "Node",
                "overwrite": false,
                "parallel": 10,
                "presignedUrls": [null, null],
                "queryId": "01c7-download",
                "src_locations": ["firn_test/a.csv.gz", "firn_test/b.csv"],
                "stageInfo": {
                    "ciphers": "AES_CBC", "credExpiryTime": 1_789_359_268_000_i64,
                    "creds": {"AWS_ID": "id", "AWS_KEY": "k", "AWS_KEY_ID": "id",
                              "AWS_SECRET_KEY": "k", "AWS_TOKEN": "t"},
                    "endPoint": null, "isClientSideEncrypted": true,
                    "location": "bucket/z6x/users/1/", "locationType": "S3",
                    "path": "users/1/", "region": "us-west-2"
                }
            },
            "code": null, "message": null, "success": true
        });
        let resp: PutGetExecResponse = serde_json::from_value(get).unwrap();
        assert!(matches!(resp.data.command, CommandType::Download));
        assert_eq!(resp.data.parallel, 10);
        assert_eq!(resp.data.threshold, None);
        assert!(!resp.data.auto_compress);
        assert_eq!(resp.data.src_locations.len(), 2);
        match &resp.data.encryption_material {
            EncryptionMaterialVariant::Multiple(list) => {
                assert!(list[0].is_some());
                assert!(list[1].is_none());
            }
            EncryptionMaterialVariant::Single(_) => panic!("GET carries a list"),
        }
        assert!(matches!(resp.data.stage_info, PutGetStageInfo::Aws(_)));

        let put = serde_json::json!({
            "data": {
                "autoCompress": true, "command": "UPLOAD",
                "encryptionMaterial": {"queryId": "q", "queryStageMasterKey": "AAAA", "smkId": 1},
                "overwrite": false, "parallel": 4, "queryId": "01c7-upload",
                "sourceCompression": "auto_detect",
                "src_locations": ["/tmp/x.csv"],
                "stageInfo": {
                    "creds": {"AWS_ID": "id", "AWS_KEY": "k", "AWS_KEY_ID": "id",
                              "AWS_SECRET_KEY": "k", "AWS_TOKEN": "t"},
                    "location": "bucket/z6x/users/1/", "locationType": "S3", "region": "us-west-2"
                },
                "threshold": 209_715_200
            },
            "code": null, "message": null, "success": true
        });
        let resp: PutGetExecResponse = serde_json::from_value(put).unwrap();
        assert!(matches!(resp.data.command, CommandType::Upload));
        assert!(resp.data.auto_compress);
        assert_eq!(resp.data.threshold, Some(209_715_200));
        assert!(matches!(
            resp.data.encryption_material,
            EncryptionMaterialVariant::Single(_)
        ));
    }

    #[tokio::test]
    async fn already_compressed_files_are_uploaded_unchanged_and_unencrypted_when_no_material() {
        let dir = tempdir();
        let src = dir.join("data.gz");
        std::fs::write(&src, b"not really gzip").unwrap();
        let store = InMemory::new();
        let row = upload_file(
            &store,
            "p/",
            src.to_str().unwrap(),
            &UploadOptions {
                auto_compress: true,
                overwrite: true,
                encryption: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(row.target, "data.gz");
        assert_eq!(row.target_size, 15);
        let obj = store
            .get(&object_store::path::Path::parse("p/data.gz").unwrap())
            .await
            .unwrap();
        assert!(metadata_from(&obj.attributes).is_none());
        assert_eq!(obj.bytes().await.unwrap().as_ref(), b"not really gzip");
        let _ = std::fs::remove_dir_all(dir);
    }
}
