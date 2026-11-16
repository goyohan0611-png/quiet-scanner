//! Signed manifests bind every payload byte. Rules snapshots are inert, never executed.
use ed25519_dalek::{pkcs8::DecodePublicKey, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_FILE: u64 = 128 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Release,
    Rules,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub kind: Kind,
    pub version: String,
    pub sequence: u64,
    pub target: String,
    pub files: Vec<Entry>,
}

pub fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() < 512
        && path.split('/').all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && !s.starts_with('.')
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_+.".contains(&c))
        })
}
fn regular(path: &Path, limit: u64) -> Result<fs::File> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err("not a bounded regular file".into());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err("file changed during inspection".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.ino() != metadata.ino() || opened.dev() != metadata.dev() {
            return Err("file identity changed".into());
        }
    }
    Ok(file)
}
fn bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    regular(path, limit)?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("file exceeds limit".into());
    }
    Ok(bytes)
}
pub fn digest_file(path: &Path) -> Result<(u64, String)> {
    let mut file = regular(path, MAX_FILE)?;
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > MAX_FILE {
            return Err("file grew beyond limit".into());
        }
        hash.update(&buffer[..n]);
    }
    Ok((size, hex::encode(hash.finalize())))
}
fn walk(root: &Path, directory: &Path, paths: &mut BTreeSet<String>) -> Result<()> {
    if paths.len() > 4096 {
        return Err("too many files".into());
    }
    for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_str()
            .ok_or("non UTF-8 path")?
            .replace('\\', "/");
        if !safe_relative(&relative) || relative.split('/').count() > 32 {
            return Err("unsafe or overly deep bundle path".into());
        }
        let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("symlinks are not accepted in bundles".into());
        }
        if metadata.is_dir() {
            walk(root, &path, paths)?;
        } else if metadata.is_file() {
            if relative == "manifest.json" || relative == "signature.bin" {
                continue;
            }
            if !safe_relative(&relative) {
                return Err("unsafe bundle path".into());
            }
            paths.insert(relative);
        } else {
            return Err("special files are not accepted".into());
        }
    }
    Ok(())
}
fn paths(root: &Path) -> Result<BTreeSet<String>> {
    if !fs::symlink_metadata(root)
        .map_err(|e| e.to_string())?
        .is_dir()
    {
        return Err("bundle root must be a directory".into());
    }
    let mut paths = BTreeSet::new();
    walk(root, root, &mut paths)?;
    if paths.is_empty() || paths.len() > 4096 {
        return Err("invalid file count".into());
    }
    Ok(paths)
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1
            || self.sequence == 0
            || self.version.is_empty()
            || self.version.len() > 64
            || !self
                .version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
            || self.target != "linux-x86_64"
            || self.files.is_empty()
            || self.files.len() > 4096
        {
            return Err("invalid manifest metadata".into());
        }
        let mut unique = BTreeSet::new();
        let mut total = 0_u64;
        for entry in &self.files {
            if !safe_relative(&entry.path)
                || !unique.insert(entry.path.clone())
                || entry.size > MAX_FILE
                || entry.sha256.len() != 64
                || !entry
                    .sha256
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Err("invalid manifest file entry".into());
            }
            if self.kind == Kind::Rules
                && !entry.path.starts_with("rules/")
                && !entry.path.starts_with("data/")
            {
                return Err("rules bundle may only contain rules/ and data/".into());
            }
            total = total.checked_add(entry.size).ok_or("size overflow")?;
        }
        if total > MAX_TOTAL {
            return Err("bundle exceeds total size limit".into());
        }
        if self.kind == Kind::Release
            && unique
                != BTreeSet::from(["quiet-guard".to_string(), "quiet-guard.service".to_string()])
        {
            return Err("release must contain exactly executable and unit".into());
        }
        Ok(())
    }
}
pub fn build(root: &Path, kind: Kind, sequence: u64, version: String) -> Result<Manifest> {
    let files = paths(root)?
        .into_iter()
        .map(|path| {
            let (size, sha256) = digest_file(&root.join(&path))?;
            Ok(Entry { path, size, sha256 })
        })
        .collect::<Result<Vec<_>>>()?;
    let manifest = Manifest {
        schema: 1,
        kind,
        version,
        sequence,
        target: "linux-x86_64".into(),
        files,
    };
    manifest.validate()?;
    Ok(manifest)
}
pub fn verify(root: &Path, key_path: &Path) -> Result<Manifest> {
    let document = bytes(&root.join("manifest.json"), MAX_MANIFEST)?;
    let signature = Signature::from_slice(&bytes(&root.join("signature.bin"), 64)?)
        .map_err(|_| "invalid signature length")?;
    let key = String::from_utf8(bytes(key_path, 4096)?).map_err(|_| "invalid public key")?;
    let key = VerifyingKey::from_public_key_pem(&key).map_err(|_| "invalid Ed25519 public key")?;
    key.verify_strict(&document, &signature)
        .map_err(|_| "signature verification failed")?;
    let manifest: Manifest = serde_json::from_slice(&document).map_err(|e| e.to_string())?;
    manifest.validate()?;
    let actual = paths(root)?;
    let expected = manifest
        .files
        .iter()
        .map(|e| e.path.clone())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "missing or unlisted payload file; extra={:?}; missing={:?}",
            actual.difference(&expected).take(8).collect::<Vec<_>>(),
            expected.difference(&actual).take(8).collect::<Vec<_>>()
        ));
    }
    for entry in &manifest.files {
        let (size, hash) = digest_file(&root.join(&entry.path))?;
        if size != entry.size || hash != entry.sha256 {
            return Err(format!("payload mismatch: {}", entry.path));
        }
    }
    Ok(manifest)
}
pub fn stage_rules(source: &Path, key: &Path, store: &Path) -> Result<PathBuf> {
    let manifest = verify(source, key)?;
    if manifest.kind != Kind::Rules {
        return Err("expected a rules bundle".into());
    }
    // Stage only. Activation and engine reload belong to the later integration.
    fs::create_dir_all(store).map_err(|e| e.to_string())?;
    let metadata = fs::symlink_metadata(store).map_err(|e| e.to_string())?;
    if !metadata.is_dir() {
        return Err("snapshot store is not a real directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err("snapshot store ownership/permissions invalid".into());
        }
        fs::set_permissions(store, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    let manifest_bytes = bytes(&source.join("manifest.json"), MAX_MANIFEST)?;
    let id = hex::encode(Sha256::digest(&manifest_bytes));
    let destination = store.join(format!("{}-{id}", manifest.sequence));
    if destination.exists() {
        return Err("snapshot already exists; never overwrite".into());
    }
    let temporary = store.join(format!("stage-{}", std::process::id()));
    fs::create_dir(&temporary).map_err(|e| e.to_string())?;
    let result = (|| {
        for entry in manifest
            .files
            .iter()
            .map(|e| e.path.as_str())
            .chain(["manifest.json", "signature.bin"])
        {
            let target = temporary.join(entry);
            fs::create_dir_all(target.parent().ok_or("no parent")?).map_err(|e| e.to_string())?;
            let mut input = regular(&source.join(entry), MAX_FILE)?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
                .map_err(|e| e.to_string())?;
            let count = std::io::copy(&mut input.by_ref().take(MAX_FILE + 1), &mut output)
                .map_err(|e| e.to_string())?;
            if count > MAX_FILE {
                return Err("file grew while staging".into());
            }
            output.sync_all().map_err(|e| e.to_string())?;
        }
        verify(&temporary, key)?;
        fs::rename(&temporary, &destination).map_err(|e| e.to_string())?;
        Ok(destination)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("bundle");
        fs::create_dir_all(root.join("rules")).unwrap();
        fs::write(root.join("rules/sample.yaml"), "name: sample\n").unwrap();
        let manifest = build(&root, Kind::Rules, 1, "test-1".into()).unwrap();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        // Deterministic fixture key, never used to sign a product release.
        let key = SigningKey::from_bytes(&[42; 32]);
        fs::write(root.join("manifest.json"), &bytes).unwrap();
        fs::write(root.join("signature.bin"), key.sign(&bytes).to_bytes()).unwrap();
        fs::write(
            d.path().join("public.pem"),
            key.verifying_key()
                .to_public_key_pem(Default::default())
                .unwrap(),
        )
        .unwrap();
        (d, root)
    }
    #[test]
    fn rejects_traversal_and_platform_alias_paths() {
        for bad in [
            "../etc/passwd",
            "/tmp/x",
            "C:/x",
            "a\\b",
            "a//b",
            "a/./b",
            "a/../b",
            ".hidden",
            "a\nfile",
            "",
        ] {
            assert!(!safe_relative(bad), "{bad}");
        }
    }
    #[test]
    fn authentic_bundle_can_be_staged_without_activation() {
        let (d, root) = fixture();
        let key = d.path().join("public.pem");
        assert_eq!(verify(&root, &key).unwrap().sequence, 1);
        let staged = stage_rules(&root, &key, &d.path().join("snapshots")).unwrap();
        fs::write(root.join("rules/sample.yaml"), "changed").unwrap();
        assert!(verify(&staged, &key).is_ok());
        assert!(verify(&root, &key).is_err());
    }
    #[test]
    fn signature_payload_and_extra_files_are_all_verified() {
        let (d, root) = fixture();
        let key = d.path().join("public.pem");
        fs::write(root.join("extra"), "unexpected").unwrap();
        assert!(verify(&root, &key).unwrap_err().contains("unlisted"));
        fs::remove_file(root.join("extra")).unwrap();
        fs::write(root.join("manifest.json"), "{}").unwrap();
        assert!(verify(&root, &key).unwrap_err().contains("signature"));
    }
    #[test]
    fn rejects_wrong_signing_key() {
        let (d, root) = fixture();
        let wrong = SigningKey::from_bytes(&[24; 32]);
        fs::write(
            d.path().join("public.pem"),
            wrong
                .verifying_key()
                .to_public_key_pem(Default::default())
                .unwrap(),
        )
        .unwrap();
        assert!(verify(&root, &d.path().join("public.pem")).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlink_payloads() {
        let (d, root) = fixture();
        fs::remove_file(root.join("rules/sample.yaml")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("rules/sample.yaml")).unwrap();
        assert!(verify(&root, &d.path().join("public.pem")).is_err());
    }
}
