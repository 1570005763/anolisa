//! Private, bounded snapshots bind the complete delivered tree rather than model text alone.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{Mode, OFlags, openat};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

use crate::{Error, Result};

const MAX_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
pub(crate) const MAX_TEXT_BYTES: usize = 600_000;

pub(crate) struct Snapshot {
    directory: TempDir,
    pub hash: String,
    pub files: BTreeMap<String, String>,
    pub omitted: Vec<String>,
}

impl Snapshot {
    pub fn create(input: &Path) -> Result<Self> {
        let root = File::from(openat(
            rustix::fs::CWD,
            input,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let directory = tempfile::Builder::new()
            .prefix("asc-score-source-")
            .tempdir()?;
        let mut snapshot = Self {
            directory,
            hash: String::new(),
            files: BTreeMap::new(),
            omitted: Vec::new(),
        };
        let mut digest = Sha256::new();
        digest.update(b"agent-sec-skill-score/source-tree-v2\0");
        let mut budget = Budget::default();
        let destination = snapshot.directory.path().to_path_buf();
        snapshot.copy(&root, Path::new(""), &destination, &mut digest, &mut budget)?;
        if !snapshot.files.contains_key("SKILL.md") {
            return Err(Error::Contract(
                "Skill must contain a readable UTF-8 SKILL.md".into(),
            ));
        }
        snapshot.hash = format!("{:x}", digest.finalize());
        Ok(snapshot)
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    fn copy(
        &mut self,
        source: &File,
        relative: &Path,
        target: &Path,
        digest: &mut Sha256,
        budget: &mut Budget,
    ) -> Result<()> {
        let before_directory = source.metadata()?;
        // Read directory names through the opened descriptor, never through a replaceable input path.
        let directory = PathBuf::from(format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(source)
        ));
        let mut names = std::fs::read_dir(directory)?
            .map(|entry| entry.map(|e| e.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        names.sort();
        for name in names {
            let path = relative.join(&name);
            let label = path
                .to_str()
                .ok_or_else(|| Error::Contract("input contains a non-UTF-8 filename".into()))?;
            budget.entries += 1;
            if budget.entries > 8192 || path.components().count() > 64 {
                return Err(Error::Contract(format!(
                    "input exceeds entry/depth limit at {label}"
                )));
            }
            let mut file = File::from(
                openat(
                    source,
                    &name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| {
                    Error::Contract(format!(
                        "cannot safely read input {label}; links and special files are unsupported"
                    ))
                })?,
            );
            let metadata = file.metadata()?;
            if !metadata.is_file() && !metadata.is_dir() {
                return Err(Error::Contract(format!(
                    "special input file is unsupported: {label}"
                )));
            }
            let mode = metadata.mode() & 0o777;
            digest.update((label.len() as u64).to_be_bytes());
            digest.update(label.as_bytes());
            digest.update(if metadata.is_dir() { b"d" } else { b"f" });
            digest
                .update(((mode & 0o111) | if metadata.is_dir() { 0o100 } else { 0 }).to_be_bytes());
            let output = target.join(&name);
            if metadata.is_dir() {
                std::fs::create_dir(&output)?;
                std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))?;
                self.copy(&file, &path, &output, digest, budget)?;
                std::fs::set_permissions(
                    &output,
                    std::fs::Permissions::from_mode(0o700 | (mode & 0o111)),
                )?;
            } else {
                self.copy_file(&mut file, &metadata, label, &output, digest, budget)?;
            }
        }
        let after_directory = source.metadata()?;
        if before_directory.mtime() != after_directory.mtime()
            || before_directory.mtime_nsec() != after_directory.mtime_nsec()
            || before_directory.ctime() != after_directory.ctime()
            || before_directory.ctime_nsec() != after_directory.ctime_nsec()
        {
            return Err(Error::Contract(format!(
                "input directory changed while snapshotting: {}",
                relative.display()
            )));
        }
        Ok(())
    }
    fn copy_file(
        &mut self,
        file: &mut File,
        metadata: &std::fs::Metadata,
        label: &str,
        output: &Path,
        digest: &mut Sha256,
        budget: &mut Budget,
    ) -> Result<()> {
        let mode = metadata.mode() & 0o777;
        if metadata.len() > MAX_FILE_BYTES {
            return Err(Error::Contract(format!(
                "input file exceeds 32 MiB: {label}"
            )));
        }
        let mut bytes = Vec::new();
        (&mut *file)
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if after.len() != metadata.len()
            || bytes.len() as u64 != metadata.len()
            || after.mtime() != metadata.mtime()
            || after.mtime_nsec() != metadata.mtime_nsec()
            || after.ctime() != metadata.ctime()
            || after.ctime_nsec() != metadata.ctime_nsec()
        {
            return Err(Error::Contract(format!(
                "input changed while snapshotting: {label}"
            )));
        }
        budget.bytes += bytes.len() as u64;
        if bytes.len() as u64 > MAX_FILE_BYTES || budget.bytes > MAX_TREE_BYTES {
            return Err(Error::Contract(format!(
                "input exceeds size limit at {label}"
            )));
        }
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(&bytes);
        let mut writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output)?;
        writer.write_all(&bytes)?;
        // Preserve executable bits; owner read/write is required for the private snapshot lifecycle.
        writer.set_permissions(std::fs::Permissions::from_mode(0o600 | (mode & 0o111)))?;
        if let Ok(text) = std::str::from_utf8(&bytes)
            && !text.contains('\0')
            && budget.text + text.len() <= MAX_TEXT_BYTES
        {
            budget.text += text.len();
            self.files.insert(label.into(), text.into());
            return Ok(());
        }
        self.omitted.push(format!(
            "{label} (binary or model-review limit; included in execution digest)"
        ));
        Ok(())
    }
}

#[derive(Default)]
struct Budget {
    entries: usize,
    bytes: u64,
    text: usize,
}

pub(crate) fn catalog(files: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    files
        .iter()
        .flat_map(|(path, text)| {
            text.lines()
                .enumerate()
                .map(move |(index, line)| (format!("source:{path}:{}", index + 1), line.into()))
        })
        .collect()
}

pub(crate) fn contained_relative(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && !value.contains("//")
        && !value.ends_with('/')
}

pub(crate) fn private_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Contract("JSON path lacks parent".into()))?;
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(file.as_file_mut(), value)?;
    file.as_file_mut().write_all(b"\n")?;
    file.persist(path).map_err(|e| Error::Io(e.error))?;
    Ok(())
}

pub(crate) fn read_json(path: &Path, limit: u64) -> Result<serde_json::Value> {
    let file = File::from(openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > limit {
        return Err(Error::Contract(
            "JSON input is not a bounded private regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Contract("JSON input exceeds limit".into()));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_covers_dependencies_binaries_and_execute_permissions() {
        let root = tempfile::tempdir().expect("directory");
        std::fs::write(root.path().join("SKILL.md"), "hello").expect("skill");
        std::fs::create_dir(root.path().join("node_modules")).expect("deps");
        let binary = root.path().join("node_modules/data");
        std::fs::write(&binary, [0, 1]).expect("binary");
        let first = Snapshot::create(root.path()).expect("snapshot");
        std::fs::write(&binary, [0, 2]).expect("change");
        let second = Snapshot::create(root.path()).expect("snapshot");
        assert_ne!(first.hash, second.hash);
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
            .expect("permissions");
        assert_ne!(
            second.hash,
            Snapshot::create(root.path()).expect("snapshot").hash
        );
        std::os::unix::fs::symlink("/etc/passwd", root.path().join("link")).expect("link");
        assert!(Snapshot::create(root.path()).is_err());
    }
}
