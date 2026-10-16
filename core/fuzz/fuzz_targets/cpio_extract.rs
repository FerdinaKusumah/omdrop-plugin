//! `archive::extract` of an arbitrary `/Upload` body into a fresh directory,
//! checking the all-or-nothing invariant: on success exactly the reported
//! files exist, all regular and visible, and no `.omdrop-partial-*` file is
//! left; on failure the directory is empty; and nothing is ever created
//! beside it.
//!
//! Input: a mode byte, then the body. An even mode byte passes the rest on
//! unchanged (a DVZip or gzip body); an odd one wraps the rest in one stored
//! DVZip block, so mutations land on the CPIO archive directly.

#![no_main]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use omdrop_proto::archive::{
    DVZIP_STORED, ExtractLimits, ExtractProgress, MAX_FILE_NAME_BYTES, PARTIAL_PREFIX, Partials,
    extract,
};

const LIMITS: ExtractLimits = ExtractLimits {
    byte_limit: 1 << 20,
    max_members: 64,
    min_free_bytes: 0,
};

/// A directory of this process's own under
/// `~/.cache/omdrop-core-target/fuzz-scratch`, never tmpfs. It outlives the
/// process (statics are not dropped); remove the scratch tree after a run.
static SCRATCH: LazyLock<tempfile::TempDir> = LazyLock::new(|| {
    let home = std::env::var_os("HOME").expect("HOME is set");
    let base = PathBuf::from(home).join(".cache/omdrop-core-target/fuzz-scratch");
    fs::create_dir_all(&base).expect("creating the scratch directory");
    tempfile::Builder::new()
        .prefix("cpio_extract-")
        .tempdir_in(base)
        .expect("creating this process's scratch directory")
});

fn names(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .expect("listing a scratch directory")
        .map(|e| {
            e.expect("reading a directory entry")
                .file_name()
                .into_string()
                .expect("UTF-8 file name")
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let body = if mode & 1 == 1 {
        let mut body = (DVZIP_STORED | rest.len() as u32).to_be_bytes().to_vec();
        body.extend_from_slice(rest);
        body
    } else {
        rest.to_vec()
    };

    let root = SCRATCH.path();
    let dest = root.join("dest");
    fs::create_dir(&dest).expect("creating the destination");
    let partials = Partials::new();
    let progress = ExtractProgress::new();
    let result = extract(&body[..], &dest, &LIMITS, &partials, &progress);

    let present = names(&dest);
    assert_eq!(
        names(root),
        BTreeSet::from(["dest".to_string()]),
        "files created outside the destination"
    );
    assert!(
        progress.decoded() <= LIMITS.byte_limit + 1,
        "decoded {} bytes past the {}-byte limit",
        progress.decoded(),
        LIMITS.byte_limit
    );
    match &result {
        Ok(extracted) => {
            let stored: BTreeSet<String> = extracted.names.iter().cloned().collect();
            assert_eq!(stored.len(), extracted.names.len(), "a name stored twice");
            assert_eq!(present, stored, "files differ from the reported names");
            let mut total = 0u64;
            for name in &stored {
                assert!(
                    !name.starts_with(PARTIAL_PREFIX),
                    "partial file {name:?} left"
                );
                assert!(!name.starts_with('.'), "hidden file {name:?}");
                assert!(!name.contains('/'), "separator in {name:?}");
                assert!(name.len() <= MAX_FILE_NAME_BYTES, "overlong name {name:?}");
                let meta = fs::symlink_metadata(dest.join(name)).expect("stat a stored file");
                assert!(meta.file_type().is_file(), "{name:?} is not a regular file");
                total += meta.len();
            }
            assert!(total <= LIMITS.byte_limit, "{total} bytes stored");
        }
        Err(e) => assert!(present.is_empty(), "failed with {e} but left {present:?}"),
    }

    partials.remove_all();
    fs::remove_dir_all(&dest).expect("removing the destination");
});
