use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use object::{Object, ObjectSection};

use crate::Error;

pub(crate) const GIT_RECENCY_MAPPING_ENV: &str = "LIBAFL_GIT_RECENCY_MAPPING_PATH";

const SIDECAR_MAGIC_V1: &[u8; 8] = b"LAFLGIT1";
const SIDECAR_MAGIC_V2: &[u8; 8] = b"LAFLGIT2";
pub(crate) const SIDECAR_EXT: &str = "libafl_git_recency";

const GITREC_SECTION_NAMES: &[&str] = &["libafl_gitrec", "__DATA,__libafl_gitrec"];
const SANCOV_GUARDS_SECTION_NAMES: &[&str] = &[
    "__sancov_guards",
    "__DATA,__sancov_guards",
    ".sancov_guards",
];

#[derive(Debug, Clone)]
struct SidecarLoc {
    file: String,
    line: u32,
}

#[derive(Debug, Clone)]
struct SidecarEntry {
    locs: Vec<SidecarLoc>,
}

fn sidecar_path_for_object(obj: &Path) -> PathBuf {
    let mut s: OsString = obj.as_os_str().to_os_string();
    s.push(".");
    s.push(SIDECAR_EXT);
    PathBuf::from(s)
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

fn read_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn write_u64_le(out: &mut impl Write, v: u64) -> Result<(), Error> {
    out.write_all(&v.to_le_bytes()).map_err(Error::Io)
}

fn parse_sidecar(bytes: &[u8]) -> Result<Vec<SidecarEntry>, Error> {
    let entries = parse_sidecar_stream(bytes)?;
    Ok(entries)
}

fn git(repo_root: &Path, args: &[&str]) -> Result<Output, Error> {
    Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(Error::Io)
}

fn repo_root(cwd: &Path) -> Result<PathBuf, Error> {
    let out = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(Error::Io)?;

    if !out.status.success() {
        return Err(Error::Unknown(format!(
            "git rev-parse --show-toplevel failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if root.is_empty() {
        return Err(Error::Unknown(
            "git rev-parse --show-toplevel returned empty output".to_string(),
        ));
    }
    Ok(PathBuf::from(root))
}

fn head_time_epoch_seconds(repo_root: &Path) -> Result<u64, Error> {
    let out = git(repo_root, &["show", "-s", "--format=%ct", "HEAD"])?;
    if !out.status.success() {
        return Err(Error::Unknown(format!(
            "git show failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    s.parse::<u64>()
        .map_err(|e| Error::Unknown(format!("failed to parse HEAD time '{s}': {e}")))
}

fn is_header_line(line: &str) -> bool {
    let mut it = line.split_whitespace();
    let Some(hash) = it.next() else {
        return false;
    };
    let Some(orig_line) = it.next() else {
        return false;
    };
    let Some(final_line) = it.next() else {
        return false;
    };

    if !hash.chars().all(|c| c == '^' || c.is_ascii_hexdigit()) {
        return false;
    }
    if orig_line.parse::<u32>().is_err() {
        return false;
    }
    if final_line.parse::<u32>().is_err() {
        return false;
    }
    true
}

fn blame_times_for_lines(
    repo_root: &Path,
    file_rel: &str,
    needed_lines: &HashSet<u32>,
) -> Result<HashMap<u32, u64>, Error> {
    let (min_line, max_line) = needed_lines
        .iter()
        .fold((u32::MAX, 0u32), |acc, &v| (acc.0.min(v), acc.1.max(v)));
    if min_line == u32::MAX || max_line == 0 {
        return Ok(HashMap::new());
    }

    let range = format!("{min_line},{max_line}");
    let out = git(
        repo_root,
        &["blame", "--line-porcelain", "-L", &range, "--", file_rel],
    )?;

    if !out.status.success() {
        // Treat failures as "unknown/old", per plan.
        return Ok(HashMap::new());
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut res: HashMap<u32, u64> = HashMap::new();

    let mut current_final_line: Option<u32> = None;
    let mut current_committer_time: Option<u64> = None;

    for line in text.lines() {
        if current_final_line.is_none() && is_header_line(line) {
            let mut it = line.split_whitespace();
            let _hash = it.next().unwrap();
            let _orig = it.next().unwrap();
            let final_line = it.next().unwrap();
            current_final_line = final_line.parse::<u32>().ok();
            current_committer_time = None;
            continue;
        }

        if let Some(rest) = line.strip_prefix("committer-time ") {
            current_committer_time = rest.trim().parse::<u64>().ok();
            continue;
        }

        if line.starts_with('\t') {
            if let (Some(final_line), Some(time)) = (current_final_line, current_committer_time)
                && needed_lines.contains(&final_line)
            {
                res.insert(final_line, time);
            }
            current_final_line = None;
            current_committer_time = None;
        }
    }

    Ok(res)
}

fn read_gitrec_and_guard_counts(link_output: &Path) -> Result<(Option<Vec<u8>>, usize), Error> {
    let bytes = fs::read(link_output).map_err(Error::Io)?;
    let obj = object::File::parse(&*bytes).map_err(|e| {
        Error::Unknown(format!(
            "failed to parse linked output as object file '{}': {e}",
            link_output.display()
        ))
    })?;

    let mut guard_bytes_total: u64 = 0;
    let mut gitrec_bytes: Vec<u8> = Vec::new();
    let mut saw_gitrec = false;

    for section in obj.sections() {
        let Ok(name) = section.name() else {
            continue;
        };

        if GITREC_SECTION_NAMES.contains(&name) {
            let data = section.uncompressed_data().map_err(|e| {
                Error::Unknown(format!(
                    "failed to read section '{name}' from '{}': {e}",
                    link_output.display()
                ))
            })?;
            gitrec_bytes.extend_from_slice(&data);
            saw_gitrec = true;
        }

        if SANCOV_GUARDS_SECTION_NAMES.contains(&name) {
            guard_bytes_total = guard_bytes_total.saturating_add(section.size());
        }
    }

    let guard_bytes_total = usize::try_from(guard_bytes_total).map_err(|_| {
        Error::Unknown("coverage guard section size does not fit usize".to_string())
    })?;
    if guard_bytes_total % 4 != 0 {
        return Err(Error::Unknown(format!(
            "coverage guard section size ({guard_bytes_total}) is not a multiple of 4"
        )));
    }
    let guard_count = guard_bytes_total / 4;

    Ok((saw_gitrec.then_some(gitrec_bytes), guard_count))
}

fn parse_sidecar_stream(bytes: &[u8]) -> Result<Vec<SidecarEntry>, Error> {
    let mut entries: Vec<SidecarEntry> = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        if offset + 16 > bytes.len() {
            return Err(Error::Unknown(
                "git recency sidecar truncated while reading header".to_string(),
            ));
        }
        let magic = &bytes[offset..offset + 8];
        let is_v1 = magic == SIDECAR_MAGIC_V1;
        let is_v2 = magic == SIDECAR_MAGIC_V2;
        if !is_v1 && !is_v2 {
            return Err(Error::Unknown(
                "git recency sidecar magic mismatch".to_string(),
            ));
        }

        let len = read_u64_le(&bytes[offset + 8..offset + 16]);
        let len = usize::try_from(len).map_err(|_| {
            Error::Unknown("git recency sidecar length does not fit usize".to_string())
        })?;
        offset += 16;

        if is_v1 {
            for _ in 0..len {
                if offset + 8 > bytes.len() {
                    return Err(Error::Unknown(
                        "git recency sidecar truncated while reading entry header".to_string(),
                    ));
                }
                let line = read_u32_le(&bytes[offset..offset + 4]);
                let path_len = read_u32_le(&bytes[offset + 4..offset + 8]) as usize;
                offset += 8;

                if offset + path_len > bytes.len() {
                    return Err(Error::Unknown(
                        "git recency sidecar truncated while reading path".to_string(),
                    ));
                }

                let mut locs = Vec::new();
                if line != 0 && path_len != 0 {
                    let path_bytes = &bytes[offset..offset + path_len];
                    let file = String::from_utf8(path_bytes.to_vec()).map_err(|e| {
                        Error::Unknown(format!("git recency sidecar contains non-utf8 path: {e}"))
                    })?;
                    locs.push(SidecarLoc { file, line });
                }
                offset += path_len;

                entries.push(SidecarEntry { locs });
            }
        } else {
            // v2: per-entry list of (path,line) debug locations.
            for _ in 0..len {
                if offset + 4 > bytes.len() {
                    return Err(Error::Unknown(
                        "git recency sidecar truncated while reading entry header".to_string(),
                    ));
                }
                let nlocs = read_u32_le(&bytes[offset..offset + 4]) as usize;
                offset += 4;

                let mut locs: Vec<SidecarLoc> = Vec::with_capacity(nlocs);
                for _ in 0..nlocs {
                    if offset + 8 > bytes.len() {
                        return Err(Error::Unknown(
                            "git recency sidecar truncated while reading location header"
                                .to_string(),
                        ));
                    }
                    let line = read_u32_le(&bytes[offset..offset + 4]);
                    let path_len = read_u32_le(&bytes[offset + 4..offset + 8]) as usize;
                    offset += 8;

                    if offset + path_len > bytes.len() {
                        return Err(Error::Unknown(
                            "git recency sidecar truncated while reading path".to_string(),
                        ));
                    }

                    if line != 0 && path_len != 0 {
                        let path_bytes = &bytes[offset..offset + path_len];
                        let file = String::from_utf8(path_bytes.to_vec()).map_err(|e| {
                            Error::Unknown(format!(
                                "git recency sidecar contains non-utf8 path: {e}"
                            ))
                        })?;
                        locs.push(SidecarLoc { file, line });
                    }
                    offset += path_len;
                }

                entries.push(SidecarEntry { locs });
            }
        }
    }

    Ok(entries)
}

/// Generate a git-recency mapping file (`pcguard_index -> git blame timestamp`) for a linked binary.
///
/// This is the same logic the `libafl_cc` wrapper runs at link time when
/// `LIBAFL_GIT_RECENCY_MAPPING_PATH` is set.
pub fn generate_git_recency_mapping(
    mapping_out: &Path,
    link_output: &Path,
    object_files: &[PathBuf],
    cwd: &Path,
) -> Result<(), Error> {
    let link_output = if link_output.is_absolute() {
        link_output.to_path_buf()
    } else {
        cwd.join(link_output)
    };

    let repo_root = repo_root(cwd)?;
    let repo_root = fs::canonicalize(&repo_root).map_err(Error::Io)?;

    let head_time = head_time_epoch_seconds(&repo_root)?;

    let (embedded_bytes, guard_count) = read_gitrec_and_guard_counts(&link_output)?;

    let entries = if let Some(bytes) = embedded_bytes {
        parse_sidecar_stream(&bytes)?
    } else {
        let mut entries: Vec<SidecarEntry> = Vec::new();
        for obj in object_files {
            let sidecar_path = sidecar_path_for_object(obj);
            let sidecar_bytes = fs::read(&sidecar_path).map_err(|e| {
                Error::Unknown(format!(
                    "missing git recency sidecar for object {}: {e}",
                    obj.display()
                ))
            })?;
            entries.extend(parse_sidecar(&sidecar_bytes)?);
        }
        entries
    };

    if entries.len() != guard_count {
        return Err(Error::Unknown(format!(
            "git recency mapping entry count ({}) does not match guard count ({guard_count}) in '{}'",
            entries.len(),
            link_output.display()
        )));
    }

    let mut resolved: Vec<Vec<(String, u32)>> = Vec::with_capacity(entries.len());
    for entry in entries {
        let mut locs: Vec<(String, u32)> = Vec::new();
        for loc in entry.locs {
            if loc.line == 0 {
                continue;
            }

            let p = PathBuf::from(loc.file);
            let p = if p.is_absolute() { p } else { cwd.join(p) };
            let Ok(p) = fs::canonicalize(&p) else {
                continue;
            };
            if !p.starts_with(&repo_root) {
                continue;
            }

            let rel = p.strip_prefix(&repo_root).unwrap();
            let rel = rel.to_string_lossy().replace('\\', "/");
            locs.push((rel, loc.line));
        }
        locs.sort_unstable();
        locs.dedup();
        resolved.push(locs);
    }

    let mut needed_by_file: HashMap<String, HashSet<u32>> = HashMap::new();
    for entry_locs in &resolved {
        for (file, line) in entry_locs {
            needed_by_file
                .entry(file.clone())
                .or_default()
                .insert(*line);
        }
    }

    let mut times_by_file: HashMap<String, HashMap<u32, u64>> = HashMap::new();
    for (file, needed_lines) in &needed_by_file {
        let times = blame_times_for_lines(&repo_root, file, needed_lines)?;
        times_by_file.insert(file.clone(), times);
    }

    let mut timestamps: Vec<u64> = Vec::with_capacity(resolved.len());
    for entry_locs in resolved {
        let mut max_t = 0u64;
        for (file, line) in entry_locs {
            let t = times_by_file
                .get(&file)
                .and_then(|m| m.get(&line))
                .copied()
                .unwrap_or(0);
            max_t = max_t.max(t);
        }
        timestamps.push(max_t);
    }

    let mut out = fs::File::create(mapping_out).map_err(Error::Io)?;
    write_u64_le(&mut out, head_time)?;
    write_u64_le(&mut out, timestamps.len() as u64)?;
    for t in timestamps {
        write_u64_le(&mut out, t)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SIDECAR_MAGIC_V1, SIDECAR_MAGIC_V2, parse_sidecar, parse_sidecar_stream};

    #[test]
    fn test_parse_sidecar_empty() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SIDECAR_MAGIC_V2);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        let entries = parse_sidecar(&bytes).unwrap();
        assert!(entries.is_empty());
    }

    fn build_sidecar_blob_v1(entries: &[(u32, Option<&str>)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SIDECAR_MAGIC_V1);
        bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for (line, path) in entries {
            bytes.extend_from_slice(&line.to_le_bytes());
            if let Some(path) = path {
                bytes.extend_from_slice(&(path.len() as u32).to_le_bytes());
                bytes.extend_from_slice(path.as_bytes());
            } else {
                bytes.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        bytes
    }

    fn build_sidecar_blob_v2(entries: &[&[(u32, Option<&str>)]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SIDECAR_MAGIC_V2);
        bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for locs in entries {
            bytes.extend_from_slice(&(locs.len() as u32).to_le_bytes());
            for (line, path) in *locs {
                bytes.extend_from_slice(&line.to_le_bytes());
                if let Some(path) = path {
                    bytes.extend_from_slice(&(path.len() as u32).to_le_bytes());
                    bytes.extend_from_slice(path.as_bytes());
                } else {
                    bytes.extend_from_slice(&0u32.to_le_bytes());
                }
            }
        }
        bytes
    }

    #[test]
    fn test_parse_sidecar_v1() {
        let bytes = build_sidecar_blob_v1(&[(12, Some("a.c")), (0, None)]);
        let entries = parse_sidecar(&bytes).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].locs.len(), 1);
        assert_eq!(entries[0].locs[0].line, 12);
        assert_eq!(entries[0].locs[0].file.as_str(), "a.c");
        assert!(entries[1].locs.is_empty());
    }

    #[test]
    fn test_parse_sidecar_stream_concat() {
        let blob1 = build_sidecar_blob_v2(&[&[(12, Some("a.c")), (0, None)], &[]]);
        let blob2 = build_sidecar_blob_v2(&[&[(7, Some("b.c"))]]);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&blob1);
        bytes.extend_from_slice(&blob2);

        let entries = parse_sidecar_stream(&bytes).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].locs.len(), 1);
        assert_eq!(entries[0].locs[0].line, 12);
        assert_eq!(entries[0].locs[0].file.as_str(), "a.c");
        assert!(entries[1].locs.is_empty());
        assert_eq!(entries[2].locs.len(), 1);
        assert_eq!(entries[2].locs[0].line, 7);
        assert_eq!(entries[2].locs[0].file.as_str(), "b.c");
    }
}
