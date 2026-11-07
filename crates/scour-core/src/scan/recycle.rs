//! Parser for Windows Recycle Bin `$I` metadata files.
//!
//! When a file is sent to the recycle bin, Windows stores two entries in
//! `<drive>:\$Recycle.Bin\<user-SID>\`:
//!   * `$I<id><ext>` — a small metadata record (original path, size, delete time);
//!   * `$R<id><ext>` — the actual file or directory contents.
//!
//! This module decodes the `$I` record. It is compiled on every platform (and
//! unit-tested) so the bit-twiddling is verified regardless of host, even
//! though it is only *used* by the Windows branch of the trash scanner.
//!
//! `$I` layout (little-endian):
//! ```text
//!   0  u64   header/version (1 = pre-Win10, 2 = Win10+)
//!   8  u64   original size in bytes
//!  16  u64   deletion time (Windows FILETIME, 100ns ticks since 1601-01-01)
//!  24  ...   original path, UTF-16LE:
//!              v1: fixed 520 bytes (260 code units, NUL-padded)
//!              v2: u32 length in code units (incl. NUL), then that many units
//! ```

#![allow(dead_code)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Difference between the Windows FILETIME epoch (1601-01-01) and the Unix
/// epoch (1970-01-01), in seconds.
const FILETIME_UNIX_DELTA_SECS: u64 = 11_644_473_600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecycleMeta {
    /// Original size of the deleted item, as recorded by Windows.
    pub original_size: u64,
    /// Original absolute path before deletion.
    pub original_path: String,
    /// When the item was deleted, if the timestamp is representable.
    pub deleted_at: Option<SystemTime>,
}

/// Parse a `$I` metadata record. Returns `None` if the bytes are too short or
/// structurally invalid.
pub fn parse_i_file(bytes: &[u8]) -> Option<RecycleMeta> {
    if bytes.len() < 24 {
        return None;
    }
    let version = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let original_size = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let filetime = u64::from_le_bytes(bytes[16..24].try_into().ok()?);

    let units: Vec<u16> = if version >= 2 {
        // v2: length prefix (code units including the trailing NUL).
        if bytes.len() < 28 {
            return None;
        }
        let len = u32::from_le_bytes(bytes[24..28].try_into().ok()?) as usize;
        let start: usize = 28;
        let end = start.checked_add(len.checked_mul(2)?)?;
        if end > bytes.len() {
            return None;
        }
        decode_utf16le(&bytes[start..end])
    } else {
        // v1: fixed 520-byte (260 code unit) field.
        let start = 24;
        let end = start + 520;
        if end > bytes.len() {
            return None;
        }
        decode_utf16le(&bytes[start..end])
    };

    let original_path = utf16_to_string_trimmed(&units);
    if original_path.is_empty() {
        return None;
    }

    Some(RecycleMeta {
        original_size,
        original_path,
        deleted_at: filetime_to_systemtime(filetime),
    })
}

fn decode_utf16le(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// Decode UTF-16 code units up to (but excluding) the first NUL terminator.
fn utf16_to_string_trimmed(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// Convert a Windows FILETIME to `SystemTime`. Returns `None` for timestamps
/// before the Unix epoch (which should not occur for real deletions).
fn filetime_to_systemtime(filetime: u64) -> Option<SystemTime> {
    let total_secs = filetime / 10_000_000;
    let nanos = (filetime % 10_000_000) * 100;
    let unix_secs = total_secs.checked_sub(FILETIME_UNIX_DELTA_SECS)?;
    Some(UNIX_EPOCH + Duration::new(unix_secs, nanos as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        v.extend_from_slice(&[0, 0]); // NUL terminator
        v
    }

    #[test]
    fn parses_v2_record() {
        let path = "C:\\Users\\sam\\report.txt";
        let name = utf16le(path);
        let units = (name.len() / 2) as u32; // includes NUL

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes()); // version 2
        bytes.extend_from_slice(&4096u64.to_le_bytes()); // size
        bytes.extend_from_slice(&0u64.to_le_bytes()); // filetime (pre-epoch -> None)
        bytes.extend_from_slice(&units.to_le_bytes()); // length prefix
        bytes.extend_from_slice(&name);

        let meta = parse_i_file(&bytes).expect("v2 should parse");
        assert_eq!(meta.original_size, 4096);
        assert_eq!(meta.original_path, path);
        assert_eq!(meta.deleted_at, None);
    }

    #[test]
    fn parses_v1_record_with_fixed_field() {
        let path = "D:\\data\\old.bin";
        let mut field = utf16le(path);
        field.resize(520, 0); // pad to the fixed 260-code-unit field

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u64.to_le_bytes()); // version 1
        bytes.extend_from_slice(&123u64.to_le_bytes()); // size
        // A realistic FILETIME: 2021-01-01T00:00:00Z.
        let ft = (1_609_459_200u64 + FILETIME_UNIX_DELTA_SECS) * 10_000_000;
        bytes.extend_from_slice(&ft.to_le_bytes());
        bytes.extend_from_slice(&field);

        let meta = parse_i_file(&bytes).expect("v1 should parse");
        assert_eq!(meta.original_size, 123);
        assert_eq!(meta.original_path, path);
        let secs = meta
            .deleted_at
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(secs, 1_609_459_200);
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse_i_file(&[0u8; 8]).is_none());
        // v2 claims a huge name length that exceeds the buffer.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&9999u32.to_le_bytes());
        assert!(parse_i_file(&bytes).is_none());
    }
}
