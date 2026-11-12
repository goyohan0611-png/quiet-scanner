use crate::packet;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::Path,
    sync::OnceLock,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Entry {
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub prefixes: Vec<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Book {
    #[serde(default)]
    pub entries: Vec<Entry>,
}
#[derive(Default)]
pub struct Description {
    pub vendor: String,
    pub kind: String,
    pub note: String,
    pub from_book: bool,
    pub exact: bool,
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?
    }
    let temp = path.with_extension("json.tmp");
    {
        let mut file =
            fs::File::create(&temp).map_err(|e| format!("저장 파일을 만들지 못했습니다: {e}"))?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("기록 저장 실패: {e}"))?;
    }
    fs::rename(&temp, path).map_err(|e| format!("저장 파일 교체 실패: {e}"))
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}
impl Book {
    pub fn defaults() -> Self {
        serde_json::from_slice(include_bytes!("../../src/device-book.json"))
            .expect("bundled device book")
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::defaults());
        }
        let mut b: Self = read_json(path)?;
        if b.entries.is_empty() {
            return Ok(b);
        }
        // The legacy loader accepted separated MACs and ignored incomplete
        // prefixes. Preserve that behavior when importing an existing book.
        for e in &mut b.entries {
            e.prefixes = e
                .prefixes
                .iter()
                .filter_map(|p| packet::digits(p).ok())
                .filter(|p| (6..=12).contains(&p.len()))
                .collect();
        }
        b.entries.retain(|e| !e.prefixes.is_empty());
        Ok(b)
    }
    pub fn rows(&self) -> Vec<[String; 4]> {
        let mut rows: Vec<_> = self
            .entries
            .iter()
            .flat_map(|e| {
                e.prefixes
                    .iter()
                    .map(move |p| [p.clone(), e.vendor.clone(), e.kind.clone(), e.note.clone()])
            })
            .collect();
        rows.sort_by(|a, b| {
            a[1].to_lowercase()
                .cmp(&b[1].to_lowercase())
                .then(a[0].cmp(&b[0]))
        });
        rows
    }
    pub fn lookup(&self, p: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.prefixes.iter().any(|x| x.eq_ignore_ascii_case(p)))
    }
    pub fn describe(&self, mac: &str) -> Description {
        let hex = packet::digits(mac).unwrap_or_default();
        let mut result = Description {
            vendor: vendor(&hex),
            ..Default::default()
        };
        for width in (6..=hex.len()).rev() {
            if let Some(e) = self.lookup(&hex[..width]) {
                if !e.vendor.is_empty() {
                    result.vendor = e.vendor.clone()
                }
                result.kind = e.kind.clone();
                result.note = e.note.clone();
                result.from_book = true;
                result.exact = width == 12;
                break;
            }
        }
        result
    }
    pub fn upsert(
        &mut self,
        prefix: &str,
        vendor: &str,
        kind: &str,
        note: &str,
    ) -> Result<bool, String> {
        let p = packet::digits(prefix)?;
        if p.len() < 6 || p.len() > 12 || (p.len() % 2 != 0 && self.lookup(&p).is_none()) {
            return Err("MAC 앞자리는 3~6바이트로 입력하십시오. 예: 70-B3-D5-21".into());
        }
        if vendor.len() > 400 || kind.len() > 400 || note.len() > 1200 {
            return Err("사전 입력 내용이 너무 깁니다.".into());
        }
        let created = self.lookup(&p).is_none();
        self.remove(&p);
        self.entries.push(Entry {
            vendor: vendor.trim().into(),
            kind: kind.trim().into(),
            note: note.trim().into(),
            prefixes: vec![p],
        });
        Ok(created)
    }
    pub fn remove(&mut self, p: &str) {
        for e in &mut self.entries {
            e.prefixes.retain(|v| !v.eq_ignore_ascii_case(p))
        }
        self.entries.retain(|e| !e.prefixes.is_empty());
    }
    pub fn save(&self, path: &Path) -> Result<(), String> {
        atomic_write(
            path,
            &serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?,
        )
    }
}
fn vendor(mac: &str) -> String {
    static OUI: OnceLock<HashMap<String, String>> = OnceLock::new();
    let table = OUI.get_or_init(|| {
        let mut text = String::new();
        let _ =
            GzDecoder::new(&include_bytes!("../../src/oui.dat.gz")[..]).read_to_string(&mut text);
        text.lines()
            .filter_map(|line| {
                line.split_once('\t')
                    .map(|(p, v)| (p.to_ascii_lowercase(), v.to_owned()))
            })
            .collect()
    });
    for width in (1..=mac.len()).rev() {
        if let Some(name) = table.get(&mac[..width]) {
            return name.clone();
        }
    }
    "미확인".into()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_separators_and_incomplete_prefixes() {
        let root =
            std::env::temp_dir().join(format!("quiet-legacy-book-test-{}", rand::random::<u64>()));
        let path = root.join("book.json");
        atomic_write(&path,br#"{"entries":[{"vendor":"old","prefixes":["00-0C-0C-0C-0C-0C","02-04-","bad"]},{"vendor":"override","prefixes":["000c0c0c0c0c"]}]}"#).unwrap();
        let b = Book::load(&path).unwrap();
        assert_eq!(b.rows().len(), 2);
        assert_eq!(b.describe("00:0c:0c:0c:0c:0c").vendor, "override");
        assert!(b.lookup("0204").is_none());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
    #[test]
    fn longest_prefix_and_removal() {
        let mut b = Book::default();
        b.upsert("70-B3-D5", "기본", "", "").unwrap();
        b.upsert("70-B3-D5-21", "녹화기", "NVR", "").unwrap();
        b.upsert("70-B3-D5-21-B7-CE", "한 대", "특정 장비", "")
            .unwrap();
        assert_eq!(b.describe("70:b3:d5:21:b7:ce").vendor, "한 대");
        b.remove("70b3d521b7ce");
        assert_eq!(b.describe("70:b3:d5:21:b7:ce").kind, "NVR");
        b.remove("70b3d521");
        assert_eq!(b.describe("70:b3:d5:21:b7:ce").vendor, "기본");
    }
    #[test]
    fn defaults_and_user_validation() {
        assert!(Book::defaults().rows().len() > 2000);
        let mut b = Book::default();
        for p in ["zz-70-B3-D5", "70-B3-D", "70-B3-D5-21-B7-CE-FF"] {
            assert!(b.upsert(p, "", "", "").is_err())
        }
    }
    #[test]
    fn persistence_replaces_existing_file() {
        let root = std::env::temp_dir().join(format!("quiet-book-test-{}", rand::random::<u64>()));
        let path = root.join("book.json");
        let mut b = Book::default();
        b.upsert("70b3d521", "첫번째", "NVR", "").unwrap();
        b.save(&path).unwrap();
        b.upsert("70b3d521", "수정", "NVR", "").unwrap();
        b.save(&path).unwrap();
        assert_eq!(
            Book::load(&path).unwrap().describe("70b3d521b7ce").vendor,
            "수정"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}
