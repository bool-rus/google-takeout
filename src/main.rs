use std::process::exit;
use std::collections::{HashSet, HashMap};
use std::path::PathBuf;
use std::io::{Read, BufReader, BufRead, Write};


use anyhow::Result;
use chrono::TimeZone;
use libflate::gzip::Decoder;
use serde::Deserialize;
use tar::{Archive, Entry};
use xxhash_rust::xxh64::Xxh64;

type FileHash = u64;
type DateTime = chrono::DateTime<chrono::Utc>;


fn main() {
    simple_logger::SimpleLogger::new().env().init().unwrap();
    std::fs::create_dir_all("takeout");
    let mut lib = Library::default();
    loop {
        match process_stdin(&mut lib) {
            Ok(true) => break,
            Ok(false) => log::info!("archive finished"),
            Err(e) => {
                log::error!("{e}");
                exit(1);
            }
        }
    }
    println!("albums:");
    for name in lib.albums.keys() {
        println!("\t{name}");
    }
    println!("duplicates_counter: {}", lib.duplicates_counter);
}

fn process_stdin(lib: &mut Library) -> Result<bool> {
    let mut stdin = std::io::stdin();
    let decoded = match Decoder::new(&mut stdin) {
        Ok(d) => d,
        Err(e) => if matches!(e.kind(), std::io::ErrorKind::UnexpectedEof) {
            return Ok(true);
        } else {
            Err(e)?
        }
    };
    let mut archive = Archive::new(decoded);
    archive.set_ignore_zeros(true);
    for entry in archive.entries()? {
        process_entry(lib, entry?)?;
    }
    Ok(false)
}

fn process_entry<'a, R: Read + 'a>(lib: &mut Library, mut entry: Entry<'a, R>) -> Result<()> {

    let size = entry.size();
    let path = entry.path()?.to_path_buf();
    let pathstr = path.to_string_lossy();
    let tar_meta = TarMeta::new(&path, size);
    if let Some(ex) = path.extension() {
        if ex.to_str() == Some("json") {
            let mut buf = String::with_capacity(size as usize);
            entry.read_to_string(&mut buf)?;
            let meta: Metadata = serde_json::from_str(buf.as_str())?;
            lib.add_meta(path, meta);
            log::warn!("json founded!");
            return Ok(());
        }
    }
    let lib_hash = lib.find_duplicates(&tar_meta);
    let mut hasher = if lib_hash.is_some() {
        HashedWrite::new()
    } else {
        let file = std::fs::File::create("takeout/current")?;
        HashedWrite::with_write(file)
    };
    std::io::copy(&mut entry, &mut hasher)?;
    let hash = hasher.digest();
    let is_duplicate = lib.add_file(path.clone(), hash, size);

    if let Some(_file) = hasher.writer() {
        if is_duplicate {
            std::fs::remove_file("takeout/current")?;
        } else  {
            let mut save_path = PathBuf::from(format!("takeout/{hash:016x}"));
            if let Some(ex) = path.extension() {
                save_path = save_path.with_extension(ex);
            }
            std::fs::rename("takeout/current", save_path)?;
        }
    }
    if let Some(lib_hash) = lib_hash {
        if lib_hash != hash {
            log::error!("Different files with same size and name");
        }
    }

    // Inspect metadata about the file
    log::info!("{hash:016x}: {pathstr}");
    Ok(())
}

#[derive(Default)]
struct Album {
    files: HashSet<FileHash>
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct TarMeta {
    name: Option<PathBuf>,
    size: u64,
}

impl TarMeta {
    fn new(path: &PathBuf, size: u64) -> Self {
        let name = path.file_name().map(PathBuf::from);
        Self { name, size}
    }
}

#[derive(Default)]
struct Library {
    duplicates_counter: u32,
    files_by_hash: HashMap<FileHash, Option<PathBuf>>,  
    files_by_path: HashMap<PathBuf, FileHash>, 
    files_by_tar_meta: HashMap<TarMeta, FileHash>,
    albums: HashMap<String, Album>, //
    meta: HashMap<PathBuf, Metadata>,
}

impl Library {
    pub fn find_duplicates(&mut self, meta: &TarMeta) -> Option<FileHash> {
        self.files_by_tar_meta.get(meta).copied()
    }
    fn add_file_by_tarmeta(&mut self, path: &PathBuf, size: u64, hash: FileHash) {
        let key = TarMeta::new(&path, size);
        self.files_by_tar_meta.insert(key, hash);
    }
    pub fn add_meta(&mut self, path: PathBuf, meta: Metadata) {
        let mut prev_stem = path.clone();
        loop {
            let stem = prev_stem.with_extension("");
            if stem == prev_stem {
                break;
            } else {
                prev_stem = stem.clone();
                self.meta.insert(stem, meta.clone());
            }
        }
    }
    pub fn add_file(&mut self, path: PathBuf, hash: FileHash, size: u64) -> bool {
        let mut is_duplicate = true;

        self.add_file_by_tarmeta(&path, size, hash);
        self.files_by_hash.entry(hash).or_insert_with(||{
            is_duplicate = false;
            path.extension().map(PathBuf::from)
        });
        if is_duplicate {
            self.duplicates_counter += 1;
        }

        if let Some(parent) = path.parent() {
            let album = parent.file_name().map(|s|s.to_string_lossy().to_string()).unwrap_or("UNKNOWN".to_string());
            let album = self.albums.entry(album).or_default();
            album.files.insert(hash.clone());
        }
        
        self.files_by_path.insert(path, hash);

        is_duplicate
    }
}


#[derive(Clone, Debug, Deserialize)]
struct Metadata {
    #[serde(rename = "photoTakenTime", deserialize_with="property_to_float")]
    taken_time: DateTime,
}



pub fn property_to_float<'de, D>(deserializer: D) -> Result<DateTime, D::Error>
    where D: serde::de::Deserializer<'de>,
{   
    #[derive(Deserialize)]
    struct TakenTime {
        pub timestamp: String,
    }

    let helper = TakenTime::deserialize(deserializer)?;
    
    let value = helper.timestamp.parse::<i64>().unwrap();
    let r = chrono::Utc.timestamp_opt(value, 0).unwrap();
    Ok(r)
}


#[test]
fn test_path() {
    let p = PathBuf::from("one/two/three/file.ex.json");
    let extension = p.extension().unwrap().to_string_lossy();
    let parent = p.parent().unwrap();
    let parent_name = parent.file_name().unwrap();
    let name = p.file_name().unwrap();
    let stem = p.with_extension("").with_extension("").with_extension("");
    println!("extension: {}, parent: {}, parent_name: {}, name: {}, stem: {}", extension, parent.to_string_lossy(), 
        parent_name.to_string_lossy(), name.to_string_lossy(), stem.to_string_lossy());
}

#[test]
fn test_deser() {
    let s = include_str!("../2012-03-29-005.jpg.json");
    let meta = serde_json::from_str::<Metadata>(s).unwrap();
    println!("meta: {:?}", meta);
}

struct HashedWrite<W> {
    hash: Xxh64,
    write: Option<W>,
}
impl<W> HashedWrite<W> {
    pub fn new() -> Self {
        Self { hash: Xxh64::new(0), write: None }
    }
    pub fn with_write(write: W) -> Self {
        Self { hash: Xxh64::new(0), write: Some(write)}
    }
    pub fn digest(&self) -> FileHash {
        self.hash.digest()
    }
    pub fn writer(self) -> Option<W> {
        self.write
    }
}

impl <W: Write> Write for HashedWrite<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let size = if let Some(w) = &mut self.write {
            w.write(buf)?
        } else {
            buf.len()
        };
        self.hash.update(&buf[0..size]);
        Ok(size)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.write.as_mut().map(|w|w.flush()).unwrap_or(Ok(()))
    }
}