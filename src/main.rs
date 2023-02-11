use std::process::exit;
use std::collections::{HashSet, HashMap};
use std::path::PathBuf;
use std::io::{Read, BufReader, BufRead};


use anyhow::Result;
use chrono::TimeZone;
use libflate::gzip::Decoder;
use serde::Deserialize;
use sha2::{Sha256, Digest};
use tar::{Archive, Entry};

type FileHash = Vec<u8>;
type DateTime = chrono::DateTime<chrono::Utc>;


fn main() {
    simple_logger::SimpleLogger::new().env().init().unwrap();
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

fn process_entry<'a, R: Read + 'a>(lib: &mut Library, mut file: Entry<'a, R>) -> Result<()> {

    let size = file.size();
    let path = file.path()?.to_path_buf();
    if let Some(ex) = path.extension() {
        if ex.to_str() == Some("json") {
            let mut buf = String::with_capacity(size as usize);
            file.read_to_string(&mut buf)?;
            let meta: Metadata = serde_json::from_str(buf.as_str())?;
            lib.add_meta(path, meta);
            return Ok(());
        }
    }
    //let header = file.header();
    //println!("{:?}", header);
    //println!("{}", header.mode()?);
    let mut hasher = Sha256::new();
    let mut reader = BufReader::with_capacity(128*1024, file);

    loop {
        let buf = reader.fill_buf()?;
        let n = buf.len();
        if buf.len() == 0 {
            break;
        }
        hasher.update(&buf);
        reader.consume(n);
    }
    let hash = hasher.finalize().to_vec();
    lib.add_file(path.clone(), hash.clone());
    let strhash = hash.iter().fold(String::new(), |s, b|{
        format!("{s}{:02x}", b)
    });
    let path = path.to_string_lossy();
    // Inspect metadata about the file
    log::info!("{strhash}: {path}");
    Ok(())
}

#[derive(Default)]
struct Album {
    files: HashSet<FileHash>
}
#[derive(Default)]
struct Library {
    files_by_hash: HashMap<FileHash, Vec<PathBuf>>,  
    files_by_path: HashMap<PathBuf, FileHash>, 
    albums: HashMap<String, Album>, //
    meta: HashMap<PathBuf, Metadata>,
}

impl Library {
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
    pub fn add_file(&mut self, path: PathBuf, hash: FileHash) -> bool {
        let mut is_duplicate = false;
        let paths = self.files_by_hash.entry(hash.clone()).or_default();
        if !paths.is_empty() {
            is_duplicate = true;
        }
        paths.push(path.clone());

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