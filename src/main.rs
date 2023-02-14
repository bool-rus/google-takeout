use std::process::exit;
use std::collections::{HashSet, HashMap};
use std::path::PathBuf;
use std::io::{Read, Write};
use std::time::SystemTime;


use anyhow::Result;
use chrono::TimeZone;
use libflate::gzip::Decoder;
use serde::Deserialize;
use tar::{Archive, Entry};
use xxhash_rust::xxh64::Xxh64;

type FileHash = u64;
type DateTime = chrono::DateTime<chrono::Local>;

const TAKEOUT: &str = "takeout";
const CURRENT: &str = "current";
const DATE_FORMAT: &str = "%Y/%m/%d/%Y%m%d_%H%M%S";


fn main() {
    simple_logger::SimpleLogger::new().env().init().unwrap();
    std::fs::create_dir_all("takeout").unwrap();
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
    log::info!("albums:");
    for name in lib.albums.keys() {
        println!("\t{name}");
    }
    log::info!("duplicates_counter: {}", lib.duplicates_counter);

    log::info!("analyse dates");
    let result = lib.analyze();
    update_folder(&result).unwrap();
    log::info!("save albums");
    for (name, album) in result.albums {
        save_album(name, album, &result.files).unwrap();
    }

}

fn save_album(name: String, album: Album, map: &HashMap<FileHash, (PathBuf, Metadata)>) -> Result<()> {
    let mut file = std::fs::File::create(name)?;
    for hash in album.files {
        if let Some((ex, md)) = map.get(&hash) {
            let path = make_path(hash, ex, &md.taken_time);
            file.write_all(path.to_string_lossy().as_bytes())?;
            file.write_all("\n".as_bytes())?;
        }
    }
    file.flush()?;
    Ok(())
}

fn make_path(hash: u64, extension: &PathBuf, dt: &DateTime) -> PathBuf {
    let mut path = PathBuf::from(TAKEOUT);
    path.push(format!("{}_{hash:016x}", dt.format(DATE_FORMAT).to_string()));
    path.with_extension(extension)
}

fn update_folder(result: &AnalyzeResult) -> Result<()> {
    for (&hash, (extension, meta)) in &result.files {
        let date = meta.taken_time;
        let mut from_path = PathBuf::from(TAKEOUT);
        from_path.push(format!("{hash:016x}"));
        let to_path = make_path(hash, extension, &date);
        log::info!("move {hash:016x} to {}", to_path.to_string_lossy());
        if let Some(parent) = to_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(from_path, to_path.clone())?;
        let st: SystemTime = date.into();
        filetime::set_file_mtime(to_path, st.into())?;
    }
    Ok(())
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

fn process_json(lib: &mut Library, path: &PathBuf, text: &str) -> Result<()> {
    let meta: Metadata = serde_json::from_str(text)?;
    lib.add_meta(path.clone(), meta);
    return Ok(());
}

fn fix_json_path(path: PathBuf) -> PathBuf {
    let regex = regex::Regex::new(r"(.*?)\.(.*?)\((\d+)\)").unwrap(); //fix some.jpg(1).json to some(1).jpg.json
    let pathstr = path.to_string_lossy();
    let replaced = regex.replace(pathstr.as_ref(), "$1($3).$2");
    PathBuf::from(replaced.as_ref())
}

fn process_entry<'a, R: Read + 'a>(lib: &mut Library, mut entry: Entry<'a, R>) -> Result<()> {

    let size = entry.size();
    if size == 0 {
        return Ok(())
    }
    let mtime = entry.header().mtime().ok();
    let path = entry.path()?.to_path_buf();
    let tar_meta = TarMeta::new(&path, size);
    if let Some(ex) = path.extension() {
        if ex.to_str() == Some("json") {
            log::info!("Founded json: {}", path.to_string_lossy());
            let mut buf = String::with_capacity(size as usize);
            entry.read_to_string(&mut buf)?;
            let path = fix_json_path(path);
            if let Err(e) = process_json(lib, &path, buf.as_str()) {
                log::error!("Err on process {}: {e}", path.to_string_lossy());
                log::trace!("json: {buf}");
            }
            return Ok(());
        }
    }
    let current_path = format!("{TAKEOUT}/{CURRENT}");
    let lib_hash = lib.find_duplicates(&tar_meta);
    let mut hasher = if lib_hash.is_some() {
        HashedWrite::new()
    } else {
        let file = std::fs::File::create(&current_path)?;
        HashedWrite::with_write(file)
    };
    std::io::copy(&mut entry, &mut hasher)?;
    let hash = hasher.digest();
    let is_duplicate = lib.add_file(path.clone(), hash, size);

    if let Some(_file) = hasher.writer() {
        if is_duplicate {
            std::fs::remove_file(&current_path)?;
        } else  {
            let save_path = PathBuf::from(format!("{TAKEOUT}/{hash:016x}"));
            std::fs::rename(&current_path, save_path)?;
        }
    }
    if let Some(lib_hash) = lib_hash {
        if lib_hash != hash {
            log::error!("Different files with same size and name");
        }
    }
    log::info!("{hash:016x} {}", path.to_string_lossy());
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
    files_by_hash: HashMap<FileHash, Vec<PathBuf>>,  
    files_by_tar_meta: HashMap<TarMeta, FileHash>,
    albums: HashMap<String, Album>, //
    meta: HashMap<PathBuf, Metadata>,
}

fn next_stem(path: &PathBuf) -> Option<PathBuf> {
    let next = path.with_extension("");
    if &next == path {
        None
    } else {
        Some(next)
    }
}

impl Library {
    pub fn find_duplicates(&mut self, meta: &TarMeta) -> Option<FileHash> {
        self.files_by_tar_meta.get(meta).copied()
    }
    fn add_file_by_tarmeta(&mut self, path: &PathBuf, size: u64, hash: FileHash) {
        let key = TarMeta::new(&path, size);
        self.files_by_tar_meta.insert(key, hash);
    }
    pub fn add_meta(&mut self, mut path: PathBuf, meta: Metadata) {
        while let Some(next) = next_stem(&path) {
            path = next;
            self.meta.insert(path.clone(), meta.clone());
        }
    }
    pub fn add_file(&mut self, path: PathBuf, hash: FileHash, size: u64) -> bool {
        let mut is_duplicate = false;

        self.add_file_by_tarmeta(&path, size, hash);
        let paths = self.files_by_hash.entry(hash).or_default();
        if !paths.is_empty() {
            is_duplicate = true;
            self.duplicates_counter += 1;
        }
        paths.push(path.clone());

        if let Some(parent) = path.parent() {
            let album = parent.file_name().map(|s|s.to_string_lossy().to_string()).unwrap_or("UNKNOWN".to_string());
            let album = self.albums.entry(album).or_default();
            album.files.insert(hash.clone());
        }

        is_duplicate
    }

    pub fn analyze(self) -> AnalyzeResult {
        let mut files = HashMap::default();
        let mut unknown_hashes = Vec::new();
        let Library { duplicates_counter, mut files_by_hash, files_by_tar_meta, albums, meta } = self;
        for (hash, paths) in files_by_hash {
            let ex = paths.first().unwrap().extension().map(PathBuf::from).unwrap_or(PathBuf::from(""));
            if let Some(metadata) = find_meta_in_paths(&meta, &paths) {
                files.insert(hash, (ex, metadata));
            } else if let Some(metadata) = find_meta_in_paths(&meta, &paths) { 
                files.insert(hash, (ex, metadata));
            } else {
                unknown_hashes.push(hash);
            }
        }
        AnalyzeResult { unknown_hashes, files, albums}
    }
}

fn find_meta_in_fixed_paths(map: &HashMap<PathBuf, Metadata>, paths: &[PathBuf]) -> Option<Metadata> {
    let regex = regex::Regex::new(r"(.*)-\w+").unwrap();
    let fixed_paths: Vec<_> = paths.into_iter().map(|p|{
        let s = p.to_string_lossy();
        let fixed = regex.replace(s.as_ref(), "$1");
        PathBuf::from(fixed.as_ref())
    }).collect();

    find_meta_in_paths(map, &fixed_paths)
}

fn find_meta_in_paths(map: &HashMap<PathBuf, Metadata>, paths: &[PathBuf]) -> Option<Metadata> {
    for path in paths {
        let meta = find_meta(map, path);
        if meta.is_some() {
            return meta;
        }
    }
    None
}
fn find_meta(map: &HashMap<PathBuf, Metadata>, path: &PathBuf) -> Option<Metadata> {
    let mut path = path.clone();
    while let Some(next) = next_stem(&path) {
        path = next;
        let metadata = map.get(&path);
        if metadata.is_some() {
            return metadata.cloned();
        }
    }
    None
}
struct AnalyzeResult {
    unknown_hashes: Vec<FileHash>,
    files: HashMap<FileHash, (PathBuf, Metadata)>,
    albums: HashMap<String, Album>,
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
    let r = chrono::Local.timestamp_opt(value, 0).unwrap();
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

#[test]
fn test_format() {
    let dt = chrono::Utc::now();
    let dt_utc: DateTime = dt.into();
    assert_eq!(dt.timestamp(), dt_utc.timestamp());
    let dt_str = dt.format("%Y/%m/%d/%Y%m%d_%H%M%S").to_string();
    println!("{dt_str}");
}

#[test]
fn test_regex() {
    let input =  "Takeout/Google Фото/Рыбалка/IMG_20170715_142514-EFFECTS.jpg(1).json";
    let output = "Takeout/Google Фото/Рыбалка/IMG_20170715_142514-EFFECTS(1).jpg.json";
    let regex = regex::Regex::new(r"(.*?)\.(.*?)\((\d+)\)").unwrap();
    let real = regex.replace(input, "$1($3).$2");
    assert_eq!(output, real.as_ref())
}

#[test]
fn test_regex2() {
    let input  = "Takeout/Google Фото/Рыбалка/IMG_20170715_142514_EFFECTS-измененный.jpg";
    let output = "Takeout/Google Фото/Рыбалка/IMG_20170715_142514_EFFECTS.jpg";
    let regex = regex::Regex::new(r"(.*)-\w+").unwrap();
    let real = regex.replace(input, "$1");
    assert_eq!(output, real.as_ref());
    let real = regex.replace(output, "$1");
    assert_eq!(output, real.as_ref());
}