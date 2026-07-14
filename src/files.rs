//! Get the wordlist from the file
//!
//! Try to do it without copies by mapping the file in memory

use std::fs::{File, OpenOptions};

use anyhow::Result;
use csv::WriterBuilder;
use memchr::memchr_iter;
use memmap2::Mmap;

use crate::fuzz::FuzzResult;

/// Stores the access to the wordlist
pub struct WordList {
    mmap: Mmap,
    words: Vec<(usize, usize)>,
}

impl WordList {
    /// Map the wordlist's file into memory
    /// 
    /// Credit: https://oneuptime.com/blog/post/2026-01-25-parse-large-files-zero-copy-rust/view
    pub fn new(wordlist_path: &str) -> Result<WordList> {
        let file = File::open(wordlist_path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        let mut words = Vec::new();
        let mut start = 0;

        for end in memchr_iter(b'\n', &mmap) {
            words.push((start, end));
            start = end + 1;
        }

        if start < mmap.len() {
            words.push((start, mmap.len()));
        }

        Ok(WordList { mmap, words })
    }

    /// Return an interator to the wordlist
    pub fn words(&self) -> impl Iterator<Item = &str> {
        self.words.iter().map(move |&(start, end)| {
            std::str::from_utf8(&self.mmap[start..end])
                .expect("Couldn't convert the bytes to an str")
        })
    }
}

/// Write the data to a file in CSV format
pub fn write_to_disk(data: &[FuzzResult], output: &str) -> Result<()> {
    // Overwrite the file
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output)?;

    let mut wtr = WriterBuilder::new()
        .has_headers(true)
        .from_writer(file);

    wtr.flush()?;

    for item in data {
        wtr.serialize(item)?;
    }
    
    wtr.flush()?;

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
 
    /// Helper: write `content` to a temp file and return its path
    fn write_temp_file(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("failed to create temp file");
        f.write_all(content.as_bytes()).expect("failed to write temp file");
        f.flush().expect("failed to flush temp file");
        f
    }
 
    #[test]
    fn wordlist_parses_simple_newline_separated_words() {
        let f = write_temp_file("admin\nlogin\nFUZZ\n");
        let wl = WordList::new(f.path().to_str().unwrap()).unwrap();
        let words: Vec<&str> = wl.words().collect();
        assert_eq!(words, vec!["admin", "login", "FUZZ"]);
    }
 
    #[test]
    fn wordlist_handles_missing_trailing_newline() {
        let f = write_temp_file("one\ntwo\nthree");
        let wl = WordList::new(f.path().to_str().unwrap()).unwrap();
        let words: Vec<&str> = wl.words().collect();
        assert_eq!(words, vec!["one", "two", "three"]);
    }
 
    #[test]
    fn wordlist_handles_empty_lines() {
        let f = write_temp_file("a\n\nb\n");
        let wl = WordList::new(f.path().to_str().unwrap()).unwrap();
        let words: Vec<&str> = wl.words().collect();
        assert_eq!(words, vec!["a", "", "b"]);
    }
 
    #[test]
    fn wordlist_handles_empty_file() {
        let f = write_temp_file("");
        let wl = WordList::new(f.path().to_str().unwrap()).unwrap();
        let words: Vec<&str> = wl.words().collect();
        assert!(words.is_empty());
    }
 
    #[test]
    fn wordlist_errors_on_missing_file() {
        let result = WordList::new("/nonexistent/path/to/wordlist.txt");
        assert!(result.is_err());
    }
 
    #[test]
    fn write_to_disk_creates_valid_csv_with_expected_rows() {
        let out = tempfile::NamedTempFile::new().unwrap();
        let path = out.path().to_str().unwrap().to_string();
 
        let data = vec![
            FuzzResult {
                method: "GET".to_string(),
                path: "/admin".to_string(),
                status: 200,
                len: 42,
                time_ms: 12.5,
            },
            FuzzResult {
                method: "POST".to_string(),
                path: "/login".to_string(),
                status: 404,
                len: 0,
                time_ms: 3.2,
            },
        ];
 
        write_to_disk(&data, &path).unwrap();
 
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines = content.lines();
        assert_eq!(lines.next().unwrap(), "method,path,status,len,time_ms");
        assert_eq!(lines.next().unwrap(), "GET,/admin,200,42,12.5");
        assert_eq!(lines.next().unwrap(), "POST,/login,404,0,3.2");
    }
 
    #[test]
    fn write_to_disk_overwrites_existing_file() {
        let out = tempfile::NamedTempFile::new().unwrap();
        let path = out.path().to_str().unwrap().to_string();
        std::fs::write(&path, "leftover garbage data\n").unwrap();
 
        let data = vec![FuzzResult {
            method: "GET".to_string(),
            path: "/x".to_string(),
            status: 200,
            len: 1,
            time_ms: 1.0,
        }];
 
        write_to_disk(&data, &path).unwrap();
 
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("leftover garbage data"));
        assert!(content.contains("/x"));
    }
}