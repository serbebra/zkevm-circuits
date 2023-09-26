use std::{collections::HashSet, path::Path};

/// Recursive iterator over all json files in a directory.
pub struct TracesFileIterator {
    read_dirs: Vec<std::fs::ReadDir>,
    size_filter: HashSet<usize>,
}

impl TracesFileIterator {
    pub fn from_dir<P: AsRef<Path>>(dir: P) -> Self {
        Self {
            read_dirs: vec![std::fs::read_dir(dir).expect("read dir failed")],
            size_filter: HashSet::new(),
        }
    }
}

impl Iterator for TracesFileIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.read_dirs.last_mut().unwrap().next() {
                Some(entry) => {
                    let entry = entry.unwrap();
                    let path = entry.path();
                    if path.is_dir() {
                        self.read_dirs
                            .push(std::fs::read_dir(path).expect("read dir failed"));
                    } else if path.extension().map(|s| s == "json").unwrap_or(false) {
                        let trace = std::fs::read_to_string(path).expect("read file failed");
                        if self.size_filter.contains(&trace.as_bytes().len()) {
                            continue;
                        }
                        self.size_filter.insert(trace.as_bytes().len());
                        return Some(trace);
                    }
                }
                None => {
                    self.read_dirs.pop();
                    if self.read_dirs.is_empty() {
                        return None;
                    }
                }
            }
        }
    }
}
