use crate::fat32::Fat32;
use std::fs::File;

mod fat32;

fn main() {
    let file = File::open("./test.fat32").unwrap();
    let mut fat32 = Fat32::new(file).unwrap();

    let root = fat32.read_root();
    for entry in root {
        let entry = entry.unwrap();
        println!(
            "{} {}{} size: {}b cluster: {} creation time: {}",
            if entry.is_dir { "DIR " } else { "FILE" },
            entry.name,
            if entry.read_only { " readonly" } else { "" },
            entry.size,
            entry.cluster,
            entry.created
        );
    }
}
