use std::fs::File;
use crate::fat32::Fat32;

mod fat32;

fn main() {
    let file = File::open("./test.fat32").unwrap();
    let mut fat32 = Fat32::new(file).unwrap();

    let root = fat32.read_root().unwrap();
    println!("{:?}", root);
}
