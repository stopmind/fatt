use std::clone::Clone;
use std::io;
use std::io::{Read, Seek, SeekFrom};
use thiserror::Error;
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, Unaligned};
use zerocopy::little_endian::{U16, U32};

const BOOT_SIG: [u8; 2] = 0xAA55u16.to_le_bytes();
const BPB32_SIG1: u8 = 0x28;
const BPB32_SIG2: u8 = 0x29;
const BPB32_IDENTIFIER: &[u8] = "FAT32   ".as_bytes();
const BPB32_BOOT_CODE_LEN: i64 = 420;
const UNKNOWN_CLUSTER: u32 = 0xFFFFFFFF;

#[derive(Debug, Error)]
pub enum Fat32Error {
    #[error("io error: {0}")]
    IoError(#[from] io::Error),
    #[error("fs is corrupted: {0}")]
    Corrupted(&'static str)
}

pub type Fat32Result<T> = Result<T, Fat32Error>;

#[derive(Copy, Clone, Debug, Immutable, IntoBytes, Unaligned, FromBytes)]
#[repr(C, packed)]
pub struct BPB32 {
    jump: [u8; 3],
    oem: [u8; 8],
    sector_size: U16,
    sectors_per_cluster: u8,
    reserved_sectors: U16,
    fats_count: u8,
    root_entry_count: U16,
    total_sectors: U16,
    media_type: u8,
    __fat12_sectors_per_fat: [u8; 2],
    sectors_per_track: U16,
    heads_count: U16,
    hidden_sectors: U32,
    large_sectors_count: U32,

    // Extended
    sectors_per_fat: U32,
    flags: U16,
    fat_ver: U16,
    root_cluster: U32,
    fs_info_sector: U16,
    backup_boot_sector: U16,
    __reserved0: [u8; 12],
    drive_number: u8,
    __reserved1: u8,
    signature: u8,
    volume_serial: U32,
    volume_label: [u8; 11],
    sys_identifier: [u8; 8],
}

const FSINFO_LEAD_SIG: u32 = 0x41615252;
const FSINFO_MAIN_SIG: u32 = 0x61417272;
const FSINFO_TRAIL_SIG: u32 = 0xAA550000;
const FSINFO_RESERVED: i64 = 480;

#[derive(Copy, Clone, Debug, Immutable, IntoBytes, Unaligned, FromBytes)]
#[repr(C, packed)]
pub struct FsInfo {
    main_signature: U32,
    free_clusters_count: U32,
    first_search_cluster: U32,
    __reserved: [u8; 12],
    trail_signature: U32,
}


pub struct Fat32<R> {
    reader: R,

    clusters_start: u64,
    cluster_size: u64,
    clusters_count: u32,

    fat_entries: Box<[u32]>,
    fats_count: u8,

    root: u32
}

impl<R> Fat32<R>
where
    R: Read + Seek
{
    pub fn new(mut reader: R) -> Fat32Result<Self> {
        use Fat32Error::*;

        // read BPB
        let mut bpb = BPB32::new_zeroed();
        reader.read_exact(bpb.as_mut_bytes())?;

        reader.seek_relative(BPB32_BOOT_CODE_LEN)?;

        let mut boot_sig = [0u8; 2];
        reader.read_exact(&mut boot_sig)?;
        if boot_sig != BOOT_SIG {
            return Err(Corrupted("invalid boot signature"));
        }

        if bpb.signature != BPB32_SIG1 && bpb.signature != BPB32_SIG2 {
            return Err(Corrupted("invalid BPB signature"));
        }

        if bpb.sys_identifier != BPB32_IDENTIFIER {
            return Err(Corrupted("invalid BPB identifier"));
        }

        if bpb.sector_size == 0 {
            return Err(Corrupted("invalid sector size"));
        }

        if bpb.sectors_per_cluster == 0 {
            return Err(Corrupted("invalid cluster size"));
        }

        let sectors_count = match bpb.total_sectors.get() {
            0 => bpb.large_sectors_count.get(),
            v => v as u32
        };
        let clusters_count = sectors_count / bpb.sectors_per_cluster as u32;

        // read fs info
        reader.seek_relative(bpb.sector_size.get() as i64 * (bpb.fs_info_sector.get() - 1) as i64)?;

        let mut lead_signature = U32::ZERO;
        reader.read_exact(lead_signature.as_mut_bytes())?;
        if lead_signature.get() != FSINFO_LEAD_SIG {
            return Err(Corrupted("invalid FSInfo lead signature"));
        }

        reader.seek_relative(FSINFO_RESERVED)?;

        let mut fs_info = FsInfo::new_zeroed();
        reader.read_exact(fs_info.as_mut_bytes())?;

        if fs_info.main_signature != FSINFO_MAIN_SIG {
            return Err(Corrupted("invalid FSInfo main signature"));
        }

        if fs_info.trail_signature != FSINFO_TRAIL_SIG {
            return Err(Corrupted("invalid FSInfo trail signature"));
        }

        let cluster_size = bpb.sector_size.get() as u64 * bpb.sectors_per_cluster as u64;
        let fat_size = bpb.sectors_per_fat.get() as u64 * bpb.sector_size.get() as u64;

        let mut fat_entries = Vec::from_fn(fat_size as usize / size_of::<u32>(), |_| 0u32).into_boxed_slice();
        let reserved = bpb.reserved_sectors.get() as u64 * bpb.sector_size.get() as u64;
        reader.seek(SeekFrom::Start(reserved))?;
        reader.read_exact(fat_entries.as_mut_bytes())?;

        #[cfg(target_endian = "big")]
        {
            for ent in &mut fat_entries {
                *ent = ent.swap_bytes()
            }
        }

        let clusters_start = reserved + fat_size * bpb.fats_count as u64;

        Ok(Self {
            reader,

            clusters_start,
            cluster_size,
            clusters_count,

            fat_entries,
            fats_count: bpb.fats_count,

            root: bpb.root_cluster.get(),
        })
    }

    fn get_cluster_value(&mut self, cluster: u32) -> u32 {
        self.fat_entries[cluster as usize]
    }

    pub fn read_root(&mut self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        Fat32Read::new(self, self.root, None)
            .read_to_end(&mut buf)?;
        Ok(buf)
    }
}

const FREE_CLUSTER: u32 = 0;
const BAD_CLUSTER: u32 = 0x0FFFFFF7;
const LAST_CLUSTER: u32 = 0x0FFFFFF8 ;

pub struct Fat32Read<'a, R> {
    fs: &'a mut Fat32<R>,
    start_cluster: u32,
    current_cluster: u32,
    cluster_num: u64,

    cluster_offset: u64,
    pos: u64,
    len: Option<u64>
}

impl<'a, R> Fat32Read<'a, R>  {
    fn new(fs: &'a mut Fat32<R>, cluster: u32, len: Option<u64>) -> Self {
        Fat32Read {
            len, fs,
            start_cluster: cluster,
            current_cluster: cluster,
            cluster_num: 0,
            cluster_offset: 0,
            pos: 0,
        }
    }

    fn start(&mut self) {
        self.current_cluster = self.start_cluster;
        self.cluster_num = 0;
        self.cluster_offset = 0;
    }
}

impl<'a, R> Fat32Read<'a, R>
where R: Read + Seek
{
    /// returns true if cluster changed
    fn next_cluster(&mut self) -> io::Result<bool> {
        match self.fs.get_cluster_value(self.current_cluster) {
            x if x == FREE_CLUSTER || x == BAD_CLUSTER => Err(io::Error::other("fat table corrupted")),
            LAST_CLUSTER.. => Ok(false),
            next => {
                self.current_cluster += next;
                self.cluster_offset = 0;
                self.cluster_num += 1;
                Ok(true)
            }
        }
    }
}

impl<'a, R> Read for Fat32Read<'a, R>
where R: Read + Seek
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let mut remaining = buf.len();
        if let Some(len) = self.len {
            remaining = remaining.min((len - self.pos) as usize);
        }

        let mut buf_offset = 0usize;

        while remaining != 0 {
            if self.cluster_offset == self.fs.cluster_size && !self.next_cluster()? { break }

            let to_read = remaining.min((self.fs.cluster_size - self.cluster_offset) as usize);
            let fs_start = self.fs.clusters_start + self.fs.cluster_size * (self.current_cluster - 2) as u64 + self.cluster_offset;

            self.fs.reader.seek(SeekFrom::Start(fs_start))?;
            self.fs.reader.read_exact(&mut buf[buf_offset..buf_offset+to_read])?;

            self.pos += to_read as u64;
            self.cluster_offset += to_read as u64;
            buf_offset += to_read;
            remaining -= to_read;
        }

        Ok(buf_offset)
    }
}

impl<'a, R> Seek for Fat32Read<'a, R>
where R: Read + Seek
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(pos) => pos as i64,
            SeekFrom::End(off) => {
                if let Some(len) = self.len { len as i64 + off }
                else { return Err(io::Error::other("cant seek from end on reader with unknown len")) }
            },
            SeekFrom::Current(off) => self.pos as i64 + off
        };

        if new_pos < 0 {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid seek to a negative position"))
        } else if let Some(len) = self.len && new_pos >= len as i64 {
            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        } else {
            let new_pos = new_pos as u64;
            let new_cluster_num = new_pos / self.fs.cluster_size;
            let new_cluster_offset = new_pos % self.fs.cluster_size;

            // TODO: even on fail current cluster will be changed, I will fix it in future...
            if new_cluster_num > self.cluster_num {
                for _ in self.cluster_num..new_cluster_num {
                    if !self.next_cluster()? {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof))
                    }
                }
            } else if new_cluster_num < self.cluster_num {
                self.start();
                for _ in 0..new_cluster_num {
                    if !self.next_cluster()? {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof))
                    }
                }
            }

            self.cluster_offset = new_cluster_offset;

            Ok(new_pos)
        }
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.pos)
    }
}