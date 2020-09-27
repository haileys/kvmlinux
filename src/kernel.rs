use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use byteorder::{ByteOrder, LittleEndian};
use derive_more::From;

const SECTOR_SIZE: usize = 512;

const K_SETUP_SECTS_B: usize    = 0x1f1;
const K_SYSSIZE_D: usize        = 0x1f4;
const K_HEADER_MAGIC_D: usize   = 0x202;

pub const K_VIDMODE_W: usize              = 0x1fa;
pub const K_TYPE_OF_LOADER_B: usize       = 0x210;
pub const K_LOADFLAGS_B: usize            = 0x211;
// pub const K_SETUP_MOVE_SIZE_W: usize      = 0x212;
pub const K_RAMDISK_IMAGE_D: usize        = 0x218;
pub const K_RAMDISK_SIZE_D: usize         = 0x21c;
pub const K_HEAP_END_PTR_W: usize         = 0x224;
// pub const K_EXT_LOADER_TYPE_B: usize      = 0x227;
pub const K_CMD_LINE_PTR_D: usize         = 0x228;

pub struct Image {
    setup_bytes: usize,
    kernel_bytes: usize,
    bzimage: Vec<u8>,
}

#[derive(From, Debug)]
pub enum LoadError {
    InvalidKernel,
    Io(io::Error)
}

impl Image {
    pub fn open(path: &Path) -> Result<Self, LoadError> {
        let mut file = File::open(path)?;

        let mut bzimage = Vec::new();
        file.read_to_end(&mut bzimage)?;

        // verify magic number

        if bzimage.len() < K_HEADER_MAGIC_D + 4 {
            return Err(LoadError::InvalidKernel);
        }

        let magic = LittleEndian::read_u32(&bzimage[K_HEADER_MAGIC_D..][0..4]);

        if magic != 0x53726448 {
            return Err(LoadError::InvalidKernel);
        }

        // pull size of setup and kernel code out of header

        let setup_sects = bzimage[K_SETUP_SECTS_B];
        let setup_bytes = setup_sects as usize * SECTOR_SIZE;

        let kernel_paras = LittleEndian::read_u32(&bzimage[K_SYSSIZE_D..][0..4]);
        let kernel_bytes = kernel_paras as usize * 16;

        let expected_size =
            SECTOR_SIZE + // boot sector
            setup_bytes +
            kernel_bytes;

        if bzimage.len() < expected_size {
            return Err(LoadError::InvalidKernel);
        }

        Ok(Image {
            bzimage,
            setup_bytes,
            kernel_bytes,
        })
    }

    pub fn setup_code(&self) -> &[u8] {
        &self.bzimage[SECTOR_SIZE..][0..self.setup_bytes]
    }

    pub fn kernel_code(&self) -> &[u8] {
        &self.bzimage[SECTOR_SIZE..][self.setup_bytes..][0..self.kernel_bytes]
    }
}
