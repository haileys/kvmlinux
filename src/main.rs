extern crate kvm_ioctls;
extern crate kvm_bindings;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process;
use std::ptr;

use kvm_bindings::{KVM_MEM_LOG_DIRTY_PAGES, KVM_MAX_CPUID_ENTRIES};
use kvm_bindings::{kvm_userspace_memory_region, kvm_pit_config};
use kvm_ioctls::VcpuExit;
use kvm_ioctls::{Kvm, VmFd, VcpuFd};

mod kernel;

const PAGE_SIZE: u64 = 0x1000;

const MMIO_KVMLINUX_INT: u64 = 0xff000;
const MMIO_KVMLINUX_UART: u64 = 0xff010;
const MMIO_KVMLINUX_UART_HI: u64 = 0xff018;

static BIOS_BYTES: &[u8] = include_bytes!("../bios.bin");

struct Machine {
    kvm: Kvm,
    vm: VmFd,
    cpu: VcpuFd,
}

impl Machine {
    pub fn new() -> Result<Self, kvm_ioctls::Error> {
        let kvm = Kvm::new()?;
        let vm = kvm.create_vm()?;
        vm.create_pit2(kvm_pit_config::default())?;
        vm.create_irq_chip()?;
        let cpu = vm.create_vcpu(0)?;

        Ok(Machine {
            kvm,
            vm,
            cpu,
        })
    }

    fn dump_csip(&self) {
        let regs = self.cpu.get_regs().unwrap();
        let sregs = self.cpu.get_sregs().unwrap();
        eprintln!("CS:IP => {:04x}:{:08x}", sregs.cs.selector, regs.rip);
    }
}

fn main() {
    unsafe {
        signal_hook::register(signal_hook::SIGUSR1, || {
            // do nothing
        }).unwrap();
    }

    let args = env::args_os().collect::<Vec<_>>();

    if args.len() != 3 {
        eprintln!("usage: kvmlinux <path to bzimage> <path to initramfs>");
        process::exit(0);
    }

    let kernel = kernel::Image::open(Path::new(&args[1])).unwrap();
    let initramfs = fs::read(&args[2]).unwrap();

    let machine = Machine::new().unwrap();

    // just pass thru the host cpuid
    let supported_cpuid = machine.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
    machine.cpu.set_cpuid2(&supported_cpuid).unwrap();

    const SETUP_BASE: usize = 0x1000;
    const SETUP_LOAD: usize = 0x1200;
    const HEAP_END: usize = 0xe000;

    let lowmem_addr = 0x0;
    let lowmem_size = 0xa0000; // 640k

    let extmem_addr = 0x100000;
    let extmem_size = 128 * 1024 * 1024;

    let bios_addr = 0xf0000;
    let bios_size = 0x1000;

    let kernel_len_aligned = (kernel.kernel_code().len() as u64 + (PAGE_SIZE - 1)) & !(PAGE_SIZE - 1);
    let initramfs_addr = extmem_addr + kernel_len_aligned;

    // TODO check errors for these mmaps...

    let lowmem_virt: *mut u8 = unsafe {
        libc::mmap(
            ptr::null_mut(),
            lowmem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        ) as *mut u8
    };

    let extmem_virt: *mut u8 = unsafe {
        libc::mmap(
            ptr::null_mut(),
            extmem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        ) as *mut u8
    };

    let bios_virt: *mut u8 = unsafe {
        libc::mmap(
            ptr::null_mut(),
            bios_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        ) as *mut u8
    };

    // map regions of memory
    let lowmem_slot = 0;
    let extmem_slot = 1;
    let bios_slot = 2;
    unsafe {
        machine.vm.set_user_memory_region(kvm_userspace_memory_region {
            slot: lowmem_slot,
            guest_phys_addr: lowmem_addr as u64,
            memory_size: lowmem_size as u64,
            userspace_addr: lowmem_virt as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        }).unwrap();

        machine.vm.set_user_memory_region(kvm_userspace_memory_region {
            slot: extmem_slot,
            guest_phys_addr: extmem_addr as u64,
            memory_size: extmem_size as u64,
            userspace_addr: extmem_virt as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        }).unwrap();

        machine.vm.set_user_memory_region(kvm_userspace_memory_region {
            slot: bios_slot,
            guest_phys_addr: bios_addr as u64,
            memory_size: bios_size as u64,
            userspace_addr: bios_virt as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        }).unwrap();
    }

    // write IVT entries
    unsafe {
        for i in 0..256 {
            let ivt_ent = lowmem_virt.add(i * 4) as *mut u32;
            let isr: u32 = 0xf000_0000 + i as u32 * 8;
            *ivt_ent = isr;
        }
    }

    // write setup and kernel code
    unsafe {
        let setup = kernel.setup_code();
        ptr::copy(setup.as_ptr(), lowmem_virt.add(SETUP_LOAD), setup.len());

        // *lowmem_virt.add(SETUP_LOAD + 0) = 0xcd;
        // *lowmem_virt.add(SETUP_LOAD + 1) = 0x7f;

        let kern = kernel.kernel_code();
        ptr::copy(kern.as_ptr(), extmem_virt, kern.len());

        let initramfs_virt = extmem_virt.add((initramfs_addr - extmem_addr) as usize);
        ptr::copy(initramfs.as_ptr(), initramfs_virt, initramfs.len());

        ptr::copy(BIOS_BYTES.as_ptr(), bios_virt, BIOS_BYTES.len());
    }

    // set setup parameters
    unsafe {
        unsafe fn write_8(setup: *mut u8, offset: usize, value: u8) {
            *setup.add(offset) = value;
        }

        unsafe fn write_16(setup: *mut u8, offset: usize, value: u16) {
            *(setup.add(offset) as *mut u16) = value;
        }

        unsafe fn write_32(setup: *mut u8, offset: usize, value: u32) {
            *(setup.add(offset) as *mut u32) = value;
        }

        let setup_virt = lowmem_virt.add(SETUP_BASE);

        // vidmode VIDEO_CURRENT_MODE - aka do nothing
        write_16(setup_virt, kernel::K_VIDMODE_W, 0x0f04);

        // we are not a registered loader
        write_8(setup_virt, kernel::K_TYPE_OF_LOADER_B, 0xff);

        // set flags
        const LOADED_HIGH_FLAG: u8 = 0x01;
        const CAN_USE_HEAP_FLAG: u8 = 0x80;
        write_8(setup_virt, kernel::K_LOADFLAGS_B, LOADED_HIGH_FLAG | CAN_USE_HEAP_FLAG);

        // ramdisk
        write_32(setup_virt, kernel::K_RAMDISK_SIZE_D, initramfs.len() as u32);
        write_32(setup_virt, kernel::K_RAMDISK_IMAGE_D, initramfs_addr as u32);

        // set heap end
        write_16(setup_virt, kernel::K_HEAP_END_PTR_W, HEAP_END as u16);

        // cmdline lives at HEAP_END
        let cmdline = b"quiet initrd=1 root=/dev/ram init=/busybox console=uart,mmio,0xff010\0";
        ptr::copy(cmdline.as_ptr(), lowmem_virt.add(HEAP_END), cmdline.len());
        write_32(setup_virt, kernel::K_CMD_LINE_PTR_D, HEAP_END as u32);
    }

    // set initial segments

    let mut vcpu_sregs = machine.cpu.get_sregs().unwrap();
    // setup kernel data segment
    vcpu_sregs.ds.base = SETUP_BASE as u64;
    vcpu_sregs.ds.selector = (SETUP_BASE >> 4) as u16;
    // copy to other data segments
    vcpu_sregs.ss = vcpu_sregs.ds;
    vcpu_sregs.es = vcpu_sregs.ds;
    vcpu_sregs.fs = vcpu_sregs.ds;
    vcpu_sregs.gs = vcpu_sregs.ds;
    // set code segment
    vcpu_sregs.cs.base = SETUP_LOAD as u64;
    vcpu_sregs.cs.selector = (SETUP_LOAD >> 4) as u16;
    machine.cpu.set_sregs(&vcpu_sregs).unwrap();

    // initial registers

    let mut vcpu_regs = machine.cpu.get_regs().unwrap();
    vcpu_regs.rip = 0; // start at beginning of kernel code seg
    vcpu_regs.rsp = HEAP_END as u64;
    vcpu_regs.rflags = 2; // bit 1 is reserved must be set
    machine.cpu.set_regs(&vcpu_regs).unwrap();

    // 6. Run code on the vCPU.
    loop {
        match machine.cpu.run() {
            Ok(VcpuExit::IoIn(addr, data)) => {
                eprintln!(
                    "IO in, Address: {:#x}. Data: {:#x}",
                    addr,
                    data[0],
                );

                machine.dump_csip();
            }
            Ok(VcpuExit::IoOut(addr, data)) => {
                eprintln!(
                    "IO out, Address: {:#x}. Data: {:#x}",
                    addr,
                    data[0],
                );

                machine.dump_csip();
            }
            Ok(VcpuExit::MmioRead(addr, data)) => {
                if addr >= MMIO_KVMLINUX_UART && addr < MMIO_KVMLINUX_UART_HI {
                    let reg = addr - MMIO_KVMLINUX_UART;

                    if reg == 5 {
                        data[0] = 0x60; // UART_LSR_TEMT | UART_LSR_THRE, iow
                                        // transmitter buffers empty, ready to receive
                    } else {
                        eprintln!("Read from UART reg {}", reg);
                    }
                } else {
                    eprintln!(
                        "Received an MMIO Read Request for the address {:#x}.",
                        addr,
                    );

                    machine.dump_csip();
                }
            }
            Ok(VcpuExit::MmioWrite(addr, data)) => {
                if addr == MMIO_KVMLINUX_INT {
                    let regs = machine.cpu.get_regs().unwrap();
                    let sregs = machine.cpu.get_sregs().unwrap();

                    // TODO this is super unsafe
                    let csip_ptr = sregs.ss.base + regs.rsp + 6;
                    let csip = unsafe { *(lowmem_virt.add(csip_ptr as usize) as *mut u32) };

                    let int_nr = data[0];

                    eprintln!("Interrupt 0x{:02x} at {:04x}:{:04x}! AX={:04x}",
                        int_nr,
                        csip >> 16,
                        csip & 0xffff,
                        regs.rax & 0xffff);

                    if int_nr == 0x10 && (regs.rax >> 8) & 0xff == 0x0e {
                        eprintln!("print char!!");

                        let c = (regs.rax & 0xff) as u8;

                        // put char
                        let mut stdout = io::stdout();
                        stdout.write(&[c]).unwrap();
                        stdout.flush().unwrap();
                    }
                } else if addr >= MMIO_KVMLINUX_UART && addr < MMIO_KVMLINUX_UART_HI {
                    let reg = addr - MMIO_KVMLINUX_UART;

                    if reg == 0 {
                        // write reg
                        let mut stdout = io::stdout();
                        stdout.write(&[data[0]]).unwrap();
                        stdout.flush().unwrap();
                    } else {
                        eprintln!("Write to UART reg {}", reg);
                    }
                } else {
                    eprintln!(
                        "Received an MMIO Write Request to the address {:#x}.",
                        addr,
                    );

                    machine.dump_csip();
                }
            }
            Ok(VcpuExit::Hlt) => {
                eprintln!("Halt.");
                machine.dump_csip();
                break;
            }
            Err(e) if e.errno() == libc::EINTR => {
                // machine.dump_csip();

                // let events = machine.cpu.get_vcpu_events().unwrap();
                // println!("Events: {:#?}", events);
            }
            r => panic!("Unexpected exit reason: {:?}", r),
        }
    }
}
