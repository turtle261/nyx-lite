use core::fmt;
use std::ffi::c_void;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
use std::{iter::Peekable, marker::PhantomData, ops::Range, sync::atomic::{AtomicU64, Ordering}};

use crate::error::MemoryError;
use libc::{mprotect, PROT_READ, PROT_WRITE};
use vm_memory::bitmap::BS;
use vm_memory::{AtomicAccess, ByteValued, GuestUsize, VolatileSlice};
use vmm::vstate::memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap
};
use vmm::Vmm;

type MResult<T> = Result<T, MemoryError>;
pub const M_PAGE_ALIGN: u64 = 0xffff_ffff_ffff_f000;
pub const M_PAGE_OFFSET: u64 = 0xfff;
pub const FRAMES_PER_PAGE_TABLE: u64 = 0x1ff;
pub const M_PTE_OFFSET: u64 = FRAMES_PER_PAGE_TABLE;
pub const M_PTE_PADDR: u64 = 0x000f_ffff_ffff_f000;
pub const PAGE_SIZE: u64 = 0x1000;
pub const BIT_PTE_PRESENT: u64 = 1;
const BIT_PTE_WRITABLE: u64 = 1 << 1;
const BIT_PTE_USER: u64 = 1 << 2;
const BIT_PTE_NX: u64 = 1 << 63;

/// Tracks host-side writes into guest memory using a lock-free bitmap.
#[derive(Debug)]
pub struct HostDirtyTracker {
    page_count: usize,
    bits: Vec<AtomicU64>,
}

impl HostDirtyTracker {
    pub fn new(page_count: usize) -> Self {
        let words = page_count.div_ceil(64);
        let mut bits = Vec::with_capacity(words);
        bits.resize_with(words, AtomicU64::default);
        Self { page_count, bits }
    }

    fn page_index(&self, page_addr: u64) -> Option<usize> {
        let idx = (page_addr / PAGE_SIZE) as usize;
        (idx < self.page_count).then_some(idx)
    }

    pub fn mark_page(&self, page_addr: u64) {
        let Some(idx) = self.page_index(page_addr & M_PAGE_ALIGN) else {
            return;
        };
        let word = idx / 64;
        let mask = 1u64 << (idx % 64);
        if let Some(entry) = self.bits.get(word) {
            entry.fetch_or(mask, Ordering::Release);
        }
    }

    pub fn mark_range_phys(&self, start: u64, len: usize) {
        if len == 0 {
            return;
        }
        let mut addr = start & M_PAGE_ALIGN;
        let end = start
            .checked_add(len as u64 - 1)
            .unwrap_or(u64::MAX)
            & M_PAGE_ALIGN;
        while addr <= end {
            self.mark_page(addr);
            if let Some(next) = addr.checked_add(PAGE_SIZE) {
                addr = next;
            } else {
                break;
            }
        }
    }

    pub fn take_pages(&self) -> Vec<u64> {
        let mut pages = Vec::new();
        for (word_idx, entry) in self.bits.iter().enumerate() {
            let mut value = entry.swap(0, Ordering::AcqRel);
            while value != 0 {
                let bit = value.trailing_zeros() as usize;
                let page_idx = word_idx * 64 + bit;
                if page_idx < self.page_count {
                    pages.push(page_idx as u64 * PAGE_SIZE);
                }
                value &= value - 1;
            }
        }
        pages
    }

    pub fn snapshot_pages(&self) -> Vec<u64> {
        let mut pages = Vec::new();
        for (word_idx, entry) in self.bits.iter().enumerate() {
            let mut value = entry.load(Ordering::Acquire);
            while value != 0 {
                let bit = value.trailing_zeros() as usize;
                let page_idx = word_idx * 64 + bit;
                if page_idx < self.page_count {
                    pages.push(page_idx as u64 * PAGE_SIZE);
                }
                value &= value - 1;
            }
        }
        pages
    }

    pub fn clear(&self) {
        for entry in &self.bits {
            entry.store(0, Ordering::Release);
        }
    }

    pub fn page_count(&self) -> usize {
        self.page_count
    }
}

impl Default for HostDirtyTracker {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Page-level mapping flags for injected page table entries.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PageMapping {
    pub writable: bool,
    pub executable: bool,
    pub user: bool,
}

impl Default for PageMapping {
    fn default() -> Self {
        Self {
            writable: true,
            executable: true,
            user: true,
        }
    }
}

pub trait PageAllocator {
    fn alloc_page(&mut self) -> Option<GuestAddress>;
}

pub struct VecPageAllocator {
    pages: Vec<GuestAddress>,
}

impl VecPageAllocator {
    pub fn new(pages: Vec<GuestAddress>) -> Self {
        Self { pages }
    }
}

impl PageAllocator for VecPageAllocator {
    fn alloc_page(&mut self) -> Option<GuestAddress> {
        self.pages.pop()
    }
}

pub trait VirtualMemoryBackend: Send + Sync {
    fn read_virtual_bytes(&self, cr3: u64, vaddr: u64, buffer: &mut [u8]) -> MResult<usize>;
    fn write_virtual_bytes(&self, cr3: u64, vaddr: u64, buffer: &[u8]) -> MResult<usize>;
    fn read_virtual_u64(&self, cr3: u64, vaddr: u64) -> MResult<u64>;
    fn write_virtual_u64(&self, cr3: u64, vaddr: u64, val: u64) -> MResult<()>;
    fn read_phys_u64(&self, paddr: u64) -> MResult<u64>;
    fn write_phys_u64(&self, paddr: u64, val: u64) -> MResult<()>;
    fn resolve_vaddr(&self, cr3: u64, vaddr: u64) -> MResult<GuestAddress>;
}

impl<T> VirtualMemoryBackend for T
where
    T: NyxMemExtension + Send + Sync,
{
    fn read_virtual_bytes(&self, cr3: u64, vaddr: u64, buffer: &mut [u8]) -> MResult<usize> {
        NyxMemExtension::read_virtual_bytes(self, cr3, vaddr, buffer)
    }

    fn write_virtual_bytes(&self, cr3: u64, vaddr: u64, buffer: &[u8]) -> MResult<usize> {
        NyxMemExtension::write_virtual_bytes(self, cr3, vaddr, buffer)
    }

    fn read_virtual_u64(&self, cr3: u64, vaddr: u64) -> MResult<u64> {
        NyxMemExtension::read_virtual_u64(self, cr3, vaddr)
    }

    fn write_virtual_u64(&self, cr3: u64, vaddr: u64, val: u64) -> MResult<()> {
        NyxMemExtension::write_virtual_u64(self, cr3, vaddr, val)
    }

    fn read_phys_u64(&self, paddr: u64) -> MResult<u64> {
        NyxMemExtension::read_phys(self, paddr)
    }

    fn write_phys_u64(&self, paddr: u64, val: u64) -> MResult<()> {
        NyxMemExtension::write_phys(self, paddr, val)
    }

    fn resolve_vaddr(&self, cr3: u64, vaddr: u64) -> MResult<GuestAddress> {
        NyxMemExtension::resolve_vaddr(self, cr3, vaddr)
    }
}

#[derive(Clone)]
pub struct LockedVmm {
    inner: Arc<Mutex<Vmm>>,
}

impl LockedVmm {
    pub fn new(inner: Arc<Mutex<Vmm>>) -> Self {
        Self { inner }
    }
}

impl VirtualMemoryBackend for LockedVmm {
    fn read_virtual_bytes(&self, cr3: u64, vaddr: u64, buffer: &mut [u8]) -> MResult<usize> {
        let vmm = self.inner.lock().unwrap();
        vmm.read_virtual_bytes(cr3, vaddr, buffer)
    }

    fn write_virtual_bytes(&self, cr3: u64, vaddr: u64, buffer: &[u8]) -> MResult<usize> {
        let vmm = self.inner.lock().unwrap();
        vmm.write_virtual_bytes(cr3, vaddr, buffer)
    }

    fn read_virtual_u64(&self, cr3: u64, vaddr: u64) -> MResult<u64> {
        let vmm = self.inner.lock().unwrap();
        vmm.read_virtual_u64(cr3, vaddr)
    }

    fn write_virtual_u64(&self, cr3: u64, vaddr: u64, val: u64) -> MResult<()> {
        let vmm = self.inner.lock().unwrap();
        vmm.write_virtual_u64(cr3, vaddr, val)
    }

    fn read_phys_u64(&self, paddr: u64) -> MResult<u64> {
        let vmm = self.inner.lock().unwrap();
        vmm.read_phys(paddr)
    }

    fn write_phys_u64(&self, paddr: u64, val: u64) -> MResult<()> {
        let vmm = self.inner.lock().unwrap();
        vmm.write_phys(paddr, val)
    }

    fn resolve_vaddr(&self, cr3: u64, vaddr: u64) -> MResult<GuestAddress> {
        let vmm = self.inner.lock().unwrap();
        vmm.resolve_vaddr(cr3, vaddr)
    }
}

#[derive(Clone)]
/// Convenience wrapper for guest virtual memory access in a process context (CR3).
pub struct ProcessMemory<B>
where
    B: VirtualMemoryBackend + Clone,
{
    backend: B,
    cr3: u64,
    host_dirty: Option<Arc<HostDirtyTracker>>,
}

impl<B> ProcessMemory<B>
where
    B: VirtualMemoryBackend + Clone,
{
    pub fn new(backend: B, cr3: u64) -> Self {
        Self {
            backend,
            cr3,
            host_dirty: None,
        }
    }

    pub fn with_host_dirty(mut self, tracker: Arc<HostDirtyTracker>) -> Self {
        self.host_dirty = Some(tracker);
        self
    }

    pub fn cr3(&self) -> u64 {
        self.cr3
    }

    pub fn resolve_vaddr(&self, vaddr: u64) -> MResult<GuestAddress> {
        self.backend.resolve_vaddr(self.cr3, vaddr)
    }

    pub fn read_u64(&self, vaddr: u64) -> MResult<u64> {
        self.backend.read_virtual_u64(self.cr3, vaddr)
    }

    pub fn write_u64(&self, vaddr: u64, val: u64) -> MResult<()> {
        self.backend.write_virtual_u64(self.cr3, vaddr, val)?;
        self.mark_host_dirty_virtual_range(vaddr, std::mem::size_of::<u64>());
        Ok(())
    }

    pub fn read_bytes(&self, vaddr: u64, buffer: &mut [u8]) -> MResult<usize> {
        self.backend.read_virtual_bytes(self.cr3, vaddr, buffer)
    }

    pub fn write_bytes(&self, vaddr: u64, buffer: &[u8]) -> MResult<usize> {
        let bytes = self.backend.write_virtual_bytes(self.cr3, vaddr, buffer)?;
        self.mark_host_dirty_virtual_range(vaddr, bytes);
        Ok(bytes)
    }

    pub fn map_page(
        &self,
        vaddr: u64,
        paddr: u64,
        mapping: PageMapping,
        mut allocator: Option<&mut dyn PageAllocator>,
    ) -> MResult<()> {
        if (vaddr & M_PAGE_OFFSET) != 0 || (paddr & M_PAGE_OFFSET) != 0 {
            return Err(MemoryError::UnalignedAddress(vaddr));
        }
        let (l1, l2, l3, l4, _) = split_vaddr(vaddr);
        let mut table = self.cr3 & M_PAGE_ALIGN;
        let indices = [l1, l2, l3];

        for index in indices {
            let entry_addr = table + index * 8;
            let entry = self.backend.read_phys_u64(entry_addr)?;
            if (entry & BIT_PTE_PRESENT) == 0 {
                let Some(allocator) = allocator.as_deref_mut() else {
                    return Err(MemoryError::MissingPageTable(vaddr));
                };
                let new_page = allocator
                    .alloc_page()
                    .ok_or(MemoryError::PageTableAllocationFailed(vaddr))?;
                self.zero_page(new_page.0)?;
                let mut flags = BIT_PTE_PRESENT | BIT_PTE_WRITABLE;
                if mapping.user {
                    flags |= BIT_PTE_USER;
                }
                self.backend.write_phys_u64(entry_addr, new_page.0 | flags)?;
                table = new_page.0;
            } else {
                table = entry & M_PTE_PADDR;
            }
        }

        let mut flags = BIT_PTE_PRESENT;
        if mapping.writable {
            flags |= BIT_PTE_WRITABLE;
        }
        if mapping.user {
            flags |= BIT_PTE_USER;
        }
        if !mapping.executable {
            flags |= BIT_PTE_NX;
        }
        let final_entry = (paddr & M_PTE_PADDR) | flags;
        self.backend.write_phys_u64(table + l4 * 8, final_entry)?;
        Ok(())
    }

    pub fn unmap_page(&self, vaddr: u64) -> MResult<()> {
        if (vaddr & M_PAGE_OFFSET) != 0 {
            return Err(MemoryError::UnalignedAddress(vaddr));
        }
        let (l1, l2, l3, l4, _) = split_vaddr(vaddr);
        let mut table = self.cr3 & M_PAGE_ALIGN;
        let indices = [l1, l2, l3];
        for index in indices {
            let entry_addr = table + index * 8;
            let entry = self.backend.read_phys_u64(entry_addr)?;
            if (entry & BIT_PTE_PRESENT) == 0 {
                return Err(MemoryError::MissingPageTable(vaddr));
            }
            table = entry & M_PTE_PADDR;
        }
        self.backend.write_phys_u64(table + l4 * 8, 0)?;
        Ok(())
    }

    pub fn inject_code(
        &self,
        vaddr: u64,
        paddr: u64,
        code: &[u8],
        mapping: PageMapping,
        allocator: Option<&mut dyn PageAllocator>,
    ) -> MResult<()> {
        self.map_page(vaddr, paddr, mapping, allocator)?;
        self.write_bytes(vaddr, code)?;
        Ok(())
    }

    pub fn cursor(&self, vaddr: u64) -> VirtualMemoryCursor<B> {
        VirtualMemoryCursor {
            process: self.clone(),
            addr: vaddr,
        }
    }

    fn mark_host_dirty_virtual_range(&self, vaddr: u64, len: usize) {
        let Some(tracker) = &self.host_dirty else {
            return;
        };
        if len == 0 {
            return;
        }
        let start = vaddr & M_PAGE_ALIGN;
        let end = vaddr
            .checked_add(len as u64 - 1)
            .unwrap_or(u64::MAX)
            & M_PAGE_ALIGN;
        let mut cur = start;
        while cur <= end {
            if let Ok(paddr) = self.backend.resolve_vaddr(self.cr3, cur) {
                tracker.mark_page(paddr.0);
            }
            if let Some(next) = cur.checked_add(PAGE_SIZE) {
                cur = next;
            } else {
                break;
            }
        }
    }

    fn zero_page(&self, paddr: u64) -> MResult<()> {
        let mut offset = 0u64;
        while offset < PAGE_SIZE {
            self.backend.write_phys_u64(paddr + offset, 0)?;
            offset += 8;
        }
        Ok(())
    }
}

/// A contiguous guest memory region exposed for sharing with the host.
#[derive(Clone)]
pub struct SharedMemoryRegion<B>
where
    B: VirtualMemoryBackend + Clone,
{
    process: ProcessMemory<B>,
    addr: u64,
    len: usize,
}

impl<B> SharedMemoryRegion<B>
where
    B: VirtualMemoryBackend + Clone,
{
    pub fn new(process: ProcessMemory<B>, addr: u64, len: usize) -> Self {
        Self { process, addr, len }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn read_at(&self, offset: usize, buffer: &mut [u8]) -> MResult<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let max_len = (self.len - offset).min(buffer.len());
        self.process
            .read_bytes(self.addr + offset as u64, &mut buffer[..max_len])
    }

    pub fn write_at(&self, offset: usize, buffer: &[u8]) -> MResult<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let max_len = (self.len - offset).min(buffer.len());
        self.process
            .write_bytes(self.addr + offset as u64, &buffer[..max_len])
    }

    pub fn cursor(&self) -> VirtualMemoryCursor<B> {
        self.process.cursor(self.addr)
    }
}

/// A cursor that implements `Read`/`Write`/`Seek` over guest virtual memory.
pub struct VirtualMemoryCursor<B>
where
    B: VirtualMemoryBackend + Clone,
{
    process: ProcessMemory<B>,
    addr: u64,
}

impl<B> Seek for VirtualMemoryCursor<B>
where
    B: VirtualMemoryBackend + Clone,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(offset) => self.addr = offset,
            SeekFrom::Current(offset) => {
                match self.addr.checked_add_signed(offset){
                    Some(new) => self.addr = new,
                    None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Offset caused address Over/Underflow"))
                }
            }
            SeekFrom::End(offset) => {
                match checked_sub_signed(u64::MAX, offset){
                    Some(new) => self.addr = new,
                    None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Offset caused address Over/Underflow"))
                }
            }
        }
        Ok(self.addr)
    }
}

impl<B> Read for VirtualMemoryCursor<B>
where
    B: VirtualMemoryBackend + Clone,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self
            .process
            .read_bytes(self.addr, buf)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        if let Some(next) = self.addr.checked_add(bytes as u64) {
            self.addr = next;
        }
        Ok(bytes)
    }
}

impl<B> Write for VirtualMemoryCursor<B>
where
    B: VirtualMemoryBackend + Clone,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes = self
            .process
            .write_bytes(self.addr, buf)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        if let Some(next) = self.addr.checked_add(bytes as u64) {
            self.addr = next;
        }
        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn read_phys<T: ByteValued + AtomicAccess>(mem: &GuestMemoryMmap, paddr: u64) -> MResult<T> {
    let size = std::mem::size_of::<T>();
    return mem
        .load(GuestAddress(paddr), Ordering::Relaxed)
        .map_err(|_| MemoryError::CantReadPhysicalPage(GuestAddress(paddr), size));
}

pub fn write_phys<T: ByteValued + AtomicAccess>(mem: &GuestMemoryMmap, paddr: u64, val: T)-> MResult<()>{
    let size = std::mem::size_of::<T>();
    assert!(paddr & M_PAGE_OFFSET <= PAGE_SIZE - (size as u64));
    return mem.store(val, GuestAddress(paddr), Ordering::Relaxed)
        .map_err(|_| MemoryError::CantWritePhysicalPage(GuestAddress(paddr), size));
}

pub fn read_phys_u64(mem: &GuestMemoryMmap, paddr: u64) -> MResult<u64>{
    return read_phys(mem, paddr);
}
pub fn read_phys_u8(mem: &GuestMemoryMmap, paddr: u64) -> MResult<u8> {
    return read_phys(mem, paddr)
}

pub enum PagePermission{
    R,
    W,
    RW,
    None,
}


pub trait NyxMemExtension{
    fn resolve_vaddr(&self, cr3: u64, vaddr: u64) -> MResult<GuestAddress>;
    fn read_virtual<T: ByteValued + AtomicAccess>(&self, cr3: u64, vaddr: u64) -> MResult<T>;
    fn write_virtual<T: ByteValued + AtomicAccess>(&self, cr3: u64, vaddr: u64, val: T) -> MResult<()>;

    fn read_phys<T: ByteValued + AtomicAccess>(&self, paddr: u64) -> MResult<T>;
    fn write_phys<T: ByteValued + AtomicAccess>(&self, paddr: u64, val: T) -> MResult<()>;

    fn set_physical_page_permission(&mut self, phys_addr: u64, perm: PagePermission);
    fn set_virtual_page_permission(&mut self, cr3: u64, vaddr: u64, perm: PagePermission);

    fn read_virtual_u8(&self, cr3: u64, vaddr: u64) -> MResult<u8>;
    fn write_virtual_u8(&self, cr3: u64, vaddr: u64, val: u8) -> MResult<()>;
    fn read_virtual_u64(&self, cr3: u64, vaddr: u64) -> MResult<u64>;
    fn write_virtual_u64(&self, cr3: u64, vaddr: u64, val: u64) -> MResult<()>;
    fn read_virtual_cstr(&self, cr3: u64, guest_vaddr: u64) -> Vec<u8>;

    fn read_virtual_bytes(&self, cr3: u64, vaddr: u64, buffer: &mut[u8]) -> MResult<usize>;
    fn write_virtual_bytes(&self, cr3: u64, guest_vaddr: u64, buffer: &[u8]) -> MResult<usize>;
}

pub trait GetMem{
    fn get_mem(&self) -> &GuestMemoryMmap;
}

impl GetMem for Vmm{
    fn get_mem(&self) -> &GuestMemoryMmap {
        self.vm.guest_memory()
    }
}

impl<GetMemT> NyxMemExtension for GetMemT where GetMemT: GetMem{
    fn read_virtual_cstr(&self, cr3: u64, guest_vaddr: u64) -> Vec<u8>{
        let mem = self.get_mem();
        let mut res = Vec::new();
        let mut cur_addr = guest_vaddr;
        for pte in walk_virtual_pages(mem, cr3, guest_vaddr&M_PAGE_ALIGN, M_PAGE_ALIGN){
            if !pte.present() || pte.missing_page() {
                return res;
            }
            let slice = mem.get_slice(pte.phys_addr(), PAGE_SIZE as usize).unwrap();
            while cur_addr < pte.vaddrs.end {
                let u8_char = slice.load::<u8>((cur_addr&M_PAGE_OFFSET) as usize, Ordering::Relaxed).unwrap();
                res.push(u8_char);
                cur_addr += 1;
                if u8_char == 0 {
                    return res;
                }
            }
        }
        return res;
    }

    fn resolve_vaddr(&self, cr3: u64, vaddr: u64) -> MResult<GuestAddress>{
        let mem = self.get_mem();
        let paddr = resolve_vaddr(mem, cr3, vaddr)?;
        return Ok(GuestAddress(paddr));
    }

    fn read_phys<T: ByteValued + AtomicAccess>(&self, paddr: u64) -> MResult<T> {
        let mem = self.get_mem();
        read_phys(mem, paddr)
    }

    fn write_phys<T: ByteValued + AtomicAccess>(&self, paddr: u64, val: T) -> MResult<()> {
        let mem = self.get_mem();
        write_phys(mem, paddr, val)
    }

    fn read_virtual<T: ByteValued + AtomicAccess>(&self, cr3: u64, vaddr: u64) -> MResult<T>{
        let mem = self.get_mem();
        let paddr = resolve_vaddr(mem, cr3, vaddr)?;
        return read_phys(mem, paddr)
    }

    fn write_virtual<T: ByteValued + AtomicAccess>(&self, cr3: u64, vaddr: u64, value: T) -> MResult<()>{
        let mem = self.get_mem();
        let paddr = resolve_vaddr(mem, cr3, vaddr)?;
        return write_phys(mem, paddr, value)
    }

    fn read_virtual_u64(&self, cr3: u64, vaddr: u64) -> MResult<u64>{
        return self.read_virtual(cr3, vaddr);
    }

    fn write_virtual_u64(&self, cr3: u64, vaddr: u64, val: u64) -> MResult<()>{
        return self.write_virtual(cr3, vaddr, val)
    }
    fn read_virtual_u8(&self, cr3: u64, vaddr: u64) -> MResult<u8> {
        return self.read_virtual(cr3, vaddr);
    }
    fn write_virtual_u8(&self, cr3: u64, vaddr: u64, val: u8) -> MResult<()>{
        return self.write_virtual(cr3, vaddr, val);
    }

    fn read_virtual_bytes<'buffer>(&self, cr3: u64, guest_vaddr: u64, buffer: &'buffer mut[u8]) -> MResult<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mem = self.get_mem();
        let mut num_bytes = 0;
        let start_page = guest_vaddr & M_PAGE_ALIGN;
        let last_page = (guest_vaddr + (buffer.len() as u64) - 1) & M_PAGE_ALIGN;
        for pte in walk_virtual_pages(mem, cr3, start_page, last_page) {
            if !pte.present() || pte.missing_page() {
                return Ok(num_bytes);
            }
            let guest_slice = mem.get_slice(pte.phys_addr(), PAGE_SIZE as usize).unwrap();
            let page_vaddr = pte.vaddrs.start;
            assert_eq!(guest_slice.len(), PAGE_SIZE as usize);
            let slice_start = if page_vaddr < guest_vaddr { (guest_vaddr-page_vaddr) as usize } else {0};
            let num_copied = guest_slice.subslice(slice_start, guest_slice.len()-slice_start).unwrap().copy_to(&mut buffer[num_bytes..]);
            num_bytes += num_copied;
            if num_bytes >= buffer.len() {
                break;
            }
        }
        return Ok(num_bytes);
    }

    fn write_virtual_bytes(&self, cr3: u64, guest_vaddr: u64, buffer: &[u8]) -> MResult<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mem = self.get_mem();
        let mut num_bytes = 0;
        let start_page = guest_vaddr & M_PAGE_ALIGN;
        let last_page = (guest_vaddr + (buffer.len() as u64) - 1) & M_PAGE_ALIGN;
        for pte in walk_virtual_pages(mem, cr3, start_page, last_page) {
            if !pte.present() || pte.missing_page() {
                return Ok(num_bytes);
            }
            let guest_slice = mem.get_slice(pte.phys_addr(), PAGE_SIZE as usize).unwrap();
            let page_vaddr = pte.vaddrs.start;
            assert_eq!(guest_slice.len(), PAGE_SIZE as usize);
            let slice_start = if page_vaddr < guest_vaddr { (guest_vaddr-page_vaddr) as usize } else {0};
            let buff_slice = &buffer[num_bytes..];
            let guest_slice = guest_slice.subslice(slice_start, guest_slice.len()-slice_start).unwrap();
            guest_slice.copy_from(buff_slice);
            let num_copied = buff_slice.len().min(guest_slice.len());
            num_bytes += num_copied;
            if num_bytes >= buffer.len() {
                break;
            }
        }
        return Ok(num_bytes);
    }

    fn set_physical_page_permission(&mut self, paddr: u64, perm: PagePermission){
        let page_addr = paddr & M_PAGE_ALIGN;
        let region = self.get_mem().find_region(GuestAddress(page_addr)).unwrap();
        assert!(region.to_region_addr(GuestAddress(page_addr)).is_some());
        let offset = page_addr - region.start_addr().0 as u64;
        let prot = match perm {
            PagePermission::None => 0,
            PagePermission::R => PROT_READ,
            PagePermission::W => PROT_WRITE,
            PagePermission::RW => PROT_READ | PROT_WRITE,
        };
        unsafe{
            let ptr = region.as_ptr().offset(offset as isize);
            mprotect(ptr as *mut c_void, PAGE_SIZE as usize, prot);
        }
    }
    
    fn set_virtual_page_permission(&mut self, cr3: u64, vaddr: u64, perm: PagePermission) {
       let phys_addr = self.resolve_vaddr(cr3, vaddr).unwrap();
       self.set_physical_page_permission(phys_addr.0, perm);
    }
}

fn read_page_table_entry(
    mem: &GuestMemoryMmap,
    paddr: u64,
    offset: u64,
) -> Result<u64, MemoryError> {
    let entry = read_phys_u64(mem, paddr + offset * 8)?;
    if (entry & BIT_PTE_PRESENT) != 0 {
        return Ok(entry & M_PTE_PADDR);
    }
    return Err(MemoryError::PageNotPresent(GuestAddress(paddr), offset));
}

pub fn resolve_vaddr(mem: &GuestMemoryMmap, cr3: u64, vaddr: u64) -> MResult<u64> {
    let mask = M_PAGE_ALIGN;
    let (l1, l2, l3, l4, offset) = split_vaddr(vaddr);
    let pml4_addr = read_page_table_entry(mem, cr3 & mask, l1)?;
    let pdp_addr = read_page_table_entry(mem, pml4_addr, l2)?;
    let pd_addr = read_page_table_entry(mem, pdp_addr, l3)?;
    let pt_addr = read_page_table_entry(mem, pd_addr, l4)?;
    let addr = pt_addr + offset;
    return Ok(addr);
}

// Primary function to walk virtual address spaces. Will merge all adjacent
// unmapped/invalid pages & only return leave nodes of the page tables
pub fn walk_virtual_pages<'mem>(
    mem: &'mem GuestMemoryMmap,
    cr3: u64,
    start: u64,
    last_page: u64,
) -> impl Iterator<Item = PTE> + 'mem {
    MergedPTEWalker::new(PTEWalker::new(mem, cr3, start, last_page).filter(|pte| pte.level == 3))
}

// walks the page tables between start and end. Note: End is inclusive, not
// exclusive. I.e. the last page will be starting at end. Will return all node
// in the page tables (including not-presen & invalid phys address nodes)
pub fn walk_page_tables(
    mem: &GuestMemoryMmap,
    cr3: u64,
    start: u64,
    last_page: u64,
) -> PTEWalker<'_> {
    PTEWalker::new(mem, cr3, start, last_page)
}

pub fn walk_page_tables_merged<'mem>(
    mem: &'mem GuestMemoryMmap,
    cr3: u64,
    start: u64,
    last_page: u64,
) -> MergedPTEWalker<'mem, PTEWalker<'mem>> {
    MergedPTEWalker::new(PTEWalker::new(mem, cr3, start, last_page))
}

pub fn split_vaddr(vaddr: u64) -> (u64, u64, u64, u64, u64) {
    let l1 = (vaddr >> 39) & M_PTE_OFFSET;
    let l2 = (vaddr >> 30) & M_PTE_OFFSET;
    let l3 = (vaddr >> 21) & M_PTE_OFFSET;
    let l4 = (vaddr >> 12) & M_PTE_OFFSET;
    let addr = (vaddr >> 0) & M_PAGE_OFFSET;
    return (l1, l2, l3, l4, addr);
}

pub fn join_vaddr(l1: u64, l2: u64, l3: u64, l4: u64, offset: u64) -> u64 {
    let l1 = (l1 & M_PTE_OFFSET) << 39;
    let l2 = (l2 & M_PTE_OFFSET) << 30;
    let l3 = (l3 & M_PTE_OFFSET) << 21;
    let l4 = (l4 & M_PTE_OFFSET) << 12;
    return l1 | l2 | l3 | l4 | (offset & M_PAGE_OFFSET);
}
pub struct PTE {
    pub vaddrs: Range<u64>,
    pub val: u64,
    pub level: u8,
    pub missing_page: bool,
}

impl<'mem> core::fmt::Debug for PTE {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("PTE")
            .field("level", &self.level)
            .field("val", &format_args!("{:X?}", self.val))
            .field("vaddrs", &format_args!("{:X?}", self.vaddrs))
            .finish()
    }
}

impl PTE {
    pub fn present(&self) -> bool {
        (self.val & BIT_PTE_PRESENT) != 0
    }
    pub fn phys_addr(&self) -> GuestAddress {
        GuestAddress(self.val & M_PTE_PADDR)
    }
    pub fn missing_page(&self) -> bool {
        self.missing_page
    }

    fn merge_with(&mut self, other: &PTE) -> bool {
        let same_level = self.level == other.level;
        let adjacent = self.vaddrs.end == other.vaddrs.start;
        if self.present() || !same_level || !adjacent {
            return false;
        }
        let both_missing_page = self.missing_page() && other.missing_page();
        let both_not_present = !self.present() && !other.present();
        if both_missing_page || both_not_present {
            self.vaddrs.end = other.vaddrs.end;
            return true;
        }
        return false;
    }
}

pub struct PTEWalker<'mem> {
    mem: &'mem GuestMemoryMmap,
    offsets: [u64; 4],
    bases: [u64; 4],
    last_page: u64,
    level: usize,
}

impl<'mem> core::fmt::Debug for PTEWalker<'mem> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("PTEWalker")
            .field("level", &self.level)
            .field("offsets", &format_args!("{:?}", self.offsets))
            .field("bases", &format_args!("{:X?}", self.bases))
            .field("last_page", &format_args!("{:X?}", self.last_page))
            .finish()
    }
}

impl<'mem> Iterator for PTEWalker<'mem> {
    type Item = PTE;
    fn next(&mut self) -> Option<Self::Item> {
        let res = self.iter_next();
        return res;
    }
}

impl<'mem> PTEWalker<'mem> {
    pub fn new(mem: &'mem GuestMemoryMmap, cr3: u64, start: u64, last_page: u64) -> Self {
        let (l1, l2, l3, l4, offset) = split_vaddr(start);
        assert_eq!(offset, 0);
        Self {
            mem,
            offsets: [l1, l2, l3, l4],
            bases: [cr3 & M_PAGE_ALIGN, 0, 0, 0],
            level: 0,
            last_page,
        }
    }

    fn get_cur_pte(&self) -> PTE {
        let vaddrs = self.make_vaddr_range();
        let level = self.level.try_into().unwrap();
        let base = self.bases[self.level];
        let offset = self.offsets[self.level];
        if let Ok(val) = read_phys_u64(self.mem, base + offset * 8) {
            PTE {
                vaddrs,
                val,
                level,
                missing_page: false,
            }
        } else {
            PTE {
                vaddrs,
                val: 0,
                level,
                missing_page: true,
            }
        }
    }

    fn advance_cursor_up(&mut self) {
        loop {
            let cur = &mut self.offsets[self.level];
            *cur += 1;
            if *cur >= 0x1ff {
                if self.level == 0 {
                    return;
                }
                *cur = 0;
                self.level -= 1;
            } else {
                return;
            }
        }
    }

    fn advance_cursor_down(&mut self, new_base_addr: u64) {
        assert_eq!(new_base_addr & M_PAGE_OFFSET, 0);
        self.level += 1;
        //This should be imlied as advance_cursor_up set's the offset[cur] to 0 before going up one level.
        //If we don't do this explicitly, we can initialliza the level to 0 and the offsets to a given vaddr to start iterating from that given vaddr
        //self.offsets[self.level]=0;
        self.bases[self.level] = new_base_addr;
    }

    fn make_vaddr_range(&self) -> Range<u64> {
        let l1 = self.offsets[0];
        let l2 = if self.level >= 1 { self.offsets[1] } else { 0 };
        let l3 = if self.level >= 2 { self.offsets[2] } else { 0 };
        let l4 = if self.level >= 3 { self.offsets[3] } else { 0 };
        let start = join_vaddr(l1, l2, l3, l4, 0);
        let size = [
            PAGE_SIZE * 512 * 512 * 512,
            PAGE_SIZE * 512 * 512,
            PAGE_SIZE * 512,
            PAGE_SIZE,
        ][self.level];
        start..start + size
    }

    fn iter_next(&mut self) -> Option<PTE> {
        // It appears that we see high kernel addresses sometimes (i.e.
        // ffffffff823b1ad8 during the boot breakpoint vmexit). Those aren't
        // handled correctly right now. Investigate expected behavior
        if self.offsets[0] > M_PTE_OFFSET {
            return None;
        }
        let res = self.get_cur_pte();
        if res.vaddrs.start > self.last_page {
            return None;
        }
        if res.present() && self.level < 3 {
            self.advance_cursor_down(res.phys_addr().0);
        } else {
            self.advance_cursor_up();
        }
        return Some(res);
    }
}

pub struct MergedPTEWalker<'mem, PTEIter: Iterator<Item = PTE> + 'mem> {
    inner: Peekable<PTEIter>,
    _phantom: PhantomData<&'mem PTEIter>,
}

impl<'mem, BaseIter: Iterator<Item = PTE>> MergedPTEWalker<'mem, BaseIter> {
    pub fn new(iter: BaseIter) -> Self {
        let inner = iter.peekable();
        Self {
            inner,
            _phantom: PhantomData,
        }
    }
}

impl<'mem, BaseIter: Iterator<Item = PTE>> Iterator for MergedPTEWalker<'mem, BaseIter> {
    type Item = PTE;
    fn next(&mut self) -> Option<Self::Item> {
        let mut cur = self.inner.next()?;
        while let Some(next) = self.inner.peek() {
            if !cur.merge_with(next) {
                break;
            }
            self.inner.next();
        }
        return Some(cur);
    }
}

pub struct VirtSpace<'vm>{
    pub cr3: u64,
    pub vmm: &'vm Vmm,
    pub addr: u64,
}

// currently not a stable feature.
fn checked_sub_signed(x: u64, y: i64) -> Option<u64>{
    return x.checked_sub(y as u64);
}

impl<'vm> Seek for VirtSpace<'vm> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(offset) => self.addr = offset,
            SeekFrom::Current(offset) => {
                match self.addr.checked_add_signed(offset){
                    Some(new) => self.addr = new,
                    None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Offset caused address Over/Underflow"))
                }
            }
            SeekFrom::End(offset) => {
                match checked_sub_signed(u64::MAX, offset){
                    Some(new) => self.addr = new,
                    None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Offset caused address Over/Underflow"))
                }
            }
        }
        Ok(self.addr)
    }
}

impl<'vm> Read for VirtSpace<'vm> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self
            .vmm
            .read_virtual_bytes(self.cr3, self.addr, buf)
            .unwrap();
        if let Some(next) = self.addr.checked_add(bytes as u64) {
            self.addr = next;
        }
        Ok(bytes)
    }
}

impl<'vm> Write for VirtSpace<'vm> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes = self
            .vmm
            .write_virtual_bytes(self.cr3, self.addr, buf)
            .unwrap();
        if let Some(next) = self.addr.checked_add(bytes as u64) {
            self.addr = next;
        }
        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(()) // No-op for in-memory buffer
    }
}




pub struct VirtMappedRange {
    cr3: u64,
    start: u64,
    end: u64,
    tlb: Vec<GuestAddress>,
}

impl VirtMappedRange {
    pub fn new(cr3: u64, start_page: u64, end_page: u64) -> Self {
        assert!(end_page >= start_page);
        assert!(start_page & M_PAGE_OFFSET == 0);
        assert!(end_page & M_PAGE_OFFSET == 0);
        Self {
            cr3,
            start: start_page,
            end: end_page,
            tlb: vec![],
        }
    }

    pub fn validate(&mut self, mem: &GuestMemoryMmap) -> Result<(), MemoryError> {
        self.tlb
            .reserve(((self.end - self.start) / PAGE_SIZE).try_into().unwrap());
        self.tlb.clear();
        for pte in walk_virtual_pages(
            mem,
            self.cr3,
            self.start & M_PAGE_OFFSET,
            self.end & M_PAGE_OFFSET,
        ) {
            if !pte.present() {
                return Err(MemoryError::PageNotPresent(
                    pte.phys_addr(),
                    pte.vaddrs.start,
                ));
            }
            if pte.missing_page() {
                return Err(MemoryError::CantAccessMissingPhysicalPage(pte.phys_addr()));
            }
            self.tlb.push(pte.phys_addr());
        }
        return Ok(());
    }

    pub fn iter<'mem>(
        &'mem mut self,
        mem: &'mem GuestMemoryMmap,
    ) -> impl Iterator<
        Item = (
            u64,
            VolatileSlice<'mem, BS<'mem, <GuestRegionMmap as GuestMemoryRegion>::B>>,
        ),
    > + 'mem {
        self.tlb.iter().enumerate().map(|(i, guest_phys_addr)| {
        if let Some(region) = mem.find_region(*guest_phys_addr) {
           let start = region.to_region_addr(*guest_phys_addr).unwrap();
           let cap = region.len() - start.raw_value();
           let len = std::cmp::min(cap, PAGE_SIZE as GuestUsize);
           assert_eq!(len, PAGE_SIZE as GuestUsize);
           let volatile_slice = region.as_volatile_slice().unwrap();
           return (self.start+(i as u64)*PAGE_SIZE, volatile_slice)
        }
        panic!("couldn't access memory for cr3: {:x}, addr: {:x} - region for physical {:x} not found ", 
        self.cr3,
        self.start + (i as u64) * PAGE_SIZE,
        guest_phys_addr.raw_value());
    })
    }
}

#[cfg(test)]
mod tests {

    use std::collections::HashSet;

    use vmm::vmm_config::machine_config::HugePageConfig;
    use vmm::vstate::memory::{self, GuestMemory, GuestMemoryRegion};

    use super::*;

    #[derive(Clone)]
    struct MemWrapper {
        mem: GuestMemoryMmap,
    }

    impl GetMem for MemWrapper {
        fn get_mem(&self) -> &GuestMemoryMmap {
            &self.mem
        }
    }

    #[test]
    fn test_process_memory_marks_host_dirty() {
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE * 8;
        allocated_pages.insert(cr3);
        let vaddr = 0x4000;
        let paddr = make_vpage(&mem, cr3, vaddr, &mut allocated_pages);

        let total_pages = mem
            .iter()
            .map(|region| {
                let len = region.len() as usize;
                (len + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize
            })
            .sum();
        let wrapper = MemWrapper { mem };
        let tracker = Arc::new(HostDirtyTracker::new(total_pages));
        let process = ProcessMemory::new(wrapper, cr3).with_host_dirty(tracker.clone());

        process.write_u64(vaddr, 0xdead_beef).unwrap();
        let dirty_pages = tracker.snapshot_pages();
        assert!(dirty_pages.contains(&paddr.0));
    }

    #[test]
    fn test_virtual_memory_cursor_advances() {
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE * 8;
        allocated_pages.insert(cr3);
        let vaddr = 0x4000;
        make_vpage(&mem, cr3, vaddr, &mut allocated_pages);
        make_vpage(&mem, cr3, vaddr + PAGE_SIZE, &mut allocated_pages);

        let wrapper = MemWrapper { mem };
        let process = ProcessMemory::new(wrapper, cr3);
        let mut cursor = process.cursor(vaddr);
        let payload = vec![0x5a_u8; (PAGE_SIZE as usize) + 16];
        let written = cursor.write(&payload).unwrap();
        assert_eq!(written, payload.len());

        let mut read_back = vec![0_u8; payload.len()];
        let mut read_cursor = process.cursor(vaddr);
        let read = read_cursor.read(&mut read_back).unwrap();
        assert_eq!(read, payload.len());
        assert_eq!(read_back, payload);
    }

    #[test]
    fn test_map_page_with_allocator() {
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE * 8;
        allocated_pages.insert(cr3);

        let target_page = allocate_page(&mem, &mut allocated_pages);
        let pt1 = allocate_page(&mem, &mut allocated_pages);
        let pt2 = allocate_page(&mem, &mut allocated_pages);
        let pt3 = allocate_page(&mem, &mut allocated_pages);
        let mut allocator = VecPageAllocator::new(vec![pt1, pt2, pt3]);

        let wrapper = MemWrapper { mem };
        let process = ProcessMemory::new(wrapper, cr3);
        let vaddr = 0x9000;
        process
            .map_page(
                vaddr,
                target_page.0,
                PageMapping {
                    writable: true,
                    executable: false,
                    user: true,
                },
                Some(&mut allocator),
            )
            .unwrap();

        process.write_u64(vaddr, 0x1122_3344_5566_7788).unwrap();
        let val = process.read_u64(vaddr).unwrap();
        assert_eq!(val, 0x1122_3344_5566_7788);
        let resolved = process.resolve_vaddr(vaddr).unwrap();
        assert_eq!(resolved, target_page);
    }

    #[test]
    fn test_resolve_address() {
        let mem = make_mem();
        let fake_cr3 = PAGE_SIZE * 8;
        let vaddr = 0x400000;
        let l1_addr = fake_cr3 + PAGE_SIZE;
        let l2_addr = fake_cr3 + PAGE_SIZE * 2;
        let l3_addr = fake_cr3 + PAGE_SIZE * 3;
        let target_1 = PAGE_SIZE;
        let target_2 = PAGE_SIZE * 3;
        let target_3 = PAGE_SIZE * 5;

        store(
            &mem,
            GuestAddress(fake_cr3 + 8 * ((vaddr >> 39) & M_PTE_OFFSET)),
            l1_addr | BIT_PTE_PRESENT,
        );
        store(
            &mem,
            GuestAddress(l1_addr + 8 * ((vaddr >> 30) & M_PTE_OFFSET)),
            l2_addr | BIT_PTE_PRESENT,
        );
        store(
            &mem,
            GuestAddress(l2_addr + 8 * ((vaddr >> 21) & M_PTE_OFFSET)),
            l3_addr | BIT_PTE_PRESENT,
        );
        store(
            &mem,
            GuestAddress(l3_addr + 8 * (((vaddr + 0 * PAGE_SIZE) >> 12) & M_PTE_OFFSET)),
            target_1 | BIT_PTE_PRESENT,
        );
        store(
            &mem,
            GuestAddress(l3_addr + 8 * (((vaddr + 1 * PAGE_SIZE) >> 12) & M_PTE_OFFSET)),
            target_2 | BIT_PTE_PRESENT,
        );
        store(
            &mem,
            GuestAddress(l3_addr + 8 * (((vaddr + 2 * PAGE_SIZE) >> 12) & M_PTE_OFFSET)),
            target_3 | BIT_PTE_PRESENT,
        );
        assert_eq!(resolve_vaddr(&mem, fake_cr3, vaddr).unwrap(), target_1);
        let walk = walk_virtual_pages(&mem, fake_cr3, vaddr, vaddr + PAGE_SIZE * 2)
            .map(|pte| (pte.vaddrs.start, pte.phys_addr()))
            .collect::<Vec<_>>();
        assert_eq!(
            walk,
            vec![
                (vaddr + 0 * PAGE_SIZE, GuestAddress(target_1)),
                (vaddr + 1 * PAGE_SIZE, GuestAddress(target_2)),
                (vaddr + 2 * PAGE_SIZE, GuestAddress(target_3)),
            ]
        );
    }

    #[test]
    fn test_make_pages() {
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE * 8;
        allocated_pages.insert(cr3);
        let t1 = make_vpage(&mem, cr3, 0x41000, &mut allocated_pages);
        let t2 = make_vpage(&mem, cr3, 0x42000, &mut allocated_pages);
        let t3 = make_vpage(&mem, cr3, 0x43000, &mut allocated_pages);

        assert_eq!(resolve_vaddr(&mem, cr3, 0x41000).unwrap(), t1.0);
        assert_eq!(resolve_vaddr(&mem, cr3, 0x42000).unwrap(), t2.0);
        assert_eq!(resolve_vaddr(&mem, cr3, 0x43000).unwrap(), t3.0);
        let walk = walk_virtual_pages(&mem, cr3, 0x41000, 0x41000 + PAGE_SIZE * 2)
            .map(|pte| (pte.vaddrs.start, pte.phys_addr()))
            .collect::<Vec<_>>();
        assert_eq!(
            walk,
            vec![
                (0x41000 + 0 * PAGE_SIZE, t1),
                (0x41000 + 1 * PAGE_SIZE, t2),
                (0x41000 + 2 * PAGE_SIZE, t3),
            ]
        );
    }

    #[test]
    fn test_walk_past_boundary() {
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE * 8;
        allocated_pages.insert(cr3);
        let boundary = 0x8000000000;
        let t1 = make_vpage(&mem, cr3, boundary - PAGE_SIZE, &mut allocated_pages);
        let t2 = make_vpage(&mem, cr3, boundary, &mut allocated_pages);
        let t3 = make_vpage(&mem, cr3, boundary + PAGE_SIZE, &mut allocated_pages);
        let walk = walk_virtual_pages(&mem, cr3, boundary - PAGE_SIZE, boundary + PAGE_SIZE)
            .map(|pte| (pte.vaddrs.start, pte.phys_addr()))
            .collect::<Vec<_>>();
        assert_eq!(
            walk,
            vec![
                (boundary - PAGE_SIZE, t1),
                (boundary, t2),
                (boundary + PAGE_SIZE, t3),
            ]
        );
    }

    #[test]
    fn test_walk_missing_page() {
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE * 8;
        allocated_pages.insert(cr3);
        let boundary = 0x8000000000;
        let t1 = make_vpage(&mem, cr3, boundary - PAGE_SIZE, &mut allocated_pages);
        // t2 is missing
        let t3 = make_vpage(&mem, cr3, boundary + PAGE_SIZE, &mut allocated_pages);
        let walk = walk_virtual_pages(&mem, cr3, boundary - PAGE_SIZE, boundary + 3 * PAGE_SIZE)
            .map(|pte| {
                (
                    pte.vaddrs.start,
                    pte.phys_addr(),
                    pte.present(),
                    pte.missing_page(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            walk,
            vec![
                (boundary - PAGE_SIZE, t1, true, false),
                (boundary, GuestAddress(0), false, false),
                (boundary + PAGE_SIZE, t3, true, false),
                (boundary + PAGE_SIZE * 2, GuestAddress(0), false, false),
            ]
        );
    }

    #[test]
    fn test_pte_walker() {
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE * 8;
        allocated_pages.insert(cr3);
        let boundary = 0x8000000000;
        let t1 = make_vpage(&mem, cr3, boundary - PAGE_SIZE, &mut allocated_pages);
        let t2 = make_vpage(&mem, cr3, boundary, &mut allocated_pages);
        let t3 = make_vpage(&mem, cr3, boundary + PAGE_SIZE, &mut allocated_pages);
        let last_page = 0xffffffff_ffffffff;
        let walk = PTEWalker::new(&mem, cr3, boundary - PAGE_SIZE, last_page)
            .filter(|i| i.present())
            .map(|i| (i.level, i.vaddrs))
            .collect::<Vec<_>>();
        let expected = [
            (0, 0x0..0x8000000000),
            (1, 0x7fc0000000..0x8000000000),
            (2, 0x7fffe00000..0x8000000000),
            (3, 0x7ffffff000..0x8000000000),
            (0, 0x8000000000..0x10000000000),
            (1, 0x8000000000..0x8040000000),
            (2, 0x8000000000..0x8000200000),
            (3, 0x8000000000..0x8000001000),
            (3, 0x8000001000..0x8000002000),
        ];
        assert_eq!(walk, expected);

        let walk = PTEWalker::new(&mem, cr3, boundary - PAGE_SIZE, boundary + PAGE_SIZE)
            .filter(|i| i.level == 3 && i.present())
            .map(|i| (i.level, i.vaddrs.start, i.phys_addr()))
            .collect::<Vec<_>>();
        let expected = [
            (3, 0x7ffffff000, t1),
            (3, 0x8000000000, t2),
            (3, 0x8000001000, t3),
        ];
        assert_eq!(walk, expected);
    }

    #[test]
    fn test_ptr_walker_missing_page() {
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE * 8;
        allocated_pages.insert(cr3);
        let boundary = 0x8000000000;
        let t1 = make_vpage(&mem, cr3, boundary - PAGE_SIZE, &mut allocated_pages);
        // t2 is missing
        let t3 = make_vpage(&mem, cr3, boundary + PAGE_SIZE, &mut allocated_pages);

        let walk = PTEWalker::new(&mem, cr3, boundary - PAGE_SIZE, boundary + PAGE_SIZE)
            .filter(|i| i.level == 3 && i.present())
            .map(|i| (i.level, i.vaddrs.start, i.phys_addr()))
            .collect::<Vec<_>>();
        let expected = [(3, 0x7ffffff000, t1), (3, 0x8000001000, t3)];
        assert_eq!(walk, expected);
    }

    #[test]
    fn test_ptr_walker_missing_page_table() {
        let mem = make_mem();
        let mut allocated_pages = HashSet::new();
        let cr3 = PAGE_SIZE * 8;
        allocated_pages.insert(cr3);
        let boundary = 0x8000000000;
        let t1 = make_vpage(&mem, cr3, boundary - PAGE_SIZE, &mut allocated_pages);
        //t2 and t3 are later invalidating by breaking the page table entry
        let _t2 = make_vpage(&mem, cr3, boundary, &mut allocated_pages);
        let _t3 = make_vpage(&mem, cr3, boundary + PAGE_SIZE, &mut allocated_pages);
        let t4 = make_vpage(&mem, cr3, boundary + PAGE_SIZE * 512, &mut allocated_pages);

        let (l1, l2, _l3, l4, _offset) = split_vaddr(boundary);
        let b2 = read_page_table_entry(&mem, cr3, l1).unwrap();
        let b3 = read_page_table_entry(&mem, b2, l2).unwrap();
        store_page_table_entry(&mem, GuestAddress(b3), l4, PAGE_SIZE * 512); // store invalid pointer in page table

        let walk = PTEWalker::new(&mem, cr3, boundary - PAGE_SIZE, boundary + PAGE_SIZE * 512)
            .filter(|i| i.present() || i.missing_page())
            .map(|i| (i.level, i.vaddrs.start, i.phys_addr(), i.missing_page()))
            .collect::<Vec<_>>();

        let mut expected = vec![
            (0, 0, GuestAddress(0x2000), false),
            (1, 0x7fc0000000, GuestAddress(0x3000), false),
            (2, 0x7fffe00000, GuestAddress(0x4000), false),
            (3, 0x7ffffff000, t1 /*GuestAddress(0x1000)*/, false),
            (0, 0x8000000000, GuestAddress(0x6000), false),
            (1, 0x8000000000, GuestAddress(0x7000), false),
            (2, 0x8000000000, GuestAddress(0x200000), false),
        ];
        let mut missed_pages: Vec<(u8, u64, GuestAddress, bool)> = (boundary
            ..(boundary + PAGE_SIZE * 511))
            .step_by(PAGE_SIZE as usize)
            .map(|addr| (3, addr, GuestAddress(0), true))
            .collect();
        expected.append(&mut missed_pages);
        expected.append(&mut vec![
            (2, 0x8000200000, GuestAddress(0xc000), false),
            (3, 0x8000200000, t4, false),
        ]);
        //for (i,(real,expected)) in walk.iter().zip(expected.iter()).enumerate(){
        //    if real != expected {
        //        println!("at {} got {:X?}, expected {:X?}",i, real, expected);
        //        assert!(false);
        //    }
        //}
        assert_eq!(walk.len(), expected.len());
        assert_eq!(walk, expected);
    }

    fn allocate_page(mem: &GuestMemoryMmap, allocated_pages: &mut HashSet<u64>) -> GuestAddress {
        let mut selected_page = 0;
        'outer: for region in mem.iter() {
            for page in (region.start_addr().0..region.start_addr().0 + (region.size() as u64))
                .step_by(PAGE_SIZE as usize)
            {
                if page != 0 && !allocated_pages.contains(&page) {
                    selected_page = page;
                    break 'outer;
                }
            }
        }
        assert_ne!(selected_page, 0);
        allocated_pages.insert(selected_page);
        return GuestAddress(selected_page);
    }

    fn get_or_make_page_table_entry(
        mem: &GuestMemoryMmap,
        allocated_pages: &mut HashSet<u64>,
        page_table: GuestAddress,
        offset: u64,
    ) -> GuestAddress {
        if let Err(MemoryError::PageNotPresent(..)) =
            read_page_table_entry(mem, page_table.0, offset)
        {
            let new_page = allocate_page(mem, allocated_pages);
            store_page_table_entry(mem, page_table, offset, new_page.0);
        }
        let page = read_page_table_entry(mem, page_table.0, offset).unwrap();
        return GuestAddress(page);
    }
    fn make_vpage(
        mem: &GuestMemoryMmap,
        cr3: u64,
        vaddr: u64,
        allocated_pages: &mut HashSet<u64>,
    ) -> GuestAddress {
        let target_page = allocate_page(mem, allocated_pages);
        let (l1, l2, l3, l4, offset) = split_vaddr(vaddr);
        assert_eq!(offset, 0); //page aligned;

        let l2_page = get_or_make_page_table_entry(mem, allocated_pages, GuestAddress(cr3), l1);
        let l3_page = get_or_make_page_table_entry(mem, allocated_pages, l2_page, l2);
        let l4_page = get_or_make_page_table_entry(mem, allocated_pages, l3_page, l3);
        store_page_table_entry(mem, l4_page, l4, target_page.0);
        return target_page;
    }

    fn make_mem() -> GuestMemoryMmap {
        let page_size = PAGE_SIZE as usize;

        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(PAGE_SIZE * 8);
        let mem_regions = [
            (region_1_address, page_size * 8),
            (region_2_address, page_size * 8),
        ];
        let regions = memory::anonymous(mem_regions.into_iter(), false, HugePageConfig::None)
            .expect("failed to allocate test memory");
        memory::test_utils::into_region_ext(regions)
    }

    fn store(mem: &GuestMemoryMmap, addr: GuestAddress, val: u64) {
        mem.store(val, addr, Ordering::Relaxed).unwrap();
    }

    fn store_page_table_entry(mem: &GuestMemoryMmap, paddr: GuestAddress, offset: u64, value: u64) {
        store(
            mem,
            GuestAddress(paddr.0 + offset * 8),
            value | BIT_PTE_PRESENT,
        );
    }
}
