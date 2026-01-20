use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::ptr::NonNull;
use std::fs::File;
use std::path::PathBuf;
use std::os::unix::io::FromRawFd;
use std::sync::{Arc, Mutex};
use std::ffi::CStr;
use std::thread::JoinHandle;
use std::time::{self, Duration};
use std::thread;

use anyhow::Result;

use event_manager::SubscriberOps;
use iced_x86::OpAccess;
use vmm::arch::GUEST_PAGE_SIZE;
use vmm::arch::x86_64::generated::msr_index::{
    MSR_IA32_DEBUGCTLMSR, MSR_IA32_DS_AREA, MSR_IA32_TSC, MSR_IA32_TSC_ADJUST,
    MSR_IA32_TSC_DEADLINE,
};
use vmm::device_manager::mmio::MMIODeviceManager;
use vmm::devices::virtio::block::device::Block;
use vmm::devices::virtio::block::persist::BlockState;
use vmm::devices::virtio::queue::Queue;
use vmm::devices::virtio::persist::QueueConstructorArgs;
use vmm::devices::virtio::generated::virtio_ids::VIRTIO_ID_BLOCK;
use vmm::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vmm::logger::debug;
use vmm::persist::MicrovmState;
use vmm::cpu_config::templates::StaticCpuTemplate;
use vmm::resources::VmResources;
use vmm::snapshot::Persist;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vstate::memory::{GuestMemoryExtension, GuestRegionMmapExt};
use vmm::vstate::memory::{
    Bitmap, Bytes, GuestAddress, GuestMemory, GuestMemoryRegion, MemoryRegionAddress,
};
use vmm::vstate::vcpu::{VcpuEmulation, VcpuError, VCPU_RTSIG_OFFSET};
use vmm::Vcpu;
use vmm::Vmm;
use vmm::{EventManager, VcpuEvent};
use vmm::utils::get_page_size;
use vm_memory::Address;

use kvm_bindings::{
    kvm_dirty_gfn, kvm_enable_cap, kvm_guest_debug, kvm_guest_debug_arch, kvm_msr_entry, kvm_regs,
    kvm_sregs, Msrs, KVM_CAP_DIRTY_LOG_RING, KVM_DIRTY_LOG_PAGE_OFFSET,
    KVM_GUESTDBG_BLOCKIRQ, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_INJECT_BP, KVM_GUESTDBG_SINGLESTEP,
    KVM_GUESTDBG_USE_HW_BP, KVM_GUESTDBG_USE_SW_BP,
};

use crate::error::MemoryError;
use crate::breakpoints::{BreakpointManager, BreakpointManagerTrait};
use crate::disassembly::{disassemble_memory_accesses, is_control_flow};
use crate::firecracker_wrappers::build_microvm_for_boot;
use crate::hw_breakpoints::HwBreakpoints;
use crate::snapshot::{BaseRegionSnapshot, MemorySnapshot, NyxSnapshot, SnapshotType};
use crate::timer_event::TimerEvent;
use crate::vm_continuation_statemachine::{RunMode, VMContinuationState, VMExitUserEvent};
use crate::mem::{
    self, GetMem, HostDirtyTracker, LockedVmm, NyxMemExtension, PageAllocator, PageMapping,
    ProcessMemory, SharedMemoryRegion,
};

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum DebugState{
    Breakpoint,
    SingleStep,
    Continue,
}
const EXECDONE: u64 = 0x656e6f6463657865;
const SNAPSHOT: u64 = 0x746f687370616e73;
const NYX_LITE: u64 = 0x6574696c2d78796e;
const SHAREMEM: u64 = 0x6d656d6572616873;
const DBGPRINT: u64 = 0x746e697270676264;
const DBG_EXCEPTION_BREAKPOINT : u32 = 3;
const DBG_EXCEPTION_SINGLESTEP : u32 = 1;
const DR6_BS : u64 = 1<<14 ; // Single-Step execution
const DR6_HWBP_0: u64 = 1 << 0;
const DR6_HWBP_1: u64 = 1 << 1;
const DR6_HWBP_2: u64 = 1 << 2;
const DR6_HWBP_3: u64 = 1 << 3;
const KVM_DIRTY_GFN_F_DIRTY: u32 = 1;
const KVM_DIRTY_GFN_F_RESET: u32 = 2;
const KVM_DIRTY_RING_MAX_ENTRIES: usize = 65536;
const CANONICAL_USER_LIMIT: u64 = 0x0000_8000_0000_0000;
const DEBUGCTL_BTF: u64 = 1 << 1;
const DEBUGCTL_BTS: u64 = 1 << 7;
const DEBUGCTL_BTINT: u64 = 1 << 8;
const DEBUGCTL_BTS_OFF_OS: u64 = 1 << 9;
const DEBUGCTL_BTS_OFF_USR: u64 = 1 << 10;

fn is_canonical_user_addr(addr: u64) -> bool {
    addr < CANONICAL_USER_LIMIT
}

#[derive(Debug, Copy, Clone)]
struct DirtyRingEntry {
    slot: u32,
    offset: u64,
}

#[derive(Debug)]
struct DirtyRingState {
    entries: NonNull<kvm_dirty_gfn>,
    entry_count: usize,
    head: u32,
    page_size: u64,
    slot_bases: HashMap<u32, GuestAddress>,
    slot_sizes: HashMap<u32, usize>,
}

impl DirtyRingState {
    fn drain(&mut self) -> Vec<DirtyRingEntry> {
        let mut entries = Vec::new();
        let count = self.entry_count as u32;
        for _ in 0..self.entry_count {
            let idx = (self.head % count) as usize;
            let entry_ptr = unsafe { self.entries.as_ptr().add(idx) };
            let entry = unsafe { std::ptr::read_volatile(entry_ptr) };
            if (entry.flags & KVM_DIRTY_GFN_F_DIRTY) == 0 {
                break;
            }
            entries.push(DirtyRingEntry {
                slot: entry.slot,
                offset: entry.offset,
            });
            let new_flags = entry.flags | KVM_DIRTY_GFN_F_RESET;
            unsafe {
                std::ptr::write_volatile(&mut (*entry_ptr).flags, new_flags);
            }
            self.head = self.head.wrapping_add(1);
        }
        entries
    }
}
pub struct NyxVM {
    pub vmm: Arc<Mutex<Vmm>>,
    pub vcpu: Vcpu,
    pub event_thread_handle: JoinHandle<Result<(), anyhow::Error>>,
    event_manager: RefCell<EventManager>,
    pub vm_resources: VmResources,
    pub block_devices: Vec<Arc<Mutex<Block>>>,
    pub timeout_timer: Arc<Mutex<TimerEvent>>,
    pub continuation_state: VMContinuationState,
    pub breakpoint_manager: Box<dyn BreakpointManagerTrait>,
    pub hw_breakpoints: HwBreakpoints,
    pub active_snapshot: Option<Arc<NyxSnapshot>>,
    pub serial_pty: Option<SerialPty>,
    regs_cache: RefCell<Option<kvm_regs>>,
    sregs_cache: RefCell<Option<kvm_sregs>>,
    last_nyx_breakpoint: RefCell<Option<(u64, u64)>>,
    dirty_ring: Option<DirtyRingState>,
    dirty_ring_backlog: Vec<DirtyRingEntry>,
    host_dirty: Arc<HostDirtyTracker>,
    shared_pages: HashSet<u64>,
}

#[derive(Debug)]
pub struct SerialPty {
    pub master: File,
    pub slave_path: PathBuf,
}

fn create_serial_pty() -> std::io::Result<SerialPty> {
    let mut master: libc::c_int = 0;
    let mut slave: libc::c_int = 0;
    let mut name = [0 as libc::c_char; 128];
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            name.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let slave_path = unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    unsafe { libc::close(slave) };
    let master_file = unsafe { File::from_raw_fd(master) };
    Ok(SerialPty {
        master: master_file,
        slave_path: PathBuf::from(slave_path),
    })
}

fn register_kick_signal_handler() {
    extern "C" fn handle_signal(
        _: libc::c_int,
        _: *mut libc::siginfo_t,
        _: *mut libc::c_void,
    ) {
        std::sync::atomic::fence(Ordering::Acquire);
    }
    vmm::utils::signal::register_signal_handler(
        vmm::utils::signal::sigrtmin() + VCPU_RTSIG_OFFSET,
        handle_signal,
    )
    .expect("Failed to register vcpu signal handler");
}


#[derive(Debug)]
pub enum UnparsedExitReason {
    Shutdown,
    Hypercall,
    Timeout,
    NyxBreakpoint,
    GuestBreakpoint,
    SingleStep,
    Interrupted,
    HWBreakpoint(u8),
    BadMemoryAccess,
}

#[derive(Debug)]
pub enum ExitReason {
    Shutdown,
    Hypercall(u64, u64, u64, u64, u64),
    BadMemoryAccess(Vec<(u64, OpAccess)>),
    RequestSnapshot,
    ExecDone(u64),
    SharedMem(String, u64, usize),
    DebugPrint(String),
    Timeout,
    Breakpoint,
    HWBreakpoint(u8),
    SingleStep,
    Interrupted,
}

/// Configuration for enabling Branch Trace Store (BTS) via DEBUGCTL.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BtsConfig {
    pub enable: bool,
    pub interrupt: bool,
    pub off_user: bool,
    pub off_kernel: bool,
}

/// Control whether shared memory pages are snapshotted or preserved across resets.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SharedMemoryPolicy {
    Snapshot,
    Preserve,
}

impl NyxVM {
    // NOTE: due to the fact that timeout timers are tied to the thread that
    // makes the NyxVM (see TimerEvent for more details), it's probably unsafe
    // to use a NyxVM in a different thread than the one that made it.
    pub fn new(instance_id: String, config_json: &str) -> Self {
        let mmds_size_limit = 0;

        let instance_info = InstanceInfo {
            id: instance_id.clone(),
            state: VmState::NotStarted,
            vmm_version: "0.1".to_string(),
            app_name: "Firecracker-Lite".to_string(),
        };

        let mut event_manager = EventManager::new().expect("Unable to create EventManager");

        // Build the microVm.
        let mut vm_resources =
            VmResources::from_json(&config_json, &instance_info, mmds_size_limit, None)
                .expect("couldn't parse config json");
        let mut serial_pty = None;
        if vm_resources.serial_out_path.is_none() {
            if let Ok(pty) = create_serial_pty() {
                vm_resources.serial_out_path = Some(pty.slave_path.clone());
                serial_pty = Some(pty);
            }
        }

        let block_devices = vm_resources
            .block
            .devices
            .iter()
            .cloned()
            .collect::<Vec<_>>();

        vm_resources.machine_config.track_dirty_pages = true;

        vm_resources.boot_timer = false;

        debug!("event_start: build microvm for boot");

        let (vmm, mut vcpu) = build_microvm_for_boot(&instance_info, &vm_resources, &mut event_manager)
            .expect("couldn't prepare vm");
        debug!("event_end: build microvm for boot");

        let dirty_ring = {
            let vmm_guard = vmm.lock().unwrap();
            Self::try_enable_dirty_ring(&vmm_guard, &mut vcpu)
        };
        
        let timeout_timer = Arc::new(Mutex::new(TimerEvent::new()));
        event_manager.add_subscriber(timeout_timer.clone());
        // This will allow the timeout timer to send the signal that makes KVM exit immediatly
        register_kick_signal_handler();
        // Run the event manager in the same thread to avoid non-Send subscribers.
        let event_thread_handle = thread::Builder::new()
            .name("event_thread".to_string())
            .spawn(|| Ok(()))
            .unwrap();
        let total_pages = {
            let vmm_guard = vmm.lock().unwrap();
            vmm_guard
                .vm
                .guest_memory()
                .iter()
                .map(|region| {
                    let len = region.len() as usize;
                    (len + mem::PAGE_SIZE as usize - 1) / mem::PAGE_SIZE as usize
                })
                .sum()
        };

        return Self {
            vcpu,
            vmm,
            event_manager: RefCell::new(event_manager),
            vm_resources,
            event_thread_handle,
            block_devices,
            timeout_timer,
            continuation_state: VMContinuationState::Main,
            breakpoint_manager: Box::new(BreakpointManager::new()),
            hw_breakpoints: HwBreakpoints::new(),
            active_snapshot: None,
            serial_pty,
            regs_cache: RefCell::new(None),
            sregs_cache: RefCell::new(None),
            last_nyx_breakpoint: RefCell::new(None),
            dirty_ring,
            dirty_ring_backlog: Vec::new(),
            host_dirty: Arc::new(HostDirtyTracker::new(total_pages)),
            shared_pages: HashSet::new(),
        };
    }

    fn try_enable_dirty_ring(vmm: &Vmm, vcpu: &mut Vcpu) -> Option<DirtyRingState> {
        if vmm
            .kvm()
            .fd
            .check_extension_raw(u64::from(KVM_CAP_DIRTY_LOG_RING))
            == 0
        {
            return None;
        }

        let page_size = get_page_size().ok()? as usize;
        let run_size = vmm.vm.fd().run_size();
        let offset_bytes = (KVM_DIRTY_LOG_PAGE_OFFSET as usize).checked_mul(page_size)?;
        if run_size <= offset_bytes {
            debug!("dirty ring unsupported: vcpu mmap too small");
            return None;
        }

        let max_entries =
            (run_size - offset_bytes) / std::mem::size_of::<kvm_dirty_gfn>();
        if max_entries == 0 {
            debug!("dirty ring unsupported: no space for entries");
            return None;
        }
        let entry_count = std::cmp::min(max_entries, KVM_DIRTY_RING_MAX_ENTRIES);

        let mut cap = kvm_enable_cap::default();
        cap.cap = KVM_CAP_DIRTY_LOG_RING;
        cap.args[0] = entry_count as u64;
        if let Err(err) = vmm.vm.fd().enable_cap(&cap) {
            debug!("dirty ring enable failed: {}", err);
            return None;
        }

        let run_ptr = vcpu.kvm_vcpu.fd.get_kvm_run() as *mut _ as *mut u8;
        let ring_ptr = unsafe { run_ptr.add(offset_bytes) as *mut kvm_dirty_gfn };
        let entries = NonNull::new(ring_ptr)?;

        let mut slot_bases = HashMap::new();
        let mut slot_sizes = HashMap::new();
        for region in vmm.vm.guest_memory().iter() {
            let slot_size = region.slot_size();
            for slot in region.slot_range() {
                if let Some(base) = region.slot_base(slot) {
                    slot_bases.insert(slot, base);
                    slot_sizes.insert(slot, slot_size);
                }
            }
        }

        Some(DirtyRingState {
            entries,
            entry_count,
            head: 0,
            page_size: page_size as u64,
            slot_bases,
            slot_sizes,
        })
    }

    pub fn process_memory(&self, cr3: u64) -> ProcessMemory<LockedVmm> {
        let backend = LockedVmm::new(self.vmm.clone());
        ProcessMemory::new(backend, cr3).with_host_dirty(self.host_dirty.clone())
    }

    pub fn current_process_memory(&self) -> ProcessMemory<LockedVmm> {
        let cr3 = self.sregs().cr3;
        self.process_memory(cr3)
    }

    /// Registers a guest memory range as shared and optionally excludes it from snapshot resets.
    pub fn register_shared_region(
        &mut self,
        cr3: u64,
        vaddr: u64,
        len: usize,
        policy: SharedMemoryPolicy,
    ) -> Result<SharedMemoryRegion<LockedVmm>, MemoryError> {
        if len == 0 {
            return Ok(SharedMemoryRegion::new(
                self.process_memory(cr3),
                vaddr,
                0,
            ));
        }
        if policy == SharedMemoryPolicy::Preserve {
            let start = vaddr & mem::M_PAGE_ALIGN;
            let end = vaddr
                .checked_add(len as u64 - 1)
                .unwrap_or(u64::MAX)
                & mem::M_PAGE_ALIGN;
            let mut cur = start;
            let process = self.process_memory(cr3);
            while cur <= end {
                let phys = process.resolve_vaddr(cur)?;
                self.shared_pages.insert(phys.raw_value());
                if let Some(next) = cur.checked_add(mem::PAGE_SIZE) {
                    cur = next;
                } else {
                    break;
                }
            }
        }
        Ok(SharedMemoryRegion::new(
            self.process_memory(cr3),
            vaddr,
            len,
        ))
    }

    pub fn register_shared_region_current(
        &mut self,
        vaddr: u64,
        len: usize,
        policy: SharedMemoryPolicy,
    ) -> Result<SharedMemoryRegion<LockedVmm>, MemoryError> {
        let cr3 = self.sregs().cr3;
        self.register_shared_region(cr3, vaddr, len, policy)
    }

    pub fn inject_mapping(
        &self,
        cr3: u64,
        vaddr: u64,
        paddr: u64,
        mapping: PageMapping,
        allocator: Option<&mut dyn PageAllocator>,
    ) -> Result<(), MemoryError> {
        self.process_memory(cr3)
            .map_page(vaddr, paddr, mapping, allocator)
    }

    pub fn inject_code(
        &self,
        cr3: u64,
        vaddr: u64,
        paddr: u64,
        code: &[u8],
        mapping: PageMapping,
        allocator: Option<&mut dyn PageAllocator>,
    ) -> Result<(), MemoryError> {
        self.process_memory(cr3)
            .inject_code(vaddr, paddr, code, mapping, allocator)
    }

    fn take_memory_snapshot_with_state(
        vmm: &Vmm,
        snap_type: SnapshotType,
        dirty_ring: &mut Option<DirtyRingState>,
        dirty_ring_backlog: &mut Vec<DirtyRingEntry>,
        host_dirty: &HostDirtyTracker,
        shared_pages: &HashSet<u64>,
    ) -> MemorySnapshot {
        let memory = match snap_type {
        SnapshotType::Base => {
            let mut regions = Vec::new();
            for region in vmm.vm.guest_memory().iter() {
                let region_len: usize = region.len().try_into().unwrap_or(0);
                let mut memory = vec![0; region_len];
                region
                    .read_slice(&mut memory, MemoryRegionAddress(0))
                    .unwrap();
                regions.push(BaseRegionSnapshot {
                    start: region.start_addr().raw_value(),
                    data: Arc::from(memory),
                });
            }
            MemorySnapshot::Base(regions)
        },
        SnapshotType::Incremental => {
            let mut map = HashMap::new();
            Self::iter_dirty_pages_with_state(
                vmm,
                dirty_ring,
                dirty_ring_backlog,
                host_dirty,
                |region, region_offset, guest_addr| {
                    if shared_pages.contains(&guest_addr) {
                        return;
                    }
                    let mut data = vec![0; GUEST_PAGE_SIZE as usize];

                    region
                        .read_slice(&mut data, MemoryRegionAddress(region_offset as u64))
                        .unwrap();
                    map.insert(guest_addr, data);
                },
            );
            MemorySnapshot::Incremental(map)
        }};

        Self::reset_dirty_tracking_with_state(vmm, dirty_ring, dirty_ring_backlog, host_dirty);
        return memory;
    }

    pub fn take_snapshot(&mut self) -> Arc<NyxSnapshot> {
        let snap_type = if self.active_snapshot.is_some() { SnapshotType::Incremental } else {SnapshotType::Base};
        return self.take_snapshot_with_type(snap_type);
    }

    pub fn take_base_snapshot(&mut self) -> Arc<NyxSnapshot> {
        return self.take_snapshot_with_type(SnapshotType::Base);
    }

    pub fn take_snapshot_with_type(&mut self, snap_type: SnapshotType) -> Arc<NyxSnapshot>{
        if snap_type == SnapshotType::Incremental {
            assert!(self.active_snapshot.is_some(), "can't take an incremental snapshot without a basis snapshot!");
        }
        let memory = {
            let vmm = self.vmm.lock().unwrap();
            Self::take_memory_snapshot_with_state(
                &vmm,
                snap_type,
                &mut self.dirty_ring,
                &mut self.dirty_ring_backlog,
                &self.host_dirty,
                &self.shared_pages,
            )
        };

        //let block_device_snapshots = self.block_devices.iter().map(|dev| {
        //    // This flushes all changes to the backing file
        //    // - however this should not be needed, as we aren't shutting downt
        //    // the process - For now, it's fine if the OS caches changes to the backing
        //    // file for us. Eventually we will store all updates in memory and
        //    // never change the backing file, so it won't be needed either
        //    // dev.prepare_save();
        //    BlockDeviceSnapshot::from(dev)
        //}).collect();

        let msrs = self
            .vcpu
            .kvm_vcpu
            .get_msrs(
                [
                    MSR_IA32_TSC,
                    MSR_IA32_TSC_DEADLINE,
                    MSR_IA32_TSC_ADJUST,
                ]
                .into_iter(),
            )
            .unwrap();
        let tsc = msrs[&MSR_IA32_TSC];
        let parent = self.active_snapshot.take();
        let depth = parent.as_ref().map(|p| p.depth+1).unwrap_or(0);
        let vmm = self.vmm.lock().unwrap();
        let new_snap =  Arc::new(NyxSnapshot {
            parent,
            depth, 
            memory,
            state: self.save_vm_state(&vmm),
            tsc,
            continuation_state: self.continuation_state.clone()
        });
        self.active_snapshot = Some(new_snap.clone());
        return new_snap;
    }

    fn save_vm_state(&self, vmm: &Vmm) -> MicrovmState {
        let vm_state = vmm.vm.save_state().unwrap();
        let device_states = vmm.device_manager.save();
        let vcpu_state = self.vcpu.kvm_vcpu.save_state().unwrap();
        let vm_info = vmm::persist::VmInfo::from(&self.vm_resources);
        let kvm_state = vmm.kvm().save_state();
        // this is missing pio device state - notably shutdown and serial devices
        return MicrovmState {
            vm_info: vm_info,
            kvm_state,
            vm_state,
            vcpu_states: vec![vcpu_state],
            device_states,
        };
    }

    fn apply_snapshot_mmio(
        mmio: &MMIODeviceManager,
        mem: &vmm::vstate::memory::GuestMemoryMmap,
        snap: &NyxSnapshot,
    ) {
        let ds = &snap.state.device_states.mmio_state;
        let blocks = &ds.block_devices;
        for block_snap in blocks.iter() {
            if let BlockState::Virtio(vio_block_snap_state) = &block_snap.device_state {
                let vstate = &vio_block_snap_state.virtio_state;
                let device_id = &block_snap.device_id;
                let bus_dev = mmio
                    .get_virtio_device(VIRTIO_ID_BLOCK, device_id)
                    .unwrap();
                let mut mmio_transport = bus_dev.inner().lock().unwrap();
                block_snap.transport_state.apply_to(&mut mmio_transport);
                let mut locked_dev = mmio_transport.locked_device();
                let cow_file_engine = locked_dev.as_cow_file_engine().expect("Trying to apply a snapshot to a non-cow block device");
                cow_file_engine.reset_to(vio_block_snap_state.cow_state.id);
                locked_dev.set_acked_features(vstate.acked_features);
                locked_dev
                    .interrupt_status()
                    .store(vstate.interrupt_status, Ordering::Relaxed);

                let queue_args = QueueConstructorArgs {
                    mem: mem.clone(),
                    is_activated: locked_dev.is_activated(),
                };
                let uses_notif_suppression =
                    (vstate.acked_features & (1u64 << VIRTIO_RING_F_EVENT_IDX)) != 0;
                for (queue, queue_snap) in locked_dev
                    .queues_mut()
                    .iter_mut()
                    .zip(vstate.queues.iter())
                {
                    let mut new_queue = Queue::restore(queue_args.clone(), queue_snap).unwrap();
                    if uses_notif_suppression {
                        new_queue.enable_notif_suppression();
                    }
                    let _ = std::mem::replace(queue, new_queue);
                }
            } else {
                panic!("trying to apply snapshot for a non-virtio block device. Not supported");
            }
        }
    }

    fn apply_tsc(&mut self, tsc: u64) {
        //let msrs = self.vcpu.kvm_vcpu.get_msrs([MSR_IA32_TSC, MSR_IA32_TSC_DEADLINE, MSR_IA32_TSC_ADJUST].into_iter()).unwrap();
        //println!("MSRS: TSC {:x} (snapshot: {:x}) TSCDEADLINE {:x} TSC_ADJUST {:x}", msrs[&MSR_IA32_TSC], snap.tsc, msrs[&MSR_IA32_TSC_DEADLINE], msrs[&MSR_IA32_TSC_ADJUST]);
        let msrs_to_set = [
            // KVM "helpfully" tries to prevent us from updating TSC in small increments and ignores small delta updates.
            // update to an insane value first
            kvm_msr_entry {
                index: MSR_IA32_TSC,
                data: tsc.wrapping_add(0xdeadc0debeef),
                ..Default::default()
            },
            // then update to what we actually want it to be.
            kvm_msr_entry {
                index: MSR_IA32_TSC,
                data: tsc,
                ..Default::default()
            },
        ];
        let msrs_wrapper = Msrs::from_entries(&msrs_to_set).unwrap();
        let num_set = self.vcpu.kvm_vcpu.fd.set_msrs(&msrs_wrapper).unwrap();
        assert_eq!(num_set, msrs_to_set.len());
        //let msrs = self.vcpu.kvm_vcpu.get_msrs([MSR_IA32_TSC, MSR_IA32_TSC_DEADLINE, MSR_IA32_TSC_ADJUST].into_iter()).unwrap();
        //println!("MSRS: TSC {:x} (snapshot: {:x}) TSCDEADLINE {:x} TSC_ADJUST {:x}", msrs[&MSR_IA32_TSC], snap.tsc, msrs[&MSR_IA32_TSC_DEADLINE], msrs[&MSR_IA32_TSC_ADJUST]);
    }

    fn reset_dirty_tracking_with_state(
        vmm: &Vmm,
        dirty_ring: &mut Option<DirtyRingState>,
        dirty_ring_backlog: &mut Vec<DirtyRingEntry>,
        host_dirty: &HostDirtyTracker,
    ) {
        vmm.vm.guest_memory().reset_dirty();
        if dirty_ring.is_some() {
            dirty_ring_backlog.clear();
            if let Err(err) = vmm.vm.reset_dirty_rings() {
                debug!("failed to reset dirty ring: {}", err);
            }
        } else {
            vmm.vm.reset_dirty_bitmap();
        }
        host_dirty.clear();
    }

    fn drain_dirty_ring_backlog(
        vmm: &Vmm,
        dirty_ring: &mut Option<DirtyRingState>,
        dirty_ring_backlog: &mut Vec<DirtyRingEntry>,
    ) {
        let Some(ring) = dirty_ring.as_mut() else {
            return;
        };
        let entries = ring.drain();
        if !entries.is_empty() {
            dirty_ring_backlog.extend(entries);
        }
        if let Err(err) = vmm.vm.reset_dirty_rings() {
            debug!("failed to reset dirty ring: {}", err);
        }
    }

    fn dirty_ring_entry_to_region_offset<'a>(
        ring: &DirtyRingState,
        mem: &'a vmm::vstate::memory::GuestMemoryMmap,
        entry: DirtyRingEntry,
    ) -> Option<(&'a GuestRegionMmapExt, usize, u64)> {
        let base = *ring.slot_bases.get(&entry.slot)?;
        let slot_size = *ring.slot_sizes.get(&entry.slot)?;
        let offset_bytes = entry.offset.checked_mul(ring.page_size)?;
        if offset_bytes >= slot_size as u64 {
            return None;
        }
        let guest_addr = base.raw_value().checked_add(offset_bytes)?;
        let region = mem.find_region(GuestAddress(guest_addr))?;
        let region_offset = guest_addr
            .checked_sub(region.start_addr().raw_value())?
            .try_into()
            .ok()?;
        Some((region, region_offset, guest_addr))
    }

    /// callback will be called with the guest memory GuestRegionMmap object,
    /// the region offset of the dirty page, and the guest physical address.
    fn iter_dirty_pages_with_state<Callback>(
        vmm: &Vmm,
        dirty_ring: &mut Option<DirtyRingState>,
        dirty_ring_backlog: &mut Vec<DirtyRingEntry>,
        host_dirty: &HostDirtyTracker,
        mut callback: Callback,
    )
    where
        Callback: FnMut(&GuestRegionMmapExt, usize, u64),
    {
        let mut seen = HashSet::new();
        let host_pages = host_dirty.snapshot_pages();
        for guest_addr in host_pages {
            if let Some(region) = vmm.vm.guest_memory().find_region(GuestAddress(guest_addr)) {
                let region_offset = guest_addr
                    .checked_sub(region.start_addr().raw_value())
                    .and_then(|val| usize::try_from(val).ok());
                if let Some(region_offset) = region_offset {
                    if seen.insert(guest_addr) {
                        callback(region, region_offset, guest_addr);
                    }
                }
            }
        }

        if dirty_ring.is_some() {
            Self::drain_dirty_ring_backlog(vmm, dirty_ring, dirty_ring_backlog);
            let ring = dirty_ring.as_mut().unwrap();
            let mut pending = std::mem::take(dirty_ring_backlog);
            for entry in pending.drain(..) {
                if let Some((region, region_offset, guest_addr)) =
                    Self::dirty_ring_entry_to_region_offset(ring, vmm.vm.guest_memory(), entry)
                {
                    if seen.insert(guest_addr) {
                        callback(region, region_offset, guest_addr);
                    }
                }
            }

            let page_size = ring.page_size as usize;
            for region in vmm.vm.guest_memory().iter() {
                let firecracker_bitmap = region.bitmap();
                let region_len: usize = region.len().try_into().unwrap_or(0);
                for region_offset in (0..region_len).step_by(page_size) {
                    if firecracker_bitmap.dirty_at(region_offset) {
                        let guest_addr =
                            region.start_addr().raw_value() + region_offset as u64;
                        if seen.insert(guest_addr) {
                            callback(region, region_offset, guest_addr);
                        }
                    }
                }
            }
            return;
        }

        let kvm_dirty_bitmap = vmm.vm.get_dirty_bitmap().unwrap();
        let page_size: usize = mem::PAGE_SIZE as usize;

        for (slot, region) in vmm.vm.guest_memory().iter().enumerate() {
            let slot = u32::try_from(slot).unwrap();
            let kvm_bitmap = kvm_dirty_bitmap.get(&slot).unwrap();
            let firecracker_bitmap = region.bitmap();

            for (i, v) in kvm_bitmap.iter().enumerate() {
                for j in 0..64 {
                    let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;
                    let index: usize = (i * 64) + j;
                    let page_addr = index * page_size;
                    let is_firecracker_page_dirty = firecracker_bitmap.dirty_at(page_addr);

                    if is_kvm_page_dirty || is_firecracker_page_dirty {
                        let guest_addr =
                            region.start_addr().raw_value() + page_addr as u64;
                        callback(region, page_addr, guest_addr);
                    }
                }
            }
        }
    }

    fn apply_deltas_to_least_common_ancestor(vmm: &mut Vmm, mut pages_reset: &mut HashSet<u64>, active: Arc<NyxSnapshot>, snapshot: Arc<NyxSnapshot>){
        let mut active_ancestor = active.clone();
        let mut snap_ancestor = snapshot.clone();
        let mem = vmm.get_mem();
        // for every delta in a parent of snapshot, we can apply it directly
        let reset_snap_pages = |snap_ancestor: Arc<NyxSnapshot>, reset_pages: &mut HashSet<u64>|{
            for (page,slice) in snap_ancestor.iter_delta(){
                if !reset_pages.contains(&page){
                    reset_pages.insert(page);
                    mem.write_slice(slice, GuestAddress(page)).unwrap();
                }
            }
            snap_ancestor.parent.as_ref().expect("Only snapshots with depth 0 can be root snapshots").clone()
        };
        // however, for deltas in the parent of the currently active snapshot, we need to reset them to the same page from snapshot instead.
        let reset_active_pages = |active_ancestor: Arc<NyxSnapshot>, reset_pages: &mut HashSet<u64>|{
            for (page,_) in active_ancestor.iter_delta(){
                if !reset_pages.contains(&page){
                    reset_pages.insert(page);
                    snapshot.get_page(page as usize, |slice|{
                        mem.write_slice(slice, GuestAddress(page)).unwrap();
                    });
                }
            }
            active_ancestor.parent.as_ref().expect("Only snapshots with depth 0 can be root snapshots").clone()
        };
        // first we make sure cur and active are on the same depth
        while snap_ancestor.depth > active_ancestor.depth {
            snap_ancestor = reset_snap_pages(snap_ancestor, &mut pages_reset);
        }
        while active_ancestor.depth > snap_ancestor.depth {
            active_ancestor = reset_active_pages(active_ancestor, &mut pages_reset);
        }
        // once they are on the same depth we can walk both of them upwards until they meet and we reset all pages to the LCA
        while !Arc::ptr_eq(&active_ancestor, &snap_ancestor){
            assert_eq!(active.depth, snap_ancestor.depth);
            active_ancestor = reset_active_pages(active_ancestor, &mut pages_reset);
            snap_ancestor =reset_snap_pages(snap_ancestor, &mut pages_reset);
        }
    }

    fn ensure_snapshot_compat(&self, snapshot: &NyxSnapshot) {
        let info = &snapshot.state.vm_info;
        let machine = &self.vm_resources.machine_config;
        let cpu_template = StaticCpuTemplate::from(&machine.cpu_template);
        assert_eq!(
            info.mem_size_mib,
            machine.mem_size_mib as u64,
            "snapshot memory size mismatch"
        );
        assert_eq!(info.smt, machine.smt, "snapshot smt mismatch");
        assert_eq!(
            info.cpu_template,
            cpu_template,
            "snapshot cpu template mismatch"
        );
        assert_eq!(
            info.huge_pages, machine.huge_pages,
            "snapshot huge page config mismatch"
        );
        assert_eq!(
            info.enable_nested_virt, machine.enable_nested_virt,
            "snapshot nested virt mismatch"
        );
        assert_eq!(
            snapshot.state.vcpu_states.len(),
            machine.vcpu_count as usize,
            "snapshot vcpu count mismatch"
        );
    }

    /// Applies a snapshot. If there is no active snapshot, only a root snapshot is accepted.
    pub fn apply_snapshot(&mut self, snapshot: &Arc<NyxSnapshot>) {
        let mut vmm = self.vmm.lock().unwrap();
        self.ensure_snapshot_compat(snapshot);

        if self.active_snapshot.is_none() {
            if snapshot.depth != 0 || snapshot.memory.is_incremental() {
                panic!("can only apply root snapshots to VMs without an active snapshot");
            }
            let shared_pages = self.shared_pages.clone();
            for region in vmm.vm.guest_memory().iter() {
                let region_len: usize = region.len().try_into().unwrap_or(0);
                for offset in (0..region_len).step_by(GUEST_PAGE_SIZE as usize) {
                    let guest_addr = region.start_addr().raw_value() + offset as u64;
                    if shared_pages.contains(&guest_addr) {
                        continue;
                    }
                    snapshot.get_page(guest_addr as usize, |slice| {
                        region
                            .write_slice(slice, MemoryRegionAddress(offset as u64))
                            .unwrap();
                    });
                }
            }
            Self::reset_dirty_tracking_with_state(
                &vmm,
                &mut self.dirty_ring,
                &mut self.dirty_ring_backlog,
                &self.host_dirty,
            );
            self.active_snapshot = Some(snapshot.clone());
            self.vcpu
                .kvm_vcpu
                .restore_state(&snapshot.state.vcpu_states[0])
                .unwrap();
            let guest_mem = vmm.vm.guest_memory().clone();
            Self::apply_snapshot_mmio(&vmm.device_manager.mmio_devices, &guest_mem, snapshot);
            let vm = Arc::get_mut(&mut vmm.vm)
                .expect("exclusive VM access required to restore state");
            vm.restore_state(&snapshot.state.vm_state).unwrap();
            vmm.clear_shutdown_exit_code();
            drop(vmm);
            self.apply_tsc(snapshot.tsc);
            self.continuation_state = snapshot.continuation_state.clone();
            self.regs_cache.replace(None);
            self.sregs_cache.replace(None);
            return;
        }

        let mut pages_reset = HashSet::new();
        let active_snapshot = self
            .active_snapshot
            .as_ref()
            .expect("can only apply snapshots on VMs with an active snapshot");

        let fast_path = Arc::ptr_eq(snapshot, active_snapshot);
        let shared_pages = self.shared_pages.clone();

        Self::iter_dirty_pages_with_state(
            &vmm,
            &mut self.dirty_ring,
            &mut self.dirty_ring_backlog,
            &self.host_dirty,
            |region, region_offset, guest_addr| {
                if shared_pages.contains(&guest_addr) {
                    return;
                }
                let target_addr = MemoryRegionAddress(region_offset.try_into().unwrap());
                snapshot.get_page(guest_addr as usize, |slice| {
                    region.write_slice(slice, target_addr).unwrap();
                    if !fast_path {
                        pages_reset.insert(guest_addr);
                    }
                });
            },
        );

        if !fast_path {
            Self::apply_deltas_to_least_common_ancestor(&mut vmm, &mut pages_reset, active_snapshot.clone(), snapshot.clone());
        } 

        self.active_snapshot = Some(snapshot.clone());
        Self::reset_dirty_tracking_with_state(
            &vmm,
            &mut self.dirty_ring,
            &mut self.dirty_ring_backlog,
            &self.host_dirty,
        );

        // The only ACPIDevice is the vmgenid device which we disable - no need to restore
        //println!("acpi state: {:#?}", &state.acpi_dev_state);
        //println!("vmm acpi_device_manager {:#?}", vmm.acpi_device_manager);

        self.vcpu
            .kvm_vcpu
            .restore_state(&snapshot.state.vcpu_states[0])
            .unwrap();

        // we currently can't restore the net mmio device, only the block one
        let guest_mem = vmm.vm.guest_memory().clone();
        Self::apply_snapshot_mmio(&vmm.device_manager.mmio_devices, &guest_mem, snapshot);
        // cpu might need to restore piodevices, investigate
        //Self::apply_snapshot_pio(&mut vmm.pio_device_manager, snap);

        let vm = Arc::get_mut(&mut vmm.vm).expect("exclusive VM access required to restore state");
        vm.restore_state(&snapshot.state.vm_state).unwrap();
        vmm.clear_shutdown_exit_code();

        // this should be done last, because KVM keeps tsc running - even when
        // the VM isn't. Doing this early will introduce additional
        // noise/nondeterminism
        drop(vmm);
        self.apply_tsc(snapshot.tsc);
        self.continuation_state = snapshot.continuation_state.clone();
        self.regs_cache.replace(None);
        self.sregs_cache.replace(None);
    }

    pub fn sregs(&self) -> kvm_sregs {
        if let Some(sregs) = self.sregs_cache.borrow().clone() {
            return sregs;
        }
        let sregs = self.vcpu.kvm_vcpu.fd.get_sregs().unwrap();
        self.sregs_cache.borrow_mut().replace(sregs);
        sregs
    }
    pub fn regs(&self) -> kvm_regs {
        if let Some(regs) = self.regs_cache.borrow().clone() {
            return regs;
        }
        let regs = self.vcpu.kvm_vcpu.fd.get_regs().unwrap();
        self.regs_cache.borrow_mut().replace(regs);
        regs
    }

    pub fn set_regs(&mut self, regs: &kvm_regs) {
        self.vcpu.kvm_vcpu.fd.set_regs(regs).unwrap();
        self.regs_cache.borrow_mut().replace(regs.clone());
        self.continuation_state = VMContinuationState::Main;
    }

    fn read_debugctl(&self) -> u64 {
        self.vcpu
            .kvm_vcpu
            .get_msrs([MSR_IA32_DEBUGCTLMSR].into_iter())
            .ok()
            .and_then(|msrs| msrs.get(&MSR_IA32_DEBUGCTLMSR).copied())
            .unwrap_or(0)
    }

    fn write_debugctl(&mut self, value: u64) {
        let msrs_to_set = [kvm_msr_entry {
            index: MSR_IA32_DEBUGCTLMSR,
            data: value,
            ..Default::default()
        }];
        let msrs_wrapper = Msrs::from_entries(&msrs_to_set).unwrap();
        let num_set = self.vcpu.kvm_vcpu.fd.set_msrs(&msrs_wrapper).unwrap();
        assert_eq!(num_set, 1);
    }

    /// Configures BTS tracing and DS area pointer for the current vCPU.
    pub fn configure_bts(&mut self, ds_area_paddr: u64, config: BtsConfig) -> Result<(), MemoryError> {
        if (ds_area_paddr & mem::M_PAGE_OFFSET) != 0 {
            return Err(MemoryError::UnalignedAddress(ds_area_paddr));
        }
        let mut debugctl = self.read_debugctl();
        if config.enable {
            debugctl |= DEBUGCTL_BTS;
            if config.interrupt {
                debugctl |= DEBUGCTL_BTINT;
            } else {
                debugctl &= !DEBUGCTL_BTINT;
            }
            if config.off_kernel {
                debugctl |= DEBUGCTL_BTS_OFF_OS;
            } else {
                debugctl &= !DEBUGCTL_BTS_OFF_OS;
            }
            if config.off_user {
                debugctl |= DEBUGCTL_BTS_OFF_USR;
            } else {
                debugctl &= !DEBUGCTL_BTS_OFF_USR;
            }
        } else {
            debugctl &= !(DEBUGCTL_BTS | DEBUGCTL_BTINT | DEBUGCTL_BTS_OFF_OS | DEBUGCTL_BTS_OFF_USR);
        }
        let msrs_to_set = [
            kvm_msr_entry {
                index: MSR_IA32_DS_AREA,
                data: ds_area_paddr,
                ..Default::default()
            },
            kvm_msr_entry {
                index: MSR_IA32_DEBUGCTLMSR,
                data: debugctl,
                ..Default::default()
            },
        ];
        let msrs_wrapper = Msrs::from_entries(&msrs_to_set).unwrap();
        let num_set = self.vcpu.kvm_vcpu.fd.set_msrs(&msrs_wrapper).unwrap();
        assert_eq!(num_set, 2);
        Ok(())
    }

    pub fn set_debug_state(&mut self, run_mode: RunMode, vmexit_on_swbp: bool ){
        let mut control = KVM_GUESTDBG_ENABLE;
        if run_mode.is_step() {
            control |= KVM_GUESTDBG_SINGLESTEP;
            control |= KVM_GUESTDBG_BLOCKIRQ;
        };
        // Set or clear BTF (branch trace flag) when requested.
        let mut debugctl = self.read_debugctl();
        if let RunMode::BranchStep = run_mode {
            debugctl |= DEBUGCTL_BTF;
        } else {
            debugctl &= !DEBUGCTL_BTF;
        }
        self.write_debugctl(debugctl);
        control |= if vmexit_on_swbp {KVM_GUESTDBG_USE_SW_BP} else {KVM_GUESTDBG_INJECT_BP};
        let mut arch  = kvm_guest_debug_arch::default();
        if self.hw_breakpoints.any_active() {
            control |= KVM_GUESTDBG_USE_HW_BP;
            arch.debugreg[0] = self.hw_breakpoints.addr(0);
            arch.debugreg[1] = self.hw_breakpoints.addr(1);
            arch.debugreg[2] = self.hw_breakpoints.addr(2);
            arch.debugreg[3] = self.hw_breakpoints.addr(3);
            arch.debugreg[7] = self.hw_breakpoints.compute_dr7();
        }
        let dbg_info = kvm_guest_debug {
            control,
            pad: 0,
            arch
        };
        self.vcpu.kvm_vcpu.fd.set_guest_debug(&dbg_info).unwrap();
    }

    pub fn is_nyx_hypercall(&self) -> bool {
        let regs = self.regs();
        return regs.rax == NYX_LITE;
    }

    pub fn parse_hypercall(&self) -> ExitReason{
        let regs = self.regs();
        if self.is_nyx_hypercall(){
            let hypercall = match regs.r8 {
                SHAREMEM => {
                    ExitReason::SharedMem(
                        String::from_utf8_lossy(&self.read_cstr_current(regs.r9)).to_string(),
                        regs.r10,
                        regs.r11.try_into().unwrap(),
                    )
                }
                DBGPRINT => {
                    ExitReason::DebugPrint(
                        String::from_utf8_lossy(&self.read_cstr_current(regs.r9)).to_string(),
                    )
                }
                SNAPSHOT => ExitReason::RequestSnapshot,
                EXECDONE => ExitReason::ExecDone(regs.r9),
                _ => ExitReason::Hypercall(regs.r8, regs.r9, regs.r10, regs.r11, regs.r12),
            };
            return hypercall;
        } 
        panic!("Don't call parse_hypercall on a non-hypercall vmexit!");
    }

    pub fn parse_bad_memory_access(&self) -> ExitReason {
        let regs = self.regs();
        let sregs = self.sregs();
        let data = self.read_current_bytes(regs.rip, 16);
        let accesses = disassemble_memory_accesses(&data, &regs, &sregs);
        return ExitReason::BadMemoryAccess(accesses);
    }

    pub fn run_inner(&mut self, timeout: Duration) -> UnparsedExitReason{
        let start_time = time::Instant::now();
        self.timeout_timer.lock().unwrap().set_timeout(timeout);
        loop {
            self.regs_cache.replace(None);
            self.sregs_cache.replace(None);
            let _ = self.event_manager.borrow_mut().run_with_timeout(0);
            let mut exit = None;
            match self.vcpu.run_emulation() {
                // Emulation ran successfully, continue.
                Ok(VcpuEmulation::Handled) => {}
                Ok(VcpuEmulation::DirtyRingFull) => {
                    let vmm = self.vmm.lock().unwrap();
                    Self::drain_dirty_ring_backlog(
                        &vmm,
                        &mut self.dirty_ring,
                        &mut self.dirty_ring_backlog,
                    );
                }
                // Emulation was interrupted, check external events.
                Ok(VcpuEmulation::Interrupted) => {
                    if time::Instant::now().duration_since(start_time) >= timeout {
                        exit = Some(UnparsedExitReason::Timeout);
                    } else {
                        println!("[STOP] interrupt");
                        exit = Some(UnparsedExitReason::Interrupted);
                    }
                }
                Ok(VcpuEmulation::Stopped) => {
                    exit = Some(UnparsedExitReason::Shutdown);
                }
                Ok(VcpuEmulation::DebugEvent(dbg)) => {
                    let regs = self.regs();
                    let exc_reason = match dbg.exception {
                        DBG_EXCEPTION_BREAKPOINT if regs.rax == NYX_LITE => {
                            self.last_nyx_breakpoint.replace(None);
                            UnparsedExitReason::Hypercall
                        }
                        DBG_EXCEPTION_BREAKPOINT if regs.rax != NYX_LITE => {
                            let sregs = self.sregs();
                            if self.breakpoint_manager.forward_guest_bp(sregs.cr3, regs.rip){
                                self.last_nyx_breakpoint.replace(None);
                                UnparsedExitReason::GuestBreakpoint
                            } else {
                                self.last_nyx_breakpoint
                                    .replace(Some((sregs.cr3, regs.rip)));
                                UnparsedExitReason::NyxBreakpoint
                            }
                        }
                        DBG_EXCEPTION_SINGLESTEP if (dbg.dr6 & DR6_BS)     != 0 =>  UnparsedExitReason::SingleStep,
                        DBG_EXCEPTION_SINGLESTEP if (dbg.dr6 & DR6_HWBP_0) != 0 =>  UnparsedExitReason::HWBreakpoint(0),
                        DBG_EXCEPTION_SINGLESTEP if (dbg.dr6 & DR6_HWBP_1) != 0 =>  UnparsedExitReason::HWBreakpoint(1),
                        DBG_EXCEPTION_SINGLESTEP if (dbg.dr6 & DR6_HWBP_2) != 0 =>  UnparsedExitReason::HWBreakpoint(2),
                        DBG_EXCEPTION_SINGLESTEP if (dbg.dr6 & DR6_HWBP_3) != 0 =>  UnparsedExitReason::HWBreakpoint(3),

                        excp => {panic!("Unexpected Debug Exception From KVM: {excp} {:x?} ", dbg);}
                    };
                    exit = Some(exc_reason)
                },
                Err(VcpuError::FaultyKvmExit(err)) if err == "Bad address (os error 14)" => {
                    exit = Some(UnparsedExitReason::BadMemoryAccess)
                },
                Err(err) => {panic!("KVM returned unexpected error {:?}", err)}
            }
            while let Ok(ev) = self.vcpu.event_receiver.try_recv() {
                match ev {
                    VcpuEvent::Finish => {
                        exit = Some(UnparsedExitReason::Shutdown);
                    }
                    event => {
                        println!(">== recieved event: {:?}", event);
                    }
                }
            }
            if let Some(exitreason) = exit {
                self.timeout_timer.lock().unwrap().disable();
                return exitreason;
            }
        }
    }

    pub fn parse_exit_reason(&self, unparsed: VMExitUserEvent) -> ExitReason{
        match unparsed {
            VMExitUserEvent::Hypercall => self.parse_hypercall(),
            VMExitUserEvent::BadMemoryAccess => self.parse_bad_memory_access(),
            VMExitUserEvent::Interrupted => ExitReason::Interrupted,
            VMExitUserEvent::Breakpoint => ExitReason::Breakpoint,
            VMExitUserEvent::SingleStep => ExitReason::SingleStep,
            VMExitUserEvent::Shutdown => ExitReason::Shutdown,
            VMExitUserEvent::Timeout => ExitReason::Timeout,
            VMExitUserEvent::HWBreakpoint(x) => ExitReason::HWBreakpoint(x),
        }
    }
    pub fn continue_vm(&mut self, run_mode: RunMode, timeout: Duration) -> ExitReason {
        let unparsed = VMContinuationState::step(self, run_mode, timeout);
        return self.parse_exit_reason(unparsed);
    }

    pub fn run(&mut self, timeout: Duration) -> ExitReason {
        return self.continue_vm(RunMode::Run, timeout);
    }

    pub fn single_step(&mut self, timeout: Duration) -> ExitReason{
        return self.continue_vm(RunMode::SingleStep, timeout);
    }




    pub fn add_breakpoint(&mut self, cr3: u64, vaddr: u64) {
        self.breakpoint_manager.add_breakpoint(cr3,vaddr);
    }

    pub fn remove_all_breakpoints(&mut self){
        self.breakpoint_manager.remove_all_breakpoints();
    }

    pub(crate) fn disable_last_nyx_breakpoint(&mut self) {
        let mut vmm = self.vmm.lock().unwrap();
        if let Some((cr3, rip)) = *self.last_nyx_breakpoint.borrow() {
            self.breakpoint_manager.disable_breakpoint(&mut vmm, cr3, rip);
        } else {
            self.breakpoint_manager.disable_all_breakpoints(&mut vmm);
        }
    }

    pub fn read_cstr_current(&self, guest_vaddr: u64) -> Vec<u8> {
        let cr3 = self.sregs().cr3;
        let vmm = self.vmm.lock().unwrap();
        vmm.read_virtual_cstr(cr3, guest_vaddr)
    }
    pub fn read_current_u64(&self, vaddr: u64) -> u64 {
        self.current_process_memory()
            .read_u64(vaddr)
            .unwrap()
    }
    pub fn write_current_u64(&self, vaddr: u64, val: u64) {
        self.current_process_memory()
            .write_u64(vaddr, val)
            .unwrap();
    }

    pub fn write_current_bytes(&self, vaddr: u64, buffer: &[u8]) -> usize {
        self.current_process_memory()
            .write_bytes(vaddr, buffer)
            .unwrap()
    }

    pub fn read_current_bytes(&self, vaddr: u64, num_bytes: usize) -> Vec<u8> {
        let mut res = Vec::with_capacity(num_bytes);
        res.resize(num_bytes, 0);
        let bytes_copied = self
            .current_process_memory()
            .read_bytes(vaddr, &mut res)
            .unwrap();
        res.truncate(bytes_copied);
        if is_canonical_user_addr(vaddr) {
            assert_eq!(bytes_copied, num_bytes);
        }
        return res;
    }

    pub fn branch_step(&mut self, timeout: Duration) -> ExitReason{
        let start = time::Instant::now();
        let mut prev_rip = self.regs().rip;
        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return ExitReason::Timeout;
            }
            let remaining = timeout.saturating_sub(elapsed);
            let exit = self.continue_vm(RunMode::BranchStep, remaining);
            match exit {
                ExitReason::SingleStep => {
                    let bytes = self.read_current_bytes(prev_rip, 16);
                    if is_control_flow(prev_rip, &bytes) {
                        return ExitReason::SingleStep;
                    }
                    prev_rip = self.regs().rip;
                }
                other => return other,
            }
        }
    }

    pub fn set_lbr(&mut self) {
        panic!("reading lbr doesn't seem to be supported by KVM");
        //let msrs_to_set = [
        //    kvm_msr_entry {
        //        index: MSR_IA32_DEBUGCTLMSR,
        //        data: 1,
        //        ..Default::default()
        //    },
        //];
        //let msrs_wrapper = Msrs::from_entries(&msrs_to_set).unwrap();
        //let num_set = self.vcpu.kvm_vcpu.fd.set_msrs(&msrs_wrapper).unwrap();
        //assert_eq!(num_set, msrs_to_set.len());
    }

    pub fn get_lbr(&mut self){
        panic!("None of this seems supported by KVM?");
        // it appears XSAVE nees AI32_XSS[15] to actually store LBR data, and we can't set AI32_XSS via kvm.
        // let xsave = self.vcpu.kvm_vcpu.fd.get_xsave().unwrap();
        // println!("got xsave: {:x?}",xsave);
        //
        // this is all even more broken. All of this only applies to AMD cpus:
        ////let lbr_tos = self.vcpu.kvm_vcpu.get_msrs(&[MSR_LBR_TOS]).unwrap()[&0];
        // let msrs_to_set = [
        //     kvm_msr_entry {
        //         index: 0x00000680,
        //         data: 1,
        //         ..Default::default()
        //     },
        // ];
        // let mut msrs_wrapper = Msrs::from_entries(&msrs_to_set).unwrap();
        // let lbr_tos = self.vcpu.kvm_vcpu.fd.get_msrs(&mut msrs_wrapper).unwrap();
        // assert_eq!(lbr_tos, 1);
        // msrs_wrapper.as_slice().iter().for_each(|msr| {
        //     println!("got MSR_IA32_DEBUGCTLMSR: {}, {:?} {:?}", lbr_tos, msr.index, msr.data);
        // });
        ////let mut lbr_stack = Vec::with_capacity(32);
        //
        //for i in 0..32 {
        //    let msrs_to_set = [
        //        kvm_msr_entry {
        //            index: MSR_IA32_LASTBRANCHFROMIP+i,
        //            data: 1338,
        //            ..Default::default()
        //        },
        //        kvm_msr_entry {
        //            index: MSR_IA32_LASTBRANCHTOIP+i,
        //            data: 1339,
        //            ..Default::default()
        //        },
        //        kvm_msr_entry {
        //            index: MSR_LBR_TOS,
        //            data: 1337,
        //            ..Default::default()
        //        },
        //    ];
        //    let mut msrs_wrapper = Msrs::from_entries(&msrs_to_set).unwrap();
        //    let lbr_tos = self.vcpu.kvm_vcpu.fd.get_msrs(&mut msrs_wrapper).unwrap();
        //    assert_eq!(lbr_tos, 3);
        //    msrs_wrapper.as_slice().iter().for_each(|msr| {
        //        println!("got MSR_IA#@_LASTBRANCHTOIP: {}, {:?} {:?}", lbr_tos, msr.index, msr.data);
        //    });
        //    //lbr_stack.push((
        //    //    self.vcpu.kvm_vcpu.get_msrs(&[MSR_IA32_LASTINTFROMIP+i]).unwrap()[&0],
        //    //    self.vcpu.kvm_vcpu.get_msrs(&[MSR_IA32_LASTBRANCHTOIP+i]).unwrap()[&0],
        //    //));
        //}
        ////println!("LBR: {:x?} top: {:?}", lbr_stack, lbr_tos);
    }


}
