use std::collections::BTreeMap;

use vmm::Vmm;

use crate::mem::NyxMemExtension;

pub struct Breakpoint {
    pub cr3: u64,
    pub vaddr: u64,
    pub orig_val: Option<u8>,
    pub enabled: bool,
}

impl Breakpoint {
    pub fn new(cr3: u64, vaddr: u64) -> Self {
        return Self {
            cr3,
            vaddr,
            orig_val: None,
            enabled: false,
        };
    }
}

// A trait so users can define their own logic for deciding which breakpoints to handle.
pub trait BreakpointManagerTrait {
    // should we forward the current breakpoint to the guest rather than handle it ourselfs?
    fn known_breakpoint(&self, cr3: u64, rip: u64) -> bool;
    fn disable_all_breakpoints(&mut self, vmm: &mut Vmm);
    fn enable_all_breakpoints(&mut self, vmm: &mut Vmm);
    fn disable_breakpoint(&mut self, vmm: &mut Vmm, _cr3: u64, _vaddr: u64) {
        self.disable_all_breakpoints(vmm);
    }
    fn enable_breakpoint(&mut self, vmm: &mut Vmm, _cr3: u64, _vaddr: u64) {
        self.enable_all_breakpoints(vmm);
    }
    fn add_breakpoint(&mut self, cr3: u64, vaddr: u64);
    fn remove_breakpoint(&mut self, cr3: u64, vaddr: u64);
    fn remove_all_breakpoints(&mut self);

    fn forward_guest_bp(&self, cr3: u64, rip: u64) -> bool {
        return !self.known_breakpoint(cr3, rip);
    }
}

pub struct BreakpointManager {
    pub breakpoints: BTreeMap<(u64, u64), Breakpoint>,
    all_enabled: bool,
}

impl BreakpointManager {
    pub fn new() -> Self {
        return Self {
            breakpoints: BTreeMap::new(),
            all_enabled: false,
        };
    }
}

impl BreakpointManagerTrait for BreakpointManager {
    fn known_breakpoint(&self, cr3: u64, rip: u64) -> bool {
        let known_bp = self.breakpoints.contains_key(&(cr3, rip));
        return known_bp;
    }
    fn disable_all_breakpoints(&mut self, vmm: &mut Vmm) {
        for bp in self.breakpoints.values_mut() {
            if !bp.enabled {
                continue;
            }
            vmm.write_virtual_u8(bp.cr3, bp.vaddr, bp.orig_val.unwrap())
                .unwrap();
            bp.enabled = false;
        }
        self.all_enabled = false;
    }
    fn enable_all_breakpoints(&mut self, vmm: &mut Vmm) {
        if self.all_enabled {
            return;
        }
        for bp in self.breakpoints.values_mut() {
            if bp.enabled {
                continue;
            }
            if bp.orig_val.is_none() {
                bp.orig_val = Some(vmm.read_virtual_u8(bp.cr3, bp.vaddr).unwrap());
            }
            vmm.write_virtual_u8(bp.cr3, bp.vaddr, 0xcc).unwrap();
            bp.enabled = true;
        }
        self.all_enabled = true;
    }
    fn disable_breakpoint(&mut self, vmm: &mut Vmm, cr3: u64, vaddr: u64) {
        if let Some(bp) = self.breakpoints.get_mut(&(cr3, vaddr)) {
            if bp.enabled {
                vmm.write_virtual_u8(bp.cr3, bp.vaddr, bp.orig_val.unwrap())
                    .unwrap();
                bp.enabled = false;
                self.all_enabled = false;
            }
        }
    }
    fn enable_breakpoint(&mut self, vmm: &mut Vmm, cr3: u64, vaddr: u64) {
        if let Some(bp) = self.breakpoints.get_mut(&(cr3, vaddr)) {
            if !bp.enabled {
                if bp.orig_val.is_none() {
                    bp.orig_val = Some(vmm.read_virtual_u8(bp.cr3, bp.vaddr).unwrap());
                }
                vmm.write_virtual_u8(bp.cr3, bp.vaddr, 0xcc).unwrap();
                bp.enabled = true;
            }
        }
    }

    fn add_breakpoint(&mut self, cr3: u64, vaddr: u64) {
        let breakpoint = Breakpoint::new(cr3, vaddr);
        self.breakpoints.insert((cr3, vaddr), breakpoint);
        self.all_enabled = false;
    }

    fn remove_breakpoint(&mut self, cr3: u64, vaddr: u64) {
        self.breakpoints.remove(&(cr3, vaddr));
        self.all_enabled = false;
    }
    fn remove_all_breakpoints(&mut self) {
        self.breakpoints.clear();
        self.all_enabled = false;
    }
}
