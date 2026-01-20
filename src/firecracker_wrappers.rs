use std::sync::{Arc, Mutex};
use std::{io, thread};

use anyhow::Result;

use event_manager::SubscriberOps;
use vmm::builder::StartMicrovmError;
use vmm::cpu_config::templates::GetCpuTemplate;
use vmm::initrd::InitrdConfig;
use vmm::resources::VmResources;
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::vstate::memory;
use vmm::Vcpu;
use vmm::Vmm;
use vmm::{EventManager, VcpuHandle};

use kvm_bindings::{kvm_guest_debug, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_SW_BP};
use kvm_bindings::KVM_CAP_NESTED_STATE;

#[cfg(target_arch = "x86_64")]
use vmm::cpu_config::x86_64::cpuid::common::get_vendor_id_from_host;
#[cfg(target_arch = "x86_64")]
use vmm::cpu_config::x86_64::cpuid::{CpuidKey, CpuidTrait, KvmCpuidFlags, VENDOR_ID_AMD, VENDOR_ID_INTEL};
#[cfg(target_arch = "x86_64")]
use vmm::cpu_config::x86_64::custom_cpu_template::{
    CpuidLeafModifier, CpuidRegister, CpuidRegisterModifier, CustomCpuTemplate,
};
#[cfg(target_arch = "x86_64")]
use vmm::cpu_config::templates::KvmCapability;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ResizeFdTableError {
    /// Failed to get RLIMIT_NOFILE
    GetRlimit,
    /// Failed to call dup2 to resize fdtable
    Dup2(io::Error),
    /// Failed to close dup2'd file descriptor
    Close(io::Error),
}

#[cfg(target_arch = "x86_64")]
fn ensure_nested_kvm_caps(template: &mut CustomCpuTemplate) {
    if !template.kvm_capabilities.iter().any(|cap| {
        matches!(cap, KvmCapability::Add(value) if *value == KVM_CAP_NESTED_STATE)
    }) {
        template.kvm_capabilities.push(KvmCapability::Add(KVM_CAP_NESTED_STATE));
    }
}

#[cfg(target_arch = "x86_64")]
fn set_cpuid_bit(
    template: &mut CustomCpuTemplate,
    leaf: u32,
    subleaf: u32,
    register: CpuidRegister,
    bit: u8,
) {
    let mask = 1u32 << bit;
    if let Some(leaf_mod) = template
        .cpuid_modifiers
        .iter_mut()
        .find(|entry| entry.leaf == leaf && entry.subleaf == subleaf)
    {
        if let Some(reg_mod) = leaf_mod
            .modifiers
            .iter_mut()
            .find(|entry| entry.register == register)
        {
            reg_mod.bitmap.filter |= mask;
            reg_mod.bitmap.value |= mask;
        } else {
            leaf_mod.modifiers.push(CpuidRegisterModifier {
                register,
                bitmap: vmm::cpu_config::templates::RegisterValueFilter {
                    filter: mask,
                    value: mask,
                },
            });
        }
    } else {
        template.cpuid_modifiers.push(CpuidLeafModifier {
            leaf,
            subleaf,
            flags: KvmCpuidFlags::EMPTY,
            modifiers: vec![CpuidRegisterModifier {
                register,
                bitmap: vmm::cpu_config::templates::RegisterValueFilter {
                    filter: mask,
                    value: mask,
                },
            }],
        });
    }
}

#[cfg(target_arch = "x86_64")]
fn ensure_nested_virt_supported(
    kvm: &vmm::arch::x86_64::kvm::Kvm,
    template: &mut CustomCpuTemplate,
) -> Result<(), StartMicrovmError> {
    if kvm.fd.check_extension_raw(u64::from(KVM_CAP_NESTED_STATE)) == 0 {
        return Err(StartMicrovmError::NestedVirtUnsupported(
            "KVM_CAP_NESTED_STATE not supported by host".to_string(),
        ));
    }

    let vendor = get_vendor_id_from_host().map_err(|err| {
        StartMicrovmError::NestedVirtUnsupported(format!(
            "unable to read CPUID vendor: {err}"
        ))
    })?;

    if &vendor == VENDOR_ID_INTEL {
        let key = CpuidKey { leaf: 0x1, subleaf: 0 };
        let entry = kvm.supported_cpuid.get(&key).ok_or_else(|| {
            StartMicrovmError::NestedVirtUnsupported("missing CPUID leaf 0x1".to_string())
        })?;
        if entry.result.ecx & (1 << 5) == 0 {
            return Err(StartMicrovmError::NestedVirtUnsupported(
                "host CPUID does not advertise VMX support".to_string(),
            ));
        }
        set_cpuid_bit(template, 0x1, 0x0, CpuidRegister::Ecx, 5);
        Ok(())
    } else if &vendor == VENDOR_ID_AMD {
        let key = CpuidKey {
            leaf: 0x8000_0001,
            subleaf: 0,
        };
        let entry = kvm.supported_cpuid.get(&key).ok_or_else(|| {
            StartMicrovmError::NestedVirtUnsupported("missing CPUID leaf 0x80000001".to_string())
        })?;
        if entry.result.ecx & (1 << 2) == 0 {
            return Err(StartMicrovmError::NestedVirtUnsupported(
                "host CPUID does not advertise SVM support".to_string(),
            ));
        }
        set_cpuid_bit(template, 0x8000_0001, 0x0, CpuidRegister::Ecx, 2);
        Ok(())
    } else {
        Err(StartMicrovmError::NestedVirtUnsupported(
            "unsupported CPU vendor for nested virtualization".to_string(),
        ))
    }
}

/// Attempts to resize the processes file descriptor table to match RLIMIT_NOFILE or 2048 if no
/// RLIMIT_NOFILE is set (this can only happen if firecracker is run outside the jailer. 2048 is
/// the default the jailer would set).
///
/// We do this resizing because the kernel default is 64, with a reallocation happening whenever
/// the tabel fills up. This was happening for some larger microVMs, and reallocating the
/// fdtable while a lot of file descriptors are active (due to being eventfds/timerfds registered
/// to epoll) incurs a penalty of 30ms-70ms on the snapshot restore path.
pub fn resize_fdtable() -> Result<(), ResizeFdTableError> {
    let mut rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: We pass a pointer to a valid area of memory to which we have exclusive mutable access
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlimit as *mut libc::rlimit) } < 0 {
        return Err(ResizeFdTableError::GetRlimit);
    }

    // If no jailer is used, there might not be an NOFILE limit set. In this case, resize
    // the table to the default that the jailer would usually impose (2048)
    let limit: libc::c_int = if rlimit.rlim_cur == libc::RLIM_INFINITY {
        2048
    } else {
        rlimit.rlim_cur.try_into().unwrap_or(2048)
    };

    // Resize the file descriptor table to its maximal possible size, to ensure that
    // firecracker will not need to reallocate it later. If the file descriptor table
    // needs to be reallocated (which by default happens once more than 64 fds exist,
    // something that happens for reasonably complex microvms due to each device using
    // a multitude of eventfds), this can incur a significant performance impact (it
    // was responsible for a 30ms-70ms impact on snapshot restore times).
    if limit > 3 {
        // SAFETY: Duplicating stdin is safe
        if unsafe { libc::dup2(0, limit - 1) } < 0 {
            return Err(ResizeFdTableError::Dup2(io::Error::last_os_error()));
        }

        // SAFETY: Closing the just created duplicate is safe
        if unsafe { libc::close(limit - 1) } < 0 {
            return Err(ResizeFdTableError::Close(io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Builds and starts a microVM based on the current Firecracker VmResources configuration.
///
/// The built microVM and all the created vCPUs start off in the paused state.
/// To boot the microVM and run those vCPUs, `Vmm::resume_vm()` needs to be
/// called.
pub fn build_microvm_for_boot(
    instance_info: &InstanceInfo,
    vm_resources: &VmResources,
    event_manager: &mut EventManager,
) -> Result<(Arc<Mutex<Vmm>>, Vcpu), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let boot_config = vm_resources
        .boot_source
        .builder
        .as_ref()
        .ok_or(MissingKernelConfig)?;

    let track_dirty_pages = vm_resources.machine_config.track_dirty_pages;

    let vhost_user_device_used = vm_resources
        .block
        .devices
        .iter()
        .any(|b| b.lock().expect("Poisoned lock").is_vhost_user());

    // Page faults are more expensive for shared memory mapping, including  memfd.
    // For this reason, we only back guest memory with a memfd
    // if a vhost-user-blk device is configured in the VM, otherwise we fall back to
    // an anonymous private memory.
    //
    // The vhost-user-blk branch is not currently covered by integration tests in Rust,
    // because that would require running a backend process. If in the future we converge to
    // a single way of backing guest memory for vhost-user and non-vhost-user cases,
    // that would not be worth the effort.
    let regions = vmm::arch::arch_memory_regions(vm_resources.machine_config.mem_size_mib << 20);
    let guest_regions = if vhost_user_device_used {
        memory::memfd_backed(&regions, track_dirty_pages, vm_resources.machine_config.huge_pages)
            .map_err(StartMicrovmError::GuestMemory)?
    } else {
        memory::anonymous(
            regions.iter().copied(),
            track_dirty_pages,
            vm_resources.machine_config.huge_pages,
        )
        .map_err(StartMicrovmError::GuestMemory)?
    };
    // Clone the command-line so that a failed boot doesn't pollute the original.
    #[allow(unused_mut)]
    let mut boot_cmdline = boot_config.cmdline.clone();

    let mut cpu_template = vm_resources
        .machine_config
        .cpu_template
        .get_cpu_template()?
        .into_owned();
    if vm_resources.machine_config.enable_nested_virt {
        #[cfg(target_arch = "x86_64")]
        {
            ensure_nested_kvm_caps(&mut cpu_template);
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            return Err(StartMicrovmError::NestedVirtUnsupported(
                "nested virtualization is only supported on x86_64".to_string(),
            ));
        }
    }

    let (mut vmm, mut vcpus) = vmm::builder::create_vmm_and_vcpus(
        instance_info,
        event_manager,
        guest_regions,
        None,
        track_dirty_pages,
        vm_resources.machine_config.vcpu_count,
        cpu_template.kvm_capabilities.clone(),
    )?;

    if vm_resources.machine_config.enable_nested_virt {
        #[cfg(target_arch = "x86_64")]
        {
            ensure_nested_virt_supported(vmm.kvm(), &mut cpu_template)?;
        }
    }

    let entry_addr = vmm::arch::load_kernel(&boot_config.kernel_file, vmm.vm.guest_memory())?;
    let initrd = InitrdConfig::from_config(boot_config, vmm.vm.guest_memory())?;

    if vm_resources.pci_enabled {
        vmm.device_manager.enable_pci(&vmm.vm)?;
    } else {
        boot_cmdline.insert("pci", "off")?;
    }

    // BEGIN NYX-LITE PATCH
    assert_eq!(vcpus.len(), 1);
    let debug_struct = kvm_guest_debug {
        // Configure the vcpu so that a KVM_DEBUG_EXIT would be generated
        // when encountering a software breakpoint during execution
        control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
        pad: 0,
        // Reset all arch-specific debug registers
        arch: Default::default(),
    };

    vcpus[0].kvm_vcpu.fd.set_guest_debug(&debug_struct).unwrap();
    // END NYX-LITE PATCH
    // The boot timer device needs to be the first device attached in order
    // to maintain the same MMIO address referenced in the documentation
    // and tests.
    // if vm_resources.boot_timer {
    //     vmm::builder::attach_boot_timer_device(&mut vmm, request_ts)?;
    // }
    vmm::builder::attach_block_devices(
        &mut vmm.device_manager,
        &vmm.vm,
        &mut boot_cmdline,
        vm_resources.block.devices.iter(),
        event_manager,
    )?;
    vmm::builder::attach_net_devices(
        &mut vmm.device_manager,
        &vmm.vm,
        &mut boot_cmdline,
        vm_resources.net_builder.iter(),
        event_manager,
    )?;

    // no need for nondeterminism - we don't like that anyway
    //#[cfg(target_arch = "x86_64")]
    //vmm::builder::attach_vmgenid_device(&mut vmm)?;

    let vm_arc = vmm.vm.clone();
    let kvm_ptr = vmm.kvm() as *const _;
    // SAFETY: kvm_ptr points to vmm.kvm which outlives this call, and vm_arc
    // keeps the VM alive while we mutably borrow the device manager.
    unsafe {
        vmm::arch::configure_system_for_boot(
            &*kvm_ptr,
            vm_arc.as_ref(),
            &mut vmm.device_manager,
            vcpus.as_mut(),
            &vm_resources.machine_config,
            &cpu_template,
            entry_addr,
            &initrd,
            boot_cmdline,
        )?;
    }

    let mut vcpu = vcpus.into_iter().next().unwrap();
    let event_sender = vcpu.event_sender.take().expect("vCPU already started");
    let response_receiver = vcpu.response_receiver.take().unwrap();
    let vcpu_fd = vcpu
        .copy_kvm_vcpu_fd(vmm.vm.as_ref())
        .map_err(StartMicrovmError::VcpuFdCloneError)?;
    let vcpu_join_handle = thread::Builder::new()
        .name(format!("fake vcpu thread"))
        .spawn(|| {})
        .unwrap();
    let handle = VcpuHandle::new(event_sender, response_receiver, vcpu_fd, vcpu_join_handle);

    //END NYX-LITE PATCH
    vmm.vcpus_handles.push(handle);
    let vmm = Arc::new(Mutex::new(vmm));
    event_manager.add_subscriber(vmm.clone());

    vcpu.set_mmio_bus(vmm.lock().unwrap().vm.common.mmio_bus.clone());
    vcpu.kvm_vcpu
        .set_pio_bus(vmm.lock().unwrap().vm.pio_bus.clone());
    Ok((vmm, vcpu))
}
