//! Retain the original PCI fabric after disabling each captured function.
use super::*;
use alloc::rc::Rc;
use core::{any::Any, cell::RefCell, cmp::Reverse, fmt};
use stela_boot_core::ecam::topology;
use stela_drivers::bus::dma::mapping::DmaError;
use stela_drivers::{
    bus::pci::{
        ConfigEffect, ConfigError, ConfigFailure,
        capability::capabilities,
        owned::{
            ConfigParts, OwnedConfig, PreparedConfig, UnpublishedConfig,
            grant::{
                CompletionCheck, ConfigCustody, ConfigEpoch, ConfigOperation, DriverCustody,
                DriverGrant, Operation, PrepublicationCustody, PrepublicationGrant,
            },
        },
        regs::{COMMAND, COMMAND_MASTER},
        requester::{ClaimError, containment::Plan, wait_for_pending_transactions},
    },
    sync::{FaultState, FirstFault},
};

/// The captured native fabric with PCI command, interrupt and requester
/// controls contained and its original writable maps retired.
pub(crate) struct ContainedPci<'a> {
    source: &'a Source,
    functions: usize,
}

impl<'a> ContainedPci<'a> {
    pub(crate) fn source(&self) -> &'a Source {
        self.source
    }

    pub(crate) fn functions(&self) -> usize {
        self.functions
    }

    /// Original populated bridge routes in upstream-first order.
    pub(crate) fn bridges(&self) -> Result<Vec<Address>, Error> {
        let cohort = self
            .source
            .pci_slots
            .0
            .try_borrow()
            .map_err(|_| Error::Busy)?;
        let Cohort::Parked(fabric) = &*cohort else {
            return Err(Error::Unavailable);
        };
        let mut bridges = Vec::new();
        for slot in &fabric.slots {
            let Some(buses) = slot.header.bridge else {
                continue;
            };
            let secondary = buses.to_le_bytes()[1];
            if secondary > slot.address.bus
                && fabric
                    .slots
                    .binary_search_by_key(&(slot.address.segment, secondary), |slot| {
                        (slot.address.segment, slot.address.bus)
                    })
                    .is_ok()
            {
                bridges.try_reserve(1).map_err(|_| Error::Exhausted)?;
                bridges.push(slot.address);
            }
        }
        Ok(bridges)
    }

    /// Compare firmware's framebuffer association with the same parked
    /// function and its current BAR. This grants no reset or scanout access.
    ///
    /// # Safety
    /// The caller keeps the original configuration writers excluded.
    pub(crate) unsafe fn check_framebuffer(
        &self,
        source: crate::pci_io::FramebufferSource,
    ) -> Result<(), Error> {
        // SAFETY: the original source and its configuration exclusion are kept.
        unsafe {
            self.source.with_config_inventory(|_, reader| {
                for (offset, expected) in source.bar.words() {
                    let observed = reader.read32(source.address, offset)?;
                    if offset < 0x10 {
                        self.check_observation(source.address, offset, observed)?;
                    }
                    if expected != observed {
                        return Err(Error::InvalidPlatformReply);
                    }
                }
                Ok(())
            })
        }?;
        self.source
            .framebuffer
            .set(Ok(source))
            .map_err(|_| Error::Busy)
    }

    pub(crate) fn check_observation(
        &self,
        address: Address,
        offset: u16,
        value: u32,
    ) -> Result<(), Error> {
        let cohort = self.source.pci_slots.0.borrow();
        let Cohort::Parked(fabric) = &*cohort else {
            return Err(Error::Unavailable);
        };
        let index = fabric
            .slots
            .binary_search_by_key(&address, |slot| slot.address)
            .map_err(|_| Error::OutsideResource)?;
        if fabric.slots[index].header.word(offset) != Some(value) {
            return Err(Error::InvalidPlatformReply);
        }
        Ok(())
    }

    /// Observe every parked function through the same read-only census.
    pub(crate) fn check_stopped(
        &self,
        reader: &mut ConfigInventory<'_>,
    ) -> Result<(), ContainmentError> {
        if !core::ptr::eq(self.source, reader.source) {
            return Err(Error::InvalidPlatformReply.into());
        }
        let cohort = self.source.pci_slots.0.borrow();
        let Cohort::Parked(fabric) = &*cohort else {
            return Err(Error::Unavailable.into());
        };
        for slot in &fabric.slots {
            slot.check_stopped(|offset, width| {
                reader
                    .read(slot.address, offset, width)
                    .map_err(mapping_error)
            })?;
        }
        Ok(())
    }

    /// Recheck one parked page at a time, borrowing any already kept
    /// remapper configuration through its own original read-only owner.
    ///
    /// # Safety
    /// Caller keeps the original writer exclusion. `kept` returns a reader
    /// only for the exact original remapper function; other pages are disjoint.
    pub(crate) unsafe fn recheck_stopped_scoped(
        &self,
        mut kept: impl FnMut(Address, u16, u8) -> Option<Result<u32, ConfigError>>,
    ) -> Result<(), ContainmentError> {
        let cohort = self.source.pci_slots.0.borrow();
        let Cohort::Parked(fabric) = &*cohort else {
            return Err(Error::Unavailable.into());
        };
        for slot in &fabric.slots {
            let mut map = None;
            let checked = slot.check_stopped(|offset, width| {
                if let Some(value) = kept(slot.address, offset, width) {
                    return value;
                }
                if map.is_none() {
                    let (_, span) = self
                        .source
                        .config_page(slot.address)
                        .map_err(mapping_error)?;
                    // SAFETY: this exact original slot has no other current
                    // observation owner. Its sole read-only view is scoped.
                    map = Some(
                        unsafe { ConfigScope::open(self.source, span) }.map_err(mapping_error)?,
                    );
                }
                map.as_ref()
                    .expect("scoped function map")
                    .read(usize::from(offset), u16::from(width))
                    .map_err(mapping_error)
            });
            if let Some(mut map) = map {
                // SAFETY: all observations returned synchronously.
                unsafe { map.retire() }
                    .map_err(|error| ContainmentError::from(error).at(slot.address))?;
            }
            checked?;
        }
        Ok(())
    }

    /// Reopen a read-only view after the remapping units have drained.
    ///
    /// # Safety
    /// The original source still excludes every configuration and topology writer.
    pub(crate) unsafe fn recheck_stopped(&self) -> Result<(), ContainmentError> {
        // SAFETY: the caller retains the original exclusive census ownership.
        unsafe {
            self.source
                .with_config_inventory(|_, reader| self.check_stopped(reader))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ContainmentError {
    address: Option<Address>,
    cause: Cause,
    effect: ConfigEffect,
}

#[derive(Clone, Copy, Debug)]
enum Cause {
    Claim(ClaimError),
    Topology(topology::Error),
    BridgeForwarding,
    BridgeAlias,
}

/// A plain sentence for the boot log: the function, what failed and what it
/// means for containment.
impl fmt::Display for ContainmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(address) = self.address {
            write!(f, "{address}: ")?;
        }
        match self.cause {
            Cause::Claim(ClaimError::Mapping(error)) if self.address.is_none() => {
                write!(
                    f,
                    "the PCI configuration space cannot be mapped ({error:?})"
                )
            }
            Cause::Claim(ClaimError::Config(error)) => {
                write!(f, "{error}")?;
                if let ConfigFailure::Readback {
                    offset: COMMAND, ..
                } = error.reason
                {
                    f.write_str(
                        "; the function keeps bus mastering or INTx on, so Stela cannot hold it \
                         stopped",
                    )?;
                }
                Ok(())
            }
            Cause::Claim(cause) => {
                write!(f, "{cause}")?;
                if let ConfigEffect::WriteMayHaveApplied { offset, .. } = self.effect {
                    write!(f, " after Stela wrote its register {offset:#x}")?;
                }
                Ok(())
            }
            Cause::Topology(cause) => write!(f, "the PCI topology is inconsistent ({cause:?})"),
            Cause::BridgeForwarding => f.write_str("upstream bridge forwarding is unavailable"),
            Cause::BridgeAlias => f.write_str("bridge DMA requester aliases are unqualified"),
        }
    }
}

impl From<ClaimError> for ContainmentError {
    fn from(cause: ClaimError) -> Self {
        let effect = match cause {
            ClaimError::Config(error) => error.effect,
            _ => ConfigEffect::None,
        };
        Self {
            address: None,
            cause: Cause::Claim(cause),
            effect,
        }
    }
}

impl From<topology::Error> for ContainmentError {
    fn from(cause: topology::Error) -> Self {
        Self {
            address: None,
            cause: Cause::Topology(cause),
            effect: ConfigEffect::None,
        }
    }
}

impl From<Error> for ContainmentError {
    fn from(error: Error) -> Self {
        ClaimError::Mapping(error).into()
    }
}

impl From<ConfigError> for ContainmentError {
    fn from(error: ConfigError) -> Self {
        ClaimError::Config(error).into()
    }
}

impl ContainmentError {
    fn at(mut self, address: Address) -> Self {
        self.address = Some(address);
        self
    }
}

struct Slot {
    address: Address,
    configuration: Option<PreparedConfig<PrepublicationGrant>>,
    refusal: Option<SlotRefusal>,
    header: Header,
    plan: Rc<Plan>,
    ancestor: Parent,
    route: topology::Parent,
    forwarding: Option<Forwarding>,
}

impl Slot {
    fn check_stopped(
        &self,
        mut read: impl FnMut(u16, u8) -> Result<u32, ConfigError>,
    ) -> Result<(), ContainmentError> {
        self.header
            .verify(|offset| read(offset, 4))
            .and_then(|()| {
                self.plan
                    .check_disabled(|offset| read(offset, 2).map(|word| word as u16))
            })
            .and_then(|()| {
                if self.header.bridge.is_some() {
                    let prepared = self
                        .configuration
                        .as_ref()
                        .ok_or_else(|| mapping_error(Error::Unavailable))?;
                    prepared.check_bridge_routing(read)?;
                }
                Ok(())
            })
            .map_err(|error| ContainmentError::from(error).at(self.address))
    }
}

enum Forwarding {
    Open {
        config: OwnedConfig,
        blocked: Box<dyn Fn() -> Result<(), DmaError>>,
        command: u16,
    },
    Refused {
        _original: ConfigParts<DriverGrant>,
        _blocked: Box<dyn Fn() -> Result<(), DmaError>>,
    },
}

impl Forwarding {
    fn check(&self) -> Result<(), ContainmentError> {
        let Self::Open {
            config,
            blocked,
            command,
        } = self
        else {
            return Err(Error::Unavailable.into());
        };
        blocked().map_err(|_| Error::Unavailable)?;
        check_command(config, *command, ConfigEffect::None)?;
        Ok(())
    }
}

fn check_command(
    config: &OwnedConfig,
    expected: u16,
    effect: ConfigEffect,
) -> Result<(), ConfigError> {
    let observed = config.try_read16(COMMAND).map_err(|mut error| {
        if effect != ConfigEffect::None {
            error.effect = effect;
        }
        error
    })?;
    if observed == expected {
        return Ok(());
    }
    Err(ConfigError {
        reason: ConfigFailure::Readback {
            offset: COMMAND,
            width: 2,
            expected: expected.into(),
            observed: observed.into(),
        },
        effect,
    })
}

#[derive(Default)]
struct Fabric {
    roots: Vec<Option<Assignment<RootBus>>>,
    slots: Vec<Slot>,
    refusal: Option<SlotRefusal>,
}

impl Fabric {
    fn check_upstream(&self, mut route: topology::Parent) -> Result<(), ContainmentError> {
        while let topology::Parent::Bridge(address) = route {
            let index = self
                .slots
                .binary_search_by_key(&address, |slot| slot.address)
                .expect("original parent remains in the fabric");
            let bridge = &self.slots[index];
            bridge
                .forwarding
                .as_ref()
                .ok_or(ContainmentError {
                    address: Some(address),
                    cause: Cause::BridgeForwarding,
                    effect: ConfigEffect::None,
                })?
                .check()
                .map_err(|error| error.at(address))?;
            route = bridge.route;
        }
        Ok(())
    }
}

struct SlotRefusal {
    error: ContainmentError,
    _original: ConfigParts<PrepublicationGrant>,
}

impl SlotRefusal {
    fn new(error: impl Into<ContainmentError>, original: ConfigParts<PrepublicationGrant>) -> Self {
        original.close_admission();
        Self {
            error: error.into(),
            _original: original,
        }
    }
}

enum Cohort {
    Unclaimed,
    Incomplete(Fabric),
    Parked(Fabric),
}

struct RootBus {
    _descriptor: &'static RootWindow,
    platform: Arc<Platform>,
    aperture: Parent,
}

// SAFETY: the descriptor comes from the retained capture. Each unique root
// bus assignment is a child of that capture's aperture owner.
unsafe impl PhysicalAssignment for RootBus {
    fn parent(&self) -> Option<&Parent> {
        Some(&self.aperture)
    }

    fn check_control(&self) -> Result<(), assignment::Error> {
        self.platform
            .check_mapping_control()
            .map_err(|_| assignment::Error::Context)
    }
}

pub(in crate::native_mmio::shared) struct PciSlots(RefCell<Cohort>);

impl PciSlots {
    pub(in crate::native_mmio::shared) const fn new() -> Self {
        Self(RefCell::new(Cohort::Unclaimed))
    }
}

#[derive(Clone, Copy)]
struct Header {
    identity: u32,
    class_revision: u32,
    layout: u32,
    bridge: Option<u32>,
}

impl Header {
    fn word(self, offset: u16) -> Option<u32> {
        match offset {
            0 => Some(self.identity),
            8 => Some(self.class_revision),
            0x0c => Some(self.layout),
            0x18 => self.bridge,
            _ => None,
        }
    }

    fn verify(
        self,
        mut read: impl FnMut(u16) -> Result<u32, ConfigError>,
    ) -> Result<(), ConfigError> {
        for offset in [0, 8, 0x0c, 0x18] {
            let Some(expected) = self.word(offset) else {
                continue;
            };
            let observed = read(offset)?;
            if observed != expected {
                return Err(ConfigError::before_effect(ConfigFailure::Readback {
                    offset,
                    width: 4,
                    expected,
                    observed,
                }));
            }
        }
        Ok(())
    }
}

// PCI Express root, upstream switch and downstream switch ports keep the
// downstream requester ID. PCI/PCI-X translation can introduce DMA aliases
// which the current single-RID attachment cannot grant.
fn check_pcie_port(config: &UnpublishedConfig) -> Result<(), ContainmentError> {
    const EXPRESS: u8 = 0x10;
    const PORT_TYPE_MASK: u16 = 0xf0;
    for entry in capabilities(config) {
        let entry = entry.map_err(ClaimError::from)?;
        if entry.id == EXPRESS {
            let flags = config.try_read16(entry.offset + 2)?;
            if matches!(flags & PORT_TYPE_MASK, 0x40 | 0x50 | 0x60) {
                return Ok(());
            }
            break;
        }
    }
    Err(ContainmentError {
        address: None,
        cause: Cause::BridgeAlias,
        effect: ConfigEffect::None,
    })
}

struct Input {
    address: Address,
    window: EcamWindow,
    span: PhysicalSpan,
    header: Header,
    plan: Rc<Plan>,
}

impl Input {
    /// `root_bus`: no bridge the census found forwards to `address`'s bus.
    fn observe(
        reader: &mut ConfigInventory<'_>,
        address: Address,
        root_bus: bool,
    ) -> Result<Option<Self>, ContainmentError> {
        let identity = reader.read32(address, 0)?;
        match identity as u16 {
            u16::MAX => return Ok(None),
            0 | 1 => return Err(Error::InvalidPlatformReply.into()),
            _ => {}
        }
        let class_revision = reader.read32(address, 8)?;
        if class_revision == u32::MAX {
            return Err(Error::InvalidPlatformReply.into());
        }
        let layout = reader.read32(address, 0x0c)?;
        let bridge = if reader.header_type(layout)? == 1 {
            if class_revision >> 16 != 0x0604 {
                return Err(Error::InvalidPlatformReply.into());
            }
            let buses = reader.read32(address, 0x18)?;
            reader.check_bridge(address, buses)?;
            Some(buses)
        } else {
            None
        };
        let plan = Plan::read(
            |offset, width| {
                reader
                    .read(address, offset, width)
                    .map_err(ClaimError::Mapping)
            },
            root_bus,
        )?;
        let (window, span) = reader
            .geometry
            .function(address, reader.source.platform.wire().roots())?;
        Ok(Some(Self {
            address,
            window,
            span,
            header: Header {
                identity,
                class_revision,
                layout,
                bridge,
            },
            plan: Rc::new(plan),
        }))
    }
}

fn census(
    windows: &[EcamWindow],
    reader: &mut ConfigInventory<'_>,
) -> Result<Vec<Input>, ContainmentError> {
    let mut inputs: Vec<Input> = Vec::new();
    for window in windows {
        for bus in window.start_bus..=window.end_bus {
            // A bridge's secondary bus is above its own, so every bridge
            // that forwards to `bus` is already in the census.
            let root_bus = !inputs.iter().any(|input| {
                input.address.segment == window.segment
                    && input.header.bridge.is_some_and(|buses| {
                        (buses >> 8 & 0xff..=buses >> 16 & 0xff).contains(&u32::from(bus))
                    })
            });
            for device in 0..32 {
                for function in 0..8 {
                    let address = Address {
                        segment: window.segment,
                        bus,
                        device,
                        function,
                    };
                    if let Some(input) = Input::observe(reader, address, root_bus)
                        .map_err(|error| error.at(address))?
                    {
                        inputs.try_reserve(1).map_err(|_| Error::Exhausted)?;
                        inputs.push(input);
                    }
                }
            }
        }
    }
    Ok(inputs)
}

#[derive(Clone)]
struct Epoch {
    platform: Arc<Platform>,
    original: Retention<Reservation>,
}

impl Epoch {
    fn context(&self) -> Result<(), Error> {
        self.platform.check_mapping_control()
    }
}

// SAFETY: this projection only keeps the original aperture and slot count.
// It creates no mapping or configuration access.
unsafe impl ConfigEpoch for Epoch {
    fn check(&self) -> Result<(), Error> {
        self.context()?;
        self.original.check_admission().map_err(Error::Assignment)
    }

    fn retain(&self) -> Result<Box<dyn ConfigEpoch>, Error> {
        self.check()?;
        Ok(Box::new(self.clone()))
    }

    fn same_epoch(&self, other: &dyn ConfigEpoch) -> Result<bool, Error> {
        self.check()?;
        other.check()?;
        Ok(other
            .as_any()
            .downcast_ref::<Self>()
            .is_some_and(|other| self.original.same_assignment(&other.original)))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct Completion {
    epoch: Epoch,
    fault: FirstFault<ConfigError>,
}

fn mapping_error(error: Error) -> ConfigError {
    ConfigError::before_effect(ConfigFailure::Mapping(error))
}

// SAFETY: the preowned validator checks the original aperture in the
// accepting context and latches its first failure without reentry.
unsafe impl CompletionCheck for Completion {
    fn postvalidate(&self) -> Result<(), ConfigError> {
        let result = self.epoch.context().map_err(mapping_error);
        if let Err(error) = result {
            self.fault.latch(error);
        }
        result
    }

    fn failure(&self) -> FaultState<ConfigError> {
        self.fault.observe()
    }
}

struct SlotCustody {
    _original: Assignment<Reservation>,
    resource: Resource,
    completion: Arc<Completion>,
    address: Address,
    window: EcamWindow,
    plan: Rc<Plan>,
    driver_lines: Option<InitialPciLines>,
}

// SAFETY: the census issues one exact slot from the original aperture
// reservation, shared by its resource backing and configuration counts.
unsafe impl ConfigCustody for SlotCustody {
    fn address(&self) -> Address {
        self.address
    }

    fn window(&self) -> EcamWindow {
        self.window
    }

    fn resource(&self) -> &Resource {
        &self.resource
    }

    fn begin(&self, operation: Operation) -> Result<ConfigOperation, ConfigError> {
        self.completion.epoch.context().map_err(mapping_error)?;
        if self.driver_lines.is_none()
            && let Operation::Write {
                offset,
                width,
                value,
            } = operation
            && !self.plan.permits(offset, width, value)
        {
            return Err(ConfigError::before_effect(
                ConfigFailure::UnqualifiedControl,
            ));
        }
        match self.completion.failure() {
            FaultState::Ready(error) => return Err(error),
            FaultState::Publishing => {
                return Err(ConfigError::before_effect(ConfigFailure::FaultPublishing));
            }
            FaultState::Empty => {}
        }
        let count = self
            .completion
            .epoch
            .original
            .begin_use(UseKind::Configuration)
            .map_err(|error| ConfigError::before_effect(ConfigFailure::Ownership(error)))?;
        // SAFETY: the accepted operation retains the exact slot and validator.
        Ok(unsafe { ConfigOperation::new(count.erase(), self.completion.clone()) })
    }

    fn retirement_context(&self) -> Result<(), Error> {
        self.completion.epoch.context()
    }

    fn retain_epoch(&self) -> Result<Box<dyn ConfigEpoch>, Error> {
        self.completion.epoch.retain()
    }
}

// SAFETY: the original exclusive source issues the slot once. Its only
// writes are the exact disabling values planned from the complete census.
unsafe impl PrepublicationCustody for SlotCustody {}

// SAFETY: only promote_parked can turn on driver operations. It joins
// the original parked slot and ancestor assignment to the checked blocked
// requester and original interrupt paths, preserving the BME seal.
unsafe impl DriverCustody for SlotCustody {}

impl Source {
    /// Take the original parked endpoint, preserving its grant and negative
    /// operation state. A refusal after taking it keeps the exact envelope in
    /// the same slot and prevents a second attempt.
    ///
    /// # Safety
    /// The caller owns the original complete remapping fabric. The check
    /// observes the exact firmware-selected unit for this segment and RID. Prior PCI
    /// writers and any legacy writer or reassignment of the topology stay
    /// excluded. This grants no endpoint stop, root binding or IRQ route.
    pub(crate) unsafe fn promote_cold_config(
        &self,
        address: Address,
        lines: &InitialPciLines,
        check_blocked: impl Fn() -> Result<(), DmaError>,
    ) -> Result<OwnedConfig, ContainmentError> {
        // SAFETY: same original exclusive, blocked requester and line paths.
        unsafe { self.promote_parked(address, lines, check_blocked, false) }
    }

    /// Restore only forwarding through one original PCIe port. Keep the
    /// routing seal, configuration owner and its original blocked context.
    ///
    /// # Safety
    /// Same proof as promote_cold_config, plus the complete original cohort
    /// was rechecked before any forwarding and all leaf owners remain parked
    /// with their master seals and new DMA roots blocked. The checker owns
    /// this port's original blocked context for as long as the port is kept.
    pub(crate) unsafe fn forward_cold_bridge(
        &self,
        address: Address,
        lines: &InitialPciLines,
        check_blocked: impl Fn() -> Result<(), DmaError> + 'static,
    ) -> Result<(), ContainmentError> {
        let blocked: Box<dyn Fn() -> Result<(), DmaError>> = Box::new(check_blocked);
        // SAFETY: the caller keeps the original stopped descendant cohort,
        // and this selects only the original Type1 port for the exact RID.
        let mut config = unsafe { self.promote_parked(address, lines, &blocked, true) }?;
        let result = (|| {
            let command = config.try_read16(COMMAND)? | COMMAND_MASTER;
            // SAFETY: the whole original fabric is drained and held, with
            // blocked contexts, disabled leaves and no competing writers.
            // The original routing seal stays enforced by the configuration.
            unsafe { config.release_bus_forwarding_seal() }?;
            config.try_write16(COMMAND, command)?;
            check_command(
                &config,
                command,
                ConfigEffect::WriteMayHaveApplied {
                    offset: COMMAND,
                    width: 2,
                },
            )?;
            Ok::<_, ConfigError>(command)
        })();
        let (forwarding, result) = match result {
            Ok(command) => (
                Forwarding::Open {
                    config,
                    blocked,
                    command,
                },
                Ok(()),
            ),
            Err(error) => {
                let original = config.into_parts();
                original.close_admission();
                (
                    Forwarding::Refused {
                        _original: original,
                        _blocked: blocked,
                    },
                    Err(ContainmentError::from(error).at(address)),
                )
            }
        };
        let mut cohort = self.pci_slots.0.borrow_mut();
        let Cohort::Parked(fabric) = &mut *cohort else {
            unreachable!("the original parked fabric stays owned")
        };
        let index = fabric
            .slots
            .binary_search_by_key(&address, |slot| slot.address)
            .expect("forwarding keeps the original slot");
        fabric.slots[index].forwarding = Some(forwarding);
        result
    }

    /// # Safety
    /// Caller holds the matching complete fabric and excludes all old PCI
    /// writers. Bridge promotion additionally requires parked descendants.
    unsafe fn promote_parked(
        &self,
        address: Address,
        lines: &InitialPciLines,
        check_blocked: impl Fn() -> Result<(), DmaError>,
        bridge: bool,
    ) -> Result<OwnedConfig, ContainmentError> {
        let check_paths = || {
            lines.check(self)?;
            check_blocked().map_err(|_| Error::Unavailable)
        };
        check_paths().map_err(|error| ContainmentError::from(error).at(address))?;
        let (index, prepared, header, plan) = {
            let mut cohort = self.pci_slots.0.try_borrow_mut().map_err(|_| Error::Busy)?;
            let Cohort::Parked(fabric) = &mut *cohort else {
                return Err(Error::Unavailable.into());
            };
            let index = fabric
                .slots
                .binary_search_by_key(&address, |slot| slot.address)
                .map_err(|_| Error::OutsideResource)?;
            let slot = &fabric.slots[index];
            if let Some(refusal) = &slot.refusal {
                return Err(refusal.error);
            }
            if (slot.header.layout >> 16) & 0x7f != u32::from(bridge) {
                return Err(ContainmentError::from(Error::OutsideResource).at(address));
            }
            fabric.check_upstream(slot.route)?;
            let slot = &mut fabric.slots[index];
            let prepared = slot.configuration.take().ok_or(Error::Busy)?;
            (index, prepared, slot.header, slot.plan.clone())
        };
        let result = (|| {
            let mapping = match self.authority.map(
                prepared.configuration_resource().clone(),
                0,
                PAGE as usize,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            ) {
                Ok(mapping) => mapping,
                Err(error) => return Err(SlotRefusal::new(error, prepared.into_parts())),
            };
            let config = prepared
                .attach(mapping)
                .map_err(|(error, original)| SlotRefusal::new(error, original))?;
            if let Err(error) = header
                .verify(|offset| config.try_read32(offset))
                .and_then(|()| plan.check_disabled(|offset| config.try_read16(offset)))
            {
                return Err(SlotRefusal::new(error, config.into_parts()));
            }
            if bridge && let Err(error) = check_pcie_port(&config) {
                return Err(SlotRefusal::new(error, config.into_parts()));
            }
            // SAFETY: the parked map retired, this is its sole successor,
            // and the original kept paths are checked again before changing
            // the original grant's operation policy.
            unsafe {
                config.promote(|owner: &mut SlotCustody| {
                    check_paths()?;
                    owner.driver_lines = Some(lines.clone());
                    Ok(())
                })
            }
            .map_err(|(error, original)| SlotRefusal::new(error, original))
        })();
        match result {
            Ok(config) => Ok(config),
            Err(mut refusal) => {
                refusal.error.address = Some(address);
                let error = refusal.error;
                let mut cohort = self.pci_slots.0.borrow_mut();
                let Cohort::Parked(fabric) = &mut *cohort else {
                    unreachable!("the original parked fabric stays owned")
                };
                fabric.slots[index].refusal = Some(refusal);
                Err(error)
            }
        }
    }

    /// Contain the captured fabric once and park each original configuration.
    /// The return value qualifies PCI-level controls for remapper takeover.
    ///
    /// # Safety
    /// Firmware and APs are stopped. The caller keeps all captured buses and
    /// their topology exclusive, including reset and hotplug.
    pub(crate) unsafe fn contain_pci(
        &self,
        tsc_hz: u64,
    ) -> Result<ContainedPci<'_>, ContainmentError> {
        {
            let mut cohort = self.pci_slots.0.borrow_mut();
            match &*cohort {
                Cohort::Unclaimed => *cohort = Cohort::Incomplete(Fabric::default()),
                Cohort::Incomplete(Fabric {
                    refusal: Some(refusal),
                    ..
                }) => return Err(refusal.error),
                _ => return Err(Error::Busy.into()),
            }
        }
        // SAFETY: the caller keeps the complete captured topology exclusive.
        // with_config_inventory retires the last read-only map before return.
        let inputs = unsafe { self.with_config_inventory(census) }?;
        // Preserve a hardware-specific diagnostic without changing ownership
        // or containment policy. The low byte of CLASS_REVISION is Revision ID.
        for input in &inputs {
            if input.header.identity == 0x790e_1022 {
                let class_revision = input.header.class_revision;
                crate::output::arguments(format_args!(
                    "HOST PCI AMD LPC {:04x}:{:02x}:{:02x}.{} class={:06x} revision={:02x}\\n",
                    input.address.segment,
                    input.address.bus,
                    input.address.device,
                    input.address.function,
                    class_revision >> 8,
                    class_revision & 0xff,
                ));
            }
        }
        let count = inputs.len();
        let mut order = Vec::new();
        order
            .try_reserve_exact(count)
            .map_err(|_| Error::Exhausted)?;
        self.prepare_fabric(inputs)?;
        order.extend(0..count);
        // Stop endpoints while their bridges still forward. Stop downstream
        // bridges before their upstream parents.
        {
            let cohort = self.pci_slots.0.borrow();
            let Cohort::Incomplete(fabric) = &*cohort else {
                unreachable!("exclusive containment owns the incomplete fabric");
            };
            order.sort_unstable_by_key(|&index| {
                let slot = &fabric.slots[index];
                (slot.header.bridge.is_some(), Reverse(slot.address.bus))
            });
        }

        for index in order {
            let (address, prepared, header, plan) = {
                let mut cohort = self.pci_slots.0.borrow_mut();
                let Cohort::Incomplete(fabric) = &mut *cohort else {
                    unreachable!("exclusive containment owns the incomplete fabric");
                };
                let slot = &mut fabric.slots[index];
                (
                    slot.address,
                    slot.configuration
                        .take()
                        .expect("one prepared configuration"),
                    slot.header,
                    slot.plan.clone(),
                )
            };
            let result = self.contain_slot(prepared, header, &plan, tsc_hz);
            let mut cohort = self.pci_slots.0.borrow_mut();
            let Cohort::Incomplete(fabric) = &mut *cohort else {
                unreachable!("exclusive containment owns the incomplete fabric");
            };
            match result {
                Ok(parked) => fabric.slots[index].configuration = Some(parked),
                Err(mut refusal) => {
                    refusal.error.address = Some(address);
                    let error = refusal.error;
                    fabric.refusal = Some(refusal);
                    return Err(error);
                }
            }
        }
        let mut cohort = self.pci_slots.0.borrow_mut();
        let Cohort::Incomplete(fabric) = &mut *cohort else {
            unreachable!("exclusive containment owns the incomplete fabric");
        };
        *cohort = Cohort::Parked(core::mem::take(fabric));
        Ok(ContainedPci {
            source: self,
            functions: count,
        })
    }

    fn prepare_fabric(&self, mut inputs: Vec<Input>) -> Result<(), ContainmentError> {
        let roots = self.platform.wire().roots();
        let mut observed = Vec::new();
        observed
            .try_reserve_exact(inputs.len())
            .map_err(|_| Error::Exhausted)?;
        observed.extend(inputs.iter().map(|input| topology::Function {
            address: input.address,
            bridge_buses: input.header.bridge,
        }));
        let parents = topology::resolve(roots, &observed)?;
        inputs.sort_unstable_by_key(|input| input.address);

        let mut fabric = Fabric::default();
        fabric
            .roots
            .try_reserve_exact(roots.len())
            .map_err(|_| Error::Exhausted)?;
        fabric
            .slots
            .try_reserve_exact(inputs.len())
            .map_err(|_| Error::Exhausted)?;
        for descriptor in roots {
            let assignment = (descriptor.space == 2).then(|| {
                Assignment::from_owned(RootBus {
                    _descriptor: descriptor,
                    platform: self.platform.clone(),
                    aperture: self.aperture.parent(),
                })
            });
            fabric.roots.push(assignment);
        }
        *self.pci_slots.0.borrow_mut() = Cohort::Incomplete(fabric);
        // Secondary bus numbers exceed their upstream bus. BDF order keeps
        // each real bridge assignment before any of its children.
        for ((address, route), input) in parents.into_iter().zip(inputs) {
            debug_assert_eq!(address, input.address);
            let parent = {
                let cohort = self.pci_slots.0.borrow();
                let Cohort::Incomplete(fabric) = &*cohort else {
                    unreachable!("exclusive containment owns the incomplete fabric");
                };
                match route {
                    topology::Parent::Root(index) => fabric.roots[index]
                        .as_ref()
                        .expect("resolved root grant")
                        .parent(),
                    topology::Parent::Bridge(bridge) => {
                        let at = fabric
                            .slots
                            .binary_search_by_key(&bridge, |slot| slot.address)
                            .expect("upstream slot is ordered before its children");
                        fabric.slots[at].ancestor.clone()
                    }
                }
            };
            let slot = self
                .prepare_slot(input, parent, route)
                .map_err(|error| error.at(address))?;
            let mut cohort = self.pci_slots.0.borrow_mut();
            let Cohort::Incomplete(fabric) = &mut *cohort else {
                unreachable!("exclusive containment owns the incomplete fabric");
            };
            fabric.slots.push(slot);
        }
        Ok(())
    }

    fn prepare_slot(
        &self,
        input: Input,
        parent: Parent,
        route: topology::Parent,
    ) -> Result<Slot, ContainmentError> {
        let (resource, original) =
            self.reservation_under(input.span, ResourceKind::Configuration, parent)?;
        let ancestor = original.parent();
        let close = original.admission_close();
        let owner = Box::new(SlotCustody {
            completion: Arc::new(Completion {
                epoch: Epoch {
                    platform: self.platform.clone(),
                    original: original.retain(),
                },
                fault: FirstFault::new(),
            }),
            _original: original,
            resource,
            address: input.address,
            window: input.window,
            plan: input.plan.clone(),
            driver_lines: None,
        });
        // SAFETY: the same affine slot backs the bounded operation and map.
        let grant = unsafe { PrepublicationGrant::from_boxed(owner, close) };
        Ok(Slot {
            address: input.address,
            configuration: Some(UnpublishedConfig::prepare(grant)),
            refusal: None,
            header: input.header,
            plan: input.plan,
            ancestor,
            route,
            forwarding: None,
        })
    }

    fn contain_slot(
        &self,
        prepared: PreparedConfig<PrepublicationGrant>,
        header: Header,
        plan: &Plan,
        tsc_hz: u64,
    ) -> Result<PreparedConfig<PrepublicationGrant>, SlotRefusal> {
        let mapping = match self.authority.map(
            prepared.configuration_resource().clone(),
            0,
            PAGE as usize,
            CacheAttribute::Uncached,
            Protection::ReadWrite,
        ) {
            Ok(mapping) => mapping,
            Err(error) => return Err(SlotRefusal::new(error, prepared.into_parts())),
        };
        let mut config = prepared
            .attach(mapping)
            .map_err(|(error, original)| SlotRefusal::new(error, original))?;
        let effect = match header
            .verify(|offset| config.try_read32(offset))
            .and_then(|()| plan.apply(&mut config))
        {
            Ok(effect) => effect,
            Err(error) => return Err(SlotRefusal::new(error, config.into_parts())),
        };
        let acknowledge = (|| -> Result<(), ClaimError> {
            let started = crate::apic::rdtsc();
            let limit = (tsc_hz / 1_000 * 64).max(1);
            wait_for_pending_transactions(&config, || {
                crate::apic::rdtsc().wrapping_sub(started) >= limit
            })?;
            // Stopped controls read back, and Bus Master is sealed: clear,
            // or proven hard-wired on a root-bus host bridge.
            plan.seal(&mut config)?;
            if header.bridge.is_some() {
                config.seal_bus_routing()?;
            }
            header.verify(|offset| config.try_read32(offset))?;
            Ok(())
        })();
        if let Err(cause) = acknowledge {
            return Err(SlotRefusal::new(
                ContainmentError {
                    address: None,
                    cause: Cause::Claim(cause),
                    effect,
                },
                config.into_parts(),
            ));
        }
        // SAFETY: the only accesses were synchronous and bounded, with no
        // escaped aliases. Source keeps this original decode and assignment.
        unsafe { config.park() }.map_err(|(error, original)| {
            SlotRefusal::new(
                ContainmentError {
                    address: None,
                    cause: Cause::Claim(ClaimError::Mapping(error)),
                    effect,
                },
                original,
            )
        })
    }
}
