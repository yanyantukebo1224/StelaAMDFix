use stela_driver_base::bus::pci::{
    ConfigError,
    requester::{ClaimError, containment::Plan},
};

fn command_plan(class_code: u32, root_bus: bool) -> Plan {
    Plan::read(
        |offset, width| -> Result<u32, ClaimError> {
            Ok(match (offset, width) {
                (0x04, 2) => 0x040f,
                // PCI config offset 0x08 stores Revision ID in bits 7:0
                // and the 24-bit Class Code in bits 31:8.
                (0x08, 4) => class_code << 16,
                (0x3d, 1) => 0,
                _ => 0,
            })
        },
        root_bus,
    )
    .expect("the synthetic PCI function has a valid basic header")
}

fn command_readback(command: u16) -> impl FnMut(u16) -> Result<u16, ConfigError> {
    move |offset| Ok(if offset == 0x04 { command } else { 0 })
}

#[test]
fn root_bus_amd_lpc_bridge_is_not_mistaken_for_a_hardwired_host_bridge() {
    // AMD 1022:790e reports class 0601. Even on the root bus, BME must
    // read clear: the class-0600 host-bridge exception does not apply.
    let plan = command_plan(0x0601, true);
    assert!(
        plan.check_disabled(command_readback(0x040f)).is_err(),
        "a root-bus LPC bridge with BME still set must remain uncontained"
    );
    assert!(
        plan.check_disabled(command_readback(0x040b)).is_ok(),
        "the same LPC bridge is accepted once BME is actually clear"
    );
}

#[test]
fn hardwired_bus_master_exception_is_limited_to_root_bus_host_bridges() {
    let root_host_bridge = command_plan(0x0600, true);
    assert!(
        root_host_bridge
            .check_disabled(command_readback(0x040f))
            .is_ok()
    );

    let downstream_host_bridge = command_plan(0x0600, false);
    assert!(
        downstream_host_bridge
            .check_disabled(command_readback(0x040f))
            .is_err()
    );

    let root_lpc_bridge = command_plan(0x0601, true);
    assert!(
        root_lpc_bridge
            .check_disabled(command_readback(0x040f))
            .is_err()
    );
}
