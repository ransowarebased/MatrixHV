extern crate alloc;

use alloc::vec::Vec;
use std::cell::{Cell, RefCell};

include!("../builds/smp-tests/definitions.rs");
core::arch::global_asm!(include_str!("../builds/smp-tests/ap-launch.S"));

mod runtime {
    pub fn error(_message: core::fmt::Arguments<'_>) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentProbeError {
    Allocation(uefi::Status),
}

struct LaunchResources {
    result: Result<u64, ResidentProbeError>,
    preparation_count: usize,
}

pub(crate) struct ResidentApLaunch<'a> {
    processor_number: usize,
    resources: &'a mut LaunchResources,
}

impl ResidentApLaunch<'_> {
    fn prepare(&mut self, guest_rsp: u64, guest_rip: u64) -> Result<u64, ResidentProbeError> {
        assert_ne!(guest_rsp, 0);
        assert_eq!(guest_rsp & 15, 0);
        assert_ne!(guest_rip, 0);
        self.resources.preparation_count += 1;
        self.resources.result
    }
}

#[unsafe(no_mangle)]
extern "efiapi" fn matrixhv_ap_launch_failed(_flags: u64) -> ! {
    panic!("The host VMLAUNCH substitute must enter the guest continuation");
}

#[derive(Clone, Copy)]
struct ProcessorInfo {
    bsp: bool,
    enabled: bool,
}

impl ProcessorInfo {
    fn is_bsp(&self) -> bool {
        self.bsp
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

struct Firmware {
    processors: Vec<ProcessorInfo>,
    callbacks: Option<Vec<usize>>,
    who_error: Option<usize>,
    count_error: Option<Status>,
    info_error: Option<usize>,
    startup_error: Option<Status>,
    startup_count: usize,
    opens: Vec<boot::OpenProtocolAttributes>,
    closes: usize,
    active_opens: usize,
}

impl Firmware {
    fn new(enabled: &[bool]) -> Self {
        Self {
            processors: enabled
                .iter()
                .enumerate()
                .map(|(processor_number, &enabled)| ProcessorInfo {
                    bsp: processor_number == 0,
                    enabled,
                })
                .collect(),
            callbacks: None,
            who_error: None,
            count_error: None,
            info_error: None,
            startup_error: None,
            startup_count: 0,
            opens: Vec::new(),
            closes: 0,
            active_opens: 0,
        }
    }
}

thread_local! {
    static FIRMWARE: RefCell<Firmware> = RefCell::new(Firmware::new(&[true, true, true]));
    static CURRENT_PROCESSOR: Cell<usize> = const { Cell::new(0) };
}

mod uefi {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Status(u8);

    impl Status {
        pub const INVALID_PARAMETER: Self = Self(1);
        pub const ACCESS_DENIED: Self = Self(2);
        pub const DEVICE_ERROR: Self = Self(3);
        pub const TIMEOUT: Self = Self(4);
    }

    pub struct Error(pub Status);

    impl Error {
        pub fn status(&self) -> Status {
            self.0
        }
    }

    pub mod boot {
        use super::{Error, Status};
        use crate::{FIRMWARE, MpServices};
        use core::ops::Deref;

        static MP: MpServices = MpServices;

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum OpenProtocolAttributes {
            GetProtocol,
            Exclusive,
        }

        pub struct OpenProtocolParams {
            pub handle: usize,
            pub agent: usize,
            pub controller: Option<usize>,
        }

        pub struct ScopedProtocol<P> {
            interface: *const P,
        }

        impl<P> Deref for ScopedProtocol<P> {
            type Target = P;

            fn deref(&self) -> &P {
                unsafe { &*self.interface }
            }
        }

        impl<P> Drop for ScopedProtocol<P> {
            fn drop(&mut self) {
                FIRMWARE.with(|firmware| {
                    let mut firmware = firmware.borrow_mut();
                    firmware.closes += 1;
                    firmware.active_opens -= 1;
                });
            }
        }

        pub fn get_handle_for_protocol<P>() -> Result<usize, Error> {
            assert!(core::any::type_name::<P>().ends_with("MpServices"));
            Ok(1)
        }

        pub fn image_handle() -> usize {
            2
        }

        pub unsafe fn open_protocol<P>(
            params: OpenProtocolParams,
            attributes: OpenProtocolAttributes,
        ) -> Result<ScopedProtocol<P>, Error> {
            assert_eq!(params.handle, 1);
            assert_eq!(params.agent, image_handle());
            assert_eq!(params.controller, None);
            assert!(core::any::type_name::<P>().ends_with("MpServices"));
            FIRMWARE.with(|firmware| {
                let mut firmware = firmware.borrow_mut();
                firmware.opens.push(attributes);
                // Model an existing consumer whose exclusive open is incompatible.
                if attributes == OpenProtocolAttributes::Exclusive {
                    return Err(Error(Status::ACCESS_DENIED));
                }
                firmware.active_opens += 1;
                Ok(ScopedProtocol {
                    interface: (&MP as *const MpServices).cast(),
                })
            })
        }
    }

    pub mod proto {
        pub mod pi {
            pub mod mp {
                use crate::{CURRENT_PROCESSOR, FIRMWARE, ProcessorInfo};
                use core::ffi::c_void;
                use core::time::Duration;

                use super::super::super::{Error, Status};

                pub struct MpServices;

                pub struct ProcessorCount {
                    pub total: usize,
                }

                impl MpServices {
                    pub fn get_number_of_processors(&self) -> Result<ProcessorCount, Error> {
                        FIRMWARE.with(|firmware| {
                            let firmware = firmware.borrow();
                            if let Some(status) = firmware.count_error {
                                return Err(Error(status));
                            }
                            Ok(ProcessorCount {
                                total: firmware.processors.len(),
                            })
                        })
                    }

                    pub fn get_processor_info(
                        &self,
                        processor: usize,
                    ) -> Result<ProcessorInfo, Error> {
                        FIRMWARE.with(|firmware| {
                            let firmware = firmware.borrow();
                            if firmware.info_error == Some(processor) {
                                return Err(Error(Status::DEVICE_ERROR));
                            }
                            Ok(firmware.processors[processor])
                        })
                    }

                    pub fn who_am_i(&self) -> Result<usize, Error> {
                        let processor = CURRENT_PROCESSOR.get();
                        FIRMWARE.with(|firmware| {
                            let firmware = firmware.borrow();
                            assert_eq!(firmware.active_opens, 1);
                            if firmware.who_error == Some(processor) {
                                return Err(Error(Status::DEVICE_ERROR));
                            }
                            Ok(processor)
                        })
                    }

                    pub fn startup_all_aps(
                        &self,
                        single_thread: bool,
                        procedure: extern "efiapi" fn(*mut c_void),
                        argument: *mut c_void,
                        event: Option<()>,
                        timeout: Option<Duration>,
                    ) -> Result<(), Error> {
                        assert!(!single_thread);
                        assert_eq!(event, None);
                        assert_eq!(timeout, Some(Duration::from_secs(10)));
                        let (processors, error) = FIRMWARE.with(|firmware| {
                            let mut firmware = firmware.borrow_mut();
                            assert_eq!(firmware.active_opens, 1);
                            firmware.startup_count += 1;
                            let processors = firmware.callbacks.clone().unwrap_or_else(|| {
                                firmware
                                    .processors
                                    .iter()
                                    .enumerate()
                                    .filter(|(_, info)| info.enabled && !info.bsp)
                                    .map(|(processor, _)| processor)
                                    .collect()
                            });
                            (processors, firmware.startup_error)
                        });
                        for processor in processors {
                            CURRENT_PROCESSOR.set(processor);
                            procedure(argument);
                        }
                        error.map_or(Ok(()), |status| Err(Error(status)))
                    }
                }
            }
        }
    }
}

fn run_batch(
    processors: &[usize],
    failing_processor: Option<usize>,
) -> (Result<(), ResidentProbeError>, Vec<usize>) {
    let mut resources: Vec<_> = processors
        .iter()
        .map(|&processor| LaunchResources {
            result: if Some(processor) == failing_processor {
                Err(ResidentProbeError::Allocation(Status::DEVICE_ERROR))
            } else {
                Ok(0x1000)
            },
            preparation_count: 0,
        })
        .collect();
    let mut launches: Vec<_> = processors
        .iter()
        .zip(&mut resources)
        .map(|(&processor_number, resources)| ResidentApLaunch {
            processor_number,
            resources,
        })
        .collect();
    let result = launch_all(&mut launches);
    drop(launches);
    (
        result,
        resources
            .iter()
            .map(|resource| resource.preparation_count)
            .collect(),
    )
}

fn reset(enabled: &[bool]) {
    FIRMWARE.with(|firmware| *firmware.borrow_mut() = Firmware::new(enabled));
}

fn assert_rejected(processors: &[usize]) {
    let (result, preparations) = run_batch(processors, None);
    assert_eq!(
        result,
        Err(ResidentProbeError::Allocation(Status::INVALID_PARAMETER))
    );
    assert!(preparations.iter().all(|&count| count == 0));
    FIRMWARE.with(|firmware| assert_eq!(firmware.borrow().startup_count, 0));
}

#[test]
fn shared_protocol_access_survives_an_incompatible_consumer_and_closes_after_callbacks() {
    reset(&[true, true, true]);
    let (result, preparations) = run_batch(&[1, 2], None);
    assert_eq!(result, Ok(()));
    assert_eq!(preparations, [1, 1]);
    FIRMWARE.with(|firmware| {
        let firmware = firmware.borrow();
        assert_eq!(firmware.opens, [boot::OpenProtocolAttributes::GetProtocol]);
        assert_eq!(firmware.closes, 1);
        assert_eq!(firmware.active_opens, 0);
    });
}

#[test]
fn preparation_failure_is_returned_even_when_firmware_reports_success() {
    reset(&[true, true, true]);
    let (result, preparations) = run_batch(&[1, 2], Some(2));
    assert_eq!(
        result,
        Err(ResidentProbeError::Allocation(Status::DEVICE_ERROR))
    );
    assert_eq!(preparations, [1, 1]);
}

#[test]
fn assembly_returns_zero_on_preparation_error_and_one_after_the_guest_probe() {
    let mut resources = LaunchResources {
        result: Err(ResidentProbeError::Allocation(Status::DEVICE_ERROR)),
        preparation_count: 0,
    };
    let mut launch = ResidentApLaunch {
        processor_number: 1,
        resources: &mut resources,
    };
    let argument = (&mut launch as *mut ResidentApLaunch<'_>).cast();
    assert_eq!(unsafe { matrixhv_ap_launch_asm(argument) }, 0);
    launch.resources.result = Ok(0x1000);
    assert_eq!(unsafe { matrixhv_ap_launch_asm(argument) }, 1);
    assert_eq!(launch.resources.preparation_count, 2);
}

#[test]
fn duplicate_launches_are_rejected_before_any_ap_starts() {
    reset(&[true, true, true]);
    assert_rejected(&[1, 1, 2]);
}

#[test]
fn missing_launch_is_rejected_before_partial_startup() {
    reset(&[true, true, true]);
    assert_rejected(&[1]);
    assert_rejected(&[]);
}

#[test]
fn bsp_disabled_and_out_of_range_launches_are_rejected() {
    reset(&[true, true, false, true]);
    assert_rejected(&[0, 1, 3]);
    assert_rejected(&[1, 2, 3]);
    assert_rejected(&[1, 3, 4]);
}

#[test]
fn an_exact_batch_can_be_unordered_and_skip_disabled_processors() {
    reset(&[true, true, false, true]);
    let (result, preparations) = run_batch(&[3, 1], None);
    assert_eq!(result, Ok(()));
    assert_eq!(preparations, [1, 1]);
}

#[test]
fn empty_batch_succeeds_only_when_no_ap_is_enabled() {
    reset(&[true, false, false]);
    assert_eq!(run_batch(&[], None), (Ok(()), Vec::new()));
    FIRMWARE.with(|firmware| assert_eq!(firmware.borrow().startup_count, 0));
}

#[test]
fn processor_query_errors_do_not_start_any_ap() {
    reset(&[true, true, true]);
    FIRMWARE.with(|firmware| firmware.borrow_mut().count_error = Some(Status::DEVICE_ERROR));
    assert_eq!(
        run_batch(&[1, 2], None).0,
        Err(ResidentProbeError::Allocation(Status::DEVICE_ERROR))
    );
    FIRMWARE.with(|firmware| assert_eq!(firmware.borrow().startup_count, 0));
    reset(&[true, true, true]);
    FIRMWARE.with(|firmware| firmware.borrow_mut().info_error = Some(2));
    assert_eq!(
        run_batch(&[1, 2], None).0,
        Err(ResidentProbeError::Allocation(Status::DEVICE_ERROR))
    );
    FIRMWARE.with(|firmware| assert_eq!(firmware.borrow().startup_count, 0));
}

#[test]
fn skipped_callbacks_cannot_produce_success() {
    reset(&[true, true, true]);
    FIRMWARE.with(|firmware| firmware.borrow_mut().callbacks = Some(vec![1]));
    let (result, preparations) = run_batch(&[1, 2], None);
    assert_eq!(
        result,
        Err(ResidentProbeError::Allocation(Status::DEVICE_ERROR))
    );
    assert_eq!(preparations, [1, 0]);
}

#[test]
fn duplicate_callbacks_do_not_reuse_mutable_launch_resources() {
    reset(&[true, true, true]);
    FIRMWARE.with(|firmware| firmware.borrow_mut().callbacks = Some(vec![1, 1, 2]));
    let (result, preparations) = run_batch(&[1, 2], None);
    assert_eq!(
        result,
        Err(ResidentProbeError::Allocation(Status::DEVICE_ERROR))
    );
    assert_eq!(preparations, [1, 1]);
}

#[test]
fn unlisted_callbacks_and_who_am_i_errors_fail_the_batch() {
    reset(&[true, true, true]);
    FIRMWARE.with(|firmware| firmware.borrow_mut().callbacks = Some(vec![1, 2, 3]));
    assert_eq!(
        run_batch(&[1, 2], None).0,
        Err(ResidentProbeError::Allocation(Status::DEVICE_ERROR))
    );
    reset(&[true, true, true]);
    FIRMWARE.with(|firmware| firmware.borrow_mut().who_error = Some(2));
    let (result, preparations) = run_batch(&[1, 2], None);
    assert_eq!(
        result,
        Err(ResidentProbeError::Allocation(Status::DEVICE_ERROR))
    );
    assert_eq!(preparations, [1, 0]);
}

#[test]
fn firmware_startup_errors_are_propagated() {
    reset(&[true, true, true]);
    FIRMWARE.with(|firmware| firmware.borrow_mut().startup_error = Some(Status::TIMEOUT));
    assert_eq!(
        run_batch(&[1, 2], None).0,
        Err(ResidentProbeError::Allocation(Status::TIMEOUT))
    );
}
