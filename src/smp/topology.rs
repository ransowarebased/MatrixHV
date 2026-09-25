use uefi::Status;
use uefi::boot;
use uefi::proto::pi::mp::MpServices;

use crate::runtime::logger;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TopologyReport {
    pub(crate) total_processors: usize,
    pub(crate) enabled_processors: usize,
    pub(crate) current_processor: usize,
    pub(crate) bsp_processor: usize,
    pub(crate) first_enabled_ap: Option<usize>,
}

pub(crate) fn enumerate() -> Result<TopologyReport, Status> {
    let handle = boot::get_handle_for_protocol::<MpServices>().map_err(|error| error.status())?;
    let mp = boot::open_protocol_exclusive::<MpServices>(handle).map_err(|error| error.status())?;
    let count = mp
        .get_number_of_processors()
        .map_err(|error| error.status())?;
    let current_processor = mp.who_am_i().map_err(|error| error.status())?;

    let mut bsp_processor = None;
    let mut first_enabled_ap = None;

    for processor_number in 0..count.total {
        let info = mp
            .get_processor_info(processor_number)
            .map_err(|error| error.status())?;
        logger::info(format_args!(
            "smp processor={} id={:#x} bsp={} enabled={} healthy={} package={} core={} thread={}",
            processor_number,
            info.processor_id,
            info.is_bsp(),
            info.is_enabled(),
            info.is_healthy(),
            info.location.package,
            info.location.core,
            info.location.thread
        ));

        if info.is_bsp() {
            if bsp_processor.replace(processor_number).is_some() {
                return Err(Status::DEVICE_ERROR);
            }
        } else if info.is_enabled() && first_enabled_ap.is_none() {
            first_enabled_ap = Some(processor_number);
        }
    }

    let bsp_processor = bsp_processor.ok_or(Status::DEVICE_ERROR)?;
    Ok(TopologyReport {
        total_processors: count.total,
        enabled_processors: count.enabled,
        current_processor,
        bsp_processor,
        first_enabled_ap,
    })
}
