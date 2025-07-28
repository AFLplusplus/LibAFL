use core::fmt::Debug;

use libafl_bolts::{Error, hash_64_fast};
use libipt::{
    block::BlockDecoder, enc_dec_builder::EncoderDecoderBuilder, error::PtErrorCode,
    event::EventType, image::Image, status::Status,
};
use num_traits::SaturatingAdd;

use crate::error_from_pt_error;

#[derive(Debug)]
pub(crate) struct Decoder<'a, T> {
    decoder: BlockDecoder<'a>,
    status: Status,
    previous_block_end_ip: u64,
    vmx_non_root: Option<bool>,
    exclude_hv: bool,
    trace_skip: u64,
    map_ptr: *mut T,
    map_len: usize,
}

impl<'a, T> Decoder<'a, T>
where
    T: SaturatingAdd + From<u8> + Debug,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        decoder_builder: EncoderDecoderBuilder<BlockDecoder<'static>>,
        exclude_hv: bool,
        image: &'a mut Image,
        trace_ptr: *mut u8,
        trace_len: usize,
        trace_skip: u64,
        map_ptr: *mut T,
        map_len: usize,
    ) -> Result<Self, Error> {
        let builder = unsafe { decoder_builder.buffer_from_raw(trace_ptr, trace_len) };

        let mut decoder = builder.build().map_err(error_from_pt_error)?;
        decoder
            .set_image(Some(image))
            .map_err(error_from_pt_error)?;
        let status = Status::empty();

        Ok(Self {
            decoder,
            status,
            previous_block_end_ip: 0,
            vmx_non_root: None,
            exclude_hv,
            trace_skip,
            map_ptr,
            map_len,
        })
    }

    pub(crate) fn decode_traces_into_map(mut self) -> Result<u64, Error> {
        'sync: loop {
            match self.decoder.sync_forward() {
                Ok(status) => {
                    self.status = status;
                    match self.decode_and_resync_loop() {
                        Ok(()) if self.status.eos() => break 'sync,
                        Ok(()) => (),
                        Err(e) => log::warn!("{e:?}"),
                    }
                }
                Err(e) => {
                    if e.code() != PtErrorCode::Eos {
                        log::warn!("PT error in sync forward {e:?}");
                    }
                    break 'sync;
                }
            }
        }

        self.decoder.sync_backward().map_err(error_from_pt_error)?;
        self.decoder.sync_offset().map_err(error_from_pt_error)
    }

    fn decode_and_resync_loop(&mut self) -> Result<(), Error> {
        loop {
            match self.decode_blocks_loop() {
                Ok(()) if self.status.eos() => return Ok(()),
                Ok(()) | Err(_) => (),
            }

            match self.resync_loop() {
                Ok(()) if self.status.eos() => return Ok(()),
                Ok(()) => (),
                Err(e) => return Err(e),
            }
        }
    }

    fn resync_loop(&mut self) -> Result<(), Error>
    where
        T: SaturatingAdd + From<u8> + Debug,
    {
        loop {
            match self.decoder.resync() {
                Ok(s) => {
                    self.status = s;
                    if self.status.eos() {
                        return Ok(());
                    }

                    // If exclude_hv is set and we are in root VMX operation, continue resyncing
                    if self.exclude_hv || matches!(self.vmx_non_root, Some(true)) {
                        return Ok(());
                    }
                }
                Err(e) => match e.code() {
                    PtErrorCode::Eos => return Ok(()),
                    PtErrorCode::EventIgnored => self.handle_event()?,
                    _ => return Err(Error::illegal_state(format!("PT error in resync {e:?}"))),
                },
            }
        }
    }

    fn decode_blocks_loop(&mut self) -> Result<(), Error>
    where
        T: SaturatingAdd + From<u8> + Debug,
    {
        #[cfg(debug_assertions)]
        let mut trace_entry_iters: (u64, u64) = (0, 0);

        loop {
            #[cfg(debug_assertions)]
            {
                let offset = self.decoder.offset().map_err(error_from_pt_error)?;
                if trace_entry_iters.0 == offset {
                    trace_entry_iters.1 += 1;
                    if trace_entry_iters.1 > 1000 {
                        return Err(Error::illegal_state(format!(
                            "PT Decoder got stuck at trace offset {offset:x}.\
                            Make sure the decoder Image has the right content and offsets.",
                        )));
                    }
                } else {
                    trace_entry_iters = (offset, 0);
                }
            }

            while self.status.event_pending() {
                self.handle_event()?;
            }

            // If exclude_hv is set and we are in root VMX operation, bail out
            if self.exclude_hv && matches!(self.vmx_non_root, Some(false)) {
                return Ok(());
            }

            match self.decoder.decode_next() {
                Ok((b, s)) => {
                    self.status = s;
                    let offset = self.decoder.offset().map_err(error_from_pt_error)?;
                    if b.ninsn() > 0 && self.trace_skip < offset {
                        let id = hash_64_fast(self.previous_block_end_ip) ^ hash_64_fast(b.ip());
                        // SAFETY: the index is < map_len since the modulo operation is applied
                        unsafe {
                            let map_loc = self.map_ptr.add(id as usize % self.map_len);
                            *map_loc = (*map_loc).saturating_add(&1u8.into());
                        }
                        self.previous_block_end_ip = b.end_ip();
                    }

                    if self.status.eos() {
                        return Ok(());
                    }
                }
                Err(e) => {
                    if e.code() != PtErrorCode::Eos {
                        let offset = self.decoder.offset().map_err(error_from_pt_error)?;
                        log::info!(
                            "PT error in block next {e:?} trace offset {offset:x} last decoded block end {:x}",
                            self.previous_block_end_ip
                        );
                    }
                    return Err(error_from_pt_error(e));
                }
            }
        }
    }

    fn handle_event(&mut self) -> Result<(), Error> {
        match self.decoder.event() {
            Ok((event, s)) => {
                self.status = s;
                match event.event_type() {
                    EventType::Paging(p) => self.vmx_non_root = Some(p.non_root()),
                    EventType::AsyncPaging(p) => self.vmx_non_root = Some(p.non_root()),
                    _ => (),
                }
                Ok(())
            }
            Err(e) => Err(Error::illegal_state(format!("PT error in event {e:?}"))),
        }
    }
}
