use chrono::{DateTime, Utc};
use std::borrow::Cow;

#[derive(Debug)]
pub struct Message<'a> {
    pub storage_header: StorageHeader<'a>,
    pub standard_header: StandardHeader,
    pub extended_header: Option<ExtendedHeader<'a>>,
    pub payload: &'a [u8],
}

pub fn parse_message(data: &[u8]) -> Option<(Message, &[u8])> {
    let start = data;

    let (storage_header, data) = parse_storage_header(data)?;

    if storage_header.pattern != &[0x44, 0x4c, 0x54, 0x01] {
        return None;
    }

    let (standard_header, data) = parse_standard_header(data)?;

    let msb_first = standard_header.htyp & 0x02 != 0;
    if msb_first {
        return None;
    }

    let with_ecu_id = standard_header.htyp & 0x04 != 0;
    let with_session_id = standard_header.htyp & 0x08 != 0;
    let with_timestamp = standard_header.htyp & 0x10 != 0;

    let (_, data) = parse_extensions(with_ecu_id, with_session_id, with_timestamp)(data)?;

    let with_extended_header = standard_header.htyp & 0x01 != 0;

    let (extended_header, data) = if with_extended_header {
        parse_extended_header(data).map(|(it, data)| (Some(it), data))?
    } else {
        (None, data)
    };

    let (_, data) = data.split_at(6);

    let parsed_bytes = data.as_ptr() as usize - start.as_ptr() as usize;

    let rest_bytes = standard_header.len as usize - (parsed_bytes) + 16;

    let (payload, data) = data.split_at(rest_bytes);

    Some((
        Message {
            standard_header,
            storage_header,
            extended_header,
            payload,
        },
        data,
    ))
}

#[derive(Debug)]
pub struct StorageHeader<'a> {
    pub pattern: &'a [u8; 4],
    pub timestamp: DateTime<Utc>,
    pub ecu: Cow<'a, str>,
}

pub fn parse_storage_header(data: &[u8]) -> Option<(StorageHeader, &[u8])> {
    let (pattern_bytes, data) = data.split_first_chunk::<4>()?;
    let (seconds_bytes, data) = data.split_first_chunk::<4>()?;
    let (microseconds_bytes, data) = data.split_first_chunk::<4>()?;
    let (ecu_bytes, data) = data.split_first_chunk::<4>()?;

    let seconds = u32::from_le_bytes(*seconds_bytes);
    let microseconds = i32::from_le_bytes(*microseconds_bytes);

    let timestamp = DateTime::from_timestamp(
        (seconds + microseconds as u32 / 1000000) as i64,
        ((microseconds % 1000000) * 1000) as u32,
    )
    .unwrap();

    let ecu = String::from_utf8_lossy(strip_null(ecu_bytes));

    Some((
        StorageHeader {
            pattern: pattern_bytes,
            timestamp,
            ecu,
        },
        data,
    ))
}

#[derive(Debug)]
pub struct StandardHeader {
    pub htyp: u8,
    pub mcnt: u8,
    pub len: u16,
}

pub fn parse_standard_header(data: &[u8]) -> Option<(StandardHeader, &[u8])> {
    let ([htyp], data) = data.split_first_chunk::<1>()?;
    let ([mcnt], data) = data.split_first_chunk::<1>()?;
    let (len_bytes, data) = data.split_first_chunk::<2>()?;

    let len = u16::from_be_bytes(*len_bytes);

    Some((
        StandardHeader {
            htyp: *htyp,
            mcnt: *mcnt,
            len,
        },
        data,
    ))
}

pub fn parse_extensions(
    ecu_id: bool,
    session_id: bool,
    timestamp: bool,
) -> impl Fn(&[u8]) -> Option<((), &[u8])> {
    return move |data: &[u8]| {
        let mut bytes = 0;

        if ecu_id {
            bytes += 4;
        }

        if session_id {
            bytes += 4;
        }

        if timestamp {
            bytes += 4;
        }

        Some(((), &data[bytes..]))
    };
}

#[derive(Debug)]
pub struct ExtendedHeader<'a> {
    pub message_type: MessageInfo,
    pub noar: u8,
    pub apid: Cow<'a, str>,
    pub ctid: Cow<'a, str>,
}

#[derive(Debug)]
pub enum MessageInfo {
    Log { level: LogTypeInfo },
    AppTrace,
    NwTrace,
    Control,
    Reserved,
}

impl MessageInfo {
    fn from_raw(ty: u8, data: u8) -> Self {
        match ty {
            0x0 => Self::Log {
                level: LogTypeInfo::from_raw(data),
            },
            0x1 => Self::AppTrace,
            0x2 => Self::NwTrace,
            0x3 => Self::Control,
            _ => Self::Reserved,
        }
    }
}

#[derive(Debug)]
pub enum LogTypeInfo {
    Fatal,
    Error,
    Warn,
    Info,
    Debug,
    Verbose,
    Reserved,
}

impl LogTypeInfo {
    fn from_raw(data: u8) -> Self {
        match data {
            0x1 => Self::Fatal,
            0x2 => Self::Error,
            0x3 => Self::Warn,
            0x4 => Self::Info,
            0x5 => Self::Debug,
            0x6 => Self::Verbose,
            _ => Self::Reserved,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            LogTypeInfo::Fatal => "fatal",
            LogTypeInfo::Error => "error",
            LogTypeInfo::Warn => "warn",
            LogTypeInfo::Info => "info",
            LogTypeInfo::Debug => "debug",
            LogTypeInfo::Verbose => "verbose",
            LogTypeInfo::Reserved => "reserved",
        }
    }
}

pub fn parse_extended_header(data: &[u8]) -> Option<(ExtendedHeader, &[u8])> {
    let ([msin], data) = data.split_first_chunk::<1>()?;
    let ([noar], data) = data.split_first_chunk::<1>()?;
    let (apid_bytes, data) = data.split_first_chunk::<4>()?;
    let (ctid_bytes, data) = data.split_first_chunk::<4>()?;

    let apid = String::from_utf8_lossy(strip_null(apid_bytes));
    let ctid = String::from_utf8_lossy(strip_null(ctid_bytes));

    let message_type = MessageInfo::from_raw((msin >> 1) & 0b111, (msin >> 4) & 0b1111);
    let verbose = msin & 0b1;

    Some((
        ExtendedHeader {
            message_type,
            noar: *noar,
            apid,
            ctid,
        },
        data,
    ))
}

pub fn strip_null(slice: &[u8]) -> &[u8] {
    for i in (0..slice.len()).rev() {
        if slice[i] != 0x0 {
            return &slice[..=i];
        }
    }

    slice
}
