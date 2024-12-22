use chrono::{DateTime, Utc};
use std::{borrow::Cow, io::Read};

#[derive(Debug)]
struct Message<'a> {
    storage_header: StorageHeader<'a>,
    standard_header: StandardHeader,
    extended_header: Option<ExtendedHeader<'a>>,
    payload: &'a [u8],
}

fn parse_message(data: &[u8]) -> Option<(Message, &[u8])> {
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

    let (unknown, data) = data.split_at(6);

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
struct StorageHeader<'a> {
    pattern: &'a [u8; 4],
    timestamp: DateTime<Utc>,
    ecu: Cow<'a, str>,
}

fn parse_storage_header(data: &[u8]) -> Option<(StorageHeader, &[u8])> {
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
struct StandardHeader {
    htyp: u8,
    mcnt: u8,
    len: u16,
}

fn parse_standard_header(data: &[u8]) -> Option<(StandardHeader, &[u8])> {
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

fn parse_extensions(
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
struct ExtendedHeader<'a> {
    msin: u8,
    noar: u8,
    apid: Cow<'a, str>,
    ctid: Cow<'a, str>,
}

fn parse_extended_header(data: &[u8]) -> Option<(ExtendedHeader, &[u8])> {
    let ([msin], data) = data.split_first_chunk::<1>()?;
    let ([noar], data) = data.split_first_chunk::<1>()?;
    let (apid_bytes, data) = data.split_first_chunk::<4>()?;
    let (ctid_bytes, data) = data.split_first_chunk::<4>()?;

    let apid = String::from_utf8_lossy(strip_null(apid_bytes));
    let ctid = String::from_utf8_lossy(strip_null(ctid_bytes));

    Some((
        ExtendedHeader {
            msin: *msin,
            noar: *noar,
            apid,
            ctid,
        },
        data,
    ))
}

fn strip_null(slice: &[u8]) -> &[u8] {
    for i in (0..slice.len()).rev() {
        if slice[i] != 0x0 {
            return &slice[..=i];
        }
    }

    slice
}

fn main() {
    let mut file = std::fs::File::open("data.dlt").unwrap();

    let mut data = Vec::with_capacity(1024 * 1024 * 1024);

    file.read_to_end(&mut data).unwrap();

    let mut data = data.as_slice();

    while !data.is_empty() {
        println!();
        let (
            Message {
                storage_header,
                standard_header,
                extended_header,
                payload,
            },
            rest,
        ) = parse_message(data).unwrap();

        let text = String::from_utf8_lossy(strip_null(payload));

        println!(
            "{:?}\n{:?}\n{:?}\n{:?}",
            storage_header, standard_header, extended_header, text
        );

        data = rest;

    }
}
