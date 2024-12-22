use clap::Parser;
use dlt_convert::{parse_message, strip_null, ExtendedHeader, LogTypeInfo, Message, MessageInfo};
use std::{io::Read, path::PathBuf};

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(short, long)]
    input: PathBuf,
}

fn main() {
    let args = Args::parse();

    let mut file = std::fs::File::open(args.input).unwrap();

    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();

    let mut data = data.as_slice();

    while !data.is_empty() {
        let (
            Message {
                storage_header,
                standard_header,
                extended_header,
                payload,
            },
            rest,
        ) = parse_message(data).unwrap();

        data = rest;

        if let Some(ExtendedHeader {
            message_type: MessageInfo::Log { level },
            apid,
            ctid,
            ..
        }) = extended_header
        {
            let text = String::from_utf8_lossy(strip_null(payload));

            println!(
                "{} [{:>4}] [{:>4}] [{}] [{}]: {}",
                storage_header.timestamp.naive_local(),
                ctid,
                apid,
                storage_header.ecu,
                level.as_str(),
                text
            );
        }
    }
}
