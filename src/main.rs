use clap::Parser;
use dlt_convert::{parse_message, strip_null, Message};
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

        let text = String::from_utf8_lossy(strip_null(payload));

        println!(
            "{} [{}]: {:?}",
            storage_header.timestamp.naive_local(),
            storage_header.ecu,
            text
        );

        data = rest;
    }
}
