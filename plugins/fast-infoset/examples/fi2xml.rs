//! Decode a Fast Infoset file to XML (interop tests): fi2xml <in.fi> [chunk-size]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data = std::fs::read(&args[1]).expect("read");
    let chunk: usize = args.get(2).and_then(|c| c.parse().ok()).unwrap_or(1 << 16);
    let mut d = fast_infoset::fi::Decoder::new();
    let mut out = String::new();
    for c in data.chunks(chunk) {
        match d.push(c) {
            Ok(s) => out.push_str(&s),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        }
    }
    match d.finish() {
        Ok(s) => out.push_str(&s),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    }
    print!("{out}");
}
