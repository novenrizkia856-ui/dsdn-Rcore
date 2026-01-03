use std::{fs, env};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: wat2wasm <input.wat> <output.wasm>");
        return;
    }

    let wat = fs::read_to_string(&args[1]).expect("read input");
    let wasm = wat::parse_str(&wat).expect("compile wat");

    fs::write(&args[2], wasm).expect("write output");

    println!("Compiled {} -> {}", args[1], args[2]);
}
