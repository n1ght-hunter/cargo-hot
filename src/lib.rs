pub mod hotpatch;
pub mod link;
pub mod rustc;
pub mod server;

pub type Result<T> = anyhow::Result<T>;

use subsecond::JumpTable;

use std::io::{Read, Write};
use std::net;
use std::thread;
use std::time::Duration;

/// Injects the hotpatch server into the current process.
/// This function will spawn a thread that connects to the hotpatch server and applies patches as they are received.
pub fn inject() {
    let aslr_reference = subsecond::aslr_reference();

    // TODO: Wasm support
    thread::spawn(move || {
        loop {
            if let Err(error) = run(aslr_reference) {
                tracing::error!("connection lost: {error}");
            }

            thread::sleep(Duration::from_secs(1));
        }
    });
}

fn run(aslr_reference: usize) -> Result<()> {
    let mut server = net::TcpStream::connect("127.0.0.1:1100")?;

    server.write_all(&aslr_reference.to_be_bytes())?;
    server.flush()?;

    let mut size = [0; std::mem::size_of::<usize>()];
    let mut buffer = Vec::new();

    loop {
        // Read the size of the patch   
        server.read_exact(&mut size)?;

        let n = usize::from_be_bytes(size);
        buffer.resize(n, 0);

        server.read_exact(&mut buffer[..n])?;

        // Deserialize the patch
        let patch: JumpTable = bincode::serde::decode_from_slice(&buffer, bincode::config::standard())?.0;

        unsafe {
            subsecond::apply_patch(patch)?;
        }
    }
}
