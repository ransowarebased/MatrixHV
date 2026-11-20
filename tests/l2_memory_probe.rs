//! Post-boot validation against this process's own allocation only.
use matrixhv_sdk::memory::{Item, info_packet, invoke, packet, read_ranges};
use matrixhv_sdk::protocol::memory::{
    HEADER_BYTES, L2_KERNEL_ROOT_CAPABILITY, L2_MEMORY_CAPABILITY, WRITE, quad, word,
};

fn run(write_self: bool, kernel_root: bool) -> Result<(), String> {
    let mut info = info_packet()?;
    invoke(&mut info)?;
    if word(&info, 72) & L2_MEMORY_CAPABILITY == 0 {
        return Err("the resident core did not confirm the scoped L2 memory transport".into());
    }
    let cr3 = quad(&info, 48);
    if kernel_root {
        if word(&info, 72) & L2_KERNEL_ROOT_CAPABILITY == 0 {
            return Err(
                "resident core does not support automatic L2 kernel-root observations".into(),
            );
        }
        let root = quad(&info, 64);
        let syscall = quad(&info, 56);
        if root == 0 {
            return Err("no scoped L2 kernel root has been observed and validated yet".into());
        }
        if !info[HEADER_BYTES..]
            .chunks_exact(8)
            .any(|entry| u64::from_le_bytes(entry.try_into().unwrap()) == root)
        {
            return Err("primary kernel root is missing from scoped root history".into());
        }
        let bytes = read_ranges(root, &[(syscall, 16)])?;
        println!(
            "l2_kernel_mapping_read=passed root={root:#x} lstar={syscall:#x} bytes={} kernel_identity_validation=neo_required",
            bytes[0].len()
        );
    }
    let mut owned = vec![0_u8; 8192];
    for (index, byte) in owned.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    let address = owned.as_mut_ptr() as u64;
    let bytes = read_ranges(cr3, &[(address, owned.len())])?;
    if bytes[0] != owned {
        return Err("self-read did not match the owned allocation".into());
    }
    println!("l2_self_read=passed bytes={} cr3={cr3:#x}", owned.len());
    if write_self {
        let expected = vec![0xa7; owned.len()];
        let mut request = packet(
            WRITE,
            u64::from(std::process::id()),
            cr3,
            &[Item {
                address,
                bytes: expected.clone(),
            }],
        )?;
        invoke(&mut request)?;
        if word(&request, HEADER_BYTES + 16) != 0
            || word(&request, HEADER_BYTES + 20) as usize != expected.len()
            || owned != expected
        {
            return Err(
                "self-write failed or was partial; inspect the response before retrying".into(),
            );
        }
        let bytes = read_ranges(cr3, &[(address, owned.len())])?;
        if bytes[0] != expected {
            return Err("self-write readback did not match".into());
        }
        println!("l2_self_write=passed bytes={} readback=passed", owned.len());
    }
    Ok(())
}

fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments
        .iter()
        .any(|argument| !matches!(argument.as_str(), "--write-self" | "--kernel-root"))
    {
        eprintln!("usage: l2_memory_probe [--write-self] [--kernel-root]");
        std::process::exit(2);
    }
    if let Err(error) = run(
        arguments.iter().any(|argument| argument == "--write-self"),
        arguments.iter().any(|argument| argument == "--kernel-root"),
    ) {
        eprintln!("l2_memory_probe: {error}");
        std::process::exit(1);
    }
}
