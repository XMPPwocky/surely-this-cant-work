// Pull in the rvos-rt crate so _start gets linked
extern crate rvos_rt;

fn main() {
    // Print command-line arguments
    let args: Vec<String> = std::env::args().collect();
    println!("args({}):{}", args.len(), args.iter().map(|a| format!(" \"{}\"", a)).collect::<String>());

    println!("--- test ---");

    // 1. Create file
    print!("1. create: ");
    match std::fs::write("/tmp/a.txt", "hello") {
        Ok(()) => println!("ok"),
        Err(e) => println!("ERR: {}", e),
    }

    // 2. Read it back
    print!("2. read: ");
    match std::fs::read_to_string("/tmp/a.txt") {
        Ok(s) => println!("ok (\"{}\")", s),
        Err(e) => println!("ERR: {}", e),
    }

    // 3. Append to file (seek to end, then write)
    print!("3. append: ");
    {
        use std::io::{Write, Seek, SeekFrom};
        match std::fs::OpenOptions::new().write(true).open("/tmp/a.txt") {
            Ok(mut f) => {
                match f.seek(SeekFrom::Start(5)) {
                    Ok(_) => {}
                    Err(e) => { println!("seek ERR: {}", e); return; }
                }
                match f.write(b" world") {
                    Ok(n) => println!("ok (wrote {})", n),
                    Err(e) => println!("write ERR: {}", e),
                }
            }
            Err(e) => println!("open ERR: {}", e),
        }
    }

    // 4. Read again (should be "hello world")
    print!("4. read: ");
    match std::fs::read_to_string("/tmp/a.txt") {
        Ok(s) => println!("ok (\"{}\")", s),
        Err(e) => println!("ERR: {}", e),
    }

    // 5. Delete
    print!("5. delete: ");
    match std::fs::remove_file("/tmp/a.txt") {
        Ok(()) => println!("ok"),
        Err(e) => println!("ERR: {}", e),
    }

    // 6. Verify deleted
    print!("6. exists: ");
    match std::fs::exists("/tmp/a.txt") {
        Ok(true) => println!("ERR: still exists"),
        Ok(false) => println!("ok (gone)"),
        Err(e) => println!("ERR: {}", e),
    }

    // 7. Stat
    print!("7. stat: ");
    match std::fs::metadata("/tmp") {
        Ok(m) => {
            let kind = if m.is_dir() { "dir" } else { "file" };
            println!("ok ({}, {} bytes)", kind, m.len());
        }
        Err(e) => println!("ERR: {}", e),
    }

    // 8. Readdir
    print!("8. readdir: ");
    std::fs::write("/tmp/x.txt", "abc").ok();
    std::fs::write("/tmp/y.txt", "defgh").ok();
    match std::fs::read_dir("/tmp") {
        Ok(entries) => {
            let names: Vec<_> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            println!("ok ({} entries: {})", names.len(), names.join(", "));
        }
        Err(e) => println!("ERR: {}", e),
    }
    // Clean up
    std::fs::remove_file("/tmp/x.txt").ok();
    std::fs::remove_file("/tmp/y.txt").ok();

    println!("--- done ---");
}
