// Pull in the rvos-rt crate so _start gets linked
extern crate rvos_rt;

fn main() {
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

    println!("--- done ---");
}
