// Pull in the rvos-rt crate so _start gets linked
extern crate rvos_rt;

fn main() {
    println!("Hello from rvOS std!");
    let v = vec![1, 2, 3, 4, 5];
    println!("Vec: {:?}", v);
    println!("Sum: {}", v.iter().sum::<i32>());
}
