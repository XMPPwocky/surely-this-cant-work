pub mod address;
pub mod frame;
pub mod heap;
pub mod page_table;

pub fn init() {
    heap::init();
    frame::init();
}
