


use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;


pub struct dpi_detection{
    udp_str_rule : Vec<&'static str>,
    tcp_str_rule : Vec<&'static str>,
}
impl dpi_detection{
    fn new() -> Self{
        dpi_detection{
            udp_str_rule : vec![&":info_hash20:"],
            tcp_str_rule : vec![&"BitTorrent protocol"]
        }
    }
    pub fn udp_is_ban_pkt(&self ,binary_data: &[u8]) -> bool {
 
        contains_any(binary_data, &self.udp_str_rule)
    }

   pub fn tcp_is_ban_pkt(&self ,binary_data: &[u8])  -> bool{
        contains_any(binary_data, &self.tcp_str_rule)
    }

 
}


fn contains_any(data: &[u8], targets: &[&str]) -> bool {
    for &target in targets {
        let target_bytes = target.as_bytes();
        if data.windows(target_bytes.len()).any(|window| window == target_bytes) {
            return true;
        }
    }
    false
}


lazy_static!{
       pub static ref DPI: Arc<Mutex<dpi_detection>>= Arc::new(Mutex::new(dpi_detection::new()));
}

pub fn ban_udp_data(data:&[u8],) -> bool {
    let checker = DPI.lock().unwrap();
    checker.udp_is_ban_pkt(&data)
}


pub fn ban_tcp_data(data: &Vec<u8>) -> bool {
    let checker = DPI.lock().unwrap();
    checker.tcp_is_ban_pkt(&data)
}

