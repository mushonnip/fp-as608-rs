use byteorder::{BigEndian, ReadBytesExt};
use serialport::{self, SerialPort};
use std::io::{self, Read, Write};
use std::time::Duration;
use std::vec::Vec;

const STARTCODE: u16 = 0xEF01;
const COMMANDPACKET: u8 = 0x1;
const ACKPACKET: u8 = 0x7;

const VERIFYPASSWORD: u8 = 0x13;
const TEMPLATEREAD: u8 = 0x1F;
const READSYSPARAM: u8 = 0x0F;

const OK: u8 = 0x0;

pub struct Device {
    uart: Box<dyn SerialPort>,
    templates: Vec<usize>,
    status_register: Option<u16>,
    system_id: Option<u16>,
    library_size: Option<u16>,
    security_level: Option<u16>,
    address: Vec<u8>,
    data_packet_size: Option<u16>,
    baudrate: Option<u16>,
    password: Vec<u8>,
}

impl Device {
    pub fn new(address: Vec<u8>, password: Vec<u8>, uart: Box<dyn SerialPort>) -> Self {
        let mut device = Self {
            uart,
            address,
            password,
            templates: vec![],
            status_register: None,
            system_id: None,
            library_size: None,
            security_level: None,
            data_packet_size: None,
            baudrate: None,
        };

        if !device.verify_password() {
            panic!("Failed to find sensor, check wiring!");
        }

        if device.read_sysparam().is_err() {
            panic!("Failed to read system parameters!");
        }

        device
    }

    pub fn verify_password(&mut self) -> bool {
        let packet: Vec<u8> = std::iter::once(VERIFYPASSWORD)
            .chain(self.password.iter().cloned())
            .collect();

        if let Err(e) = self.send_packet(&packet) {
            eprintln!("Failed to send the packet: {}", e);
            return false;
        }

        let response = self.get_packet(12).unwrap_or_else(|_| vec![0; 12]);

        response[0] == OK
    }

    pub fn send_packet(&mut self, data: &[u8]) -> io::Result<()> {
        let mut packet = vec![(STARTCODE >> 8) as u8, (STARTCODE & 0xFF) as u8];

        packet.extend_from_slice(&self.address);
        packet.push(COMMANDPACKET);

        // Calculate and add the length (data length + 2 bytes for checksum)
        let length = data.len() + 2;
        packet.push((length >> 8) as u8);
        packet.push((length & 0xFF) as u8);

        packet.extend_from_slice(data);

        // Calculate and append the checksum (sum of all bytes starting from index 6)
        let checksum: u16 = packet[6..].iter().map(|&byte| byte as u16).sum();
        packet.push((checksum >> 8) as u8);
        packet.push((checksum & 0xFF) as u8);

        self.print_debug("send_packet length:", packet.len(), "bytes");
        self.print_debug("send_packet data:", &packet, "hex");

        self.uart.write_all(&packet)?;

        Ok(())
    }

    pub fn get_packet(&mut self, expected: usize) -> io::Result<Vec<u8>> {
        let mut res = vec![0u8; expected];

        self.uart.read_exact(&mut res)?;

        self.print_debug("_get_packet received data:", &res, "hex");

        if res.len() != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to read data from sensor",
            ));
        }

        // Unpack the first two bytes as the start code
        let start = (&res[0..2]).read_u16::<BigEndian>().unwrap();
        if start != STARTCODE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Incorrect packet data",
            ));
        }

        // Unpack the next 4 bytes as the address
        let addr = res[2..6].to_vec();
        if addr != self.address {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Incorrect address",
            ));
        }

        // Unpack the packet type and length from bytes 6 to 8
        let packet_type = res[6];
        let length = (&res[7..9]).read_u16::<BigEndian>().unwrap() as usize;

        if packet_type != ACKPACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Incorrect packet data",
            ));
        }

        let reply = res[9..9 + (length - 2)].to_vec();

        self.print_debug("_get_packet reply:", &reply, "hex");

        Ok(reply)
    }

    pub fn read_templates(&mut self) -> io::Result<u8> {
        self.templates = Vec::new();
        self.read_sysparam()?;

        let mut temp_r = vec![0u8; 44];

        let total_pages = match self.library_size {
            Some(size) => ((size as f64) / 256.0).ceil() as usize,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "library_size is not set",
                ))
            }
        };

        for j in 0..total_pages {
            let read_packet = vec![TEMPLATEREAD, j as u8];
            self.send_packet(&read_packet)?;

            let r = self.get_packet(44)?;

            if r[0] == OK {
                for i in 0..32 {
                    let byte = r[i + 1];
                    for bit in 0..8 {
                        if byte & (1 << bit) != 0 {
                            self.templates.push((i * 8) + bit + (j * 256));
                        }
                    }
                }
                temp_r.clone_from_slice(&r);
            } else {
                break;
            }
        }

        Ok(temp_r[0])
    }

    pub fn read_sysparam(&mut self) -> io::Result<u8> {
        self.send_packet(&[READSYSPARAM])?;

        let r = self.get_packet(28)?;

        if r[0] != OK {
            return Err(io::Error::new(io::ErrorKind::Other, "Command failed."));
        }

        self.status_register = Some((&r[1..3]).read_u16::<BigEndian>()?);
        self.system_id = Some((&r[3..5]).read_u16::<BigEndian>()?);
        self.library_size = Some((&r[5..7]).read_u16::<BigEndian>()?);
        self.security_level = Some((&r[7..9]).read_u16::<BigEndian>()?);
        self.address = r[9..13].to_vec();
        self.data_packet_size = Some((&r[13..15]).read_u16::<BigEndian>()?);
        self.baudrate = Some((&r[15..17]).read_u16::<BigEndian>()?);

        Ok(r[0])
    }

    fn print_debug(&self, message: &str, data: impl std::fmt::Debug, data_type: &str) {
        if data_type == "hex" {
            println!("{}: {:X?}", message, data);
        } else {
            println!("{}: {:?}", message, data);
        }
    }
}

fn main() -> io::Result<()> {
    let port_name = "/dev/ttyS3";
    let baud_rate = 57600;

    let uart = serialport::new(port_name, baud_rate)
        .timeout(Duration::from_millis(100))
        .open()
        .expect("Failed to open serial port");

    let address = vec![0xFF; 4];
    let password = vec![0; 4];
    let mut device = Device::new(address, password, uart);

    let data = vec![TEMPLATEREAD];

    device.send_packet(&data)?;

    Ok(())
}
