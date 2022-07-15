#[cfg(not(target_os = "linux"))]
compile_error!("this program only works on Linux");

mod disable_system_pong;

use anyhow::{bail, Context, Result};
use disable_system_pong::DisableSystemPong;
use libc::{socket, AF_INET, AF_INET6, IPPROTO_ICMP, IPPROTO_ICMPV6, SOCK_RAW};
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags};
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime};

// It's not really a UdpSocket, but there's no IcmpSocket in std and the interface is close enough. :)
type IcmpSocket = UdpSocket;

fn open_icmp_socket(ipv6: bool) -> Result<IcmpSocket> {
    let sock = unsafe {
        if ipv6 {
            socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)
        } else {
            socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        }
    };

    if sock == -1 {
        let err = std::io::Error::last_os_error();
        if err.kind() == ErrorKind::PermissionDenied {
            bail!(
                "unable to create a raw {} ICMP socket\n\n\
                Re-run this program as root or with cap_net_raw capabilities \
                (using `setcap cap_net_raw=ep {:?}`).",
                if ipv6 { "IPv6" } else { "IPv4" },
                std::env::args_os().next().unwrap()
            );
        } else {
            return Err(err).context("creating raw ICMP socket failed");
        }
    }

    Ok(unsafe { IcmpSocket::from_raw_fd(sock) })
}

fn main() -> Result<()> {
    let (stop_read, stop_write) = UnixStream::pair()?;
    for &signal in signal_hook::consts::TERM_SIGNALS {
        signal_hook::low_level::pipe::register(signal, stop_write.try_clone()?)?;
    }

    let mut disable_pong = DisableSystemPong::activate()?;

    let sock4 = open_icmp_socket(false)?;
    let sock6 = open_icmp_socket(true)?;

    let mut buf = [0; 1024];

    loop {
        let mut fds = [
            PollFd::new(sock4.as_raw_fd(), PollFlags::POLLIN),
            PollFd::new(sock6.as_raw_fd(), PollFlags::POLLIN),
            PollFd::new(stop_read.as_raw_fd(), PollFlags::POLLIN),
        ];

        match poll(&mut fds, -1) {
            Ok(_) => {}
            Err(e) if e == Errno::EINTR => {}
            Err(e) => return Err(e).context("polling the sockets failed"),
        }

        if fds[2].revents().unwrap().contains(PollFlags::POLLIN) {
            // Got signal. Exiting.
            break;
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        for (ipv6, fd, sock) in [(false, fds[0], &sock4), (true, fds[1], &sock6)] {
            if fd.revents().unwrap().contains(PollFlags::POLLIN) {
                let ip_header_len = if ipv6 { 0 } else { 20 };

                let (len, addr) = sock.recv_from(&mut buf).context("recv_from failed")?;

                if len < ip_header_len + 8 {
                    continue;
                }

                let icmp = &mut buf[ip_header_len..len];

                let (req_type, reply_type) = if ipv6 { (128, 129) } else { (8, 0) };

                if icmp[0..2] != [req_type, 0] {
                    // Not a ping packet.
                    continue;
                }

                let id = u16::from_be_bytes(icmp[4..6].try_into().unwrap());
                let seq = u16::from_be_bytes(icmp[6..8].try_into().unwrap());

                let parsed = parse_payload(now, &icmp[8..]);

                // Transform ping packet into pong packet
                icmp[0] = reply_type;
                icmp[1] = 0;

                // Change the payload to get better ping times.
                if let Some((encoding, timestamp)) = parsed {
                    let new_timestamp =
                        if timestamp < now && (now - timestamp) < Duration::from_millis(500) {
                            // Looks like the sender is ntp-synchronized.
                            // Calculate the arrival time, minus five milliseconds to make it somewhat realistic.
                            now + (now - timestamp) - Duration::from_millis(5)
                        } else {
                            // The sender's clock isn't the same as ours.
                            // Just decrease the ping time by 50ms.
                            timestamp + Duration::from_millis(50)
                        };
                    write_timestamp_into_payload(&mut icmp[8..], encoding, new_timestamp);
                } else {
                    print!("unknown encoding for ping payload: ");
                    for &b in &icmp[8..] {
                        print!("{:02x} ", b);
                    }
                    println!();
                }

                // Update the checksum
                let checksum = checksum(&icmp[4..]);
                icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

                // Pong!
                sock.send_to(icmp, addr).context("send_to failed")?;

                println!(
                    "{}: {} bytes, id={}, seq={}, encoding={}",
                    addr.ip(),
                    icmp.len(),
                    id,
                    seq,
                    match parsed {
                        Some((PayloadEncoding::Le64, _)) => "le64",
                        Some((PayloadEncoding::Be64, _)) => "be64",
                        Some((PayloadEncoding::Le32, _)) => "le32",
                        Some((PayloadEncoding::Be32, _)) => "be32",
                        None => "unknown",
                    }
                );
            }
        }
    }

    disable_pong.deactivate()?;

    Ok(())
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum PayloadEncoding {
    Le64,
    Be64,
    Le32,
    Be32,
}

fn parse_payload(now: Duration, payload: &[u8]) -> Option<(PayloadEncoding, Duration)> {
    if payload.len() >= 16 {
        let sec = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        if sec.abs_diff(now.as_secs()) < 1000 && payload[12..16] == [0; 4] {
            let usec = u32::from_le_bytes(payload[8..12].try_into().unwrap());
            let nsec = usec.checked_mul(1000)?;
            return Some((PayloadEncoding::Le64, Duration::new(sec, nsec)));
        }
        let sec = u64::from_be_bytes(payload[0..8].try_into().unwrap());
        if sec.abs_diff(now.as_secs()) < 1000 && payload[8..12] == [0; 4] {
            let usec = u32::from_be_bytes(payload[12..16].try_into().unwrap());
            let nsec = usec.checked_mul(1000)?;
            return Some((PayloadEncoding::Be64, Duration::new(sec, nsec)));
        }
    }
    if payload.len() >= 8 {
        let sec = u64::from(u32::from_le_bytes(payload[0..4].try_into().unwrap()));
        if sec.abs_diff(now.as_secs()) < 1000 {
            let usec = u32::from_le_bytes(payload[4..8].try_into().unwrap());
            let nsec = usec.checked_mul(1000)?;
            return Some((PayloadEncoding::Le32, Duration::new(sec, nsec)));
        }
        let sec = u64::from(u32::from_be_bytes(payload[0..4].try_into().unwrap()));
        if sec.abs_diff(now.as_secs()) < 1000 {
            let usec = u32::from_be_bytes(payload[4..8].try_into().unwrap());
            let nsec = usec.checked_mul(1000)?;
            return Some((PayloadEncoding::Be32, Duration::new(sec, nsec)));
        }
    }
    None
}

fn write_timestamp_into_payload(
    payload: &mut [u8],
    encoding: PayloadEncoding,
    timestamp: Duration,
) {
    match encoding {
        PayloadEncoding::Le64 => {
            payload[0..8].copy_from_slice(&timestamp.as_secs().to_le_bytes());
            payload[8..16].copy_from_slice(&u64::from(timestamp.subsec_micros()).to_le_bytes());
        }
        PayloadEncoding::Be64 => {
            payload[0..8].copy_from_slice(&timestamp.as_secs().to_be_bytes());
            payload[8..16].copy_from_slice(&u64::from(timestamp.subsec_micros()).to_be_bytes());
        }
        PayloadEncoding::Le32 => {
            payload[0..4].copy_from_slice(&(timestamp.as_secs() as u32).to_le_bytes());
            payload[4..8].copy_from_slice(&timestamp.subsec_micros().to_le_bytes());
        }
        PayloadEncoding::Be32 => {
            payload[0..4].copy_from_slice(&(timestamp.as_secs() as u32).to_be_bytes());
            payload[4..8].copy_from_slice(&timestamp.subsec_micros().to_be_bytes());
        }
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    !bytes
        .chunks(2)
        .map(|b| u16::from_be_bytes([b[0], if b.len() == 2 { b[1] } else { 0 }]))
        .reduce(|a, b| {
            let (sum, carry) = a.overflowing_add(b);
            sum + carry as u16
        })
        .unwrap_or(0)
}
