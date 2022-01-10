use anyhow::{bail, Context, Result};
use std::fs::{read, write};

const PATH_IPV4: &str = "/proc/sys/net/ipv4/icmp_echo_ignore_all";
const PATH_IPV6: &str = "/proc/sys/net/ipv6/icmp/echo_ignore_all";

#[must_use]
pub struct DisableSystemPong {
    reenable_ipv4_on_drop: bool,
    reenable_ipv6_on_drop: bool,
}

impl DisableSystemPong {
    pub fn activate() -> Result<Self> {
        Ok(DisableSystemPong {
            reenable_ipv4_on_drop: if read(PATH_IPV4)
                .with_context(|| format!("unable to read {}", PATH_IPV4))?
                == b"1\n"
            {
                // Already disabled.
                false
            } else {
                if write(PATH_IPV4, "1\n").is_err() {
                    bail!(
                        "unable to disable the system's IPv4 ICMP echo reply\n\n\
                        Disable it manually (using `sysctl net.ipv4.icmp_echo_ignore_all=1`), \
                        or re-run this program as root."
                    );
                }
                eprintln!("disabled the system's IPv4 ICMP echo reply");
                true
            },
            reenable_ipv6_on_drop: if read(PATH_IPV6)
                .with_context(|| format!("unable to read {}", PATH_IPV6))?
                == b"1\n"
            {
                // Already disabled.
                false
            } else {
                if write(PATH_IPV6, "1\n").is_err() {
                    bail!(
                        "unable to disable the system's IPv6 ICMP echo reply\n\n\
                        Disable it manually (using `sysctl net.ipv6.icmp.echo_ignore_all=1`), \
                        or re-run this program as root."
                    );
                }
                eprintln!("disabled the system's IPv6 ICMP echo reply");
                true
            },
        })
    }

    pub fn deactivate(&mut self) -> Result<()> {
        if self.reenable_ipv4_on_drop {
            self.reenable_ipv4_on_drop = false;
            write(PATH_IPV4, "0\n")
                .context("unable to re-enable the system's IPv4 ICMP echo reply")?;
            eprintln!("re-enabled the system's IPv4 ICMP echo reply");
        }
        if self.reenable_ipv6_on_drop {
            self.reenable_ipv6_on_drop = false;
            write(PATH_IPV6, "0\n")
                .context("unable to re-enable the system's IPv6 ICMP echo reply")?;
            eprintln!("re-enabled the system's IPv6 ICMP echo reply");
        }
        Ok(())
    }
}

impl Drop for DisableSystemPong {
    fn drop(&mut self) {
        let _ = self.deactivate();
    }
}
