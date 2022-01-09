use anyhow::{bail, Context, Result};
use std::fs::{read, write};

const PATH: &str = "/proc/sys/net/ipv4/icmp_echo_ignore_all";

#[must_use]
pub struct DisableSystemPong {
    reenable_on_drop: bool,
}

impl DisableSystemPong {
    pub fn activate() -> Result<Self> {
        if read(PATH).with_context(|| format!("unable to read {}", PATH))? == b"1\n" {
            // Already disabled.
            Ok(DisableSystemPong {
                reenable_on_drop: false,
            })
        } else {
            if write(PATH, "1\n").is_err() {
                bail!(
                    "unable to disable the system's icmp echo reply\n\n\
                    Disable it manually (using `sysctl net.ipv4.icmp_echo_ignore_all=1`), \
                    or re-run this program as root."
                );
            }
            eprintln!("disabled the system's icmp echo reply");
            Ok(DisableSystemPong {
                reenable_on_drop: true,
            })
        }
    }

    pub fn deactivate(&mut self) -> Result<()> {
        if self.reenable_on_drop {
            self.reenable_on_drop = false;
            write(PATH, "0\n").context("unable to re-enable the system's icmp echo reply")?;
            eprintln!("re-enabled the system's icmp echo reply");
        }
        Ok(())
    }
}

impl Drop for DisableSystemPong {
    fn drop(&mut self) {
        if self.reenable_on_drop {
            let _ = self.deactivate();
        }
    }
}
