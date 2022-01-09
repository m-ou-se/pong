# Pong

A Linux program that replies to `ping` but modifies the payload of the ICMP
package to get lower ping times in some `ping` implementations.

See
- https://twitter.com/m_ou_se/status/1480184730058375176
- https://twitter.com/m_ou_se/status/1480184732562374656
- https://twitter.com/m_ou_se/status/1480188334605578242

Install it with `cargo install --git https://github.com/m-ou-se/pong`.

You either need to run it as root, or you need to disable your kernel's ping
reply with `sysctl net.ipv4.icmp_echo_ignore_all=1 net.ipv6.icmp.echo_ignore_all=1`
and give this program `cap_net_raw` capabilities with `setcap cap_net_raw=ep ~/.cargo/bin/pong`.
