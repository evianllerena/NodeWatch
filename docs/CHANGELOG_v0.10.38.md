# NodeWatch v0.10.38 — circuit figures

- **Internet circuits show their usage and quality.** Traffic, latency, loss and jitter come from the SD-WAN system's health statistics, which were only read while Live health was switched on — so most circuits showed "—". Reading circuits now fetches those statistics as well (once, in the background, waiting a few seconds at most), and a site's statistics no longer hide the other sites' figures.
- When a figure is genuinely not reported, the circuit says so ("no traffic figure") and shows what is known instead: tunnels up over it, then its public IP, then its port.
- Circuits are laid out on two lines (name and usage, then provider · type · bandwidth and quality), all the same size, so nothing is cut off in narrow columns.
- Settings › Connections: connected cards are the same height, with their buttons lined up along the bottom.
