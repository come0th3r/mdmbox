<div align="center">

# MDMBOX

**A Windows fork of Nekobox with an updated Sing-Box core, new Shell, and modern subscription support**

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue)](https://github.com)
[![Core](https://img.shields.io/badge/Core-Sing--Box-brightgreen)](https://github.com/SagerNet/sing-box)
[![Based on](https://img.shields.io/badge/Based%20on-Nekobox-orange)](https://github.com/MatsuriDayo/nekoray)
[![License](https://img.shields.io/badge/License-GPL--3.0-red)](LICENSE)

</div>

---

## About

MDMBOX is a fork of [Nekobox (nekoray)](https://github.com/MatsuriDayo/nekoray) — an open-source GUI proxy client originally developed by MatsuriDayo. This fork targets Windows exclusively and introduces three major changes over the upstream:

- **Updated Sing-Box core** — ships with a newer version of [sing-box](https://github.com/SagerNet/sing-box), enabling support for the latest proxy protocols and features
- **New Shell** — a reworked application shell with an improved interface and usability improvements
- **Modern subscription support** — full compatibility with current subscription formats used in production environments

> Nekobox itself is licensed under GPL-3.0. MDMBOX inherits this license and all original copyrights remain with their respective authors.

---

## Differences from Nekobox

| Feature | Nekobox (upstream) | MDMBOX |
|---|---|---|
| Sing-Box version | Older pinned release | Updated to latest stable |
| Shell / UI layer | Original shell | New reworked shell |
| Subscription formats | Partial support | Full modern support |


## Installation

**Requirements:**

- Windows 10 or 11, 64-bit

**Steps:**

1. Download the latest release from [Releases](../../releases/latest)
2. Run Installer

On first launch, Windows Firewall may request network access — allow it for full functionality.

---

## License

MDMBOX is distributed under the **GNU General Public License v3.0**, consistent with the upstream Nekobox project.  
See [LICENSE](LICENSE) for the full text.

---

## Credits

- [MatsuriDayo/nekoray](https://github.com/MatsuriDayo/nekoray) — original Nekobox project this fork is based on
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) — proxy core
