# Orko Watch (owatch) [README REQUIRES UPDATE]

![Orko Watch][logo]

[logo]: /images/orkowatchv2.png "Orko Watch Logo"

A host and network vulnerability scanner developed under Project Orko
by Purple Packet Eaters. Orko Watch performs cross-platform host-level
enumeration and security auditing across Linux, Unix, macOS, and Windows.

---

## Commands

| Command | Description |
|---|---|
| `owatch osinfo` | Gather OS fingerprint information |
| `owatch software` | List installed software packages |
| `owatch audit` | Run security audit checks |
| `owatch all` | Run all available scans |
| `owatch version` | Display current version |

## Quick Start

```bash
# See all available commands and flags
owatch --help

# Gather OS information
owatch osinfo

# List installed software
owatch software

# Run a full security audit with verbose output
owatch audit -v

# Run specific security checks
owatch audit --ssh
owatch audit --fwall
owatch audit --users
owatch audit --fperms /path/to/check

# Run all scans and save report as JSON
owatch all -o json --report-file report.json

# Skip specific modules when running all scans
owatch all --skip-modules software,audit
```

## Security Audit Flags

| Flag | Description | Default |
|---|---|---|
| `--ssh` | Run SSH configuration check | false |
| `--fwall` | Run firewall configuration check | false |
| `--users` | Run user accounts check | false |
| `--fperms` | Check permissions of specified path | — |
| `-o, --output` | Output format: text, json, yaml | text |
| `--report-file` | Save report to file | — |
| `--min-severity` | Minimum severity to report: LOW, MEDIUM, HIGH, CRITICAL | LOW |
| `--skip-checks` | Comma-separated checks to skip | — |
| `--timeout` | Maximum audit duration | 10m |
| `-v, --verbose` | Enable verbose output | false |

## Shell Completion

`owatch` can generate shell completion scripts via the `completion` subcommand.
Completion scripts are sourced into the shell session, not executed directly.

### bash
```bash
source <(owatch completion bash)
```

### zsh
```zsh
source <(owatch completion zsh)
```

### fish
```fish
owatch completion fish | source
```

### PowerShell
```powershell
owatch completion powershell | Out-String | Invoke-Expression
```

> **Note:** Shell completion requires `owatch` to be installed and available
> in PATH. It does not work with `go run` during development.

## Demo

> Coming soon — a recorded demo will be added after the first release tag.

---

## Downloads

### Windows
- [`install.ps1`][win-install]
- [`update.ps1`][win-update]
- [`uninstall.ps1`][win-uninstall]

[win-install]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/install.ps1
[win-update]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/update.ps1
[win-uninstall]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/uninstall.ps1

### Linux
- [`install.sh`][linux-install]
- [`update.sh`][linux-update]
- [`uninstall.sh`][linux-uninstall]

[linux-install]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/install.sh
[linux-update]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/update.sh
[linux-uninstall]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/uninstall.sh

### macOS
- [`install.sh`][macos-install]
- [`update.sh`][macos-update]
- [`uninstall.sh`][macos-uninstall]

> macOS scripts are not yet fully implemented. See [scripts/macos/](scripts/macos/) for current status.

[macos-install]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/macos/install.sh
[macos-update]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/macos/update.sh
[macos-uninstall]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/macos/uninstall.sh

---

## System Requirements

### Windows
- PowerShell 5.1 or higher
- Administrator privileges

### Linux
- Bash 4.0+
- sudo privileges

### macOS
- Bash 4.0+
- sudo privileges
- Full installation support coming in a future release

> **Note:** Go is not required for end users. The install scripts
> download pre-built binaries directly from GitHub Releases.
> Go 1.23+ is only required if building from source.

---

## Installation

### Windows
```powershell
# Download and run as Administrator
curl -o install.ps1 https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/install.ps1
Set-ExecutionPolicy RemoteSigned -Scope Process
.\install.ps1
```

### Linux
```bash
curl -O https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/install.sh
chmod +x install.sh
./install.sh
```

### Build from Source
```bash
git clone https://github.com/papa0four/orkowatch.git
cd orkowatch
make install
```

---

## Updating

### Windows
```powershell
curl -o update.ps1 https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/update.ps1
.\update.ps1
```

### Linux
```bash
curl -O https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/update.sh
chmod +x update.sh
./update.sh
```

---

## Uninstalling

### Windows
```powershell
curl -o uninstall.ps1 https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/uninstall.ps1
.\uninstall.ps1
```

### Linux
```bash
curl -O https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/uninstall.sh
chmod +x uninstall.sh
./uninstall.sh
```

---

## Troubleshooting

### Windows
- Unblock scripts after download:
```powershell
  Unblock-File .\install.ps1
```
- Run PowerShell as Administrator
- If `owatch` is not found after install, open a new terminal to
  reload PATH

### Linux / macOS
- Ensure script is executable: `chmod +x install.sh`
- Verify sudo access: `sudo -v`
- If `owatch` is not found after install: `source /etc/profile`
  or open a new terminal
- Check PATH includes `/usr/local/bin`: `echo $PATH`

---

## Support
For issues or questions, please open a [GitHub Issue][issues].

[issues]: https://github.com/papa0four/orkowatch/issues

---

## License
This project is licensed under the Apache License 2.0 with Commons Clause.

You are free to use, modify, and distribute this software for
non-commercial purposes. Commercial use, resale, or offering this
software as a paid service requires explicit written permission.

See [LICENSE](LICENSE) for full terms.