# Critical Path Vulnerability Scanner (CPSCAN)

![Critical Path][logo]

[logo]: /images/critical_path.jpg "Critical Path Logo"

A proof of concept (POC) vulnerability scanner developed for Critical Path Consulting leadership.

## Downloads

### Windows Scripts
- [`install.ps1`][win-install]
- [`update.ps1`][win-update]
- [`uninstall.ps1`][win-uninstall]

[win-install]: https://raw.githubusercontent.com/papa0four/cpscan/main/windows/install.ps1
[win-update]: https://raw.githubusercontent.com/papa0four/cpscan/main/windows/update.ps1
[win-uninstall]: https://raw.githubusercontent.com/papa0four/cpscan/main/windows/uninstall.ps1

### Unix/Linux/MacOS Scripts
- [`install.sh`][unix-install]
- [`update.sh`][unix-update]
- [`uninstall.sh`][unix-uninstall]

[unix-install]: https://raw.githubusercontent.com/papa0four/cpscan/main/linux/install.sh
[unix-update]: https://raw.githubusercontent.com/papa0four/cpscan/main/linux/update.sh
[unix-uninstall]: https://raw.githubusercontent.com/papa0four/cpscan/main/linux/uninstall.sh

## System Requirements

### Windows
- PowerShell 5.1 or higher
- Go 1.20+
- Administrator privileges

### Unix/Linux/MacOS
- Bash 4.0+
- Go 1.20+
- sudo privileges

## Installation

### Windows
```powershell
# Download installation script
curl -o install.ps1 https://raw.githubusercontent.com/papa0four/cpscan/main/windows/install.ps1

# Open PowerShell as Administrator and run:
Set-ExecutionPolicy RemoteSigned -Scope Process
.\install.ps1
```

### Unix/Linux/MacOS
```bash
# Download installation script
curl -O https://raw.githubusercontent.com/papa0four/cpscan/main/linux/install.sh 
chmod +x install.sh
./install.sh
```

## Updating

### Windows
```powershell
curl -o update.ps1 https://raw.githubusercontent.com/papa0four/cpscan/main/windows/update.ps1 
.\update.ps1
```

### Unix/Linux/MacOS
```bash
curl -O https://raw.githubusercontent.com/papa0four/cpscan/main/linux/update.sh
chmod +x update.sh
./update.sh
```

## Uninstalling

### Windows
```powershell
curl -o uninstall.ps1 https://raw.githubusercontent.com/papa0four/cpscan/main/windows/uninstall.ps1
.\uninstall.ps1
```

### Unix/Linux/MacOS
```bash
curl -O https://raw.githubusercontent.com/papa0four/cpscan/main/linux/uninstall.sh
chmod +x uninstall.sh
./uninstall.sh
```

## Troubleshooting

### Windows
- Ensure scripts are unblocked after download:
  ```powershell
  Unblock-File .\script.ps1
  ```
- Run PowerShell as Administrator
- Verify PATH settings if commands not found

### Unix/Linux/MacOS
- Check script permissions: `chmod +x script.sh`
- Verify sudo access: `sudo -v`
- Check PATH: `echo $PATH`

## Support
For issues or questions, please open a [GitHub Issue][issues].

[issues]: https://github.com/username/cpscan/issues

## License
[NO LICENSE](LICENSE)
