# WinSysVuln

The Windows Kernel Drivers exposes devices to user-mode programs and supports a variety of IOCTLs with non-trivial input structures. If the driver handles the user-provided data incorrectly, it constituted a locally accessible attack surface that can be exploited for privilege escalation (such as sandbox escape). 

The repo includes some driver module vulnerabilities on Windows:

[VirtualBox-VboxUSBMon.md](VirtualBox-VboxUSBMon.md)

[VMware-vmnetUserif.md](VMware-vmnetUserif.md)

[VMware-USB-monitor.md](VMware-USB-monitor.md)

[DriverGenius-MyDrivers64.md](DriverGenius-MyDrivers64.md)
