# Windows Kernel Exploitation.
Static & dynamic analysis, exploits & vuln reasearch. <br>
Mitigations bypass's <br>

# Contents

# Introduction:
HEVD-Vanilla-Bug-Class's:<br>
Exploits & Vuln Note's in order to reproduce & reuse.<br>
* <html><a href="https://github.com/akayn/demos/tree/master/HEVD-Vanilla-Bug-Class's">HEVD-Vanilla-Bug-Class's</a></html><br>
	[+] <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/Compiled.zip?raw=true">Compiled-win7x86</a></html><br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-TypeConfX86Win7.c">Type Confusion</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-ArbitraryOverwritex86win7.c">Arbitrary Overwrite</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-NullPointerDereference.c">Null Pointer Dereference</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-PoolOverFlow-Win7-x86.c">Pool OverFlow</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-StackOverFlowx86Win7.c">Stack OverFlow</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-Uaf-Win7x86.c">Use After Free</a></html>.<br>
	* <html><a href="https://github.com/akayn/demos/blob/master/HEVD-Vanilla-Bug-Class's/HEVD-UninitializedStackVariableWin7x86.c">Uninitialized Stack Variable</a></html>.<br>

kd & dev:<br>
* ShellCode: <html><a href="https://github.com/akayn/demos/blob/master/Win10/PayLoads/TokenStealingShellCode.asm">pl.asm</a></html><br>
* kernelLeaks: <html><a href="https://github.com/akayn/demos/blob/master/Primitives/HMValidateBitmap.cc">leak bitmap bAddr with HMValidateHandle</a></html><br>

Mitigations Bypass:<br>
<html><a href="https://github.com/akayn/demos/tree/master/Win10">Click Here!</a></html><br>
* [RS3-Compatible] ROP Based SMEP Bypass including Gadgets & full debugging info: <html><a href="https://github.com/akayn/demos/blob/master/Win10/SmepByPassWin10x64build.16281Rs3/SmepBypassX64Win10RS3.c">SmepBypassX64Win10RS3.c</a></html><br>
* [<= RS2-Compatible] BitMap Arbitrary OverWrite: <html><a href="https://github.com/akayn/demos/blob/master/Win10/BitMap_Win_10_15063.0.amd64fre.rs2_release.170317-1834/GdiExp.cc">GdiExp.cc</a></html><br>

	
# tutorial:
* Rop tutorial: <html><a href="https://github.com/akayn/demos/tree/master/Tutorials">Click Here!</a></html><br>

# External Resources:
* HEVD & Basics:<br>
	[+] <html><a href="https://github.com/hacksysteam/HackSysExtremeVulnerableDriver">HackSysExtremeVulnerableDriver</a></html>.<br>
	[+] <html><a href="http://www.fuzzysecurity.com/tutorials.html">B33F tuto</a></html>.<br>
			[^]            Some of the Vuln Note's in the code were taken from there. <br>
	[+] <html><a href="https://blahcat.github.io/2017/08/14/a-primer-to-windows-x64-shellcoding/">ShellCoding & kd</a></html>.<br>
* Mitigations:<br>
	[+] SMEP:<br>
		* <html><a href="https://en.wikipedia.org/wiki/Control_register#CR4">wiki</a></html>.<br>
		* <html><a href="http://j00ru.vexillium.org/?p=783">j00ru</a></html>.<br>
		* <html><a href="https://github.com/n3k/EKOParty2015_Windows_SMEP_Bypass">Enrique Nissim & Nicolas Economou</a></html>.<br>
		* <html><a href="https://www.coresecurity.com/blog/getting-physical-extreme-abuse-of-intel-based-paging-systems-part-3-windows-hals-heap">PTE-OverWrite</a></html>.<br>
		* <html><a href="https://www.blackhat.com/presentations/bh-usa-08/Shacham/BH_US_08_Shacham_Return_Oriented_Programming.pdf">return oriented Programming</a></html>.<br>
	[+] k-ASLR:<br>
		* <html><a href="https://github.com/MortenSchenk/BHUSA2017">Morten Schenk</a></html>.<br>
	[+] ReadWrite Primitives: <br>
		* <html><a href="https://sensepost.com/blog/2017/abusing-gdi-objects-for-ring0-primitives-revolution/">abusing gdi objects</a></html>.<br>

Software:<br>
* <html><a href="https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit">kd</a></html>.<br>
* <html><a href="https://developer.microsoft.com/en-us/windows/hardware/download-symbols">Symbols</a></html>.<br>
* <html><a href="https://www.hex-rays.com/products/ida/">Ida</a></html>.<br>
* <html><a href="http://www.nasm.us/">NASM</a></html>.<br>
* <html><a href="https://mh-nexus.de/en/hxd/">Hxd</a></html>.<br>

# Other:
* <html><a href="http://processhacker.sourceforge.net/doc/struct___p_r_o_c_e_s_s___h_a_n_d_l_e___t_a_b_l_e___e_n_t_r_y___i_n_f_o.html">data struct</a></html>.<br>
* <html><a href="https://www.zynamics.com/software.html">diffing (bindiff)</a></html>.<br>
* <html><a href="https://github.com/joxeankoret/diaphora">diffing (diaphora)</a></html>.<br>


# See Also:
* <html><a href="https://github.com/akayn/demos/tree/master/Win10/SmepByPassWin10x64build.16281Rs3">Smep PoC</a></html>.<br>
* <html><a href="https://github.com/akayn/demos/tree/master/Win10/BitMap_Win_10_15063.0.amd64fre.rs2_release.170317-1834">GdiExp</a></html>.<br>

# Tnx Note!
many tnx to all the great ppl b4 me that did much work already!<br>
& all others...

about author:

twitter: @_akayn<br>
https://paypal.me/theakayn<br>
