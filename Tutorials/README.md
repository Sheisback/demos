# Return Oriented Programming Tutorial 
Hi in this tutorial we will go throw a very basic way of creating a ROP (Return Oriented Programming) Chain in order to bypass SMEP and get kernel mode execution on latest windows installation despite microsoft mitigation's.
# Setup:
This tutorial is meant to be an active tutorial meaning that its best you will download the binary provided for the tutorial and experiment on your own with the main idea's presented.<br>
So this is what you will need in order to run the full tutorial by your own:<br>
HEVD: <html><a href="https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/releases">download from here<a></html>.<br>
Windows 10 RS3 (link will be added soon).<br>
WinDbg & Symbols: * <html><a href="https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit">kd</a></html>.<br>
* <html><a href="https://developer.microsoft.com/en-us/windows/hardware/download-symbols">Symbols</a></html>.<br>
Hyper-V: * <html><a href="https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v">How To unable hyper-v</a></html>.<br>
Setup File sharing beetwin the machine and the host:* <html><a href="https://technet.microsoft.com/en-us/library/ee256061(v=ws.10).aspx">Setup File Sharing.</a></html>.<br> 
My Debug Binary: * <html><a href="https://github.com/akayn/demos/blob/master/Tutorials/SMEPDEBUG/ROPDEBUG.exe?raw=true">download link.</a></html>.<br> 
# Introduction:
Return Oriented Programming (in the computer security context) is a technique used to bypass certain defence mechanisms, like DEP (Data execution Prevention) & SMEP. if you would like to read more about smep you can check out the link at the main README.md file of this project. the main charicteristic of this method is that instead of running pure shell code directlly from a user supplied buffer we instead use small snipets of code called gadgets.<br>
say for example i want to place 0x1FA5 in rsp, useally i will simply write in my shellcode:<br>
mov rsp, 0x1FA5<br>
instead when using rop we will try to find some address in memory (this can be a dll an exe image or the kernel image), that will do exactly the same. and instead of writing it in the payload we will place that memory address of that function to be executed instead. so lets say i know that at a certain Offset from the base address of some dll say hal.dll there is a good instruction, then assuming that i can get code execution if i will pass the address of that function to the exploit target on runtime it will get executed. when building a rop chain the chain will be computed from many small gagdets like this one, you can think a bout it like shellcoding with snippets from other executable memory. here is a little snippent to visualize this:<br>
![](/Tutorials/SMEPDEBUG/ropChain.PNG)

so in that picture as an example we will send to our exploit target a buffer that contains:<br>

hal+0x6bf0 followed by hal+0x668e .. and so on.<br>
You may ask yourself: why would we want to do that? why not simply write the shellcode as is?<br>
Well if you can simply write the shellcode as is then it is far easy to do that, but as mentioned b4 it may not allways be possible. so lets say a little about smep. smep is a security massure that uses hardware features in order to protect the endpoint from exploits such as kernel exploits. the main idea is to mark eache page allocated in the memory as eather kernel address space (K-executable/r/w) or user space. this way when the kernel executes code that code address is being checked (if the hardware offers that possiblety) if its a user space address or kernel mode address. if it was found that the code is marked as user space the kernel will stop the execution flow with a critical error, bsod.<br>
so if we will simply try to exploit a stack overflow like we did on windows 7, we will get this outcome:<br>
![](/Tutorials/SMEPDEBUG/bsod.PNG)

so the main idea in rop is to make the execution flow throw a kernel executable address that can pass the check until we can execute our own payload.<br>
# enough talk lets debug!!!
assuming that you have set up the environment as stated above, and you have a working machine, then open an administrator command, and type as follow:
![](/Tutorials/SMEPDEBUG/load.PNG)
b4 running anything hit break on the debugger (open debug window and click break), next open view -> registers.
scoll all the way down and the resault should be:
![](/Tutorials/SMEPDEBUG/break1.PNG)
![](/Tutorials/SMEPDEBUG/break2.PNG)
next up type g and hit enter the machine should be running as normal, run the sample exe that i have provided, you should get a break point and this output should go on the debugger:
![](/Tutorials/SMEPDEBUG/break3.PNG)
as you can see this break point is different from the one we hit b4. first take a look at the address that triggered the break point: at the break point b4 we hit :<br>
0xfffff80391595050 cc              int     3<br>
and now we got:<br>
Break instruction exception - code 0x80000003 (first chance)
0x0000017039f00046 cc              int     3<br>

as you can see the first address is a kernel space address and the second a user address. this is becouse i have place xcc in my shellcode. next up open the registers again the outcome should be as follows:<br>
![](/Tutorials/SMEPDEBUG/break4.PNG)
you may ask yourself, why is cr4 register changed and how is it that we do not get the bsod msg as b4? well becouse the binary build a rop chain as follows:

```c
  // To better align the buffer,
	// it is usefull to declare a
	// memory structure, other-wise you will get holes
	// in the buffer and end up with an access violation.
	typedef struct _RopChain {
		PUCHAR HvlEndSystemInterrupt;
		PUCHAR Var;
		PUCHAR KiEnableXSave;
		PUCHAR payload;
		// PUCHAR deviceCallBack;
	} ROPCHAIN, *PROPCHAIN;


  	// Pack The buffer as:  

	ROPCHAIN Chain;

	// nt!HvlEndSystemInterrupt+0x1e --> Pop Rcx; Retn;
	Chain.HvlEndSystemInterrupt = Ntos + 0x17d970;

	// kd> r cr4
	// ...1506f8
	Chain.Var = (PUCHAR)0x506f8;


	// nt!KiEnableXSave+0x7472 --> Mov Cr4, Rcx; Retn;
	Chain.KiEnableXSave = Ntos + 0x434a33;

```
meaning that we have sent the vuln driver a stack overflow buffer, but instead of supplying our shell code we have given the driver the buffer above that is first composed of:<br>
Pop Rcx  <-- kernel mode address<br> 
Retn<br>
0x506f8<br>
Mov Cr4, Rcx<br>
Retn<br>
(ShellCodeAddress)<br>
So basically we have "jump" to our shellcode from other kernel mode address's so we did not got the bsod, simply cuz we have given the kernel a kernl-mode address so we passed the check, next up we flipped the bit on the cr4 register value to trick the system that smep is not supported on the firmware.<br>
we can see that by running kv command.
![](/Tutorials/SMEPDEBUG/Capture2.PNG)
you can see the kernel mode address on the stack call and can see the execution flow, as well as the nop's we have placed in our buffer.
hit g again and you should see the below outcome:<br>
![](/Tutorials/SMEPDEBUG/br.PNG)
as you can see we have hit access violation, this is becouse in this demo i did not fix the return address pointer, so we can do this together, hit r on the debugger:<br>
![](/Tutorials/SMEPDEBUG/br2.PNG)
<br>as you can see the stack is a mess & the registers as well, the return address try's to read a pointer from rax, that is pointing to zero address, so we got access violation.<br>
so like we had to "jump" to our shell code to avoid SMEP, we need to jump back to a reasonable state, but how can we know what is a good address to jump back to? when we looked at the stack b4 we could see the execution flow,<br>
So 0x00007fffb29013aa the lowest address called the ioctl then we got to our shellcode from the overflow (the nop's), a good thing to do would be to make a return to one of our original call's on the stack to resume execution.
if we take a look at 0x00007fffb29013aa we can see its marked as UREV user executable,
![](/Tutorials/SMEPDEBUG/br3.PNG)
so if we will jump to that address we will be in the same situation as b4 (bsod) so we need to find another place on the stack to jump to. lets see about nt!IofCallDriver+0x59 that is on the stack as well, we can even see what code is contained at this location running the below command:
![](/Tutorials/SMEPDEBUG/brb.PNG)
So we can see that this function simply returns back to the caller and is also KREV kernel exec. so it will be a good choise. while i was finding gadgets i was doing exactly the same, looking for KREV address that contain good code for me like mov cr4, rcx. with the 'u' command on the kd. <br>
ok, but how can we jump to that address? open up the registers again and copy the first instruction address in the output of<br>
kd> u nt!IofCallDriver+0x59<br>
as follows: place it in rip (in view registers..)<br>
![](/Tutorials/SMEPDEBUG/brr.PNG)
now hit g again. back in box you should have a command running as local system.<br>
![](/Tutorials/SMEPDEBUG/Capture9.PNG)
So this is the end of the tutorial, i hope it will be usefull, now you know a bit more about ROP, and got some basic tools to build your own rop chain. my example code can be found here: <html>












