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
My Debug Binary: * <html><a href="https://github.com/akayn/demos/blob/master/Tutorials/SMEPDEBUG/RopDebug.exe?raw=true">download link.</a></html>.<br> 
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
next up (assuming that you have a debugger connected) run the sample exe that i have provided, you should get a break point and this output should go on the debugger:





