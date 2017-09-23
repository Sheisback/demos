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
