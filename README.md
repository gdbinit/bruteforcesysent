 ```
     _____
  __|___  |__  _____   __   _    __    ______
 |      >    ||     | |  | | | _|  |_ |   ___|
 |     <     ||     \ |  |_| ||_    _||   ___|
 |______>  __||__|\__\|______|  |__|  |______|
    |_____|
     _____
  __|___  |__  _____  _____   ______  ______
 |   ___|    |/     \|     | |   ___||   ___|
 |   ___|    ||     ||     \ |   |__ |   ___|
 |___|     __|\_____/|__|\__\|______||______|
    |_____|

 ```
 
Bruteforce Sysent

A small util to bruteforce sysent address with a dynamic approach
It is very fast and appears to be very reliable, even from kernel.
Compatible with OS X 10.6, 10.7, 10.8 and 10.9.

(c) 2012, fG! - reverser@put.as - http://reverse.put.as

Note: This requires kmem/mem devices to be enabled. To do so, edit `/Library/Preferences/SystemConfiguration/com.apple.Boot.plist` add `kmem=1` to the `Kernel Flags` entry, and reboot!


Version History: 
* v0.1 - Initial version, 32 and 64 bits support
* v0.2 - Bug fixing and code cleanup
