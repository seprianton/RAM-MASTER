# MEMORY-MASTER
### Python utility file to forensically investigate memory-dump files via volatility.

- [x] Requires volatility (https://github.com/volatilityfoundation/volatility) to be installed.
- [x] Sample memory dump files (https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples) are available here.
- [ ] Program still in beta version! However, what is there is working but not fully tested against all versions of windows operating systems. 

</br>

| LANGUAGE  | FILENAME         | MD5 Hash                         |
|------     |------            | -------                          |
| python    | memory_master.py | 1d484b3691db5e1f2ca3ceacc29e091c |
| text file | profiles.txt     | 90a98544725dc945df30c20fabeb3e80 |
| bash file | patch.sh         | 7a4231731982e09d9a703f7357170755 |


A python utility file that can forensically examine Microsoft Windows memory-dump files - It can pull usernames and password hashs, extract pcap files, MFT executables and much much more.

Recently added the facility to display up to 10 system users at any one time and a custom hive.

## CONSOLE DISPLAY
![Screenshot](picture1.png)
