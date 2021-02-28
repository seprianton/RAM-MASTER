#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#      PYTHON SCRIPT FILE FOR THE FORENSIC ANALYSIS OF WINDOWS MEMORY DUMP-FILES
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS AND CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic                                                               
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import os.path
import datetime
import pyfiglet
import linecache
import subprocess

from termcolor import colored

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Forensic                                                               
# Details : Conduct simple and routine tests on any user supplied arguements.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
    print("\nPlease run this python script as root...")
    exit(True)
    
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Forensic
# Details : Create functional subroutine calls from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def dispBanner(variable):
   ascii_banner = pyfiglet.figlet_format(variable).upper()
   ascii_banner = ascii_banner.rstrip("\n")
   os.system("clear")
   print(colored(ascii_banner,'red', attrs=['bold']))
   return   
   
def getTime():
   variable = str(datetime.datetime.now().time())
   variable = variable.split(".")
   variable = variable[0]
   variable = variable.split(":")
   variable = variable[0] + ":" + variable[1]
   variable = spacePadding(variable, COL1)
   return variable 
   
def spacePadding(variable,value):
   while len(variable) < value:
      variable += " "
   return variable

def prompt():
   input("\n[!] Press ENTER to continue...")
   return

def message():
   print(colored("[*] Analysing file, please wait...\n", colour3))
   return

def Display():
   print('\u2554' + '\u2550'*14 + '\u2566' + '\u2550'*21 + '\u2566' + '\u2550'*33 + '\u2566' + '\u2550'*61 + '\u2566' + '\u2550'*COL5 + '\u2557')
   print('\u2551' + " TIME   " + colored(LTM[:6],colour1) + '\u2551' + " FILENAME " + colored(fileName[:10],colour1) + " " + '\u2551' + " HIVE         OFFSET LOCATION    "  + '\u2551' + " USERNAME " + " "*17 + " NTFS PASSWORD HASH " + " "*14 + '\u2551' + " "*COL5 + '\u2551') 
   print('\u2560' + '\u2550'*14 + '\u256C' + '\u2550'*21 + '\u256C' + '\u2550'*12 + '\u2566' + '\u2550'*20 + '\u256C' + '\u2550'*61 + '\u2563' + " "*COL5 + '\u2551')
   
   print('\u2551' + " PROFILE      " + '\u2551', end=' ')
   if PR2 == "UNSELECTED         ":
      print(colored(PR2,colour2), end=' ')
   else:
      print(colored(PR2,colour1), end=' ')
   print('\u2551' + " SAM        " + '\u2551', end=' ')
   if SAM == "0x0000000000000000":
      print(colored(SAM,colour2), end=' ')
   else:
      print(colored(SAM,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[0].upper(),colour1), end=' ')
   print(colored(PA[0],colour1), end=' ')
   print('\u2551' + " "*COL4 + '\u2551')
   
   print('\u2551' + " HOST NAME    " + '\u2551', end=' ')
   if HST == "UNKNOWN            ":
      print(colored(HST[:20],colour2), end=' ')
   else:
      print(colored(HST[:20],colour1), end=' ')
   print('\u2551' + " SECURITY   " + '\u2551', end=' ')
   if SEC == "0x0000000000000000":
      print(colored(SEC,colour2), end=' ')
   else:
      print(colored(SEC,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[1].upper(),colour1), end=' ')
   print(colored(PA[1],colour1), end=' ')
   print('\u2551' + " "*COL4 + '\u2551')
   
   print('\u2551' + " SERVICE PACK " + '\u2551', end=' ')
   if SVP == "0                  ":
      print(colored(SVP,colour2), end=' ')
   else:
      print(colored(SVP,colour1), end=' ')
   print('\u2551' + " COMPONENTS " + '\u2551', end=' ')
   if COM == "0x0000000000000000":
      print(colored(COM,colour2), end=' ')
   else:
      print(colored(COM,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[2].upper(),colour1), end=' ')
   print(colored(PA[2],colour1), end=' ')
   print('\u2551' + " "*COL4 + '\u2551')
   
   print('\u2551' + " LOCAL TIME   " + '\u2551', end=' ')
   if DA2 == "NOT FOUND          ":
      print(colored(DA2,colour2), end=' ')
   else:
      print(colored(DA2,colour1), end=' ')
   print('\u2551' + " SOFTWARE   " + '\u2551', end=' ')
   if SOF == "0x0000000000000000":
      print(colored(SOF,colour2), end=' ')
   else:
      print(colored(SOF,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[3].upper(),colour1), end=' ')
   print(colored(PA[3],colour1), end=' ')
   print('\u2551' + " "*COL4 + '\u2551')
   
   print('\u2551' + " LOCAL IP     " + '\u2551', end=' ')
   if HIP == "000.000.000.000    ":
      print(colored(HIP[:COL1],colour2), end=' ')
   else:
      print(colored(HIP[:COL1],colour1), end=' ')
   print('\u2551' + " SYSTEM     " + '\u2551', end=' ')
   if SYS == "0x0000000000000000":
      print(colored(SYS,colour2), end=' ')
   else:
      print(colored(SYS,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[4].upper(),colour1), end=' ')
   print(colored(PA[4],colour1), end=' ')
   print('\u2551' + " "*COL4 + '\u2551')
   
   print('\u2551' + " LOCAL PORT   " + '\u2551', end=' ')
   if POR == "000                ":
      print(colored(POR[:COL1],colour2), end=' ')
   else:
      print(colored(POR[:COL1],colour1), end=' ')
   print('\u2551' + " NTUSER     " + '\u2551', end=' ')
   if NTU == "0x0000000000000000":
      print(colored(NTU,colour2), end=' ')
   else:
      print(colored(NTU,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[5].upper(),colour1), end=' ')
   print(colored(PA[5],colour1), end=' ')
   print('\u2551' + " "*COL4 + '\u2551')
   
   print('\u2551' + " PID VALUE    " + '\u2551', end=' ')
   if PI1[:2] == "0 ":
      print(colored(PI1[:COL1],colour2), end=' ')
   else:
      print(colored(PI1[:COL1],colour1), end=' ')
   print('\u2551' + " HARDWARE   " + '\u2551', end=' ')
   if HRD == "0x0000000000000000":
      print(colored(HRD,colour2), end=' ')
   else:
      print(colored(HRD,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[6].upper(),colour1), end=' ')
   print(colored(PA[6],colour1), end=' ')
   print('\u2551' + " "*COL4 + '\u2551')
   
   print('\u2551' + " OFFSET VALUE " + '\u2551', end=' ')
   if OFF[:2] == "0 ":
      print(colored(OFF[:COL1],colour2), end=' ')
   else:
      print(colored(OFF[:COL1],colour1), end=' ')
   print('\u2551' + " DEFUALT    " + '\u2551', end=' ')
   if DEF == "0x0000000000000000":
      print(colored(DEF,colour2), end=' ')
   else:
      print(colored(DEF,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[7].upper(),colour1), end=' ')
   print(colored(PA[7],colour1), end=' ')
   print('\u2551' + " "*COL4 + '\u2551')
   
   print('\u2551' + " PARAMETER    " + '\u2551', end=' ')
   if PRM == "UNSELECTED         ":
      print(colored(PRM[:COL1],colour2), end=' ')
   else:
      print(colored(PRM[:COL1],colour1), end=' ')
   print('\u2551' + " BOOT BCD   " + '\u2551', end=' ')
   if BCD == "0x0000000000000000":
      print(colored(BCD,colour2), end=' ')
   else:
      print(colored(BCD,colour1), end=' ')
   print('\u2551', end=' ')
   print(colored(US[8].upper(),colour1), end=' ')
   print(colored(PA[8],colour1), end=' ')
   print('\u2551' + " "*COL4 + '\u2551')
   
   print('\u2551' + " DIRECTORY    " + '\u2551', end=' ')
   if DIR == "OUTCOME            ":
      print(colored(DIR[:COL1],colour2), end=' ')
   else:
      print(colored(DIR[:COL1],colour1), end=' ')
   print('\u2551' + " " + J[:9] + "  " + '\u2551', end=' ')
   if CUS == "0x0000000000000000":
      print(colored(CUS,colour2), end=' ')
   else:
      print(colored(CUS,colour1), end=' ')
   print('\u2551', end=' ')
   if US[10] != "":
      print(colored(US[9].upper(),'red'), end=' ')
      print(colored(PA[9],'red'), end=' ')
   else:
      print(colored(US[9].upper(),colour1), end=' ')
      print(colored(PA[9],colour1), end=' ')   
   print('\u2551' + " "*COL4 + '\u2551')

   print('\u2560' + ('\u2550')*14 + '\u2569'+ ('\u2550')*21  + '\u2569' + ('\u2550')*12 + '\u2569' + ('\u2550')*20 + '\u2569' + ('\u2550')*61 + '\u2569' + ('\u2550')*COL5 + '\u2563')

# ----------------------------------------------------------------------------------------------------------------------------------------------------

   print('\u2551', end=' ')
   print(" "*10, end=' ')
   print("GENERAL SETTINGS", end=' ')
   print(" "*19, end=' ')
   print("ANALYSE", end=' ')
   print(" "*16, end=' ')
   print("IDENTIFY", end=' ')
   print(" "*12, end=' ')
   print("INVESTIGATE", end=' ')
   print(" "*16, end=' ')
   print("EXTRACT", end=' ')
   print(" "*31, end=' ')
   print('\u2551')

# ----------------------------------------------------------------------------------------------------------------------------------------------------

   print('\u2560' + ('\u2550'*165) + '\u2563')
   print('\u2551' + "(0) Re/Set PROFILE   (10) Re/Set SAM        (20) SAM        (30) Users & Passwords (40) PrintKey         (50) Desktop   (60) RSA SSL Keys DIR (70) Yara String Search" + '\u2551')
   print('\u2551' + "(1) Re/Set HOST NAME (11) Re/Set SECURITY   (21) SECURITY   (31) Default Passwords (41) ShellBags        (51) Clipboard (61) RegHiveCerts DIR (71) Time Lines DIR    " + '\u2551')
   print('\u2551' + "(2) Re/Set SERV PACK (12) Re/Set COMPONENTS (22) COMPONENTS (32) Running Processes (42) SlimCache Data   (52) Notepad   (62) Kern Drivers DIR (72) Screen Shots DIR  " + '\u2551')
   print('\u2551' + "(3) Re/Set TIMESTAMP (13) Re/Set SOFTWARE   (23) SOFTWARE   (33) Hidden Processes  (43) Connections Scan (53) Explorer  (63) DllDump PID DIR  (73) MFT Table DIR     " + '\u2551')
   print('\u2551' + "(4) Re/Set LOCAL IP  (14) Re/Set SYSTEM     (24) SYSTEM     (34) Running Services  (44) Network Scan     (54) Files     (64) MalFind PID DIR  (74) PCAP Files DIR    " + '\u2551')
   print('\u2551' + "(5) Re/Set LOCALPORT (15) Re/Set NTUSER     (25) NTUSER     (35) Running Dll's     (45) Socket Scan      (55) SymLinks  (65) VadDump PID DIR  (75) Bulk Extract DIR  " + '\u2551')
   print('\u2551' + "(6) Re/Set PID VALUE (16) Re/Set HARDWARE   (26) HARDWARE   (36) Command History   (46) Mutant Scan      (56) Drivers   (66) ProDump PID DIR  (76) Load Memory File  " + '\u2551')
   print('\u2551' + "(7) Re/Set OFFSET    (17) Re/Set DEFUALT    (27) DEFUALT    (37) Console History   (47) User Assist Keys (57) SIDs      (67) MemDump PID DIR  (77) Info Memory File  " + '\u2551')
   print('\u2551' + "(8) Re/Set PARAMETER (18) Re/Set BOOT BCD   (28) BOOT BCD   (38) Cmdline Arguments (48) Sessions         (58) EnvVars   (68) PARAMETER OFFSET (78) Shell Memory File " + '\u2551')
   print('\u2551' + "(9) Re/Set DIRECTORY (19) Re/Set "+J[:9]+"  (29) "+J[:9]+"  (39) List all Hives    (49) Domain Hashes    (59) TrueCrypt (69) PARAMETER Search (79) Exit Program      " + '\u2551')
   print('\u255A' + ('\u2550')*165 + '\u255D')
   return
   
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Forensic
# Details : Boot the system and populate system variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

os.system("clear")
os.system("xdotool key Alt+Shift+S; xdotool type 'RAM MASTER'; xdotool key Return")
dispBanner("RAM  MASTER")
print(colored("BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS\n", 'yellow', attrs=['bold']))
print("Booting - Please wait...")

if not os.path.exists('OUTCOME'):
   os.mkdir("OUTCOME")     

if not os.path.exists("volatility_2.6_lin64_standalone"):
   print("Downloading volatility 2.6 for linux...\n")
   os.system("wget https://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip")
   os.system("unzip volatility_2.6_lin64_standalone.zip")
   os.remove("volatility_2.6_lin64_standalone.zip")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Forensic
# Details : Initialise program variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

COL1 = 19
COL2 = 18
COL3 = 26
COL4 = 32
COL5 = 32
MAXX = 11
LOAD = 0

SAM = "0x0000000000000000"
SEC = "0x0000000000000000"
COM = "0x0000000000000000"
SOF = "0x0000000000000000"
SYS = "0x0000000000000000"
NTU = "0x0000000000000000"
HRD = "0x0000000000000000"
DEF = "0x0000000000000000"
BCD = "0x0000000000000000"
CUS = "0x0000000000000000"

PRO = "UNSELECTED         "
PR2 = "UNSELECTED         "
DA1 = "NOT FOUND          "
DA2 = "NOT FOUND          "
DIR = "OUTCOME            "
J   = "CUSTOM             "
HST = "UNKNOWN            "
PRM = "UNSELECTED         "
PI1 = "0                  "
PI2 = "0                  "
OFF = "0                  "
PRC = "0                  "
SVP = "0                  "
HIP = "000.000.000.000    "
POR = "000                "

X1 = " "*COL3
X2 = " "*COL4

US = [X1]*MAXX
PA = [X2]*MAXX

colour0 = 'white'
colour1 = 'green'
colour2 = 'yellow'
colour3 = 'blue'

volpath = "volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone"
fileName = "UNKNOWN   "

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : Forensic
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   LTM = getTime()
   linecache.clearcache()
   os.system("rm *.tmp")
   os.system("clear")
   Display()
   selection=input("[?] Please Select: ")
   
# Details : Make sure a file is loaded first!!.

   if selection == "79":
      LOAD = 1
   if LOAD == 0 and selection != "76":
      print("[-] Please select a file to analyse first...")
      selection = "100"
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Lets the user select a new Windows profile.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='0':
      BAK = PRO
      MATCH = 0
      PRO = input("Please enter profile: ")
      if PRO == "":
         PRO = BAK      
      with open("profiles.txt") as search:
         line = search.readline()
         while line:
            line = search.readline()
            if PRO in line:
               MATCH = 1  
      if MATCH == 0:
         PRO = BAK
         print("[-] Profile not found...")
      else:
         PRO = " --profile " + PRO
         PR2 = PRO.replace(" --profile ","") 
         PR2 = spacePadding(PR2, COL1)
      prompt()
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to change the HOST name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '1':
      value = input("Please enter HOST name: ")
      if value != '':
         HST = spacePadding(value, COL1)
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to change the SERVICE PACK version. 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '2':
      value = input("Please enter SERVICE PACK name: ")
      if value != '':
         SVP = spacePadding(value, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to change the TIME STAMP. 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '3':
      value = input("Please enter TIME STAMP: ")
      if value != '':
         DA2 = spacePadding(value, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to set the host IP value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      value = input("Please enter IP value: ")
      if value != '':
         HIP = spacePadding(value, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to Set host PORT value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      value = input("Please enter PORT value: ")
      if value != '':
         POR = spacePadding(value, COL1)
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to set the PID value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '6':
      value = input("[?] Please enter PID value: ")
      if value != '':
         PI1 = spacePadding(value, COL1)
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to set the OFFSET value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '7':
      value = input("[?] Please enter OFFSET value: ")
      if value != '':
         OFF = spacePadding(value, COL1)
         
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to set the PARAMETER string.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '8':
      value = input("Please enter parameter value: ")
      if value != '':
         PRM = spacePadding(value,COL1)
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Allows the user to change the working directory.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '9':
      directory = input("Please enter new working directory value: ")
      if os.path.exists(directory):
         print("Directory already Exists....")
      else:
         if len(directory) > 0:
            os.mkdir(directory)
            DIR = directory
            DIR = spacePadding(DIR, COL1)
            print("Working directory changed...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change SAM via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '10':
      value = input("Please enter SAM value: ")
      if value != "":
         SAM = spacePadding(value, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change SECURITY via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
      value = input("Please enter SECURITY value: ")
      if value != "":
         SEC = spacePadding(value, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change COMPENENTS via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      value = input("Please enter COMPENENTS value: ")
      if value != "":
         COM = spacePadding(value, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change SOFTWARE via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      value = input("Please enter SOFTWARE value: ")
      if value != "":
         SOF = spacePadding(value, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change SYSTEM via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      value = input("Please enter SYSTEM value: ")
      if value != "":
         SYS = spacePadding(value, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change NTUSER via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      value = input("Please enter NTUSER value: ")
      if value != "":
         NTU = spacePadding(value, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change HARDWARE via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      value = input("Please enter HARDWARE value: ")
      if value != "":
         HRD = spacePadding(value, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change DEFAULT via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      value = input("Please enter DEFUALT value: ")
      if value != "":
         DEF = spacePadding(value, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change BOOT BCD via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      value = input("Please enter BOOT BCD value: ")
      if value != "":
         BCD = spacePadding(value, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Change CUSTOM via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      value = input("Please enter " + J.rstrip() + " name: ")
      if value != "":
         J = spacePadding(value, 9)
      value = input("Please enter " + J.rstrip() + " value: ")
      if value != "":
         CUS = spacePadding(value, COL2)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows SAM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      if (SAM == "0x0000000000000000"):
         print("[-] SAM Hive missing - it is not possible to extract data...")
      else:
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hivedump -o " + SAM + " | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows SECURITY hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='21':
      if (SEC == "0x0000000000000000"):
         print("[-] SECURITY Hive missing - it is not possible to extract data...")
      else:
         message()
         os.system(volpath + " -f " + fileName + PRO + " hivedump -o " + SEC + " | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows COMPONENTS hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='22':
      if (COM == "0x0000000000000000"):
         print("[-] COMPONENTS Hive missing - it is not possible to extract data...")
      else:
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hivedump -o " + COM + " | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows SOFTWARE hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='23':
      if (SOF == "0x0000000000000000"):
         print("[-] SOFTWARE Hive missing - it is not possible to extract data...")
      else:
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hivedump -o " + SOF + " | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows SYSTEM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='24':
      if (SYS == "0x0000000000000000"):
         print("[-] SYSTEM Hive missing - it is not possible to extract data...")
      else:
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hivedump -o " + SYS + " | more")
      prompt()    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows NTUSER hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='25':
      if (NTU == "0x0000000000000000"):
         print("[-] NTUSER (Administrator) Hive missing - it is not possible to extract data...")
      else:
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hivedump -o " + NTU + " | more")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows HARDWARE hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='26':
      if (HRD == "0x0000000000000000"):
         print("[-] HARDWARE Hive missing - it is not possible to extract data...")
      else:
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hivedump -o " + HRD + " | more")
      prompt()     

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows DEFUALT hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='27':
      if (DEF == "0x0000000000000000"):
         print("[-] DEFUALT Hive missing - it is not possible to extract data...")
      else:
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hivedump -o " + DEF + " | more")
      prompt()   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows BOOT BCD hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='28':
      if (BCD == "0x0000000000000000"):
         print("[-] BOOT BCD Hive missing - it is not possible to extract data...")
      else:
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hivedump -o " + BCD + " | more")
      prompt()   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows CUSTOM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='29':
      if (CUS == "0x0000000000000000"):
         print("[-] " + J + " Hive missing - it is not possible to extract data...")
      else:
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hivedump -o " + CUS + " | more")
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Dumps the SAM file hashes for export to hashcat.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':
      if SAM == "0x0000000000000000":
         print(colored("[-] SAM HIVE missing - its not possible to extract the hashes...",colour2))
      else:
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hashdump -y " + SYS + " -s " + SAM)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Display any LSA secrets
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '31':
      message();
      os.system(volpath + " -f '" + fileName + "'" + PRO + " lsadump | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows running processes and provides a brief analyse.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '32':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " psscan | more")
      
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " psscan --output greptext > F1.tmp")
      os.system("tail -n +2 F1.tmp > F2.tmp")
      os.system("sed -i 's/>//g' F2.tmp")
      with open("F2.tmp") as read1:
         for line in read1:
            for word in line.split('|'):
                output = subprocess.check_output("echo " + word + " >> F3.tmp", shell=True)
      os.system("tail -n +2 F3.tmp > F4.tmp")
      os.system("wc -l F2.tmp > NUM.tmp")
      NUMLINES = open("NUM.tmp").readline().replace(' F2.tmp','') 
      COUNT = int(NUMLINES)
      print("\n[+] There were",COUNT,"processes running at the time of the memory dump.\n")
      read2 = open('PID.tmp','w')
      read3 = open('PPID.tmp','w')
      with open('F4.tmp') as read4:
         while COUNT > 0:
            A = read4.readline()
            B = read4.readline() # Executable name
            C = read4.readline().rstrip('\n') # PI1
            print(C, file=read2)
            D = read4.readline().rstrip('\n') # OFF             
            print(D, file=read3)		
            E = read4.readline()
            G = read4.readline()
            H = read4.readline() # blank
            COUNT = (COUNT-1)
      read2.close() # required
      read3.close() # required
      os.remove('F1.tmp')
      os.remove('F2.tmp')
      os.remove('F3.tmp')
      os.remove('F4.tmp')
      os.system("echo 'comm -13 <(sort -u PID.tmp) <(sort -u PPID.tmp) > SUSPECT.tmp' > patch.sh")
      os.system("bash patch.sh")
      os.system("sort -n SUSPECT.tmp > SUSPECT2.tmp")
      print("[+] Analyse of these processes reveals that:")
      with open('SUSPECT2.tmp') as read5:
         line = read5.readline().rstrip('\n')
         while line != "":
            if line != "0":
               print("\tParent process PPID",line,"does not have a process spawn! and should be investigated further...")
            line = read5.readline().strip('\n')
      os.remove("patch.sh")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows hidden processes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '33':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " psxview | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows running services.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '34':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " svcscan | more")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - List running dll's.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='35':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " dlllist | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '36':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " cmdscan")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '37':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " consoles")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " cmdline")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Hivelist all
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " hivelist")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Print specified key from hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='40':
      KEY = input("Please enter the key value in quotes: ")
      if KEY != "":
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " printkey -K " + KEY)
         prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shellbags.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='41':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " shellbags | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shellbags.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='42':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " shimcache | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Analyse the NETWORK connections.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='43':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " connscan | more")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Analyse the NETWORK traffic.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='44':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " netscan | more")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Analyse the NETWORK sockets.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='45':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " sockets | more")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Finds Mutants.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='46':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " mutantscan | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Show userassist key values.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '47':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " userassist")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows sessions history.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='48':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " sessions | more")
      prompt()     
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Dump domain hashes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='49':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " cachedump")
      prompt()    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows desktop information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='50':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " deskscan | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows clipboard information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='51':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " clipboard | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows notepad information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='52':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " notepad | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows IE history.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='53':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " iehistory | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows files.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='54':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " filescan | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows symlinks.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='55':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " symlinkscan | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shows drivers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='56':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " devicetree | more")
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " driverscan | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Display all SID's.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='57':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " getsids | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Display environmental variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='58':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " envars | more")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - TrueCrypt info
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='59':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " truecryptsummary | more")
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " truecryptmaster | more")
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " truecryptpassphrase | more")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Dump private and public RSA SSL keys.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='60':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " dumpcerts -D " + DIR)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Dump registry Hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " dumpregistry -D " + DIR)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Dump kernal drivers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " moddump -D " + DIR)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - List running dll's for process PID and dump.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " dlldump -p " + PI1 + " -D " + DIR)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Finds Malware.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='64':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " malfind -p " + PI1 + " -D " + DIR)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected -  Vad dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " vaddump -p " + PI1 + " --dump-dir " + DIR)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Proc dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='66':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " procdump  -p " + PI1 + " --dump-dir " + DIR)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Memory dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='67':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " memdump  -p " + PI1 + " --dump-dir " + DIR)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Search image for occurences of string.
# Modified: N/A
# ------------------------------------------------------------------------------------- 
   
   if selection =='68':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " pslist | grep " + PRM)
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " filescan | grep " + PRM)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Extract a single file based on physical OFFSET.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " dumpfiles -Q " + OFF + " -D " + DIR + " -u -n")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Yara scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='70':
      scanString = input("[?] Please enter yara string to scan: ")
      if scanString != "":
         message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " yarascan -Y " + scanString)
         prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Extract timeline.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='71':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " timeliner --output-file='" + DIR.rstrip(" ") + "/timeline.txt'")
      print(""); message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " shellbags --output-file='" + DIR.rstrip(" ") + "/time.txt'")
      prompt()

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Extract windows screenshots.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='72':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " -D " + DIR + " screenshot")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Extract the MFT table and it contents.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='73':
      message()
      os.system(volpath + " -f '" + fileName + "'" + PRO + " mftparser --output-file=" + DIR.rstrip(" ") + "/mfttable.txt")     
      message()
      os.system("strings " + DIR.rstrip(" ") + "/mfttable.txt | grep '0000000000:' > count.tmp")
      fileNum = sum(1 for line in open('count.tmp'))
      print("The table contains " + str(fileNum) + " local files < 1024 bytes in length.")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Bulk Extract all known files.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='74':
      message()
      os.system("bulk_extractor -x all -e net -o " + DIR + " '" + fileName + "'")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Bulk Extract all known files.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='75':
      message()
      os.system("bulk_extractor -o " + DIR + " '" + fileName + "'")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Select file & extract host variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '76':
      bak = fileName
      fileName = input("[?] Please enter filename: ")
      if fileName == "":
         fileName = bak
      if os.path.exists(fileName):
         fileName = spacePadding(fileName,11)
         profiles = "NOT FOUND"
         LOAD = 1
         message()
         os.system(volpath + " imageinfo -f '" + fileName + "' --output-file=image.log")
         with open("image.log") as search:
            for line in search:
               if "Suggested Profile(s) :" in line:
                  profiles = line
               if "Number of Processors" in line:
                  PRC = line
               if "Image Type (Service Pack) :" in line:
                  SVP = line
               if "Image date and time :" in line:
                  DA1 = line
               if "Image local date and time :" in line:
                  DA2 = line
         if profiles == "NOT FOUND":
            print("ERROR #001 - A windows profile was not found, see 'image.log' for further information.")
            exit(True)         
         profiles = profiles.replace("Suggested Profile(s) :","")
         profiles = profiles.replace(" ","")
         profiles = profiles.split(",")
         PRO = " --profile " + profiles[0]
         PR2 = profiles[0]
         if (PR2[:1] != "W") and (PR2[:1] != "V"):
            print("ERROR #002- A windows profile was not found, see 'image.log' for further information.")
            exit(True)
         else:
            PR2 = spacePadding(PR2,COL1)
            os.remove("image.log")   
         PRC = PRC.replace("Number of Processors :","")
         PRC = PRC.replace(" ","")
         PRC = PRC.replace("\n","")
         PRC = spacePadding(PRC, COL3)
         SVP = SVP.replace("Image Type (Service Pack) :","")
         SVP = SVP.replace(" ","")
         SVP = SVP.replace("\n","")
         SVP = spacePadding(SVP, COL1)
         DA1 = DA1.replace("Image date and time :","")
         DA1 = DA1.lstrip() 
         DA1 = DA1.rstrip("\n")
         a,b,c = DA1.split()
         DA1 = a + " @ " + b
         DA2 = DA2.replace("Image local date and time :","")
         DA2 = DA2.lstrip()
         DA2 = DA2.rstrip("\n")
         a,b,c = DA2.split()
         DA2 = a + " " + b
         DA2 = spacePadding(DA2, COL1)
         print(""); message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hivelist --output-file=hivelist.tmp")
         with open("hivelist.tmp") as search:
            for line in search:
              if "\sam" in line.lower():
                 SAM = line.split(None, 1)[0]
                 SAM = spacePadding(SAM, COL2)
              if "\security" in line.lower():
                 SEC = line.split(None, 1)[0]
                 SEC = spacePadding(SEC, COL2)
              if "\software" in line.lower():
                 SOF = line.split(None, 1)[0]
                 SOF = spacePadding(SOF, COL2)
              if "\system" in line.lower():
                 SYS = line.split(None, 1)[0]
                 SYS = spacePadding(SYS, COL2)
              if "\components" in line.lower():
                 COM = line.split(None, 1)[0]
                 COM = spacePadding(SYS, COL2)
              if "\\administrator\\ntuser.dat" in line.lower(): # \Administrator\NTUSER.DAT as there are usually multiple NTUSERS files. 
                 NTU = line.split(None, 1)[0]
                 NTU = spacePadding(SYS, COL2)
              if "\hardware" in line.lower():
                 HRD = line.split(None,1)[0]
                 HRD = spacePadding(HRD, COL2)
              if "\default" in line.lower():
                 DEF = line.split(None,1)[0]
                 DEF = spacePadding(DEF, COL2)
              if "\\bcd" in line.lower():
                 BCD = line.split(None,1)[0]
                 BCD = spacePadding(BCD, COL2)
         print(""); message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " printkey -o " + SYS + " -K 'ControlSet001\Control\ComputerName\ComputerName' --output-file=host.tmp")
         with open("host.tmp") as search:
            wordlist = (list(search)[-1])
            wordlist = wordlist.split()
            HST = str(wordlist[-1])
         if HST == "searched":					# Looks like a host name has not been found.
            HST = "NOT FOUND          "				# So set a defualt value.
         else:
            HST = HST.encode(encoding='UTF-8',errors='strict')	# Deal with a encoding issue with hostname.
            HST = str(HST)
            HST = HST.replace("b'","")
            HST = HST.replace("\\x00'","")
            HST = spacePadding(HST, COL1)
         print(""); message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " hashdump -y " + SYS + " -s " + SAM + " --output-file=hash.tmp")
         with open("hash.tmp") as search:
            count = 0
            for line in search:
               if line != "":
                  catch = line.replace(":"," ")
                  catch2 = catch.split()
                  catch3 = catch2[3]
                  PA[count] = catch3
                  US[count] = catch2[0][:COL3-1] + " "
                  US[count] = spacePadding(US[count], COL3)
                  count = count + 1
               if count > MAXX: count = MAXX        
         print(""); message()
         os.system(volpath + " -f '" + fileName + "'" + PRO + " connscan --output-file=connscan.tmp")
         os.system("sed '1d' connscan.tmp > conn1.tmp")
         os.system("sed '1d' conn1.tmp > connscan.tmp")
         os.system("cut -f 2 -d ' ' connscan.tmp > conn1.tmp")
         os.system("strings conn1.tmp | sort | uniq -c | sort -nr > connscan.tmp")
         os.system("sed '1d' conn1.tmp > connscan.tmp")         
         getip = linecache.getline('connscan.tmp', 1)         
         if getip != "":
            getip = getip.split()
            getip = getip[0].replace(':',' ')  
            HIP = getip.rsplit(' ', 1)[0]
            POR = getip.rsplit(' ', 1)[1]
            HIP = spacePadding(HIP, COL1)
            POR = spacePadding(POR, COL1)
      else:
         print("[-] The specified file was not found...")
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Select file & extract host variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '77':
      message()
      os.system(volpath + " -f '" + fileName + "' " + PRO + " verinfo | more") 
      prompt()   
      
 # ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Shell in.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '78':
      message()
      os.system(volpath + " -f '" + fileName + "' " + PRO + " volshell") 
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : Forensic
# Details : Menu option selected - Exit the program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='79':
      exit(1)
#Eof...
