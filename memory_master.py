#!/usr/bin/python
# coding:UTF-8

# -------------------------------------------------------------------------------------
#      PYTHON SCRIPT FILE FOR THE FORENSIC ANALYSIS OF WINDOWS MEMORY DUMP-FILES
#               BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import subprocess
import os.path
import fileinput
import shutil
import linecache
from termcolor import colored					# pip install termcolor

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0                                                                
# Details : Conduct simple and routine tests on user supplied arguements.   
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
    print "\nPlease run this python script as root..."
    exit(True)

if len(sys.argv) < 2:
    print "\nUse the command python memory_master.py memorydump.mem\n"
    exit(True)

fileName = sys.argv[1]

if os.path.exists(fileName) == 0:
    print "\nFile " + fileName + " was not found, did you spell it correctly?"
    exit(True)

extTest = fileName[-3:]

if extTest != "mem":
    print "This is not a .mem file...\n"
    exit (True)

while len(fileName) < 13:
  fileName += " "

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Initialise program variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

PRO = "UNSELECTED"
PR2 = "UNSELECTED"
DA1 = "NOT FOUND "
PI1 = "0            "
PI2 = "0            "
OFF = "0            "
PRM = "UNSELECTED   "
DIR = "WORKAREA     "
SAM = "0x0000000000000000"
SEC = "0x0000000000000000"
COM = "0x0000000000000000"
SOF = "0x0000000000000000"
SYS = "0x0000000000000000"
NTU = "0x0000000000000000"
HRD = "0x0000000000000000"
DEF = "0x0000000000000000"
BCD = "0x0000000000000000"
HST = "NOT FOUND      "
PRC = "0              "
SVP = "0              "
DA2 = "NOT FOUND      "
TI2 = "NOT FOUND      "
HIP = "000.000.000.000"
POR = "000            "
ADM = "NOT FOUND"
GUS = "NOT FOUND"
USR = "NOT FOUND"

U = "              "
US = []
US = [U,U,U,U,U,U,U]
PAA = "                                "
PAG = "                                "
PA = []
PA = [PAA,PAA,PAA,PAA,PAA,PAA,PAA]

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Display my universal header.    
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def Header():
   os.system("clear")
   print "\t\t\t __  __ _____ __  __  ___  ______   __  __  __    _    ____ _____ _____ ____   "
   print "\t\t\t|  \/  | ____|  \/  |/ _ \|  _ \ \ / / |  \/  |  / \  / ___|_   _| ____|  _ \  "
   print "\t\t\t| |\/| |  _| | |\/| | | | | |_) \ V /  | |\/| | / _ \ \___ \ | | |  _| | |_) | "
   print "\t\t\t| |  | | |___| |  | | |_| |  _ < | |   | |  | |/ ___ \ ___) || | | |___|  _ <  "
   print "\t\t\t|_|  |_|_____|_|  |_|\___/|_| \_\|_|   |_|  |_/_/   \_\____/ |_| |_____|_| \_\ "
   print "                                                                                     "
   print "\t\t\t             BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)           \n"

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Boot the system with populated program variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

Header()
print "Booting - Please wait...\n"
os.mkdir("WORKAREA")
# -------------------------------------------------------------------------------------
# Grab image information.
# -------------------------------------------------------------------------------------
os.system("volatility imageinfo -f " + fileName + " > image.txt")
with open("image.txt") as search:
   for word in search:
      if "Suggested Profile(s) :" in word:
         profiles = word
      if "Number of Processors" in word:
         PRC = word
      if "Image Type (Service Pack) :" in word:
         SVP = word
      if "Image date and time :" in word:
         DA1 = word
      if "Image local date and time :" in word:
         DA2 = word
os.remove("image.txt")
#-------------------------------------------------------------------------------------
# Find appropriate profile.
#-------------------------------------------------------------------------------------
profiles = profiles.replace("Suggested Profile(s) :","")
profiles = profiles.replace(" ","")
profiles = profiles.split(",")
PRO = " --profile " + profiles[0]
PR2 = profiles[0]
if (PR2[:1] == "W") or (PR2[:1] == "V"):
   while len(PR2) < 16:
      PR2 = PR2 + " "
else:
   print "ERROR - Windows profile not found..."
   exit(True)

#-------------------------------------------------------------------------------------
# Find number of processors, service pack status and creation & local dates and times.
#-------------------------------------------------------------------------------------
PRC = PRC.replace("Number of Processors :","")
PRC = PRC.replace(" ","")
PRC = PRC.replace("\n","")
while len(PRC) < 15:
   PRC = PRC + " "
SVP = SVP.replace("Image Type (Service Pack) :","")
SVP = SVP.replace(" ","")
SVP = SVP.replace("\n","")
while len(SVP) < 15:
   SVP = SVP + " "
DA1 = DA1.replace("Image date and time :","")
DA1 = DA1.lstrip()
DA1 = DA1.rstrip("\n")
a,b,c = DA1.split()
DA1 = str(a)
DA1 = DA1 + " "
while len(DA1) < 13:
   DA1 = DA1 + " "
DA2 = DA2.replace("Image local date and time :","")
DA2 = DA2.lstrip()
DA2 = DA2.rstrip("\n")
a,b,c = DA2.split()
DA2 = a
TI2 = b
while len(DA2) < 15:
   DA2 = DA2 + " "
while len(TI2) < 15:
   TI2 = TI2 + " "

#-------------------------------------------------------------------------------------
# Grab hive information if available.
#-------------------------------------------------------------------------------------
os.system("volatility -f " + fileName + PRO + " hivelist > hivelist.txt")
with open("hivelist.txt") as fp:
   line = fp.readline()
   while line:
      line = fp.readline()
      if "\SAM" in line:
         SAM = line.split(None, 1)[0]
         while len(SAM) < 18:
            SAM = SAM + " "
      if "\SECURITY" in line:
         SEC = line.split(None, 1)[0]
         while len(SEC) < 18:
            SEC = SEC + " "
      if "\SOFTWARE" in line:
         SOF = line.split(None, 1)[0]
         while len(SOF) < 18:
            SOF = SOF + " "
      if "\SYSTEM" in line:
         SYS = line.split(None, 1)[0]
         while len(SYS) < 18:
            SYS = SYS + " "
      if "\COMPONENTS" in line:
         COM = line.split(None, 1)[0]
         while len(COM) < 18:
            COM = COM + " "
      if "\Administrator\NTUSER.DAT" in line: # \Administrator\NTUSER.DAT as multiple NTUSERS files. 
         NTU = line.split(None, 1)[0]
         while len(NTU) < 18:
            NTU = NTU + " "
      if "\HARDWARE" in line:
         HRD = line.split(None,1)[0]
         while len(HRD) < 18:
            HRD = HRD + " "
      if "\DEFAULT" in line:
         DEF = line.split(None,1)[0]
         while len(DEF) < 18:
            DEF = DEF + " "
      if "\BCD" in line:
         BCD = line.split(None,1)[0]
         while len(BCD) < 18:
            BCD = BCD + " "
os.remove("hivelist.txt")

#-------------------------------------------------------------------------------------
# Grab host name if avialable.
#-------------------------------------------------------------------------------------
os.system("volatility -f " + fileName + PRO + " printkey -o " + SYS + " -K 'ControlSet001\Control\ComputerName\ComputerName' > host.txt")
with open("host.txt") as fp:
   wordlist = (list(fp)[-1])
os.remove('host.txt')
wordlist = wordlist.split()
HST = wordlist[-1].upper()
if HST == "SEARCHED":
   HST = "NOT FOUND"
while len(HST) < 15:
   HST = HST + " "
#-------------------------------------------------------------------------------------
# Grab user information if available.
#-------------------------------------------------------------------------------------
os.system("echo 'HASH FILE' > hash.txt")
os.system("volatility -f " + fileName + PRO + " hashdump -y " + SYS + " -s " + SAM + " >> hash.txt")
usercount = 0
with open("hash.txt") as fp:
   count = 0
   line = fp.readline() # Header!!
   while line:
      line = fp.readline()
      if "Administrator" in line:
         catch = line.replace(":"," ")
         catch2 = catch.split()
         catch3 = catch2[3]
         PAA = catch3
      if "Guest" in line :
         catch = line.replace(":"," ")
         catch2 = catch.split()
         catch3 = catch2[3]
         PAG = catch3
      elif ("Guest") and ("Administrator") not in line:
         if line !="":
           catch = line.replace(":"," ")
           catch2 = catch.split()
           catch3 = catch2[3]
           PA[count] = catch3
           US[count] = catch2[0][:13].upper()
           temp = US[count]
           while len(US[count]) < 14:
              US[count] = US[count] + " "
           count = count + 1


os.remove("hash.txt")
usercount = usercount -1
if ADM == "                  ":
   usercount = usercount -1
if GUS == "                  ":
   usercount = usercount -1
if usercount > 0:
   USR = "                  "
#   USR = USR + str(usercount)
#while len(USR) < 9:
#   USR = USR + " "

#-------------------------------------------------------------------------------------
# Grab local IP if alvailable.
#-------------------------------------------------------------------------------------
os.system("volatility -f " + fileName + PRO + " connscan > connscan.txt")
os.system("sed '1d' connscan.txt > conn1.txt")
os.system("sed '1d' conn1.txt > connscan.txt")
os.remove("conn1.txt")
os.system("cut -f 2 -d ' ' connscan.txt > conn1.txt")
os.system("strings conn1.txt | sort | uniq -c | sort -nr > connscan.txt")
os.system("sed '1d' conn1.txt > connscan.txt")
getip = linecache.getline('connscan.txt', 1)
if getip != "":
   getip = getip.split()
   getip = getip[0].replace(':',' ')  
   HIP = getip.rsplit(' ', 1)[0]
   POR = getip.rsplit(' ', 1)[1]
   HIP = HIP.rstrip('\n')
   while len(HIP) < 15:
      HIP = HIP + " "
   while len(POR) < 15:
      POR = POR + " "
os.remove('connscan.txt')
os.remove('conn1.txt')

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Build the top half of the screen display as a function call.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def Display():
   print "="*13,
   print colored("SYSTEM",'white'),
   print "="*19,
   print colored("SYSTEM HIVES",'white'),
   print "="*14,
   print colored("HOST INFO",'white'),
   print "="*6,
   print colored("USER INFO",'white'),
   print "="*14,
   print colored("PASSWORDS",'white'),
   print "="*13

# -------------------------------------------------------------------------------------
   print "FILENAME [",
   print colored(fileName[:13],'blue'),
   print "] SAM      [",
   if (SAM == "0x0000000000000000"):
      print colored(SAM,'red'),
   else:
      print colored(SAM,'blue'),
   print "] HOST [",
   if HST == "NOT FOUND      ":
      print colored(HST[:15],'red'),
   else:
       print colored(HST[:15],'blue'),
   print "] ADMINISTRATOR [",
   print colored(PAA,'blue'),
   print "]"

# -------------------------------------------------------------------------------------
   print "PROFILE  [",
   if PR2 == "UNSELECTED              ":
      print colored(PR2[:13],'red'),
   else:
      print colored(PR2[:13],'blue'),
   print "] SECURITY [",
   if SEC == "0x0000000000000000":
      print colored(SEC,'red'),
   else:
      print colored(SEC,'blue'),
   print "] PROC [",
   if PRC == 0:
      print colored(HST,'red'),
   else:
       print colored(PRC,'blue'),
   print "] GUEST         [",
   print colored(PAG,'blue'),
   print "]"

# -------------------------------------------------------------------------------------
   print "CREATED  [",
   if DA1 == "NOT FOUND            ":
      print colored(DA1[:13],'red'),
   else:
      print colored(DA1[:13],'blue'),
   print "] COMPONEN [",
   if COM == "0x0000000000000000":
      print colored(COM,'red'),
   else:
      print colored(COM,'blue'),
   print "] SVPK [",
   if SVP == "0             ":
      print colored(SVP,'red'),
   else:
      print colored(SVP,'blue'),
   print "]",
   print US[0] + "[",
   print colored(PA[0],'blue'),
   print "]"

# -------------------------------------------------------------------------------------
   print "-"*24,
   print "| SOFTWARE [",
   if SOF == "0x0000000000000000":
      print colored(SOF,'red'),
   else:
      print colored(SOF,'blue'),
   print "] DATE [",
   if DA2 == "NOT FOUND      ":
      print colored(DA2,'red'),
   else:
      print colored(DA2,'blue'),
   print "]",
   print US[1] + "[",
   print colored(PA[1],'blue'),
   print "]"

# -------------------------------------------------------------------------------------
   print "PID      [",
   if PI1 == "0            ":
      print colored(PI1,'red'),
   else:
      print colored(PI1,'blue'),
   print "] SYSTEM   [",
   if SYS == "0x0000000000000000":
      print colored(SYS,'red'),
   else:
      print colored(SYS,'blue'),
   print "] TIME [",
   if TI2 == "NOT FOUND      ":
      print colored(TI2,'red'),
   else:
      print colored(TI2,'blue'),
   print "]",
   print US[2] + "[",
   print colored(PA[2],'blue'),
   print "]"

# -------------------------------------------------------------------------------------
   print "PPID     [",
   if PI2[:1] == "0":
      print colored(PI2,'red'),
   else:
      print colored(PI2,'blue'),
   print "] NTUSER   [",					
   if NTU == "0x0000000000000000":
      print colored(NTU,'red'),
   else:
      print colored(NTU,'blue'),
   print "] IP   [",
   if HIP == "000.000.000.000":
      print colored(HIP,'red'),
   else:
      print colored(HIP,'blue'),
   print "]",
   print US[3] + "[",
   print colored(PA[3],'blue'),
   print "]"

# -------------------------------------------------------------------------------------
   print "OFFSET   [",
   if OFF == "0            ":
      print colored(OFF[:13],'red'),
   else:
      print colored(OFF[:13],'blue'),
   print "] HARDWARE [",					
   if HRD == "0x0000000000000000":
      print colored(HRD,'red'),
   else:
      print colored(HRD,'blue'),
   print "] PORT [",
   if POR == "000            ":
      print colored(POR,'red'),
   else:
      print colored(POR,'blue'),
   print "]",
   print US[4] + "[",
   print colored(PA[4],'blue'),
   print "]"

# -------------------------------------------------------------------------------------
   print "PARAM    [",
   if PRM == "UNSELECTED   ":
      print colored(PRM[:13],'red'),
   else:
      print colored(PRM[:13],'blue'),
   print "] DEFAULT  [",					
   if DEF == "0x0000000000000000":
      print colored(DEF,'red'),
   else:
      print colored(DEF,'blue'),
   print "]      [                 ]",
   print US[5] + "[",
   print colored(PA[5],'blue'),
   print "]"

# -------------------------------------------------------------------------------------
   print "DIR      [",
   if DIR == "WORKAREA     ":
      print colored(DIR[:13],'red'),
   else:
      print colored(DIR[:13],'blue'),
   print "] BOOT BCD [",					
   if BCD == "0x0000000000000000":
      print colored(BCD,'red'),
   else:
      print colored(BCD,'blue'),
   print "]      [                 ]",
   print US[6] + "[",
   print colored(PA[6],'blue'),
   print "]"

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Build lower half as a screen display.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------
	
   print "="*134
   print " "*7,
   print colored("SETTINGS",'white'),
   print " "*12,
   print colored("IDENTIFY",'white'),
   print " "*17,
   print colored("ANALYSE",'white'),
   print " "*26,
   print colored("INVESTIGATE",'white'),
   print " "*17,
   print colored("EXTRACT",'white')
   print "="*134

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Main menu system.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

menu = {}
menu['(0)']="Re/Set PROFILE  (10) Users/Passwords    (20) Hivelist   (30) PrintKey  (40) Connection Scan   (50) Desktop    (60) Timeline"
menu['(1)']="Re/Set PID      (11) Default Password   (21) SAM        (31) Re/Set    (41) Network Scan      (51) Clipboard  (61) Screenshots"
menu['(2)']="Re/Set PPID     (12) Running Processes  (22) SECURITY   (32) Re/Set    (42) Socket Scan       (52) Notepad    (62) MFT Table"
menu['(3)']="Re/Set OFFSET   (13) Hidden Processes   (23) COMPONENT  (33) Re/Set    (43) Mutant Scan       (53)            (63) PARAM OFFSET" 
menu['(4)']="Re/Set PARAM    (14) Running Services   (24) SOFTWARE   (34) Re/Set    (44) Malfind PID DIR   (54)            (64)"
menu['(5)']="Re/Set DIR      (15) Command History    (25) SYSTEM     (35) Re/Set    (45) PARAM Search      (55)            (65)"
menu['(6)']="                (16) Console History    (26) NTUSER     (36) Re/Set    (46) VadDump PID DIR   (56)            (66)"
menu['(7)']="                (17) Cmdline Arguments  (27) HARDWARE   (37) Re/Set    (47) ProcDump PID DIR  (57)            (67)"
menu['(8)']="                (18) User Assist Keys   (28) DEFAULT    (38) Re/Set    (48) MemDump PID DIR   (58)            (68)"
menu['(9)']="Clean/Exit      (19)                    (29) BOOT BCD   (39) Re/Set    (49)                   (59)            (69) Bulk Extracter"


# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   os.system("clear")
   Display()
   options=menu.keys()
   options.sort()
   for entry in options: 
      print entry, menu[entry]
   selection=raw_input("\nPlease Select: ")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Lets the user select a new Windows profile.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='0':
      BAK = PRO
      MATCH = 0
      PRO = raw_input("Please enter profile: ")
      if PRO == "":
         PRO = BAK      
      with open("profiles.txt") as fp:
         line = fp.readline()
         while line:
            line = fp.readline()
            if PRO in line:
               MATCH = 1  
      if MATCH == 0:
         PRO = BAK
      else:
         PRO = " --profile " + PRO
         PR2 = PRO.replace(" --profile ","")
         while len(PR2) < 13:
            PR2 += " "
      fp.close()        

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Allowd the user to set the PID value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '1':
      temp = raw_input("Please enter PPID value: ")
      if temp != '':
         PI1 = temp
      while len(PI1) < 13:
         PI1 += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Allowd the user to set the PID value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '2':
      temp = raw_input("Please enter PID value: ")
      if temp != '':
         PI2 = temp
      while len(PI2) < 13:
         PI2 += " "
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Allows the user to set the OFFSET value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '3':
      temp = raw_input("Please enter OFFSET value: ")
      if temp != '':
         OFF = temp
      while len(OFF) < 13:
         OFF += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Allows the user to set the Parameter string.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      temp = raw_input("Please enter parameter value: ")
      if temp != '':
         PRM = temp.upper()
      while len(PRM) < 13:
         PRM += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Allows the user to set the Parameter string.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      directory = raw_input("Please enter new working directory value: ")
      if os.path.exists(directory):
         print "Directory already Exists...."
      else:
         if len(DIR) > 0:
            DIR = directory.upper()
            os.mkdir(directory)
            while len(DIR) < 13:
               DIR += " "
            print "Working directory changed..."
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Clean up system files and exit the program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '9':
      if os.path.exists('WORKAREA'):
         shutil.rmtree('WORKAREA')
      if os.path.exists('timeline.txt'):
         os.remove('timeline.txt')
      if os.path.exists('mfttable.txt'):
         os.remove('mfttable.txt')
      if os.path.exists('screenShots'):
         shutil.rmtree('screenShots') 
      if os.path.exists('bulkOut'):
         shutil.rmtree('bulkOut') 
      if os.path.exists('PIData'):
         shutil.rmtree('PIData')
      if os.path.exists('malFind'):
         shutil.rmtree('malFind')   
      if os.path.exists('mutantFiles'):
         shutil.rmtree('mutantFiles') 
      if os.path.exists('vadDump'):
         shutil.rmtree('vadDump')
      exit(False)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Dumps the SAM file hashes for export to hashcat.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '10':
      if SAM == "0x0000000000000000":
         print colored("SAM HIVE missing - its not possible to extract the hashes...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hashdump -y " + SYS + " -s " + SAM)
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - PR2pays any LSA secrets
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
      os.system("volatility -f " + fileName + PRO + " lsadump")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows running processes and provides a brief analyse.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      os.system("volatility -f " + fileName + PRO + " psscan | more")
      os.system("volatility -f " + fileName + PRO + " psscan --output greptext > F1.txt")
      os.system("tail -n +2 F1.txt > F2.txt")
      os.system("sed -i 's/>//g' F2.txt")
      with open("F2.txt") as read1:
         for line in read1:
            for word in line.split('|'):
                output = subprocess.check_output("echo " + word + " >> F3.txt", shell=True)
      read1.close()
      os.system("tail -n +2 F3.txt > F4.txt")
      os.system("wc -l F2.txt > NUM.txt")
      NUMLINES = open("NUM.txt").readline().replace(' F2.txt','')
      COUNT = int(NUMLINES)
      print "\n[1]. There were",COUNT,"processes running at the time of the memory dump.\n"
      read2 = open('PID.txt','w')
      read3 = open('PPID.txt','w')
      with open('F4.txt') as read4:
         while COUNT > 0:
            A = read4.readline()
            B = read4.readline() # Executable name
            C = read4.readline().rstrip('\n') # PI1
            print >>read2,C
            D = read4.readline().rstrip('\n') # OFF             
            print >>read3,D		
            E = read4.readline()
            G = read4.readline()
            H = read4.readline() # blank
            COUNT = (COUNT-1)
      read2.close()
      read3.close()
      os.remove('F1.txt')
      os.remove('F2.txt')
      os.remove('F3.txt')
      os.remove('F4.txt')
      os.system("bash patch.sh")
      print "[2]. Analyse of these processes reveals that:"
      with open('SUSPECT.txt') as read5:
         line = read5.readline().rstrip('\n')
         while line != "":
            if line != "0":
               print "     Parent process PPID",line,"does not have a process spawn! and should be investigated further..."
            line = read5.readline().strip('\n')
      read5.close()
      os.remove('PID.txt')
      os.remove('PPID.txt')
      os.remove('NUM.txt')
      os.remove('SUSPECT.txt')
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows hidden processes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      os.system("volatility -f " + fileName + PRO + " psxview | more")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows running services.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      os.system("volatility -f " + fileName + PRO + " svcscan | more")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      os.system("volatility -f " + fileName + PRO + " cmdscan")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      os.system("volatility -f " + fileName + PRO + " consoles")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Last commands run.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      os.system("volatility -f " + fileName + PRO + " cmdline")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show userassist key values.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      os.system("volatility -f " + fileName + PRO + " userassist")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Hivelist all
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      os.system("volatility -f " + fileName + PRO + " hivelist")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows SAM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '21':
      if (SAM == "0x0000000000000000"):
         print colored("SAM Hive missing - it is not possible to extract data...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + SAM + " | more")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows SECURITY hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='22':
      if (SEC == "0x0000000000000000"):
         print colored("SECURITY Hive missing - it is not possible to extract data...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + SEC + " | more")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows COMPONENTS hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='23':
      if (COM == "0x0000000000000000"):
         print colored("COMPONENTS Hive missing - it is not possible to extract data...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + COM + " | more")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows SOFTWARE hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='24':
      if (SOF == "0x0000000000000000"):
         print colored("SOFTWARE Hive missing - it is not possible to extract data...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + SOF + " | more")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows SYSTEM hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='25':
      if (SYS == "0x0000000000000000"):
         print colored("SYSTEM Hive missing - it is not possible to extract data...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + SYS + " | more")
      raw_input("\nPress ENTER to continue...")    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows NTUSER hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='26':
      if (NTU == "0x0000000000000000"):
         print colored("NTUSER (Administrator) Hive missing - it is not possible to extract data...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + NTU + " | more")
      raw_input("\nPress ENTER to continue...") 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows HARDWARE hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='27':
      if (HRD == "0x0000000000000000"):
         print colored("HARDWARE Hive missing - it is not possible to extract data...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + HRD + " | more")
      raw_input("\nPress ENTER to continue...")     

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows DEFUALT hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='28':
      if (DEF == "0x0000000000000000"):
         print colored("DEFUALT Hive missing - it is not possible to extract data...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + DEF + " | more")
      raw_input("\nPress ENTER to continue...")   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows BOOT BCD hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='29':
      if (BCD == "0x0000000000000000"):
         print colored("BOOT BCD Hive missing - it is not possible to extract data...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + BCD + " | more")
      raw_input("\nPress ENTER to continue...")   


# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Print specified key from hive.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='30':
      KEY = raw_input("Please enter the key value in quotes: ")
      os.system("volatility -f " + fileName + PRO + " printkey -K " + KEY)
      raw_input("\nPress ENTER to continue...") 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change SAM via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '31':
      SAM = raw_input("Please enter SAM value: ")
      while len(SAM) < 18:
         SAM += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change SECURITY via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '32':
      SEC = raw_input("Please enter SECURITY value: ")
      while len(SEC) < 18:
         SEC += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change COMPENENTS via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '33':
      COM = raw_input("Please enter COMPENENTS value: ")
      while len(COM) < 18:
         COM += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change SOFTWARE via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '34':
      SOF = raw_input("Please enter SOFTWARE value: ")
      while len(SOF) < 18:
         SOF += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change SYSTEM via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '35':
      SYS = raw_input("Please enter SYSTEM value: ")
      while len(SYS) < 18:
         SYS += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change NTUSER via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '36':
      NTU = raw_input("Please enter NTUSER value: ")
      while len(NTU) < 18:
         NTU += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change HARDWARE via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '37':
      HRD = raw_input("Please enter HARDWARE value: ")
      while len(HRD) < 18:
         HRD += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change DEFAULT via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      DEF = raw_input("Please enter DEFUALT value: ")
      while len(DEF) < 18:
         DEF += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change BOOT BCD via user choice.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      BCD = raw_input("Please enter BOOT BCD value: ")
      while len(BCD) < 18:
         BCD += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Analyse the NETWORK.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='40':
      os.system("volatility -f " + fileName + PRO + " connscan")
      raw_input("\nPress ENTER to continue...") 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Analyse the NETWORK.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='41':
      os.system("volatility -f " + fileName + PRO + " netscan")
      raw_input("\nPress ENTER to continue...") 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Analyse the NETWORK.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='42':
      os.system("volatility -f " + fileName + PRO + " sockets")
      raw_input("\nPress ENTER to continue...") 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Finds Mutants!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='43':
      os.system("volatility -f " + fileName + PRO + " mutantscan")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Finds Malware!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='44':
      os.system("volatility -f " + fileName + PRO + " malfind -p " + PI1 + " -D " + DIR)
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Allows the user to Search the PARAM string.
# Modified: N/A
# ------------------------------------------------------------------------------------- 
   
   if selection =='45':
      os.system("volatility -f " + fileName + " " + PRO + " pslist | grep " + PRM)
      os.system("volatility -f " + fileName + " " + PRO + " filescan | grep " + PRM)
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected -  Vaddump!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='46':
      os.system("volatility -f " + fileName + PRO + " vaddump -p " + PI1 + " --dump-dir " + DIR)
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Proc dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='47':
      os.system("volatility -f " + fileName + PRO + " procdump  -p " + PI1 + " --dump-dir " + DIR)
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Memory dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='48':
      os.system("volatility -f " + fileName + PRO + " memdump  -p " + PI1 + " --dump-dir " + DIR)
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows desktop information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='50':
      os.system("volatility -f " + fileName + PRO + " deskscan")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows clipboard information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='51':
      os.system("volatility -f " + fileName + PRO + " clipboard")
      raw_input("\nPress ENTER to continue...")


# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Shows notepad information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='52':
      os.system("volatility -f " + fileName + PRO + " notepad")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Build timeline.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='60':
      os.system("volatility -f " + fileName + PRO + " timeliner --output-file timeline.txt")
      raw_input("\nPress ENTER to continue...")

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Download windows screenshots.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      os.system("volatility -f " + fileName + PRO + " -D " + DIR + " screenshot")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Extracts the MFT table and it contents.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      os.system("volatility -f " + fileName + PRO + " mftparser >> mfttable.txt")
      print "The MFT has been sucessfully exported to mfttable.txt..."
      os.system("strings mfttable.txt | grep '0000000000:' > count.txt")
      fileNum = sum(1 for line in open('count.txt'))
      print "The table contains " + str(fileNum) + " extractable files < 1024 bytes in length."
      os.remove("count.txt")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Extracts the file based on physical OFFSET
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      os.system("volatility -f " + fileName + PRO + " dumpfiles -Q " + OFF + " -D " + DIR + " -u -n")
      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Bulk Extract files.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      os.system("bulk_extractor -o bulkOut " + fileName)
      print "\nBulk extraction is now available in directory bulkOut...\n"
      raw_input("\nPress ENTER to continue...")

#Eof...
