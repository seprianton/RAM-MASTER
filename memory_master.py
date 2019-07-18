#!/usr/bin/python
# coding:UTF-8

# -------------------------------------------------------------------------------------
#       PYTHON UTILITY SCRIPT FILE FOR THE FORENSIC ANALYSIS OF MEMORY DUMP-FILES
#               BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Load any required imports and initialise program variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import os.path
import fileinput
from termcolor import colored	# pip install termcolor

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

while len(fileName) < 25:
  fileName += " "

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Initialise program variables and set up system requirements.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

os.system("mkdir workArea")
os.system("echo temp > ./workArea/temp.txt")

#os.system("md5sum " + fileName + " > MD5SUM.txt")
#hashvalue = open("MD5SUM.txt").readline().replace(fileName, '').rstrip('\n')

PRO = "UNSELECTED              "
DIS = "UNSELECTED              "
SAM = "0x0000000000000000"
SEC = "0x0000000000000000"
SOF = "0x0000000000000000"
COM = "0x0000000000000000"
SYS = "0x0000000000000000"
PID = "0                       "
PPID = "0                       "
PRM = "UNSELECTED              "
REG = 0
PRM0 = "0x0000000000000000"
PRM1 = "0x0000000000000000"
PRM2 = "0x0000000000000000"
PRM3 = "0x0000000000000000"
PRM4 = "0x0000000000000000"
PRM5 = "0x0000000000000000"
PRM6 = "0x0000000000000000"
PRM7 = "0x0000000000000000"
PRM8 = "0x0000000000000000"
PRM9 = "0x0000000000000000"
SCAN = 0

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Create a main menu system.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

menu = {}
menu['(1)']="Auto PROFILE.	(10) Build Timeline.	(19) View SAM.		(28) Malfind PID.		(37) Auto Processes."
menu['(2)']="Auto HIVES.\t	(11) Extract Files.	(20) View SECURITY.	(29) Mutant PID.		(38) List Processes."
menu['(3)']="			(12) 			(21) View SOFTWARE.	(30) Vaddump PID.		(39) List Services."
menu['(4)']="			(13) 			(22) View COMPONENT.	(31) Memory Dump PID.		(40)"
menu['(5)']="Set PROFILE.	(14)		 	(23) View SYSTEM.	(32) Show Screenshots.		(41)"
menu['(6)']="Set PID.		(15) 			(24) 			(33) Show Clipboard.		(42)"
menu['(7)']="Set PPID.		(16) 			(25) 			(34) Show UserAssist Keys.	(43)"
menu['(8)']="Set PARAM.		(17) 			(26) 			(35) Show Console.		(44) Exit."
menu['(9)']="Search PARAM.	(18)			(27)			(36)				(45) Clean and Exit."

while True: 
   os.system("clear")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Display universal header.    
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

   print "\t\t\t __  __ _____ __  __  ___  ______   __  __  __    _    ____ _____ _____ ____   "
   print "\t\t\t|  \/  | ____|  \/  |/ _ \|  _ \ \ / / |  \/  |  / \  / ___|_   _| ____|  _ \  "
   print "\t\t\t| |\/| |  _| | |\/| | | | | |_) \ V /  | |\/| | / _ \ \___ \ | | |  _| | |_) | "
   print "\t\t\t| |  | | |___| |  | | |_| |  _ < | |   | |  | |/ ___ \ ___) || | | |___|  _ <  "
   print "\t\t\t|_|  |_|_____|_|  |_|\___/|_| \_\|_|   |_|  |_/_/   \_\____/ |_| |_____|_| \_\ " 
   print "                                                                                     "
   print "\t\t\t            BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)            \n"

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Build and display pertinant information to the user.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------
 
   print "___________________ SYSTEM _________________________ WINDOWS HIVES __________________ UNALLOCATED __________________ UNALLOCATED ____"
   print "FILENAME [",
   print colored(str.upper(fileName[:24]),'blue'),
   print "] SAM       [",
   if (REG == 0) and (SAM == "0x0000000000000000"):
      print colored(SAM[:24],'white'),
   elif (REG == 1) and (SAM == "0x0000000000000000"):
      print colored(SAM[:24],'red'),
   else:
      print colored(SAM[:24],'blue'),
   print "] RESERVED [ " + PRM0 + " ] RESERVED [ " + PRM5 + " ]"
   print "PROFILE  [",
   if DIS == "UNSELECTED              ":
      print colored(str.upper(DIS[:24]),'white'),
   else:
      print colored(str.upper(DIS[:24]),'blue'),
   print "] SECURITY  [",
   if SEC == "0x0000000000000000":
      print colored(SEC[:24],'white'),
   else:
      print colored(SEC[:24],'blue'),
   print "] RESERVED [ " + PRM1 + " ] RESERVED [ " + PRM6 + " ]"
   print "PID      [",
   if PID[:1] == "0":
      print colored(PID[:24],'white'),
   else:
      print colored(PID[:24],'blue'),
   print "] SOFTWARE  [",
   if SOF == "0x0000000000000000":
      print colored(SOF[:24],'white'),
   else:
      print colored(SOF[:24],'blue'),
   print "] RESERVED [ " + PRM2 + " ] RESERVED [ " + PRM7 + " ]"
   print "PPID     [",
   if PPID[:1] == "0":
      print colored(PPID[:24],'white'),
   else:
      print colored(PPID[:24],'blue'),
   print "] COMPONENT [",
   if COM == "0x0000000000000000":
      print colored(COM[:24],'white'),
   else:
      print colored(COM[:24],'blue'),
   print "] RESERVED [ " + PRM3 + " ] RESERVED [ " + PRM8 + " ]"
   print "PARAM    [",
   if PRM == "UNSELECTED              ":
      print colored(PRM[:24],'white'),
   else:
      print colored(str.upper(PRM[:24]),'blue'),
   print "] SYSTEM    [",
   if (REG == 0) and (SYS == "0x0000000000000000"):
      print colored(SYS[:24],'white'),
   elif (REG == 1) and (SYS == "0x0000000000000000"):
      print colored(SYS[:24],'red'),
   else:
      print colored(SYS[:24],'blue'),
   print "] RESERVED [ " + PRM4 + " ] RESERVED [ " + PRM9 + " ]\n"

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Create the main controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

   options=menu.keys()
   options.sort()
   for entry in options: 
      print entry, menu[entry]
   selection=raw_input("\nPlease Select: ")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Automatically get the profile from the memory file.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='1':
      os.system("volatility imageinfo -f " + fileName + " > IMAGE.txt")
      with open("IMAGE.txt") as fp:
         line = fp.readline()
         PRO = line.split(None,4)[3]
         PRO = PRO.rstrip(',')
         PRO = " --profile " + PRO
         DIS = PRO.replace(" --profile ","")
         while len(DIS) < 24:
            DIS = DIS + " "
         fp.close()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Create and populate registry hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='2':
      os.system("volatility -f " + fileName + PRO + " hivelist > hivelist.txt")
      with open("hivelist.txt") as fp:  
         line = fp.readline()
         while line:
            line = fp.readline()
            if "\SAM" in line:
               SAM = line.split(None, 1)[0]
               while len(SAM) < 18:
                  SAM = SAM + " "
            if "SECURITY" in line:
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
         REG = 1
         fp.close()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - RESERVED
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='3':
      print "Reserved for later use."
      raw_input("Press any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - RESERVED
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='4':
      print "Reserved for later use."
      raw_input("Press any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Grab the profile settings from the user.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='5':
      orginal = PRO
      found = 0
      PRO = raw_input("Please enter profile: ")
      if PRO == "":
         PRO = orginal      
      with open("profiles.txt") as fp:
         line = fp.readline()
         while line:
            line = fp.readline()
            if PRO in line:
               found = 1  
      if found == 0:
         PRO = orginal
      else:
         PRO = " --profile " + PRO
         DIS = PRO.replace(" --profile ","")
         while len(DIS) < 30:
            DIS += " "
      fp.close()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - User=set the PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='6':
      PID = raw_input("Please enter PID value: ")
      while len(PID) < 24:
         PID += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - User-set the PPID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='7':
      PPID = raw_input("Please enter PPID value: ")
      while len(PPID) < 24:
         PPID += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Get parameter
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='8':
      PRM = raw_input("Please enter parameter value: ")
      while len(PRM) < 24:
         PRM += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Search PARAM.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='9':
      os.system("volatility -f " + fileName + " " + PRO + " pslist | grep " + PRM)
      selection=raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Build timeline.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='10':
      os.system("volatility -f " + fileName + PRO + " timeliner --output-file timeline.txt")
      selection=raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Get parameter
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='11':
      os.system("bulk_extractor -o bulkOut " + fileName)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Dump SAM file hashes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='19':
      if (SAM == "0x0000000000000000") or (SYS == "0x0000000000000000"):
         print colored("Not possible...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hashdump -y " + SYS + " -s " + SAM)
      selection=raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show SECURITY hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='20':
      if (SEC == "0x0000000000000000"):
         print colored("Not possible...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + SEC)
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show SOFTWARE hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='21':
      if (SOF == "0x0000000000000000"):
         print colored("Not possible...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + SOF)
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show COMPONENT hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='22':
      if (COM == "0x0000000000000000"):
         print colored("Not possible...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + COM)
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show SYSTEM hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='23':
      if (SYS == "0x0000000000000000"):
         print colored("Not possible...",'red')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + SYS)
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Find Malware!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='28':
      os.system("volatility -f " + fileName + PRO + " malfind -p " + PID + " --dump-dir workArea")
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Find Mutants!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='29':
      os.system("volatility -f " + fileName + PRO + " handles -p " + PID + " -t Mutant -s")
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected -  Vaddump!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='30':
      os.system("volatility -f " + fileName + PRO + " vaddump -p " + PID + " -D workArea")
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Memory dump PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='31':
      os.system("volatility -f " + fileName + PRO + " memdump -p " + PID + " -D workArea")
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Download windows screenshot.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      os.system("volatility -f " + fileName + PRO + " -D workArea screenshot")
      print "\nScreenshots are now available in directory workArea...\n"
      selection=raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show the clipboard
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='33':
      os.system("volatility -f " + fileName + PRO + " clipboard")
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show userassist key values.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='34':
      os.system("volatility -f " + fileName + PRO + " userassist")
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show the console information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='35':
      os.system("volatility -f " + fileName + PRO + " consoles")
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Auto analyse the running processes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='37':
      os.system("volatility -f " + fileName + PRO + " psscan --output greptext > F1.txt")
      os.system("tail -n +2 F1.txt > F2.txt")
      os.system("sed -i 's/>//g' F2.txt")
      with open("F2.txt") as fp:
         for line in fp:
            for word in line.split('|'):
		os.system("echo " + word + " >> F3.txt")
      os.system("tail -n +2 F3.txt > F4.txt")
      os.system("wc -l F2.txt > NUM.txt")
      NUMLINES = open("NUM.txt").readline().replace(' F2.txt','')
      COUNT = int(NUMLINES)
      print "[1]. There were",COUNT,"processes running at the time of the memory dump.\n"
      f2 = open('PID.txt','w')
      f3 = open('PPID.txt','w')
      with open('F4.txt') as f:
         while COUNT > 0:
            A = f.readline()
            B = f.readline() # Executable name
            C = f.readline().rstrip('\n') # PID
            print >>f2,C
            D = f.readline().rstrip('\n') # PPID             
            print >>f3,D		
            E = f.readline()
            G = f.readline()
            H = f.readline() # blank
            COUNT = (COUNT-1)
      fp.close()
      f2.close()
      f3.close()
      os.remove('F1.txt')
      os.remove('F2.txt')
      os.remove('F3.txt')
      os.remove('F4.txt')
      os.system("bash sort.sh")
      print "[2]. Analyse of these processes reveals that:"
      with open('SUSPECT.txt') as fp:
         line = fp.readline().rstrip('\n')
         while line != "":
            print "     Parent process PPID",line, "does not have a process spawn! and should be investigated further..."
            line = fp.readline().strip('\n')
      fp.close()
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show running processes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='38':
      os.system("volatility -f " + fileName + PRO + " psscan | more")
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show running services.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='39':
      os.system("volatility -f " + fileName + PRO + " svcREG | more")
      selection=raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Exit the program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='44':
      exit(0)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Clean up system files and exit the program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='45':
      if os.path.exists('MD5SUM.txt'):
         os.remove('MD5SUM.txt')
      if os.path.exists('F2.txt'):
         os.remove('F2.txt')
      if os.path.exists('hivelist.txt'):
         os.remove('hivelist.txt')
      if os.path.exists('timeline.txt'):
         os.remove('timeline.txt')
      if os.path.exists("bulkOut"): 
         os.system('cd bulkOut; rm *.*; cd ..')
         os.rmdir('bulkOut') 
      if os.path.exists('workArea'):
         os.system('cd workArea; rm *.*; cd ..')
         os.rmdir('workArea')
      exit(0)

#Eof...
