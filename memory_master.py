#!/usr/bin/python
# coding:UTF-8

# -------------------------------------------------------------------------------------
#      PYTHON UTILITY SCRIPT FILE FOR THE FORENSIC ANALYSIS OF MEMORY DUMP-FILES
#               BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Load any requiwhite imports and initialise program variables.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import subprocess
import os.path
import fileinput
import shutil
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
# Details : Display universal header.    
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def header ():
   os.system("clear")

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
# Details : Display pertinant system information.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def display():
   print "="*19,
   print colored("SYSTEM",'white'),
   print "="*25,
   print colored("WINDOWS HIVES",'white'),
   print "="*21,
   print colored("LINUX",'white'),
   print "="*25,
   print colored("MAC",'white'),
   print "="*8
   print "FILENAME [",
   print colored(str.upper(fileName[:24]),'blue'),
   print "] SAM       [",
   if (REG == 0) and (SAM == "0x0000000000000000"):
      print colored(SAM[:24],'red'),
   elif (REG == 1) and (SAM == "0x0000000000000000"):
      print colored(SAM[:24],'white'),
   else:
      print colored(SAM[:24],'blue'),
   print "] PASSWD   [",
   if PWD == "0x0000000000000000":
      print colored(PWD,'red'),
   else:
       print colored(PWD,'blue'),
   print "] RESERVED [ " + UN5 + " ]"
   print "PROFILE  [",
   if DIS == "UNSELECTED              ":
      print colored(str.upper(DIS[:24]),'red'),
   else:
      print colored(str.upper(DIS[:24]),'blue'),
   print "] SECURITY  [",
   if SEC == "0x0000000000000000":
      print colored(SEC[:24],'red'),
   else:
      print colored(SEC[:24],'blue'),
   print "] SHADOW   [",
   if SHW == "0x0000000000000000":
      print colored(SHW,'red'),
   else:
      print colored(SHW,'blue'),
   print "] RESERVED [ " + UN6 + " ]"
   print "PID      [",
   if PI1[:1] == "0":
      print colored(PI1[:24],'red'),
   else:
      print colored(PI1[:24],'blue'),
   print "] SOFTWARE  [",
   if SOF == "0x0000000000000000":
      print colored(SOF[:24],'red'),
   else:
      print colored(SOF[:24],'blue'),
   print "] RESERVED [ " + UN2 + " ] RESERVED [ " + UN7 + " ]"
   print "PPID     [",
   if PI2[:1] == "0":
      print colored(PI2[:24],'red'),
   else:
      print colored(PI2[:24],'blue'),
   print "] COMPONENT [",
   if COM == "0x0000000000000000":
      print colored(COM[:24],'red'),
   else:
      print colored(COM[:24],'blue'),
   print "] RESERVED [ " + UN3 + " ] RESERVED [ " + UN8 + " ]"
   print "PARAM    [",
   if PRM == "UNSELECTED              ":
      print colored(PRM[:24],'red'),
   else:
      print colored(str.upper(PRM[:24]),'blue'),
   print "] SYSTEM    [",
   if SYS == "0x0000000000000000":
      print colored(SYS[:24],'red'),
   else:
      print colored(SYS[:24],'blue'),
   print "] RESERVED [ " + UN4 + " ] RESERVED [ " + UN9 + " ]"
   print "*"*134
   print " "*9,
   print colored("SETTINGS",'white'),
   print " "*14,
   print colored("IDENTIFY",'white'),
   print " "*15,
   print colored("ANALYSE",'white'),
   print " "*13,
   print colored("INVESTIGATE",'white'),
   print " "*18,
   print colored("EXTRACT",'white'),
   print " "*10
   print "*"*134

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Initialise program variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

PRO = "UNSELECTED              "
DIS = "UNSELECTED              "
PRM = "UNSELECTED              "
PI1 = "0                       "
PI2 = "0                       "
SAM = "0x0000000000000000"
SEC = "0x0000000000000000"
SOF = "0x0000000000000000"
COM = "0x0000000000000000"
SYS = "0x0000000000000000"
PWD = "RESERVED          "
SHW = "RESERVED          "
UN2 = "0x0000000000000000"
UN3 = "0x0000000000000000"
UN4 = "0x0000000000000000"
UN5 = "0x0000000000000000"
UN6 = "0x0000000000000000"
UN7 = "0x0000000000000000"
UN8 = "0x0000000000000000"
UN9 = "0x0000000000000000"
SCA = 0
REG = 0

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Create a menu system.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

menu = {}
menu['(1)']="Windows PROFILE	(10) Host Name		(20) SAM		(30) Search PARAM	(40) Timeline"
menu['(2)']="Linux PROFILE	(11) User Passwords	(21) SECURITY		(31) Malfind PID	(41) Screenshots"
menu['(3)']="Mac PROFILE\t	(12) List Processes	(22) SOFTWARE		(32) Mutant PID		(42) MFT Table"
menu['(4)']="Set PID		(13) List Services	(23) COMPONENT		(33) Vaddump PID	(43) " 
menu['(5)']="Set PPID		(14) Show Clipboard	(24) SYSTEM		(34) Dump PID		(44) "
menu['(6)']="Set PARAM		(15) Show Console	(25) Network Traffic	(35) 			(45) Bulk Extractor"
menu['(7)']="			(16) Show Assist Keys	(26) 			(36)			(46) Clean and Exit"


# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   header()
   display()
   options=menu.keys()
   options.sort()
   for entry in options: 
      print entry, menu[entry]
   selection=raw_input("\nPlease Select: ")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Obtain the correct Microsoft Windows PROFILE from
#         : memory file and populate HIVE values.
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
      os.remove('IMAGE.txt')
      
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
      os.remove('hivelist.txt')

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Grab the profile settings from the user.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='2':
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
# Details : Menu option selected - Grab the profile settings from the user.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='3':
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
# Details : Menu option selected - User set the PID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='4':
      PI1 = raw_input("Please enter PID value: ")
      while len(PI1) < 24:
         PI1 += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - User set the PPID.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='5':
      PI2 = raw_input("Please enter PPID value: ")
      while len(PI2) < 24:
         PI2 += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - User set the Parameter.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='6':
      PRM = raw_input("Please enter parameter value: ")
      while len(PRM) < 24:
         PRM += " "

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Print hostname.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='10':
      print ""
      os.system("volatility -f " + fileName + PRO + " printkey -o " + SYS + " -K 'ControlSet001\Control\ComputerName\ComputerName'")
      raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Dump SAM file hashes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='11':
      print ""
      if (SAM == "0x0000000000000000") or (SYS == "0x0000000000000000"):
         print colored("Missing HIVE - its not possible to extract the hashes...",'white')	
      else:
         os.system("volatility -f " + fileName + PRO + " hashdump -y " + SYS + " -s " + SAM)
      raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show running processes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='12':
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
            D = read4.readline().rstrip('\n') # PI2             
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
      raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show running services.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='13':
      os.system("volatility -f " + fileName + PRO + " svcscan | more")
      raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show the clipboard
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='14':
      os.system("volatility -f " + fileName + PRO + " clipboard")
      raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show the console information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='15':
      os.system("volatility -f " + fileName + PRO + " consoles")
      raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show userassist key values.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='16':
      os.system("volatility -f " + fileName + PRO + " userassist")
      raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show SAM hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='20':
      os.system("volatility -f " + fileName + PRO + " hivedump -o " + SAM)
      raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show SECURITY hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='21':
      if (SEC == "0x0000000000000000"):
         print colored("Not possible...",'white')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + SEC)
      raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show SOFTWARE hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='22':
      if (SOF == "0x0000000000000000"):
         print colored("Not possible...",'white')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + SOF)
      raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show COMPONENT hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='23':
      if (COM == "0x0000000000000000"):
         print colored("Not possible...",'white')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + COM)
      raw_input("\nPlease any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Show SYSTEM hives.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='24':
      if (SYS == "0x0000000000000000"):
         print colored("Not possible...",'white')
      else:
         os.system("volatility -f " + fileName + PRO + " hivedump -o " + SYS)
      raw_input("\nPlease any key to continue...")    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Extract network traffic.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='25':
      os.system("volatility -f " + fileName + PRO + " netscan")
      raw_input("\nPlease any key to continue...")

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Search PARAM.
# Modified: N/A
# ------------------------------------------------------------------------------------- 
   
   if selection =='30':
      os.system("volatility -f " + fileName + " " + PRO + " pslist | grep " + PRM)
      raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Find Malware!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='31':
      test = os.path.exists('malFind')
      if test !=1:
         os.system('mkdir malFind')
      os.system("volatility -f " + fileName + PRO + " malfind -p " + PI1 + " --dump-dir malFind")
      print "\nMalfind extraction is now available in directory malFind...\n"
      raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Find Mutants!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      test = os.path.exists('mutantFiles')
      if test !=1:
         os.system('mkdir mutantFiles')
      os.system("volatility -f " + fileName + PRO + " handles -p " + PI1 + " -t mutantFiles -s")
      print "\nMutant extraction is now available in directory mutantFiles...\n"
      raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected -  Vaddump!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='33':
      test = os.path.exists('vadDump')
      if test !=1:
         os.system('mkdir vadDump')
      os.system("volatility -f " + fileName + PRO + " vaddump -p " + PI1 + " -D vadDump")
      print "\nVaddunp extraction is now available in directory vadDump...\n"
      raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Memory dump PI1.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='34':
      test = os.path.exists('PIData')
      if test !=1:
         os.system('mkdir PIData') 
      os.system("volatility -f " + fileName + PRO + " memdump -p " + PI1 + " -D PIData")
      print "\nPID dump is now available in directory PIData...\n"
      raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Build timeline.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='40':
      os.system("volatility -f " + fileName + PRO + " timeliner --output-file timeline.txt")

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Download windows screenshot.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='41':
      test = os.path.exists('screenShots')
      if test !=1:
         os.system('mkdir screenShots')   
      os.system("volatility -f " + fileName + PRO + " -D screenShots screenshot")
      print "\nScreenshots are now available in directory screenShots...\n"
      raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - MFT Extract.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='42':
      os.system("volatility -f " + fileName + PRO + " mftparser >> mfttable.txt")
      print "The MFT has been sucessfully exported to mfttable.txt..."
      raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Bulk Extract.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='45':
      os.system("bulk_extractor -o bulkOut " + fileName)
      print "\nBulk extraction is now available in directory bulkOut...\n"
      raw_input("Please any key to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Clean up system files and exit the program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='46':
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

#Eof...
