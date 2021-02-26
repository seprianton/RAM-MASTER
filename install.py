#!/usr/bin/python
# coding:UTF-8

import os
import sys

os.system("wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip")
os.system("unzip volatility_2.6_lin64_standalone.zip")
os.system("mv volatility_2.6_lin64_standalone /opt/volatility_2.6_lin64_standalone")
os.system("rm volatility_2.6_lin64_standalone.zip")
