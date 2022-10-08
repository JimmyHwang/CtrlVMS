#!/usr/bin/python
import os
import os.path
import sys, getopt
import json
from collections import OrderedDict
import glob
import re
import json
import shutil
from sys import platform
import platform
from shutil import copyfile
from distutils.dir_util import copy_tree
import subprocess
import datetime
from time import gmtime, strftime
import logging
import hashlib
import time

VerboseFlag = False
DebugFlag = False
ConfigObj = False
LxcObj = False
QemuObj = False

#------------------------------------------------------------------------------
# Common Functions
#------------------------------------------------------------------------------    
def Exec(cmd):
  global VerboseFlag
  if VerboseFlag:
    print("Exec: %s" % (cmd))
  p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
  (output, err) = p.communicate()
  status = p.wait()
  if VerboseFlag:
    print(output)
    print("Status=%d" % (status))
  return status, output
  
def RemoveHpeBaseFolder(base, file):
  file = file.replace(base+os.sep, "")
  return file;
  
def IsHeaderFileExists (folder):
  st = False
  for file in os.listdir(folder):
    ext = os.path.splitext(file)[1]
    if ext == ".h":
      st = True
      print(folder)
      break
  return st
  
def RemoveFiles (dict):
  count = 0
  count2 = 0
  dir_list = {}
  for key, value in dict.items():
    ext = os.path.splitext(key)[1]
    if ext in RemoveTypes:
      if os.path.isfile(key):
        dir = os.path.dirname(key)
        dir_list[dir] = 1
        if DebugFlag == False:
          os.remove (key)
        count = count + 1
        if VerboseFlag:
          print("Delete %s" % (key))
  if RemoveMode == 1:
    for dir, value in dir_list.items():
      print (dir)
      if IsHeaderFileExists(dir):
        for file in os.listdir(dir):
          full = os.path.join (dir, file)
          ext = os.path.splitext(file)[1]
          if ext == ".h":
            os.remove (full)
            count2 = count2 + 1
            if VerboseFlag:
              print("Delete2 %s" % (full))
  print("Delete Files = %d (%d)" % (count, count2))
  
def SaveDict(filename, dict):
  with open(filename, 'w') as fp:
    json.dump(dict, fp)
    
def LoadDict(filename):
  dict = None
  if os.path.isfile(filename):
    fp = open(filename, "r") 
    data = fp.read() 
    dict = json.loads(data)
  return dict

def json_decode(data):
	return json.loads(data)

def json_encode(data, beauty=None):
  if beauty == True:
    return json.dumps(data, indent=2)
  else:
    return json.dumps(data)
  
def IsLinux():
  st = False
  if platform.system() == "Linux":
    st = True
  return st
  
def IsWindows():
  st = False
  if platform.system() == "Windows":
    st = True
  return st
  
def SubstrBetweenTags(str, tag1, tag2):
  result = False
  p1 = str.upper().find(tag1.upper())
  if p1 != -1:
    p1 = p1 + len(tag1)
    if tag2 != False:
      p2 = str.upper().find(tag2.upper(), p1)
      result = str[p1:p2]
    else:
      result = str[p1:]      
  return result

def RemovePathNode(pstr, rcount, lcount):
  plist = pstr.split(os.sep)
  for x in range(0, rcount):
    plist.pop(0)
  for x in range(0, lcount):
    plist.pop()
  pstr = os.path.join(*plist)
  return pstr
  
def ReadFileToStringArray(fn):
  data = ReadTextFile(fn)
  lines = data.split("\n")
  return lines
  
def WriteStringArrayToFile(fn, lines):
  fp = open(fn, 'w')
  for item in lines:
    fp.write("%s\n" % item)
  fp.close()

def RemoveComment(lbuf):
  p = lbuf.find("#")
  if p != -1:
    lbuf = lbuf[:p]
  return lbuf

def ReadTextFile(fn):  
  fp = open(fn, "r")
  data = fp.read()
  fp.close()
  return data
  
def WriteTextFile(fn, data):
  fp = open(fn,"w")
  fp.write(data) 
  fp.close() 
  
def RelatedPath (folder, fn):
  l = len(folder)  
  if fn.find(folder.lower()) == 0:
    result = fn[l+1:]
  else:
    result = fn
  return result

def IsArray(obj):
  return type(obj).__name__ == 'list'

def hex_decode(hstr):
  value = False
  if "0x" in hstr and hstr.find("0x") == 0:
    value = int(hstr, base=16)
  return value

def ExpendSpace(line, num):
  while len(line) < num:
    line = line + " "
  return line

def GetHeadSpace(line):
  result = ""
  new_line = line.lstrip()
  c = len(line) - len(new_line)
  if c > 0:
    result = line[0:c]
  return result

def MD5(data):
  md5 = hashlib.md5()
  md5.update(data.encode('utf-8'))
  return md5.hexdigest()
  
#------------------------------------------------------------------------------
# CONFIG_CLASS
#------------------------------------------------------------------------------    
class CONFIG_CLASS:
  def __init__(self, fn):
    self.BaseFile = fn
    self.Data = {}
    self.MD5 = False
    self.Load()
    
  def Load(self):
    if os.path.exists(self.BaseFile):
      jstr = ReadTextFile(self.BaseFile)
    else:
      jstr = "{}"
    self.Data = json_decode(jstr)
    self.MD5 = MD5(jstr)      
    
  def Save(self):
    jstr = json_encode(self.Data, True)
    md5 = MD5(jstr)
    if md5 != self.MD5 or os.path.exists(self.BaseFile) == False:
      self.MD5 = md5
      WriteTextFile(self.BaseFile, jstr)
    
#------------------------------------------------------------------------------
# QEMU_CLASS
#------------------------------------------------------------------------------    
class QEMU_CLASS:
  def __init__(self):
    self.Tag = "QEMU"
    self.Items = ConfigObj.Data[self.Tag]

  def InitCfg(self):
    result = False
    cmds = "virsh list"
    (status, output) = Exec(cmds)
    lines = output.splitlines()
    self.Items = []
    for line in lines:
      fields = line.decode("utf-8").split()
      if len(fields) == 3:
        vm_id = fields[0]
        vm_name = fields[1]
        vm_state = fields[2]
        if vm_id != "Id" and vm_state == "running":
          item = {}
          item["Name"] = vm_name
          item["Managed"] = 1
          self.Items.append(item)
    ConfigObj.Data[self.Tag] = self.Items
    return result

  def WaitingFinish(self):
    quit = False
    count = 0
    while quit == False:
      delay_flag = False
      for item in self.Items:
        if item["Managed"] == 1:
          vm_name = item["Name"]
          vm_state = self.GetVmState(vm_name)
          if vm_state == "running":
            delay_flag = True
      if delay_flag == False:
        quit = True
      else:
        count = count + 1
        print("Info: Delay 10 seconds for waiting VM shutdown (%d)" % count)
        time.sleep(10)
        if count == 6:
          count = 0
          print("Info: Send shutdown signal to VM again")
          self.ShutdownAll()
    
  def Startup(self, name):
    print("Startup QEMU VM [%s]" % name)
    cmds = "virsh start %s" % (name)
    Exec(cmds)
  
  def Shutdown(self, name):
    print("Shutdown QEMU VM [%s]" % name)
    cmds = "virsh shutdown %s" % (name)
    Exec(cmds)
  
  def GetItemInfo(self, name):
    result = False
    for item in self.Items:
      if item["Name"] == name:
        result = item
        break
    return result
  
  #
  # return False      - VM not found
  #        "running"  - VM is running
  #
  def GetVmState(self, name):
    result = False
    cmds = "virsh list"
    (status, output) = Exec(cmds)
    lines = output.splitlines()
    for line in lines:
      fields = line.decode("utf-8").split()
      if len(fields) == 3:
        vm_id = fields[0]
        vm_name = fields[1]
        vm_state = fields[2]
        if vm_id != "Id" and vm_name == name:
          result = vm_state
    return result
    
  def StartupAll(self):
    for item in self.Items:
      if item["Managed"] == 1:
        vm_name = item["Name"]
        vm_state = self.GetVmState(vm_name)
        if vm_state != "running":
          self.Startup(vm_name)
        
  def ShutdownAll(self):
    for item in self.Items:
      if item["Managed"] == 1:
        vm_name = item["Name"]
        vm_state = self.GetVmState(vm_name)
        if vm_state == "running":
          self.Shutdown(vm_name)
        
  def Debug(self):
    cmds = "virsh list"
    (status, output) = Exec(cmds)
    lines = output.splitlines()
    for line in lines:
      fields = line.decode("utf-8").split()
      if len(fields) == 3:
        vm_id = fields[0]
        if vm_id != "Id":
          vm_name = fields[1]
          vm_status = fields[2]
          item = self.GetItemInfo(vm_name)
          if item != False:
            if vm_status == "running":
              print("vm_status")
              self.Shutdown(vm_name)
    
#------------------------------------------------------------------------------
# LXC_CLASS
#------------------------------------------------------------------------------    
class LXC_CLASS:
  def __init__(self):
    global ConfigObj
    self.Tag = "LXC"
    self.Items = ConfigObj.Data[self.Tag]
  
  def InitCfg(self):
    cmds = "lxc-ls -f"
    (status, output) = Exec(cmds)
    lines = output.splitlines()
    self.Items = []
    for line in lines:
      fields = line.decode("utf-8").split()
      if len(fields) == 7:
        vm_name = fields[0]
        vm_state = fields[1]
        vm_auto_start = fields[2]
        if vm_state == "RUNNING":
          item = {}
          item["Name"] = vm_name
          item["Managed"] = 1
          self.Items.append(item)
    ConfigObj.Data[self.Tag] = self.Items
     
  def Startup(self, name):
    print("Startup LXC Container [%s]" % name)
    cmds = "lxc-start -n %s" % (name)
    Exec(cmds)

  def Shutdown(self, name):
    print("Shutdown LXC Container [%s]" % name)
    cmds = "lxc-stop -n %s" % (name)
    Exec(cmds)
    
  def GetItemInfo(self, name):
    result = False
    for item in self.Items:
      if item["Name"] == name:
        result = item
        break
    return result
    
  #
  # retuen False      - Container not foundf
  #        "RUNNING"  - Container is running
  #
  def GetContainerState(self, name):
    result = False
    cmds = "lxc-ls -f"
    (status, output) = Exec(cmds)
    lines = output.splitlines()
    for line in lines:
      fields = line.decode("utf-8").split()
      if len(fields) == 7:
        vm_name = fields[0]
        vm_state = fields[1]
        vm_auto_start = fields[2]
        if vm_name == name:        
          result = vm_state
    return result
    
  def StartupAll(self):
    for item in self.Items:
      if item["Managed"] == 1:
        vm_name = item["Name"]
        vm_state = self.GetContainerState(vm_name)
        if vm_state != "RUNNING":
          self.Startup(vm_name)
        
  def ShutdownAll(self):
    for item in self.Items:
      if item["Managed"] == 1:
        vm_name = item["Name"]
        vm_state = self.GetContainerState(vm_name)
        if vm_state == "RUNNING":
          self.Shutdown(vm_name)
          
  def Debug(self):
    cmds = "lxc-ls -f"
    (status, output) = Exec(cmds)
    lines = output.splitlines()
    for line in lines:
      fields = line.decode("utf-8").split()
      if len(fields) == 7:
        vm_name = fields[0]
        vm_state = fields[1]
        vm_auto_start = fields[2]
        if vm_auto_start == "1":
          if vm_state == "RUNNING":
            self.Shutdown(vm_name)          
    
#------------------------------------------------------------------------------
# Functions
#------------------------------------------------------------------------------    
def StartupAll():
  QemuObj.StartupAll()
  LxcObj.StartupAll()
  
def ShutdownAll():
  QemuObj.ShutdownAll()
  LxcObj.ShutdownAll()
  QemuObj.WaitingFinish()
  
def InitConfigFile():
  QemuObj.InitCfg()
  LxcObj.InitCfg()
  
def TestCode():
  global QemuObj
  # QemuObj.List()
  QemuObj.ShutdownAll()
  # QemuObj.StartupAll()
  # LxcObj.List()
  
#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------    
# --dsc
# --fdf --dsc
# --autogen xxxxxx
# --autogen xxxxxx --dsc all --ptag MdePkg
#
def Help():
  print('python3 CtrlVMS.py -s -c --dest xxxx')
  print('   -h          Help')
  print('   --startup   Startup all managed VM & container')
  print('   --shutdown  Shutdown all managed VM & container')
  print('   --initcfg   Initialize Config File')
  print('   -v          Verbose flag')
  sys.exit()
  
def main(argv):
  global VerboseFlag
  global DebugFlag 
  global ConfigObj
  global LxcObj
  global QemuObj
  
  ScriptName = os.path.splitext(__file__)[0]
  log_fn = ScriptName+".log"
  cfg_fn = ScriptName+".cfg"
  logging.basicConfig(filename=log_fn, level=logging.DEBUG)  
  ConfigObj = CONFIG_CLASS(cfg_fn)
  LxcObj = LXC_CLASS()
  QemuObj = QEMU_CLASS()
  TestFlag = False
  StartupFlag = False
  ShutdownFlag = False
  InitCfgFlag = False
  
  try:
    opts, args = getopt.getopt(argv,"tv",["initcfg", "startup", "shutdown", "rpath="])
  except getopt.GetoptError:
    Help()
  for opt, arg in opts:
    if opt == '-h':
      Help()
    elif opt == '-v':
       VerboseFlag = True
    elif opt == '-l':
       LogFile = arg
    elif opt == '--debug':
       DebugFile = True
    elif opt == '--startup':
       StartupFlag = True
    elif opt == '--shutdown':
       ShutdownFlag = True
    elif opt == '--initcfg':
       InitCfgFlag = True
    elif opt == '-t':
       TestFlag = True
    
  if TestFlag:     
    TestCode()
  elif StartupFlag:
    StartupAll()
  elif ShutdownFlag:
    ShutdownAll()
  elif InitCfgFlag:
    InitConfigFile()
        
  ConfigObj.Save()
  
if __name__ == "__main__":
   main(sys.argv[1:])
else:
  print("Error: too few arguments ")
