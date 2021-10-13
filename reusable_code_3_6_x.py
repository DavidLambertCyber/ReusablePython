r'''
code tested with python 3.6.3+

example of global varibles declare and use
import pprint #debug;
a_global_varible

def a_func(bla)
  global a_global_varible # brings the global locally
  do stuff
  print a_global_varible
  
import pprint #debug
pp = pprint.PrettyPrinter(indent=2)#debug
#pp.pprint(os.scandir(FRScript['Get_FileMetadata.py'][2]))#debug

'''
def get_full_paths_size(StartDir): # return [[size,path],...] sorted by largest size
  ListFiles = []
  for root,dirs,files in os.walk(StartDir):
    for AFile in files:
      f_path = os.path.join(root,AFile)
      f_size = os.path.getsize(f_path)
      ListFiles.append([f_size,f_path])
  ListFiles.sort(reverse=True)
  return ListFiles

  def _convertList_toListOfLists(self,alist: list,maxlen: int = 25):
    #return list of lists
    cnt = 0
    subList = []
    alistOFLists = []
    if len(alist) < maxlen:
      alistOFLists.append(alist.copy())
      return alistOFLists

    for thing in alist:
      cnt += 1
      if cnt % maxlen == 0:
        alistOFLists.append(subList.copy())
        subList = []
      subList.append(thing)
      
    alistOFLists.append(subList.copy())
    PP.pprint(alistOFLists);sys.exit(0)#debug
    return alistOFLists

def JSONFile_ToDict(AFile):
  import json
  results = {}
  data = b""
  READ_FLAGS = os.O_RDONLY | os.O_BINARY
  BUFFER_SIZE = 128*1024
  fin = os.open(AFile, READ_FLAGS)
  for x in iter(lambda: os.read(fin, BUFFER_SIZE), b""):
    data += x
  os.close(fin)
  
  results = json.loads(data)
  return results

def example_date():
  # import datetime
  name = datetime.datetime.today().strftime('%Y%m%d')+'_Duplicate_Files_Deleted.csv'

def string_toDate(self,astring: str,dateFormat: str):
  #from datetime import datetime
  #07/06/17 = "%m/%d/%y"
  #20021225 = "%Y%m%d"
  adate = datetime.strptime(astring, dateFormat)
  return adate

def market_isOpen(): #return True during market hours, else return seconds till open,return -1 on error
  #holidays are not addressed
  now = datetime.datetime.now()
  market_open = now.replace(hour=9,minute=30,second=0,microsecond=0)
  market_open_morrow = (now.replace(day=(now.day + 1),hour=9,minute=30,second=0,microsecond=0))
  market_close = now.replace(hour=16,minute=0,second=0,microsecond=0)
  
  if now.weekday() < 5: #not weekend
    if now.hour >= market_open.hour and now.hour < market_close.hour: #between 0930 - 1600
      if now.hour == 9:
        if now.minute > 29:
          return True
      return True
    elif now.hour < market_open: #before market open
      now = datetime.datetime.now()
      return int(math.ceil((market_open - now).total_seconds()))
    elif now.hour >= market_close.hour: #after market open
      now = datetime.datetime.now()
      return int(math.ceil((market_open_morrow - now).total_seconds()))
  elif now.weekday() == 5:#Saturday
    now = datetime.datetime.now()
    market_open_next = (now.replace(day=(now.day + 2),hour=9,minute=30,second=0,microsecond=0))
    return int(math.ceil((market_open_next - now).total_seconds()))
  elif now.weekday() == 6:#Sunday
    now = datetime.datetime.now()
    market_open_next = (now.replace(day=(now.day + 1),hour=9,minute=30,second=0,microsecond=0))
    return int(math.ceil((market_open_next - now).total_seconds()))
    
  return -1

def Extract_MD5(AFile,DoSort): #get content of file and extract MD5, return list of MD5 all upper
  # 6B603D1E604C672E5E08EC4599CB77CC
  Regex = '(?<=\W)[a-fA-F0-9]{32}(?=\W)'
  Results = []
  Data = GC_Lines(AFile,'r',False)
  AMD5 = None
  for ALine in Data:
    AMD5 = egrep(Regex,ALine)
    if AMD5 == False:
      continue
    Results.append(str(AMD5.upper()+'\n'))
  
  if DoSort:
    Results.sort()
 
  return Results

def Upper_List(AList): # take a list and upper everything
  Results = []
  for ALine in AList:
    Results.append(ALine.upper())
 
  return Results

def GC_Lines(AFile,Mode,DoSort):# Get-Contents of AFile return Lines,  Mode='r'|'b', DoSort = True|False
  Results = None
  with open(AFile,Mode,errors='replace') as fd:
    Results = fd.readlines()
  
  if DoSort:
    Results.sort()
    
  return Results

def Out_File(AList,AFile): # write list of lines to a file, AList should have \n in item
  with open(AFile, 'w',errors='replace') as f:
    for item in AList:
      f.write("%s" % item)
  
  return True 


def Get_FullPaths(StartDir): # return array of full paths from StartDir
  ListFiles = []
  for root,dirs,files in os.walk(StartDir):
    for AFile in files:
      ListFiles.append(os.path.join(root,AFile))

  return ListFiles

  
def Usage():#todo update
  print(r'''
SYNOPSIS
  Convert-NSRLToMD5.py <NSRLFile> <ResultFileMerge>

OPTIONS
  
DESCRIPTION
 
  
  Tested Python 3.8.2

OUTPUT
   

EXAMPLE
 

STATS
  
 
''')

def Parse_Args():
  arglen = len(sys.argv)
  arglenstr = str(arglen)
  global NSRLFile,ResultFileMerge
  
  if arglen < 2 or arglen > 3:
    Usage()
    sys.exit(str(sys.argv[0])+' Error: got '+arglenstr+' arguments')

  if arglen == 2:
    NSRLFile = PurePath(Path(sys.argv[1]).resolve())
  if arglen == 3:
    NSRLFile = PurePath(Path(sys.argv[1]).resolve())
    ResultFileMerge = PurePath(Path(sys.argv[2]).resolve())

  return True

def usage():
  print(r'''
SYNOPSIS
Invoke_Trader.py [-l|-s|-v]

OPTIONS
  -b | --budget <amount-to-invest>
      Set the max amount of money used to buy stocks. 
      0 = (default) simulate, no buying occurs
      -1 = use all avalible funds in account.

  -c | --collect
      Collect Live data and dump to CSV. No calculations.

  -l | --live 
      Access the E*TRADE API using the LIVE credentials stored in the CONFIG.ini file.

  -s | --sandbox (default)
      Access the E*TRADE API using the SANDBOX credentials stored in the CONFIG.ini file.

  -v | --verbose
      Output to stdout details of program action, this is more verbose than the logs.
      Otherwise minimal output.

DESCRIPTION
  Gather statistics and make stock market trades accordingly using the E*TRADE
  API.
  
  Tested Python 3.8.2

OUTPUT
  Writes CSV files containing statistics, each file named by the ticker symbol 
  and saved to current directory. 

EXAMPLE
  Commandline
    $ py.exe .\Invoke_Trader.py -l
    $ Remove-Item *.csv ;cls;py.exe .\Invoke_Trader.py -l
    
  Sample CONFIG.ini file
    [LIVE]
    CONSUMER_KEY = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    CONSUMER_SECRET = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    SANDBOX_BASE_URL=https://apisb.etrade.com
    PROD_BASE_URL=https://api.etrade.com
    [SANDBOX]
    CONSUMER_KEY = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    CONSUMER_SECRET = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    SANDBOX_BASE_URL=https://apisb.etrade.com
    PROD_BASE_URL=https://api.etrade.com
    [LOGS]
    #DEBUG|INFO|WARNING|ERROR|CRITICAL
    LOG_LEVEL=DEBUG

STATS
  ''')

def parse_args(): #GOOD FOR LOOP
  global KEY_TYPE,VERBOSE,COLLECT,BUDGET
  arglen = len(sys.argv)
  arg = sys.argv
  opt = ''
  optList = ['-l','--live','-s','--sandox','-v','--verbose','-c','--collect','-b','--budget']

  if arglen == 0:
    KEY_TYPE = 'SANDBOX'
    return True
  
  
  for i,v in enumerate(arg):
    opt = v.lower()
    if '-' in opt and opt not in optList:
      print("Error arguments: not valid argument",file=sys.stderr,flush=True)
      usage()
      sys.exit(-1)
    if opt == '-l' or opt == '--live':
      KEY_TYPE = 'LIVE'
    if opt == '-s' or opt == '--sandbox':
      KEY_TYPE = 'SANDBOX'
    if opt == '-v' or opt == '--verbose':
      VERBOSE = True
    if opt == '-c' or opt == '--collect':
      COLLECT = True
      VERBOSE = True
      KEY_TYPE = 'LIVE'
    if opt == '-b' or opt == '--budget':
      if not arg[i+1].isdigit():
        print("Error arguments: -b or --budget must be followed by a number.",file=sys.stderr, flush=True )
        usage()
        sys.exit(-1)
      BUDGET = int(arg[i+1])
  
  return True

def Check_OSIsWindows():
  import platform
  global logging
  OSSystem = platform.system()
  if OSSystem == 'Windows':
    return True
  logging.critical('Windows only. Got '+OSSystem)
  Usage()
  return False

def exe_cmd (): #example, needs rewrite
  sigOut = subprocess.run([sigPath, '-nobanner','-a',AFile],stdout=subprocess.PIPE,shell=True).stdout.decode('utf-8') # use sigOut.stdout to access #result.stdout.decode('utf-8')
  return sigOut

def CsvTo_Dict(aCsv):#need testing
  #import csv
  resultDict = {}

  with open(aCsv,'r') as csvfile:
    r = csv.DictReader(csvfile,delimiter=',')

    for row in r:
      key = row[0]
      if key in result:
          # implement your duplicate row handling here
          pass
      result[key] = row[1:]
    
  return resultDict

def csv_to_listofdict(a_csvPath):#need testing
  #import csv
  list_dict = []
  with open(a_csvPath) as csvfile:
    r = csv.DictReader(csvfile)
    for line in r:
      print(line)
      list_dict.append(line)
    
  return list_dict

def fill_list_string(a_string,a_len):
  a_list = [a_string] * a_len
  return a_list

def get_value_from_listofdict(a_listofdict, a_term):#need testing
  for a,b in a_listofdict:
    if b.lower() is a_term:
      print (b)

def listOfDict_ToCsv(csvFilePath,listOfDict):
  keys = listOfDict[0].keys()
  with open(csvFilePath , 'w', newline='')  as output_file:
    dict_writer = csv.DictWriter(output_file, keys)
    dict_writer.writeheader()
    dict_writer.writerows(listOfDict)
  return True 
      
def dict_of_lists_to_concordance_dat(csv_file_name,a_dict_of_lists): # convert a dictionary of lists to DAT file
  # always fill fields with something
  # import csv
  COLUMN = '\x14'
  QUOTE = '\xfe'
  # requires BOM
  sorted_keys=sorted(a_dict_of_lists.keys())
  with open(csv_file_name, 'w', newline='') as f:
    w = csv.writer(f,delimiter=COLUMN,quotechar=QUOTE,quoting=csv.QUOTE_ALL)
    w.writerow(sorted_keys)
                        
    w.writerows(zip(*[a_dict_of_lists[k] for k in sorted_keys]))

def dict_of_lists_to_csv(csv_file_name,a_dict_of_lists): # convert a dictionary of lists to csv file
  # always fill fields with something
  # import csv
  sorted_keys=sorted(a_dict_of_lists.keys())
  with open(csv_file_name, 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(sorted_keys)
                        
    w.writerows(zip(*[a_dict_of_lists[k] for k in sorted_keys]))

def get_md5_dict_exclude(a_filePath,a_regexExclude): # parse a directory for all files except ones match a_regexExclude, get md5, return as dictionary
  # import os
  # requires def get_hash(a_filePath, a_hashType)
  # requires def egrep(a_regex,a_string)
  list_fileNames = []
  dict_of_md5 = {}
  a_path_test = ''
  a_md5 = ''
  
  for root,dirs,files in os.walk(a_filePath, topdown=True):
    for name in files:
      a_path_test = egrep(a_regexExclude,os.path.join(root, name))
      if a_path_test is None:
        list_fileNames.append(os.path.join(root, name))

  for a_path in list_fileNames: # if getting md5 fails, skip and log
    a_md5 = get_hash(a_path,'md5')
    if a_md5 is not None:
      dict_of_md5[a_md5]=a_path
    else:
      return
    
  return dict_of_md5  

def parse_hash_file(a_item,path_to_hash_file): # //todo -- constantly
  # import re 
  # requires def search_file(a_search_string, a_filePath)
  #contentsOfHashfile = search_file()

  a_line = search_file('SUCCESS',path_to_hash_file)
  a_hostname = ''
  
  if a_line is None:
    return
  a_item_lower = a_item.lower()
  
   
  if a_item_lower == 'success':
    if not a_line:
      return
    else:
      return 'SUCCESS'
  
  elif a_item_lower == 'md5':
    return egrep('(?<=SUCCESS )([a-fA-F0-9]{32})', a_line)
  
  elif a_item_lower == 'hostname':
    a_hostname = search_file('Acquired from Agent',path_to_hash_file)
    a_hostname = a_hostname.split('- [',1)[1]
    a_hostname = a_hostname.replace(']','').replace('\r\n','').replace('\n','').replace('\r','')
    return a_hostname
  
  elif a_item_lower == 'user': # //todo need to support Mac users --------------
    a_line = a_line[201:] # chop to paths
    a_line = a_line.split(']:[',1)[0] # get first half of both paths
    if ':\\Users\\' in a_line: # try windows path user
      a_line = egrep('(?<=Users).*',a_line) # chop to users
      a_line = a_line.split('\\')[1]
      return a_line
    elif '\\/home/' in a_line: # try linux path user
      a_line = egrep('(?<=\\/home\/).*',a_line) # chop to users
      a_line = a_line.split('/')[0]
      return a_line
    else:  #give up
      return
          
  elif a_item_lower == 'sourcepath':
    a_line = a_line[201:] # chop to paths
    a_line = a_line.split(']:[',1)[0] # get first half of both paths
    a_line = a_line[1:] # chop first char, the [
    return a_line
    
  elif a_item_lower == 'ctime':
    a_line = a_line[119:] #chop to created
    a_line = a_line[:19]
    if a_line[0] is '0' or a_line[0] is '1':
      return a_line

  elif a_item_lower == 'mtime':
    a_line = a_line[145:] #chop to modified time
    a_line = a_line[:19]
    if a_line[0] is '0' or a_line[0] is '1':
      return a_line

  elif a_item_lower == 'atime':
    a_line = a_line[171:] #chop to accessed time
    a_line = a_line[:19]
    if a_line[0] is '0' or a_line[0] is '1':
      return a_line

  elif a_item_lower == 'os':
    #determin Operating system by the source path
    # get sourcepath
    a_line = a_line[201:] # chop to paths
    a_line = a_line.split(']:[',1)[0] # get first half of both paths
    a_line = a_line[1:] # chop first char, the [
    if re.search('([A-Za-z]\:)' ,a_line):
      return 'windows'
    elif re.search('\\/',a_line):
      return 'posix'
  
  else:
    return

def remove_items(self,alist,aitem):
#remove all occurances of aitem
if isinstance(aitem,list):
  for thing in alist:
    if thing in aitem:
      alist.remove(thing)
  return alist

for thing in alist:
  if thing == aitem:
    alist.remove(thing)
return alist
    
def filter_list_files(a_fileName_Regex,a_list_Files): # Filter list of filePaths to only include regex match
  # requires def egrep(a_regex,a_string):
  result_file_list = []

  # filter to include only yara files match a_fileName_Regex
  for a_file in a_list_Files:
    if egrep(a_fileName_Regex,a_file) is not None:
      result_file_list.append(a_file)

  return result_file_list

def log_setting(a_filePath): # set the logging
  # import logging
  # defaults to append file
  # logging.debug(' This message should appear on the console')
  # logging.info(' So should this')
  # logging.warning(' And this, too')
  logging.basicConfig(filename=a_filePath,format='%(asctime)s | %(message)s', level=logging.DEBUG)

def get_num_files(start_path):
  total_size = 0
  
  for dirpath, dirnames, filenames in os.walk(start_path):
    for f in filenames:
      total_size += 1

  return total_size

def get_fileName_list(a_dir): # RECURSIVELY get list of files starting at a_dir
  # import os
  # usage: get_fileName_list('C:\\Windows')

  list_fileNames = []
  for root,dirs,files in os.walk(a_dir, topdown=False):
    for name in files:
       list_fileNames.append(os.path.join(root, name))

  return list_fileNames
  
def egrep(a_regex,a_string): # return first instance of string that match regex
  # import re
  # look before = (?<=something)
  # look after = (?=something)
  r = re.search(a_regex, a_string)
  if r is not None:
    return r.group(0)

  return False

def Extract_MD5(AFile,DoSort): #get content of file and extract MD5, return list of MD5
  # 6B603D1E604C672E5E08EC4599CB77CC
  Regex = '(?<=\W)[a-fA-F0-9]{32}(?=\W)'
  Results = []
  Data = GC_Lines(AFile,'r',False)
  AMD5 = None
  for ALine in Data:
    AMD5 = egrep(Regex,ALine)
    if AMD5 == False:
      continue
    Results.append(AMD5)
  
  if DoSort:
    Results.sort()
 
  return Results


def evtx_to_xml(Path_to_evtx): #(original)
  # import Evtx.Evtx as evtx
  # import Evtx.Views as e_views

  with evtx.Evtx(Path_to_evtx) as log:
    print(e_views.XML_HEADER)
    print("<Events>")
    for record in log.records():
        print(record.xml())
    print("</Events>")

  
  
def filter_list_files_extensionlist(a_list_whitelist_extensions, a_list_Files, keepBlankExt):
  # requires def egrep(a_regex,a_string):
  result_file_list = []

  # filter to include only files match an extension
  for a_file in a_list_Files:
    if keepBlankExt:
      if '.' not in ntpath.basename(a_file):
        result_file_list.append(a_file)
        continue        
    for a_ext in a_list_whitelist_extensions:
      if a_file.endswith('.'+a_ext):
        result_file_list.append(a_file)

  return result_file_list


def get_hash(a_filePath, a_hashType): # md5,sha1,sha256,sha512 (a_hashType) of a file (a_filePath) 
  # import hashlib
  # usage: get_hash('C:\\Windows\\notpad.exe','SHA1')

  blockSize = 1048576
  hasher = ''
  hashertype = a_hashType.lower()

  if hashertype == 'md5':
    hasher = hashlib.md5()
  elif hashertype == 'sha1':
    hasher = hashlib.sha1()
  elif hashertype == 'sha256':
    hasher =  hashlib.sha256()
  elif hashertype == 'sha512':
    hasher = hashlib.sha512()
  else:
    return

  try:
    with open(a_filePath, 'rb') as aFile:
      buf = aFile.read(blockSize)
      while len(buf) > 0:
        hasher.update(buf)
        buf = aFile.read(blockSize)
  except:
    return

  return hasher.hexdigest()

def get_md5_dict_of_filelist(a_fileList): # parse a directory for all files except ones match a_regexExclude, get md5, return as dictionary
  # import os
  # requires def get_hash(a_filePath, a_hashType)
  dict_of_md5 = {}
  a_md5 = ''

  for a_path in a_fileList: # if getting md5 fails, skip and log
    a_md5 = get_hash(a_path,'md5')
    if a_md5 is not None:
      dict_of_md5[a_md5]=a_path
    else:
      return
    
  return dict_of_md5  

def search_file(a_search_string, a_filePath): # case insensitive search 
  a_list_of_matches = []
  a_line_lower = ''
  a_search_string_lower = a_search_string.lower()

  try:
    with open(a_filePath, 'r') as a_file:
      for a_line in a_file:
        a_line_lower = a_line.lower()

        if a_search_string_lower in a_line_lower:
          a_list_of_matches.append(a_line)
  except:
    return

  if not a_list_of_matches:
    return
  elif len(a_list_of_matches) == 1:
    if a_list_of_matches[0] is not '' or a_list_of_matches[0] is not None:
      return a_list_of_matches[0]
    else:
      return
  elif len(a_list_of_matches) == 0:
    return
  else:
    for a_line in a_list_of_matches:
      print (a_line) # print adds \n remove with comma


def set_MAC_powershell(a_filePath,a_timestamp,a_mac): # usage set_MAC_powershell('.\\teim.txt','12/24/2011 07:15 am','ctime | mtime | atime')
  #import subprocess,os
  # tested powershell v5.1, python 3.6.3
  
  if os.name != 'nt':
    print('Operating System is not NT, cannot execute Powershell command to change timestamp')
    return

  a_mac = a_mac.lower()
  
  a_filePathFix = a_filePath.replace('$','`$').replace('[','`[').replace(']','`]').replace('(','`(').replace(')','`)').replace('~','`~').replace('-','`-').replace("'","`'").replace('%','`%')
  
  if a_mac == 'ctime':
    try:
      subprocess.run(['powershell.exe', '$(Get-Item "'+a_filePathFix+'").creationtime=$(Get-Date "'+a_timestamp+'")'],check=True)
    except: 
      return
  elif a_mac == 'atime':
    try:
      subprocess.run(['powershell.exe', '$(Get-Item "'+a_filePathFix+'").lastaccesstime=$(Get-Date "'+a_timestamp+'")'],check=True)
    except:
      return
  elif a_mac == 'mtime':
    try:
      subprocess.run(['powershell.exe', '$(Get-Item "'+a_filePathFix+'").lastwritetime=$(Get-Date "'+a_timestamp+'")'],check=True)
    except:
      return
  else:
    return
    
  return 0

def Get_Hash(AHashAlgo,AFilePath): # get hash of file, return upper, use a file descriptor
  AHashObj = hashlib.new(AHashAlgo)
  AHash = ''
  #O_RANDOM
  #SEQUENTIAL
  
  READ_FLAGS = os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT
  BUFFER_SIZE = 64*1024

  fin = os.open(AFilePath, READ_FLAGS)
  stat = os.fstat(fin)
  for x in iter(lambda: os.read(fin, BUFFER_SIZE), b""):
    AHashObj.update(x)

  os.close(fin)
  AHash = AHashObj.hexdigest().upper()

  return AHash

def dedup_list(self,alist):
  a = set(alist)
  return list(a)

def items_to_string(self,items,seperator = '_'):
  return (seperator.join(items))
  
# ===============================================================================
# need to test and adjust below to convert to python 3.6.x 
# Below is python version 2.7 based
#===============================================================================



def unzip_file(a_filePath, a_destPath): # unzip a filePath to the directory destPath
  # import zipfile
  with zipfile.ZipFile(a_filePath, 'r') as a_zipFile:
    a_zipFile.extractall(a_destPath)

  return True
                    

def filter_md5_by_first_char(a_char,a_md5):
  r = re.match(a_char,a_md5)
  if r is not None:
    return a_md5

  return

def get_fileName_list(a_dir): # RECURSIVELY get list of files starting at a_dir
  # import os
  # usage: get_fileName_list('C:\\Windows')

  list_fileNames = []
  for root,dirs,files in os.walk(a_dir, topdown=False):
    for name in files:
       list_fileNames.append(os.path.join(root, name))

  return list_fileNames


def list_to_csv(a_constantHeader, a_constant, a_list_header, a_list, a_csv_filename):# save a list as a CSV named a_csv_filename, with header a_list_header and a constant value a_constant for each row (a_constantHeader, a_constant optional)
  # import csv
  if (a_constantHeader is not None and a_constant is not None) and (a_constantHeader is not '' and a_constant is not ''):
    with open(a_csv_filename, 'wb') as a_csv:
      a_w = csv.writer(a_csv)
      a_w.writerow([a_constantHeader, a_list_header]) #write the header row
      for a_line in a_list:
        a_w.writerow([a_constant] + [a_line])
    return 0
  elif (a_constantHeader is '' and a_constant is '') and (a_constantHeader is not None and a_constant is not None):
    with open(a_csv_filename, 'wb') as a_csv:
      a_w = csv.writer(a_csv)
      a_w.writerow([a_list_header]) #write the header row
      for a_line in a_list:
        a_w.writerow([a_line])
    return 0
  else:
    return
                                                                                                        


def egrep(a_regex,a_string): # return first instance of string that match regex
  # import re
  # look before = (?<=something) (not include somthing, matches to right)
  # look after = (?=something) ( includes something, match to right)
  r = re.search(a_regex, a_string)
  if r is not None:
    return r.group(0)

  return

def filter_list_files(a_fileName_Regex,a_list_Files): # Filter list of filePaths to only include regex match
  # requires def egrep(a_regex,a_string):
  result_file_list = []

  # filter to include only yara files match a_fileName_Regex
  for a_file in a_list_Files:
    if egrep(a_fileName_Regex,a_file) is not None:
      result_file_list.append(a_file)

  return result_file_list

def get_md5_dict_exclude(a_filePath,a_regexExclude): # parse a directory for all files except ones match a_regexExclude, get md5, return as dictionary
  # import os,re
  # requires def get_hash(a_filePath, a_hashType)
  # requires def egrep(a_regex,a_string)
  list_fileNames = []
  dict_of_md5 = {}
  a_path_test = ''
  
  
  for root,dirs,files in os.walk(a_filePath, topdown=True):
    for name in files:
      a_path_test = egrep(a_regexExclude,os.path.join(root, name))
      if a_path_test is None:
        list_fileNames.append(os.path.join(root, name))

  for a_path in list_fileNames:
    dict_of_md5[get_hash(a_path,'md5')]=a_path
    
  return dict_of_md5

def egrep_file(a_regex, a_filePath): # return matches in a_filePath that match a_regex
  # import re
  a_list_of_matches = []
  a_search = ''

  with open(a_filePath, 'r') as a_file:
    for a_line in a_file:
      a_search = re.search(a_regex, a_line)
      if a_search is not None:
        a_list_of_matches.append(a_search.group(0))

  if not a_list_of_matches:
    return

  return a_list_of_matches


def sort_file (a_inFilePath, a_outFilePath): # read an infile, sort lines, write to outFile
  # cannot handle large files, list will exceed max integer size for length
  a_list_of_lines = []

  with open(a_inFilePath, 'r') as a_inFile:
    for a_line in a_inFile:
      a_list_of_lines.append(a_line)

  a_list_of_lines.sort()

  with open(a_outFilePath, 'w') as a_outFile:
    for a_line in a_list_of_lines:
      a_outFile.write(a_line)
                                                          

def get_hash(a_filePath, a_hashType): # return the md5,sha1,sha256,sha512 (a_hashType) of a file (a_filePath) 
  # import hashlib
  # usage: get_hash('C:\\Windows\\notpad.exe','SHA1')

  blockSize = 1048576
  hasher = ''
  hashertype = a_hashType.lower()

  if hashertype == 'md5':
    hasher = hashlib.md5()
  elif hashertype == 'sha1':
    hasher = hashlib.sha1()
  elif hashertype == 'sha256':
    hasher =  hashlib.sha256()
  elif hashertype == 'sha512':
    hasher = hashlib.sha512()
  else:
    return

  with open(a_filePath, 'rb') as aFile:
    buf = aFile.read(blockSize)
    while len(buf) > 0:
      hasher.update(buf)
      buf = aFile.read(blockSize)

  return hasher.hexdigest()

def get_md5_dict(a_filePath): # parse a directory for all files, get md5, return as dictionary
  # import os
  # requires def get_hash(a_filePath, a_hashType)
  list_fileNames = []
  dict_of_md5 = {}
  
  for root,dirs,files in os.walk(a_filePath, topdown=True):
    for name in files:
       list_fileNames.append(os.path.join(root, name))

  for a_path in list_fileNames:
    dict_of_md5[get_hash(a_path,'md5')]=a_path
    
  return dict_of_md5
  


def example_create_dict_of_lists():
  a_list_of_files = get_fileName_list(STARTDIR)

  a_dict_of_lists_files = dict(MD5=[],Path=[])
  a_dict_of_lists_toDelete = dict(MD5=[],Path=[])
               
  # Hash the files and if they repeat then add to delete list.
  for filePath in a_list_of_files:
    md5 = get_hash(filePath,'md5')
    if md5 in a_dict_of_lists_files['MD5']:
      a_dict_of_lists_toDelete['MD5'].append(md5)
      a_dict_of_lists_toDelete['Path'].append(filePath)
    else:
      a_dict_of_lists_files['MD5'].append(md5)
      a_dict_of_lists_files['Path'].append(filePath)

def example_zfill(): # set then increment
  global ControlNumber_Count
  num = str(ControlNumber_Count).zfill(5)
  CONTROLNUMBER = ControlNumberPrefix+num
  LOADFILEDATA['ControlNumber'].append(CONTROLNUMBER)
  ControlNumber_Count = ControlNumber_Count +1


def prepend_file(a_prepend, a_fileName):
  # import os
  # BOM_UTF8 = '\xef\xbb\xbf'
  file_old = open(a_fileName, mode='r') 
  file_new = open('temp', mode='a')
  file_new.write(a_prepend)
  
  for line in file_old.read():
    file_new.write(line)  
  
  file_old.close()
  file_new.close()
  os.remove(a_fileName)
  os.rename('temp',a_fileName)


def example_try_catch_except():
  try:
    print 'do some shit'
  except: #do nothing except
    pass



def copy_hash_to_file(a_hash_regex, a_inFilePath, a_outFilePath): # search inFilePath for aregex and write result to outFilePath
  # import codecs
  a_hash = ''
  
  with codecs.open(a_inFilePath, 'r','utf_8', errors='ignore') as a_inFile:
    with codecs.open(a_outFilePath, 'a', 'utf-8') as a_outFile:
      # set to ignore errors, if it can't read byte it's not part of the hash
      for line in a_inFile:
        a_hash = egrep(a_hash_regex,line)
        if a_hash is not None:
          a_outFile.write(a_hash+"\n")


def run_in_powershell(a_command_and_flags):
  # import subprocess
  results = ''
  results = subprocess.check_output(['powershell.exe', a_command_and_flags])

  if results == '':
    return

  return results

def test_is_md5(a_str):
  # import re
  return re.match('[a-fA-F0-9]{32}',a_str)

def usage():
  print '''
NAME
  search_nsrl.py - Search local copy of indexed NSRL RDS files.

SYNOPSIS
  search_nsrl.py <md5> [Path_To_indexed_files]

DESCRIPTION

'''

def parse_args():
  # import sys
  # usage: search_nsrl.py <md5> [Path_To_indexed_files]
  num = len(sys.argv)
  global PATHTOIDXFILES

  if num == 2:
    if test_is_md5(sys.argv[1]) is None:
      usage()
    else:
      return True
  elif num == 3:
    PATHTOIDXFILES = sys.argv[2]
    return True
  elif 2 < num > 3: 
    usage()

  return


def search_codec_file(a_search_string, a_filePath,a_file_codec): # case insensitive search 
  # import codecs
  # Useage: search_file('hello', '.\\', 'utf_16')
  a_list_of_matches = []
  a_line_lower = ''
  a_search_string_lower = a_search_string.lower()

  with codecs.open(a_filePath, 'r', a_file_codec) as a_file:
    for a_line in a_file:
      a_line_lower = a_line.lower()
                                        

      if a_search_string_lower in a_line_lower:
        a_list_of_matches.append(a_line)

  if not a_list_of_matches:
    return

  return a_list_of_matches

def log_setting(a_filePath):
  # import logging
  # defaults to append file
  # logging.debug('This message should appear on the console')
  # logging.info('So should this')
  # logging.warning('And this, too')
  logging.basicConfig(filename=a_filePath,format='%(asctime)s | %(message)s', level=logging.DEBUG)
  
def example_dict_of_list():
  a_dict_of_lists = dict(DateDDMMYYYY=[],SampleURL=[],Detection=[],AnalysisID=[])
  a_dict_of_lists['AnalysisID'].append(a_id)

def parse_cyfir_hash_file(a_item,path_to_hash_file): # Parse CyFIR hash file
  # import re 
  # requires def search_file(a_search_string, a_filePath)
  #contentsOfHashfile = search_file()
  a_line = search_file('SUCCESS',path_to_hash_file)
  a_item_lower = a_item.lower()
  
   
  if a_item_lower == 'success':
    if not a_line:
      return
    else:
      return 'SUCCESS'
  
  elif a_item_lower == 'md5':
    return egrep('(?<=SUCCESS )([a-fA-F0-9]{32})', a_line)
  
  elif a_item_lower == 'user': # //todo need to support Mac users --------------
    a_line = a_line[201:] # chop to paths
    a_line = a_line.split(']:[',1)[0] # get first half of both paths
    if ':\\Users\\' in a_line: # try windows path user
      a_line = egrep('(?<=Users).*',a_line) # chop to users
      a_line = a_line.split('\\')[1]
      return a_line
    elif '\\/home/' in a_line: # try linux path user
      a_line = egrep('(?<=\\/home\/).*',a_line) # chop to users
      a_line = a_line.split('/')[0]
      return a_line
    else:  #give up
      return
          
  elif a_item_lower == 'sourcepath':
    a_line = a_line[201:] # chop to paths
    a_line = a_line.split(']:[',1)[0] # get first half of both paths
    a_line = a_line[1:] # chop first char, the [
    return a_line
    
  elif a_item_lower == 'created':
    a_line = a_line[118:] #chop to created
    a_line = a_line[:25]
    a_line = a_line.replace('[','',1)
    print a_line

  elif a_item_lower == 'os':
    #determin Operating system by the source path
    # get sourcepath
    a_line = a_line[201:] # chop to paths
    a_line = a_line.split(']:[',1)[0] # get first half of both paths
    a_line = a_line[1:] # chop first char, the [
    print a_line
    if re.search('([A-Za-z]\:)' ,a_line):
      return 'windows'
    elif re.search('\\/',a_line):
      return 'posix'
    else:
      return

def sum_list(a_list):
  result = 0
  for a in a_list:
    if a == None:
      continue
    result += a
  return result

def get_max(a_list):
  results = 0
  for a in a_list:
    if a == None:
      continue
    if a > results:
      results = a
  return results
  
def get_min(a_list):
  results = 999999
  for a in a_list:
    if a == None:
      continue
    if a < results:
      results = a
  return results

def main():

if __name__== "__main__":
      main()



# ========== drafts ============================================================

  def buy_symbols(self,symbols_to_buy): #return true when bought, update dicts, log
    global logger
    simulate = self.sim
    bud = self.get_budget_dda()
    ddas = None
    bought = False
    
    if math.floor(bud['cashBuyingPower']) < bud['max_budget']:
      logger.info('cashBuyingPower is low, no more trades')
      return False

    for a_symbol in symbols_to_buy:
      ddas = self.get_symbol_dda(a_symbol)
      ddas['isSell'] = False; ddas['isBuy'] = True;ddas['isHold'] = False
      
      if simulate: # set simulate to trade 100 shares
        qty = 100
        bought = True

      if not simulate: 
        qty = int(math.floor(bud['max_budget'] / ddas['ask']))
        bought = self.api_buy_symbol(ddas,qty)#working

      if bought:
        ddas['isSell'] = False; ddas['isBuy'] = False;ddas['isHold'] = True
        ddas['numShares'] = qty
        ddas['priceBought'] = ddas['ask']
        bud = self.api_update_budget(a_symbol,None)
        cost = (ddas['priceBought'] * qty)
        bud['gainsRealized'] = (bud['gainsRealized'] - cost)
        logger.info('Bought: '+str(a_symbol)+'|NumShares: '+str(qty)+'|Cost: '+str(cost)+'|Price: '+str(ddas['priceBought'])+'|GainsRealized: '+str(bud['gainsRealized']) )
      
      if not bought:
        ddas['isSell'] = False; ddas['isBuy'] = True;ddas['isHold'] = False
 
      PP.pprint(ddas);PP.pprint(bud)#debug
      
      if math.floor(bud['cashBuyingPower']) < bud['max_budget']:
        logger.info('cashBuyingPower is low, no more trades')
        return bought
    
    #end for a_symbol in symbols_to_buy:
    return bought

  def symbols_to_buy(self): #return False of no buy, buying logic here
    #todo add logic !!!!, check budget, add quoteStatus REALTIME check, ahflag check?
    dd = self.decision_data
    resultList  = []
    for a_symbol,a_listDict in dd.items():
      if a_symbol == 'budget':
        continue
      if a_symbol == 'GE': #todo add logic !!!!, check budget, add quoteStatus REALTIME check?
         resultList.append(a_symbol)
    return resultList
  
  def symbols_to_sell(self):#return False if no sell, selling logic here 
    # todo add logic !!!!, check quoteStatus REALTIME check, ahflag check?
    bud = self.get_budget_dda()
    boughtList = bud['boughtSymbol']
    if len(boughtList) == 0:
      return False

    resultList = []
    for a_symbol in boughtList:
      if a_symbol == 'GE': #todo add logic !!!!,add quoteStatus REALTIME check?, check spread
        resultList.append(a_symbol)
  
    return resultList

  
  def sell_symbols(self,symbols_to_sell): #return true when sold, update dicts, log
    global logger
    simulate = self.sim 
    bud = self.get_budget_dda()
    ddas = None
    sold = False
    
    for a_symbol in symbols_to_sell:
      ddas = self.get_symbol_dda(a_symbol)
      ddas['isSell'] = True; ddas['isBuy'] = False;ddas['isHold'] = False
      
      if simulate:#set simulate to process 100 shares
        qty = 100
        sold = True

      if not simulate:
        qty = int(ddas['numShares'])
        sold = self.api_sell_symbol(ddas,qty)#working
        
      if sold:
        ddas['isSell'] = False; ddas['isBuy'] = False;ddas['isHold'] = False
        ddas['priceSold'] = ddas['bid']
        bud = self.api_update_budget(None,a_symbol)
        gain = (qty * ddas['bid'])
        bud['gainsRealized'] = (bud['gainsRealized'] + gain)
        logger.info('Sold: '+str(a_symbol)+'|NumShares: '+str(qty)+'|Gain: '+str(gain)+'|Price: '+str(ddas['priceSold'])+'|GainsRealized: '+str(bud['gainsRealized']) )
        
      if not sold:
        ddas['isSell'] = False; ddas['isBuy'] = False;ddas['isHold'] = True

      #PP.pprint(ddas);PP.pprint(bud)#debug
      #clear the last by getting new quote, this is done in the wait_to_buy() loop
    #end for a_symbol in symbols_to_sell:
    
    return sold

# ---------------------------------------------------------------------------
    if state == 'BUY':
      if len(dd['budget']['boughtSymbol']) < self.ticker_count:
        symbols_to_buy = self.symbols_to_buy()
      if symbols_to_buy is False:
        return state
      bought = self.buy_symbols(symbols_to_buy)
      if bought:
        state = 'SELL'
        return state
    
    if state == 'SELL':
      symbols_to_sell = self.symbols_to_sell()
      if symbols_to_sell is False:
        return state
      sold = self.sell_symbols(symbols_to_sell)
      
