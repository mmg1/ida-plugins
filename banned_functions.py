import idautils
import idc
from idaapi import Choose2

# https://msdn.microsoft.com/en-us/library/bb288454.aspx
banned_functions_list = [ "strcpy", "strcpyA", "strcpyW", "wcscpy", "_tcscpy", "_mbscpy", "StrCpy", "StrCpyA", "StrCpyW", "lstrcpy", "lstrcpyA", "lstrcpyW", "_tccpy", "_mbccpy", "_ftcscpy", "strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy", "StrCpyN", "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW", "lstrcpyn", "lstrcpynA", "lstrcpynW", "_fstrncpy", "strcat", "strcatA", "strcatW", "wcscat", "_tcscat", "_mbscat", "StrCat", "StrCatA", "StrCatW", "lstrcat", "lstrcatA", "lstrcatW", "StrCatBuff", "StrCatBuffA", "StrCatBuffW", "StrCatChainW", "_tccat", "_mbccat", "_ftcscat", "strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat", "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW", "lstrncat", "lstrcatnA", "lstrcatnW", "lstrcatn", "_fstrncat", "sprintfW", "sprintfA", "wsprintf", "wsprintfW", "wsprintfA", "sprintf", "swprintf", "_stprintf", "wvsprintf", "wvsprintfA", "wvsprintfW", "vsprintf", "_vstprintf", "vswprintf", "gets", "_getts", "_gettws", "IsBadWritePtr", "IsBadHugeWritePtr", "IsBadReadPtr", "IsBadHugeReadPtr", "IsBadCodePtr", "IsBadStringPtr", "memcpy", "RtlCopyMemory", "CopyMemory", "wmemcpy", "printf", "scanf", ]

class BannedChooser(Choose2):
  '''
  Chooser class to display results
  '''
  def __init__(self, title, items, embedded=False):
    Choose2.__init__(self, 
	  title, 
	  [ ["Address", 20], ["Function Name", 40] ],
      embedded=embedded
  	)
    self.title = title
    self.items = items
    self.icon = 41	# default to functions icon
    self.FindBannedFunctions()

  def ListFunctions(self):
    for functionAddr in Functions():
	  print(GetFunctionName(functionAddr));
    print("[+] ListFunctions() complete!");

  def FindBannedFunctions(self):
    self.items = []
    for functionAddr in Functions():
      if GetFunctionName(functionAddr) in banned_functions_list:
        xrefs = CodeRefsTo(functionAddr, False)
        # iterate over each cross-reference
        for xref in xrefs:
          print GetMnem(xref).lower()
          # is this cross-reference a function call (or jmp)
          if GetMnem(xref).lower() == "call" or GetMnem(xref).lower() == "jmp":
            print("[+] Found reference to '" + GetFunctionName(functionAddr) + "' function at address " + hex(xref))
            SetColor(xref, CIC_ITEM, 0xFF8C00)
            addr = "0x%08x" % xref
            self.items.append([addr, GetFunctionName(functionAddr), xref])
            #print hex(xref)

  def GetItems(self):
    return self.items

  def SetItems(self):
    self.items = [] if items is None else items

  def OnGetSize(self):
    return len(self.items)

  def OnClose(self):
    pass
    #print("[+] Closed " + self.title);

  def OnGetLine(self, n):
    return self.items[n]

  def OnSelectLine(self, index):
    idc.Jump(self.items[index][2])
    #print "[*] Jumping to 0x%08x" % self.items[index][2]


class BannedPlugin_t(idaapi.plugin_t):
  flags = idaapi.PLUGIN_UNL
  comment = "Banned Functions plugin for IDA"
  help = ""
  wanted_name = "Banned Functions List"
  wanted_hotkey = "Alt-F8"
  
  def init(self):
    return idaapi.PLUGIN_OK

  def run(self, arg):
    b = BannedChooser("M$ Banned Functions v0.1", [])
    b.Show()
    #idaapi.msg("run() called with %d!\n" % arg)

  def term(self):
    pass
    #idaapi.msg("term() called!\n")

def PLUGIN_ENTRY():
  return BannedPlugin_t()

'''
if __name__ == "__main__":
  banned = BannedChooser("M$ Banned Functions v0.1", []);
  banned.Show()
'''
