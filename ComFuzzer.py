

import sys
import pythoncom
import random
import win32api
import win32con
import time
import os
import shutil
from StringMutator import *
from debugger import *

HLITypeKinds = {
                pythoncom.TKIND_ENUM : (1, 'Enumeration'),
                pythoncom.TKIND_RECORD : (2, 'Record'),
                pythoncom.TKIND_MODULE : (3, 'Module'),
                pythoncom.TKIND_INTERFACE : (4, 'Interface'),
                pythoncom.TKIND_DISPATCH : (5, 'Dispatch'),
                pythoncom.TKIND_COCLASS : (6, 'CoClass'),
                pythoncom.TKIND_ALIAS : (7, 'Alias'),
                pythoncom.TKIND_UNION : (8, 'Union')
        }


funckinds = {pythoncom.FUNC_VIRTUAL : "Virtual",
             pythoncom.FUNC_PUREVIRTUAL : "Pure Virtual",
             pythoncom.FUNC_STATIC : "Static",
             pythoncom.FUNC_DISPATCH : "Dispatch",
        }
invokekinds = {pythoncom.INVOKE_FUNC: "Function",
             pythoncom.INVOKE_PROPERTYGET : "Property Get",
             pythoncom.INVOKE_PROPERTYPUT : "Property Put",
             pythoncom.INVOKE_PROPERTYPUTREF : "Property Put by reference",
        }
funcflags = [(pythoncom.FUNCFLAG_FRESTRICTED, "Restricted"),
           (pythoncom.FUNCFLAG_FSOURCE, "Source"),
           (pythoncom.FUNCFLAG_FBINDABLE, "Bindable"),
           (pythoncom.FUNCFLAG_FREQUESTEDIT, "Request Edit"),
           (pythoncom.FUNCFLAG_FDISPLAYBIND, "Display Bind"),
           (pythoncom.FUNCFLAG_FDEFAULTBIND, "Default Bind"),
           (pythoncom.FUNCFLAG_FHIDDEN, "Hidden"),
           (pythoncom.FUNCFLAG_FUSESGETLASTERROR, "Uses GetLastError"),
           ]

vartypes = {pythoncom.VT_EMPTY: "Empty",
        pythoncom.VT_NULL: "NULL",
        pythoncom.VT_I2: "Integer 2",
        pythoncom.VT_I4: "Integer 4",
        pythoncom.VT_R4: "Real 4",
        pythoncom.VT_R8: "Real 8",
        pythoncom.VT_CY: "CY",
        pythoncom.VT_DATE: "Date",
        pythoncom.VT_BSTR: "String",
        pythoncom.VT_DISPATCH: "IDispatch",
        pythoncom.VT_ERROR: "Error",
        pythoncom.VT_BOOL: "BOOL",
        pythoncom.VT_VARIANT: "Variant",
        pythoncom.VT_UNKNOWN: "IUnknown",
        pythoncom.VT_DECIMAL: "Decimal",
        pythoncom.VT_I1: "Integer 1",
        pythoncom.VT_UI1: "Unsigned integer 1",
        pythoncom.VT_UI2: "Unsigned integer 2",
        pythoncom.VT_UI4: "Unsigned integer 4",
        pythoncom.VT_I8: "Integer 8",
        pythoncom.VT_UI8: "Unsigned integer 8",
        pythoncom.VT_INT: "Integer",
        pythoncom.VT_UINT: "Unsigned integer",
        pythoncom.VT_VOID: "Void",
        pythoncom.VT_HRESULT: "HRESULT",
        pythoncom.VT_PTR: "Pointer",
        pythoncom.VT_SAFEARRAY: "SafeArray",
        pythoncom.VT_CARRAY: "C Array",
        pythoncom.VT_USERDEFINED: "User Defined",
        pythoncom.VT_LPSTR: "Pointer to string",
        pythoncom.VT_LPWSTR: "Pointer to Wide String",
        pythoncom.VT_FILETIME: "File time",
        pythoncom.VT_BLOB: "Blob",
        pythoncom.VT_STREAM: "IStream",
        pythoncom.VT_STORAGE: "IStorage",
        pythoncom.VT_STORED_OBJECT: "Stored object",
        pythoncom.VT_STREAMED_OBJECT: "Streamed object",
        pythoncom.VT_BLOB_OBJECT: "Blob object",
        pythoncom.VT_CF: "CF",
        pythoncom.VT_CLSID: "CLSID",
}

type_flags = [ (pythoncom.VT_VECTOR, "Vector"),
           (pythoncom.VT_ARRAY, "Array"),
           (pythoncom.VT_BYREF, "ByRef"),
           (pythoncom.VT_RESERVED, "Reserved"),
]
'''

class HLIRegisteredTypeLibrary(HLICOM):
    def GetSubList(self):
        import os
        clsidstr, versionStr = self.myobject
        collected = []
        helpPath = ""
        key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "TypeLib\\%s\\%s" % (clsidstr, versionStr))
        win32ui.DoWaitCursor(1)
        try:
            num = 0
            while 1:
                try:
                    subKey = win32api.RegEnumKey(key, num)
                except win32api.error:
                    break
                hSubKey = win32api.RegOpenKey(key, subKey)
                try:
                    value, typ = win32api.RegQueryValueEx(hSubKey, None)
                    if typ == win32con.REG_EXPAND_SZ:
                        value = win32api.ExpandEnvironmentStrings(value)
                except win32api.error:
                    value = ""
                if subKey=="HELPDIR":
                    helpPath = value
                elif subKey=="Flags":
                    flags = value
                else:
                    try:
                        lcid = int(subKey)
                        lcidkey = win32api.RegOpenKey(key, subKey)
                        # Enumerate the platforms
                        lcidnum = 0
                        while 1:
                            try:
                                platform = win32api.RegEnumKey(lcidkey, lcidnum)
                            except win32api.error:
                                break
                            try:
                                hplatform = win32api.RegOpenKey(lcidkey, platform)
                                fname, typ = win32api.RegQueryValueEx(hplatform, None)
                                if typ == win32con.REG_EXPAND_SZ:
                                    fname = win32api.ExpandEnvironmentStrings(fname)
                            except win32api.error:
                                fname = ""
                            collected.append((lcid, platform, fname))
                            lcidnum = lcidnum + 1
                        win32api.RegCloseKey(lcidkey)
                    except ValueError:
                        pass
                num = num + 1
        finally:
            win32ui.DoWaitCursor(0)
            win32api.RegCloseKey(key)
        # Now, loop over my collected objects, adding a TypeLib and a HelpFile
        ret = []
#               if helpPath: ret.append(browser.MakeHLI(helpPath, "Help Path"))
        ret.append(HLICLSID(clsidstr))
        for lcid, platform, fname in collected:
            extraDescs = []
            if platform!="win32":
                extraDescs.append(platform)
            if lcid:
                extraDescs.append("locale=%s"%lcid)
            extraDesc = ""
            if extraDescs: extraDesc = " (%s)" % ", ".join(extraDescs)
            ret.append(HLITypeLib(fname, "Type Library" + extraDesc))
        ret.sort()
        return ret

'''
class TypeLib:
    def __init__(self, dllName):
        self.DispatchIDs = []
        self.fullName = ""
        self.clsid = ""
        self.typelibclsid = ""
        self.Funcs = {}
        self.Progid = ""
        print "[*] FUZZING TARGET: ", dllName
        ret = EnumTypeLib()
        for a,b in ret:
            if dllName.lower() in a.lower():
                print "[+] TARGET INFO FOUND! :", a, "=>", b
                self.fullName = a
                self.typelibclsid = b
                break

        self.Progid, self.clsid =  FindDllClsid(self.fullName)
        self.tlb = pythoncom.LoadTypeLib(self.fullName)
        self.typeCount = self.tlb.GetTypeInfoCount()
        self.loaded = True



    def GetTypeDispatch(self,):
        for typdID in range(self.typeCount):
            try:
                ntype = self.tlb.GetTypeInfoType(typdID)
                if HLITypeKinds[ntype][1] == "Dispatch":
                    self.DispatchIDs.append(typdID)
            except:
                print "Error GetTypeDispatch"
                pass
    def GetFuncInfo(self,):
        self.GetTypeDispatch()
        #print self.DispatchIDs
        for id in self.DispatchIDs:
            typeinfo = self.tlb.GetTypeInfo(id)
            attr = typeinfo.GetTypeAttr()
            nfuncs = attr[6]
            for index in range(nfuncs):
                fd = typeinfo.GetFuncDesc(index)
                id = fd[0]
                name = typeinfo.GetNames(id)[0]
                self.Funcs[name] = []
                for argDesc in fd[2]:
                    typ, flags, default = argDesc
                    if type(typ) != type(()):
                        justtyp = typ & pythoncom.VT_TYPEMASK
                        typname = vartypes[justtyp]
                        self.Funcs[name].append(typname)

    def FuzzAllFunc(self,):
        print "[+] TOTAL FUNC: %d" % len(self.Funcs)
        for funName in  self.Funcs.keys():
            self.FuzzSingleFunc(funName, self.Funcs[funName])

    def FuzzSingleFunc(self, funName, funArgs):
        argContent = []
        for arg in funArgs:
            i = 0
            loarg = arg.lower()
            if "string" in loarg or "Blob" in loarg:

                argContent.append('"%s"'% MutateString())
            else:
                argContent.append(MutateInteger())
            i+=1
        data = self.ProduceWscript(self.clsid, funName, argContent)
        fp = open("tmp.wsf" , "wb+")
        try:
            fp.write(data)
        except UnicodeEncodeError:
            data = data.encode("GBK", 'ignore')
            fp.write(data)
        fp.close()
        print "[*] FUZZING FUNC:##" , funName, "## ARGS:", len(argContent)
        dbg = DebuggerMonitor("wscript.exe tmp.wsf", "log")
        dbg.setTimeOut(0.5)
        dbg.run()
        if dbg._faultDetected:
            logdir =  dbg.get_log_dir()
            try:
                shutil.copy("tmp.wsf", os.path.join(logdir, "tmp.wsf"))
            except:
                print "[*] FAILED TO SAVE TEST CASE!!!"
        #os.system("wscript.exe tmp.wsf")



    def ProduceWscript(self, clsid, funName, argContent):
        clsid = clsid[1:-1]
        data = ""
        data = "<?XML version='1.0' standalone='yes' ?>\n"
        data += "<package><job id='DoneInVBS' debug='false' error='true'>\n"
        data += "<object classid='clsid:%s' id='target' />\n" % clsid
        data += "<script language='vbscript'>\n"
        i = 0
        for arg in argContent:

            data += ("arg%d=" % i)
            i += 1
            try:
                data += arg
                data += "\n"
            except:
                data += "%d" % arg
                data += "\n"
                pass
        data += "\ntarget.%s " % funName
        for i in range(len(argContent)):
            data += "arg%d ," % i
        data= data[:-1]

        data += "\n</script></job></package>"

        return data

def MutateString():
    m1 = StringMutator(None, None)
    #m = UnicodeStringsMutator(None, None)
    #print m.getCount()
    return random.choice(m1.values)


def MutateInteger():
    return random.randint(0, 0xFFFFFFFF)

def FindDllClsid(dllname):
    key = 0
    hSubKey = 0
    ret = []
    try:
        #print "CLSID\\%s\\ProID" % clsid.upper()
        key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "CLSID")
        num = 0
        while True:
            try:
                keyName = win32api.RegEnumKey(key, num)
                #print keyName
                if num != 0:
                    subKey = win32api.RegOpenKey(key, keyName)
                    #print subKey
                    num1 = 0
                    while True:
                        try:
                            name = win32api.RegEnumKey(subKey, num1)
                            num1 += 1
                            #print name
                            dll = ""
                            progid = ""
                            if name.lower() == "progid":
                                progid = win32api.RegQueryValue(subKey, name)
                                #print progid
                            if name.lower() == "inprocserver32":
                                dll = win32api.RegQueryValue(subKey, name)
                                #print dll
                                if dll.lower() == dllname.lower():
                                    return (progid, keyName)

                        except:
                            break


                    win32api.RegCloseKey(subKey)
                num += 1

            except:
                print 222
                break;
        #hSubKey = win32api.RegOpenKey(key, 0)
        #value, typ = win32api.RegQueryValueEx(hSubKey, None)
        #print value
    except Exception, e:
        #print e
        pass

    win32api.RegCloseKey(key)

    return (-1, -1)

def ReadClsidRegKey():
    key = 0
    hSubKey = 0
    ret = []
    try:
        #print "CLSID\\%s\\ProID" % clsid.upper()
        key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "CLSID")
        num = 0
        while True:
            try:
                keyName = win32api.RegEnumKey(key, num)
                #print keyName
                if num != 0:
                    subKey = win32api.RegOpenKey(key, keyName)
                    #print subKey
                    num1 = 0
                    while True:
                        try:
                            name = win32api.RegEnumKey(subKey, num1)
                            num1 += 1
                            #print name
                            dll = ""
                            progid = ""
                            if name.lower() == "progid":
                                progid = win32api.RegQueryValue(subKey, name)
                                #print progid
                            if name.lower() == "inprocserver32":
                                dll = win32api.RegQueryValue(subKey, name)
                                #print dll
                            ret.append((dll, progid, keyName))
                        except:
                            break


                    win32api.RegCloseKey(subKey)
                num += 1

            except:
                #print 222
                break;
        #hSubKey = win32api.RegOpenKey(key, 0)
        #value, typ = win32api.RegQueryValueEx(hSubKey, None)
        #print value
    except Exception, e:
        #print e
        pass

    win32api.RegCloseKey(key)

    return ret


def EnumTypeLib():
    ret = []
    libKeys = []
    key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "TypeLib")
    try:
        num = 0
        while 1:
            try:
                keyName = win32api.RegEnumKey(key, num)
                #print keyName
            except win32api.error:
                break
            # Enumerate all version info
            subKey = win32api.RegOpenKey(key, keyName)
            name = None
            try:
                subNum = 0
                bestVersion = 0.0
                while 1:
                    try:
                        versionStr = win32api.RegEnumKey(subKey, subNum)
                    except win32api.error:
                        break
                    try:
                        versionFlt = float(versionStr)
                    except ValueError:
                        versionFlt = 0 # ????
                    if versionFlt > bestVersion:
                        bestVersion = versionFlt
                        name = win32api.RegQueryValue(subKey, versionStr)
                    subNum = subNum + 1
            finally:
                win32api.RegCloseKey(subKey)
            if name is not None:
                libKeys.append((keyName, versionStr))
                #print name
            num += 1
    except:
        pass

    for keyName, versionStr in libKeys:
        key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "TypeLib\\%s\\%s" % (keyName, versionStr))
        num = 0
        while True:
            try:
                subKey = win32api.RegEnumKey(key, num)

                #print subKey
            except:
                break
            hSubKey = win32api.RegOpenKey(key, subKey)
            try:
                value, typ = win32api.RegQueryValueEx(hSubKey, None)
                if typ == win32con.REG_EXPAND_SZ:
                    value = win32api.ExpandEnvironmentStrings(value)
            except:
                value = ""
            if subKey=="HELPDIR":
                helpPath = value
            elif subKey.lower()=="flags":
                flags = value
            else:
                try:
                    lcid = int(subKey)
                    #print key
                    #print key, subKey
                    lcidkey = win32api.RegOpenKey(key, subKey)
                    #print lcidkey
                    # Enumerate the platforms
                    lcidnum = 0
                    while 1:
                        try:
                            platform = win32api.RegEnumKey(lcidkey, lcidnum)
                            #print platform
                        except Exception, e:
                            #print 111,e
                            break
                        try:
                            hplatform = win32api.RegOpenKey(lcidkey, platform)
                            fname, typ = win32api.RegQueryValueEx(hplatform, None)
                            if fname != None:
                                ret.append((fname, keyName))
                                #print key2
                            #print fname
                            #print lcid, platform, fname

                            #if typ == win32con.REG_EXPAND_SZ:
                                #fname = win32api.ExpandEnvironmentStrings(fname)
                                #print fname
                        except win32api.error:
                            fname = ""
                        #collected.append((lcid, platform, fname))
                        lcidnum = lcidnum + 1
                    win32api.RegCloseKey(lcidkey)
                except ValueError,e:
                    #print e
                    pass
            num += 1
        win32api.RegCloseKey(key)
    return ret

if __name__=='__main__':
    '''
    typelib = TypeLib("VSTwain.dll")

    if typelib.loaded:

        eval("typelib.GetFuncInfo()")
        for key in typelib.Funcs.keys():
            print key + ":", typelib.Funcs[key]
    '''

    target = TypeLib(sys.argv[1])
    if target.loaded:
        target.GetFuncInfo()
        for i in range(100):
            target.FuzzAllFunc()





    '''
    key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "TypeLib")
    #win32ui.DoWaitCursor(1)

            if name is not None:
                #print name
                key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "TypeLib\\%s\\%s" % (keyName, versionStr))
                try:
                    num = 0
                    while 1:
                        try:
                            subKey = win32api.RegEnumKey(key, num)
                        except win32api.error:
                            break
                        hSubKey = win32api.RegOpenKey(key, subKey)
                        try:
                            value, typ = win32api.RegQueryValueEx(hSubKey, None)
                            if typ == win32con.REG_EXPAND_SZ:
                                value = win32api.ExpandEnvironmentStrings(value)
                        except win32api.error:
                            value = ""
                        if subKey=="HELPDIR":
                            helpPath = value
                        elif subKey=="Flags":
                            flags = value
                        else:
                            try:
                                lcid = int(subKey)
                                lcidkey = win32api.RegOpenKey(key, subKey)
                                # Enumerate the platforms
                                lcidnum = 0
                                while 1:
                                    try:
                                        platform = win32api.RegEnumKey(lcidkey, lcidnum)
                                    except win32api.error:
                                        break
                                    try:
                                        hplatform = win32api.RegOpenKey(lcidkey, platform)
                                        fname, typ = win32api.RegQueryValueEx(hplatform, None)
                                        if typ == win32con.REG_EXPAND_SZ:
                                            fname = win32api.ExpandEnvironmentStrings(fname)
                                            print fname
                                    except win32api.error:
                                        fname = ""
                                    collected.append((lcid, platform, fname))
                                lcidnum = lcidnum + 1
                                win32api.RegCloseKey(lcidkey)
                            except ValueError:
                                pass
                        num = num + 1
                finally:
                    win32ui.DoWaitCursor(0)
                    win32api.RegCloseKey(key)
        #ret.append(HLIRegisteredTypeLibrary((keyName, versionStr), name))
            num = num + 1
    except:
        pass
    '''