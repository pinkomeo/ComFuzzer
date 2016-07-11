

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
import xlwt

reload(sys)
sys.setdefaultencoding('utf8')

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
        self.DispatchCLSIDs = []
        self.prefullname = []
        self.pretypelibclsid = []
        self.fullName = ""
        self.clsid = ""
        self.typelibclsid = ""
        self.Funcs = {}
        self.Progid = ""
        print "[*] FUZZING TARGET: ", dllName
        ret = EnumTypeLib()
        resultcount = 0
        choosecount = 0
        for a,b in ret:
            a = str(a)
            if dllName.lower() in a.lower():
                print "[",resultcount+1,"]",b#, "=>", a
                print "     ",a
                resultcount = resultcount + 1
                #print "[+] TARGET INFO FOUND! :", a, "=>", b
                self.prefullname.append(a)
                self.pretypelibclsid.append(b)
        h = raw_input("Choose one:")
        if int(h) < resultcount+1:
            choosecount = int(h) - 1
            self.fullName = str(self.prefullname[choosecount])
            self.typelibclsid = str(self.pretypelibclsid[choosecount])
        self.Progid, self.clsid =  FindDllClsid(self.fullName)
        #self.clsid = str(self.clsid)
        self.tlb = pythoncom.LoadTypeLib(self.fullName)
        self.typeCount = self.tlb.GetTypeInfoCount()
        self.fuzzableFunc =0
        self.notsavewsf = True
        self.preProgid=dict(zip(self.clsid,self.Progid))
        #print "Progid:\n"
        print self.preProgid
        #print "clsid:\n"
        print self.clsid
        #print "typelibclsid:\n"
        #print self.typelibclsid
        #print "typelibclsidend====\n"
        self.loaded = True

    def MakeReturnTypeName(self, typ):
        justtyp = typ & pythoncom.VT_TYPEMASK
        try:
            typname = vartypes[justtyp]
        except KeyError:
            typname = "?Bad type?"
        for (flag, desc) in type_flags:
            if flag & typ:
                typname = "%s(%s)" % (desc, typname)
        return typname
    def MakeReturnType(self, returnTypeDesc):
        if type(returnTypeDesc)==type(()):
            first = returnTypeDesc[0]
            result = self.MakeReturnType(first)
            if first != pythoncom.VT_USERDEFINED:
                result = result + " " + self.MakeReturnType(returnTypeDesc[1])
            return result
        else:
            return self.MakeReturnTypeName(returnTypeDesc)
        
    def GetTypeDispatch(self,):
        for typdID in range(self.typeCount):
            try:
                ntype = self.tlb.GetTypeInfoType(typdID)
                if HLITypeKinds[ntype][1] == "CoClass":
                    self.DispatchCLSIDs.append(typdID)
                if HLITypeKinds[ntype][1] == "Dispatch":
                    self.DispatchIDs.append(typdID)
            except:
                print "Error GetTypeDispatch"
                pass
    
    def GetFuncInfo(self, clsidArray):
        self.GetTypeDispatch()
        #print self.DispatchIDs
        count = len(clsidArray)
        precount = 0
        totalFunc = 0
        fuzzable = False
        self.fuzzableFunc =0
        self.realclsid = []
        self.Progid = []
        print self.DispatchCLSIDs
        for id in self.DispatchCLSIDs:
            typeinfo = self.tlb.GetTypeInfo(id)
            attr = typeinfo.GetTypeAttr()
            print attr[0]
            if str(attr[0]) in self.clsid:
                self.realclsid.append(str(attr[0]))
                self.Progid.append(self.preProgid[str(attr[0])])
        print self.realclsid
        #print self.Progid
        clsnumber = len(self.realclsid)
        print self.DispatchIDs
        for id in self.DispatchIDs:
            print "\n"+"id:======"+str(id)
            typeinfo = self.tlb.GetTypeInfo(id)
            print attr[0]
            attr = typeinfo.GetTypeAttr()
            nfuncs = attr[6]
            #self.clsid[count] = self.clsid[count] + "#" + str(nfuncs)
            if nfuncs == 0:
                continue
            if precount >= clsnumber:
                break
            self.Funcs[self.realclsid[precount]]={}
            for index in range(nfuncs):
                fd = typeinfo.GetFuncDesc(index)
                id = fd[0]
                name = typeinfo.GetNames(id)[0]
                
                #print "----------"+str(totalFunc)
                #print name
                #print fd[8]
                typ, flags, default = fd[8]
                print self.MakeReturnType(typ)
                #print fd[2]
                if fd[4] != 1:
                    name = name + "@"
                    
                self.Funcs[self.realclsid[precount]][name] = []
                totalFunc = totalFunc + 1
                for argDesc in fd[2]:
                    typ, flags, default = argDesc
                    typname = self.MakeReturnType(typ)
                    self.Funcs[self.realclsid[precount]][name].append(typname) 
                    
            precount = precount + 1

        #print self.Funcs

        aName = self.fullName
        aName = aName.split('\\')[-1]
        styleBlueBkg = xlwt.easyxf('pattern: pattern solid, fore_colour aqua; font: bold on;')
        stylePinkBkg = xlwt.easyxf('pattern: pattern solid, fore_colour ice_blue; font: bold on;')
        styleYellowBkg = xlwt.easyxf('pattern: pattern solid, fore_colour light_yellow;')
        styleOrangeBkg = xlwt.easyxf('pattern: pattern solid, fore_colour tan;')
        styleGreenBkg = xlwt.easyxf('pattern: pattern solid, fore_colour light_green;')
        styleTurquoiseBkg = xlwt.easyxf('pattern: pattern solid, fore_colour light_turquoise;')
        styleRoseBkg = xlwt.easyxf('pattern: pattern solid, fore_colour coral;')
        styleGrayBkg = xlwt.easyxf('pattern: pattern solid, fore_colour white;')
        book = xlwt.Workbook(encoding='utf-8',style_compression=0)
        sheet = book.add_sheet(aName[0:25],cell_overwrite_ok=True)
        first_col=sheet.col(0)
        first_col.width=256*40
        sec_col=sheet.col(1)
        sec_col.width=256*40
        trd_col=sheet.col(2)
        trd_col.width=256*40
        sheet.write(0,0,aName,stylePinkBkg)
        
        xlsCount = 0
        itemCount = 0
        i = 1
        for funNameClsidItem in  self.Funcs.keys():
            sheet.write(1+xlsCount+itemCount,0,funNameClsidItem,styleBlueBkg)
            sheet.write(1+xlsCount+itemCount,1,self.preProgid[str(funNameClsidItem)],styleBlueBkg)
            sheet.write(1+xlsCount+itemCount,2,"",styleBlueBkg)
            
            for funName in  self.Funcs[funNameClsidItem].keys():
                if re.search('AddRef|QueryInterface|Release|GetTypeInfoCount|GetTypeInfo|GetIDsOfNames|Invoke', funName, re.I) is not None:
                    sheet.write(i+1,0,funName,styleGrayBkg)
                elif re.search('saveto|tofile|writeto|deletefile|RegValue|getfile|readfile|download|exe|shell', funName, re.I) is not None:
                    sheet.write(i+1,0,funName,styleRoseBkg)
                elif re.search('get|file|save|write|delete|reg|show|read|info|url|hostname|upload|net|update|thread', funName, re.I) is not None:
                    sheet.write(i+1,0,funName,styleOrangeBkg)
                else:
                    sheet.write(i+1,0,funName,styleYellowBkg)
                #print funName
                #print self.Funcs[funName]
                j = 0
                for argName in  self.Funcs[funNameClsidItem][funName]:
                    loarg = argName.lower()
                    if "string" in loarg or "Blob" in loarg:
                        sheet.write(i+1,j+1,argName,styleTurquoiseBkg)
                        fuzzable = True
                        
                    else:
                        sheet.write(i+1,j+1,argName,styleGreenBkg)
                    j = j + 1
                i = i + 1
                if fuzzable:
                    self.fuzzableFunc = self.fuzzableFunc + 1
                    fuzzable = False
            i = i + 1
            itemCount = itemCount + len(self.Funcs[funNameClsidItem])
            xlsCount = xlsCount + 1
        sheet.write(0,1,"Class: "+str(len(self.clsid))+"  Fuzzable: "+str(self.fuzzableFunc),stylePinkBkg)
        sheet.write(0,2,self.fullName,stylePinkBkg)
        if os.path.exists(r'funcResult/'+aName+"/"):
            book.save('funcResult/'+aName+"/"+aName+'.xls')
        else:
            os.makedirs(r'funcResult/'+aName+"/")
            book.save('funcResult/'+aName+"/"+aName+'.xls')

    def FuzzAllFunc(self,):
        print "[+] TOTAL FUNC: %d" % len(self.Funcs)
        for funName in  self.Funcs.keys():
            self.FuzzSingleFunc(funName, self.Funcs[funName])
    
    def FuzzFunc(self,):
        print "[+] TOTAL FUNC: %d" % len(self.Funcs)
        for funName in  self.Funcs.keys():
            if len(self.Funcs[funName])!= 0:
                self.FuzzSingleFunc(funName, self.Funcs[funName])
    
    def FindDangerFunc(self, funArgs):
        for arg in funArgs:
            loarg = arg.lower()
            if "string" in loarg or "Blob" in loarg:
                return True
        return False
        
    
    def FuzzDangerousFunc(self,):
        print "[+] TOTAL FUZZABLE FUNC: %s" % str(self.fuzzableFunc)
        for clsidName in self.Funcs.keys():
            for funName in  self.Funcs[clsidName].keys():
                if len(self.Funcs[clsidName][funName])!= 0 and self.FindDangerFunc(self.Funcs[clsidName][funName]):
                    self.FuzzSingleFunc(funName, self.Funcs[clsidName][funName], clsidName)

    def FuzzALLFuncAtOneTime(self,):
        print "[+] TOTAL FUNC: %d" % len(self.Funcs)
        self.FuzzMultipleFunc()

    def FuzzSingleFunc(self, funName, funArgs, clsidName):
        argContent = []
        for arg in funArgs:
            i = 0
            loarg = arg.lower()
            if "string" in loarg or "Blob" in loarg:
                argContent.append('"%s"'% MutateString())
            else:
                argContent.append(MutateInteger())
            i+=1
        data = self.ProduceWscript(clsidName, funName, argContent)
        fp = open("tmp.wsf" , "wb+")
        try:
            fp.write(data)
        except UnicodeEncodeError:
            data = data.encode("GBK", 'ignore')
            fp.write(data)
        fp.close()
        if self.notsavewsf:
            #timeNow = time.strftime("%Y%m%d%H%M%p", time.localtime())
            aName = self.fullName
            aName = aName.split('\\')[-1]
            fp = open("funcResult/"+aName+"/"+aName+"."+funName+".wsf" , "wb+")
            try:
                data = data.encode("utf-8", 'ignore')
                fp.write(data)
            except UnicodeEncodeError:
                data = data.encode("GBK", 'ignore')
                fp.write(data)
            fp.close()
            self.notsavewsf = True
        if "@" in funName:
            print "[*] FUZZING PROP:##" , funName.split("@")[0], "## ARGS:", len(argContent)
        else:
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

    def FuzzMultipleFunc(self,):
        funInfos = {}
        noArgfunInfos = {}
        for funName in  self.Funcs.keys():
            argContent = []
            funArgs = self.Funcs[funName]
            for arg in funArgs:
                i = 0
                loarg = arg.lower()
                if "string" in loarg or "Blob" in loarg:
                    argContent.append('"%s"'% MutateString())
                elif "bool" in loarg:
                    argContent.append(True)
                else:
                    argContent.append(MutateInteger())
                i+=1
            if len(argContent):
                funInfos[funName] = argContent
            else:
                noArgfunInfos[funName] = argContent
        data = self.ProduceWscriptSome(self.clsid, funInfos, noArgfunInfos)
        fp = open("tmp.wsf" , "wb+")
        try:
            fp.write(data)
        except UnicodeEncodeError:
            data = data.encode("GBK", 'ignore')
            fp.write(data)
        fp.close()
        if self.notsavewsf:
            timeNow = time.strftime("%Y%m%d%H%M%p", time.localtime())
            aName = self.fullName
            aName = aName.split('\\')[-1]
            fp = open("funcResult/"+aName+"/"+aName+"."+timeNow+".wsf" , "wb+")
            try:
                data = data.encode("utf-8", 'ignore')
                fp.write(data)
            except UnicodeEncodeError:
                data = data.encode("GBK", 'ignore')
                fp.write(data)
            fp.close()
            self.notsavewsf = False
        #print "[*] FUZZING FUNC:##" , funName, "## ARGS:", len(argContent)
        print "[*] FUZZING MULTIPLEFUNC:##" , self.fullName
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
        clsid = str(clsid)
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
        if "@" in funName:
            funName = funName.split("@")[0]
            data += "\ntarget.%s = " % funName
        else:
            data += "\ntarget.%s " % funName
        for i in range(len(argContent)):
            data += "arg%d ," % i
        data= data[:-1]

        data += "\n</script></job></package>"

        return data

    def ProduceWscriptAll(self, clsid, funInfos):
        #print funInfos
        clsid = str(clsid)
        clsid = clsid[1:-1]
        data = ""
        data = "<?XML version='1.0' standalone='yes' ?>\n"
        data += "<package><job id='DoneInVBS' debug='false' error='true'>\n"
        data += "<object classid='clsid:%s' id='target' />\n" % clsid
        data += "<script language='vbscript'>\n"
        i = 0
        for funName in funInfos.keys():
            argContent = funInfos[funName]

            if len(argContent):
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
                for j in range(len(argContent)):
                    data += "arg%d ," % (i-len(argContent)+j)
                data= data[:-1]
                data += "\n"
            else:
                data += "\ntarget.%s " % funName
                data += "\n"
        
        data += "\n</script></job></package>"
        return data

    def ProduceWscriptSome(self, clsid, funInfos, noArgfunInfos):
        #print funInfos
        clsid = str(clsid)
        clsid = clsid[1:-1]
        data = ""
        data = "<?XML version='1.0' standalone='yes' ?>\n"
        data += "<package><job id='DoneInVBS' debug='false' error='true'>\n"
        data += "<object classid='clsid:%s' id='target' />\n" % clsid
        data += "<script language='vbscript'>\n"
        i = 0

        someNoArgfunInfos = {}
        preNoArgfunInfos = random.sample(noArgfunInfos, 2)#random.randint(0,len(noArgfunInfos)-1))
        someNoArgfunInfos = dict([(k,noArgfunInfos.pop(k,None)) for k in preNoArgfunInfos])
        for funName in someNoArgfunInfos.keys():
            data += "\ntarget.%s " % funName
            data += "\n"

        somefunInfos = {}
        presomefunInfos = random.sample(funInfos, 2)#random.randint(0,len(funInfos)-1))
        somefunInfos = dict([(k,funInfos.pop(k,None)) for k in presomefunInfos])
        for funName in somefunInfos.keys():
            argContent = somefunInfos[funName]

            if len(argContent):
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
                for j in range(len(argContent)):
                    data += "arg%d ," % (i-len(argContent)+j)
                data= data[:-1]
                data += "\n"
            else:
                data += "\ntarget.%s " % funName
                data += "\n"
        
        data += "\n</script></job></package>"
        return data

def MutateString():
    m1 = StringMutator(None, None)
    #m = UnicodeStringsMutator(None, None)
    #print m.getCount()
    return random.choice(m1.values)


def MutateInteger():
    return random.randint(0, 0xFFFFFFFF)

# def Dospath(name):
#     re = ""
#     namesplit = name.split("\\")
#     nameend = namesplit[-1]
#     namesplit = namesplit[0:-1]
#     lastname = nameend.split(".")[-1]
#     lenlastname = 0 - (len(lastname))
#     nameend = nameend[0:lenlastname]
#     namesplit.append(nameend)
#     tempname = ""
#     for item in namesplit:
#         item = item.replace(" ","")
#         if "." in item:
#             item = split(".")
#         if len(item)>8:
#             tempname = item[0:6]
#             if tempname in re:
#                 re = re + tempname + "~" + str(re.count(tempname)+1)
#             else:
#                 re = re + tempname + "~1"
#         else:
#             re = re + item
#         re = re + "\\"
#     re = re[0:-2] + "." + lastname
#     #print re
#     return re



def FindDllClsid(dllname):
    key = 0
    hSubKey = 0
    ret = []
    aProgid = []
    aKeyName = []
    try:
        #print "CLSID\\%s\\ProID" % clsid.upper()
        key = win32api.RegOpenKey(win32con.HKEY_CLASSES_ROOT, "CLSID")
        size = win32api.RegQueryInfoKey(key)[0]
        #num = 0
        for i in range(size):
        #while True:
            try:
                keyName = win32api.RegEnumKey(key, i)
                #print keyName
                if i>-1:#num != 0:
                    subKey = win32api.RegOpenKey(key, keyName)
                    #print subKey
                    num1 = 0
                    dll = ""
                    progid = ""
                    clsid = ""
                    while True:
                        try:
                            name = win32api.RegEnumKey(subKey, num1)
                            num1 += 1
                            #print name
                            if name.lower() == "progid":
                                progid = win32api.RegQueryValue(subKey, name)
                                #print progid
                            if name.lower() == "inprocserver32":
                                dll = win32api.RegQueryValue(subKey, name)
                                if (dll.lower() == dllname.lower() or dll.lower() == win32api.GetShortPathName(dllname).lower()):
                                    print "*****"+progid+"\n"+keyName+"******\n"
                                    clsid = keyName
                        except:
                            break
                    if clsid:
                        aProgid.append(progid)
                        aKeyName.append(keyName.upper())
                    win32api.RegCloseKey(subKey)
                #num += 1

            except Exception, e:
                print e
                print 222
                break
        #hSubKey = win32api.RegOpenKey(key, 0)
        #value, typ = win32api.RegQueryValueEx(hSubKey, None)
        #print value
        print "aProgid:"
        print aProgid
        print aKeyName
        print "aKeyNameend"
        return (aProgid, aKeyName)
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

    target = TypeLib(sys.argv[1])
    if target.loaded:
        target.GetFuncInfo(target.clsid)
        print target.Funcs
        for i in range(100):
           target.FuzzDangerousFunc()

