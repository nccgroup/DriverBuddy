from idaapi import *
from idautils import *
from idc import *
from wdf import *
from wdm import *

# List of C/C++ functions that are commonly vulnerable
# TODO make a much more comprehensive list for Windows
c_functions = [
    "sprintf", 
    "strcpy",
    "strcat",
    "memcpy",
    "RtlCopyMemory",
    "gets",
    "scanf",
    ]

# List of Windows API functions that are interesting
# Will partial match to start of function name, ie, Zw will match ZwClose
winapi_functions = [
    "SeAccessCheck",
    "ProbeFor",
    "SeQueryAuthenticationIdToken",
    "IoRegisterDeviceInterface",
    "Ob",
    "Zw",
    "IofCallDriver",
    "PsCreateSystemThread",
    ]

# List of driver specific functions, modify for driver you're working on
driver_functions = []

# Data structures needed to store addresses of functions we are interested in
functions_map = {}
imports_map = {}
c_map = {}
winapi_map = {}
driver_map = {}


'''#####################################################################
cb: Callback function needed by idaapi.enum_import_names().
    Called for every function in imports section of binary.

@param ea: Address of enumerated function
@param name: Name of enumerated function
@param ord: Ordinal of enumerated function. Not used for imports.

@return int: 1 okay, -1 on error, otherwise callback return value 
#####################################################################'''

def cb(ea, name, ord):
    imports_map[name] = ea
    functions_map[name] = ea
    return True

'''#####################################################################
populate_function_map: Loads functions known to IDA from the sub
                       and imports section into a map.

@return boolean: True if functions loaded successfully, otherwise False 
#####################################################################'''

def populate_function_map():
    ret = False
    # Populate function_map with sub functions
    for address in Functions():
        name = GetFunctionName(address)
        functions_map[name] = address
        ret = True
    # Populate function_map with import functions
    implist = get_import_module_qty()
    for i in range(0, implist):
        name = get_import_module_name(i)
        enum_import_names(i, cb)
        ret = True
    return ret

'''#####################################################################
populate_c_map: Enumerate through the list of all functions and load
                vulnerable C functions found into a map.

@return boolean: True if vulnerable functions found, otherwise False 
#####################################################################'''

def populate_c_map():
    ret = False
    for name, address in functions_map.iteritems():
        if name in c_functions:
            c_map[name] = address
            ret = True
    return ret

'''#####################################################################
populate_winapi_map: Enumerate through the list of all functions and load
                     vulnerable winapi functions found into a map.

@return boolean: True if vulnerable functions found, otherwise False 
#####################################################################'''

def populate_winapi_map():
    ret = False
    for name, address in functions_map.iteritems():
        for winfunc in winapi_functions:
            if name.lower().startswith(winfunc.lower()):
                winapi_map[name] = address
                ret = True
    return ret

'''#####################################################################
populate_driver_map: Enumerate through the list of all functions and load
                     vulnerable driver functions found into a map.

@return boolean: True if vulnerable functions found, otherwise False 
#####################################################################'''

def populate_driver_map():
    ret = False
    for name, address in functions_map.iteritems():
        if name in driver_functions:
            driver_map[name] = address
            ret = True
    return ret

'''#####################################################################
populate_winapi_map: Enumerate through the list of all functions and load
                     vulnerable winapi functions found into a map.

@return boolean: True if vulnerable functions found, otherwise False 
#####################################################################'''

def populate_data_structures():
    error = False
    print "[+] Populating IDA functions...."
    error = populate_function_map()
    if error != True:
        print "[+] Couldn't populate function_map"
        return error
    print "[+] Searching for interesting C functions...."
    error = populate_c_map()
    if error != True:
        print "[-] No interesting C functions detected"
    else:
        print "[+] interesting C functions detected"
        get_xrefs(c_map)
    print "[+] Searching for interesting Windows functions...."
    error = populate_winapi_map()
    if error != True:
        print "[-] No interesting winapi functions detected"
    else:
        print "[+] interesting winapi functions detected"
        get_xrefs(winapi_map)
    print "[+] Searching for interesting driver functions...."
    error = populate_driver_map()
    if error != True:
        print "[-] No interesting specific driver functions detected"
    else:
        print "[+] interesting driver functions detected"
        get_xrefs(driver_map)

'''#####################################################################
get_xrefs: Gets cross references to vulnerable functions stored in maps.

@param fmap: function map you want xrefs for
 
#####################################################################'''

def get_xrefs(fmap):
    for name, address in fmap.iteritems():
        code_refs = CodeRefsTo(int(address), 0)
        for ref in code_refs:
            xref = "0x%08x" % ref
            print "[+] Found %s xref to %s" % (xref, name)

'''#####################################################################
get_driver_id: Attempts to determine the type of driver loaded by using
               functions found inside the imports section.

@return boolean: True if able to determine driver type, False otherwise
 
#####################################################################'''

def get_driver_id(driver_entry_address):
    print "[+] Trying to determine driver type..."
    driver_type=""
    # Iterate through imports and try to determine driver type
    for name, address in imports_map.iteritems():
        if name == "FltRegisterFilter":
            driver_type = "Mini-Filter"
            break
        elif name == "WdfVersionBind":
            driver_type = "WDF"
            populate_wdf()
  	    break
        elif name == "StreamClassRegisterMinidriver":
            driver_type = "Stream Minidriver"
            break
        elif name == "KsCreateFilterFactory":
            driver_type = "AVStream"
            break
        elif name == "PcRegisterSubdevice":
            driver_type = "PortCls"
            break
        else:
            continue
    if driver_type == "":
        driver_type = "WDM"
        # Only WDM drivers make it here so run all the WDM stuff
        real_driver_entry = check_for_fake_driver_entry(driver_entry_address)
        real_ddc_addr = locate_ddc(real_driver_entry)
        if real_ddc_addr != None:
            for ddc in real_ddc_addr.itervalues():
                define_ddc(ddc)

    return driver_type

'''#####################################################################
is_driver: Checks to determine that file loaded in IDA is actually a 
           Windows driver by ensuring DriverEntry is in the exports section.

@return boolean: True if DriverEntry found in exports, False otherwise
 
#####################################################################'''

def is_driver():
    driver_entry_address=""
    print "[+] Checking for DriverEntry..."
    for ea in Segments():
        for funcea in Functions(SegStart(ea),SegEnd(ea)):
            fn = GetFunctionName(funcea)
            if fn == "DriverEntry":
                return funcea