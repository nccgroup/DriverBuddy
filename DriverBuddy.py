from idaapi import *
from idautils import *
from idc import *
from DriverBuddy import data
from DriverBuddy import ioctl
'''#######################################################################################

DriverBuddy.py: Entry point for IDA python plugin used in Windows driver
                vulnerability research.

Written by Braden Hollembaek and Adam Pond of NCC Group
#######################################################################################'''

class DriverBuddyPlugin(plugin_t):
    flags = PLUGIN_UNL
    comment = ('Plugin to aid in Windows driver vulnerability research. ' +
               'Automatically tries to find IOCTL handlers, decode IOCTLS, '+
               'flag dangerous C/C++ functions, find Windows imports for privesc, '+
               'and identify the type of Windows driver.')
    help = ''
    wanted_name = 'Driver Buddy'
    wanted_hotkey = 'Ctrl-Alt-D'

    def init(self):
        self.hotkeys = []
        self.hotkeys.append(add_hotkey("Ctrl+Alt+I", self.decode))
        return PLUGIN_KEEP

    def run(self, args):
        print "[+] Welcome to Driver Buddy"
        autoWait() # Wait for IDA autoanalysis to complete
        driver_entry = data.is_driver()
	if driver_entry == "":
            print "[-] No DriverEntry stub found"
            print "[-] Exiting..."
            return
        print "[+] DriverEntry found"
        if data.populate_data_structures() == False:
            print "[-] Unable to load functions"
            print "[-] Exiting..."
            return
	driver_type = data.get_driver_id(driver_entry)
        if driver_type == "":
            print "[-] Unable to determine driver type assuming wdm"
        else:
            print "[+] Driver type detected: " + driver_type
        if ioctl.find_ioctls() == False:
            print "[-] Unable to automatically find any IOCTLs"
        return

    def decode(self, _=0):
        if idc.GetOpType(idc.ScreenEA(), 1) != 5:   # Immediate
            return
        value = idc.GetOperandValue(idc.ScreenEA(), 1) & 0xffffffff
        ioctl.get_ioctl_code(value)

    def term(self):
        pass

def PLUGIN_ENTRY():
    return DriverBuddyPlugin()
