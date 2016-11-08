from idaapi import *
from idautils import *
from idc import *

'''#######################################################################################

wdm.py: WDM driver specific function calls.


#######################################################################################'''


'''#######################################################################################

check_for_fake_driver_entry: Checks if DriverEntry in WDM driver is fake.

@param driver_entry_address: Address of DriverEntry function IDA autodetects.

@return real_driver_entry address

#######################################################################################'''

def check_for_fake_driver_entry(driver_entry_address):
	address = get_func(driver_entry_address)
	end_address = address.endEA
	while GetMnem(end_address) !="jmp" and GetMnem(end_address) !="call":
	    end_address -= 0x1
	real_driver_entry_address = LocByName(GetOpnd(end_address, 0))
	print "[+] Found real DriverEntry address of %08x" % real_driver_entry_address
	MakeName(real_driver_entry_address, "Real_Driver_Entry")
	return real_driver_entry_address

'''#######################################################################################

locate_ddc: Tries to automatically discover the DispatchDeviceControl in WDM drivers.
		Also looks for DispatchInternalDeviceControl. Has some experimental DDC searching

@param driver_entry_address: Address of real DriverEntry function found 
	   using check_for_fake_driver_entry.

@return dictionary containing ddc and didc addresses, None otherwise

#######################################################################################'''

def locate_ddc(driver_entry_address):
	driver_entry_func = list(FuncItems(driver_entry_address))
	# Offset to search for DispatchDeviceControl loaded into DriverObject struct
	ddc_offset = "+0E0h]"
	didc_offset = "+0E8h]"
	prev_instruction = ""
	dispatch = {}
	# Enumerate the DriverEntry function and check if DriverObject struct loads address of DispatchDeviceControl
	prev_instruction = driver_entry_func[0]
	for i in driver_entry_func[1:]:
	    if ddc_offset in GetOpnd(i, 0)[4:] and GetMnem(prev_instruction) == "lea":
	    	real_ddc = LocByName(GetOpnd(prev_instruction, 1))
	    	print "[+] Found DispatchDeviceControl 0x%08x" % real_ddc
	    	MakeName(real_ddc, "DispatchDeviceControl")
	    	dispatch["ddc"] = real_ddc
	    if didc_offset in GetOpnd(i, 0)[4:] and GetMnem(prev_instruction) == "lea":
	    	real_didc = LocByName(GetOpnd(prev_instruction, 1))
	    	print "[+] Found DispatchInternalDeviceControl 0x%08x" % real_didc
	    	MakeName(real_didc, "DispatchInternalDeviceControl")
	    	dispatch["didc"] = real_didc
	    prev_instruction = i
	
	if "ddc" in dispatch: # This is whats important so if we have it, bail
		return dispatch

    # If we didn't find ddc, check for case where function is loading known
	# IO_STACK_LOCATION and IRP addresses, indicating it could be the DispatchDeviceControl.
    # Experimental, probably going to give you false-postives
	ddc_list = []
	for f in Functions():
	    # For each function, get list of all instructions
	    instructions = list(FuncItems(f))
	    iocode = "0xDEADB33F"
	    iostack_location = "[rdx+0B8h]"
	    for i in instructions:
	        if iostack_location in GetOpnd(i, 1):
	            iostack_register = GetOpnd(i,0)
	            iocode = "["+iostack_register + "+18h]"
	        if iocode in GetDisasm(i):
	            ddc_list.append(f)
	real_ddc = {}
	# Go through potential list of DispatchDeviceControl and see if they get called from DriverEntry,
	# if so, might be real deal
	for ddc in ddc_list:
	    for count, refs in enumerate(XrefsTo(ddc,0)):
	    	reffunc = get_func(refs.frm)
	        if reffunc is not None and reffunc.startEA == driver_entry_address:
        		real_ddc[count] = ddc
        		print "[+] Possible DispatchDeviceControl 0x%08x" % ddc
        		MakeName(ddc, "Possible_DispatchDeviceControl%r" % count)
	
	if real_ddc != {}: return real_ddc
	else: return None


'''#######################################################################################

define_ddc: Defines known structs in the DispatchDeviceControl.

@param ddc_address: Address of DispatchDeviceControl found 
	   using locate_ddc.

@return None

#######################################################################################'''

def define_ddc(ddc_address):
	# Special hidden ida function to load "standard structures"
	irp_id = Til2Idb(-1, "IRP")
	io_stack_location_id = Til2Idb(-1, "IO_STACK_LOCATION")
	device_object_id = Til2Idb(-1, "DEVICE_OBJECT")
	# Register canaries
	io_stack_reg = "STR8SWAGGABRUH"
	irp_reg = "STR8SWAGGABRUH"
	device_object_reg = "STR8SWAGGABRUH"
	rdx_flag = 0
	rcx_flag = 0
	io_stack_flag = 0
	irp_reg_flag = 0
	# Get list of all instructions of DispatchDeviceControl function
	instructions = list(FuncItems(ddc_address))
	# Scan instructions until we discover rcx, or rdx being used
	for i in instructions:
		disasm = GetDisasm(i)
		src = GetOpnd(i, 1)
		if "rdx" in disasm and rdx_flag != 1 or irp_reg in disasm and irp_reg_flag !=1:
			# Check for IO_STACK_LOCATION
			if "+0B8h" in disasm:
				if "rdx+0B8h" in src or irp_reg + "+0B8h" in src:
					OpStroffEx(i, 1, irp_id, 0)
					# If it is a mov, we want to save where IO_STACK_LOCATION is
					if GetMnem(i) == "mov":
						io_stack_reg = GetOpnd(i, 0)
						io_stack_flag = 0
						print "[+] Stored IO_STACK_LOCATION in %s" % io_stack_reg 
				else:
					OpStroffEx(i, 0, irp_id, 0)
				print "[+] Made struct IO_STACK_LOCATION"
			# Check for SystemBuffer
			elif "+18h" in disasm:
				if "rdx+18h" in src or irp_reg + "+18h" in src:
					OpStroffEx(i, 1, irp_id, 0)
				else:
					OpStroffEx(i, 0, irp_id, 0)
				print "[+] Made struct IRP+SystemBuffer"
			# Check for IoStatus.Information
			elif "+38h" in disasm:
				if "rdx+38h" in src or irp_reg + "+38h" in src:
					OpStroffEx(i, 1, irp_id, 0)
				else:
					OpStroffEx(i, 0, irp_id, 0)
				print "[+] Made struct IRP+IoStatus.Information"
			# Need to keep track of where IRP is being moved
			elif GetMnem(i) == "mov" and (src == "rdx" or src == irp_reg):
				irp_reg = GetOpnd(i, 0)
				irp_reg_flag = 0
				print "[+] Stored IRP in %s" % irp_reg
			# rdx got clobbered
			elif GetMnem(i) == "mov" and GetOpnd(i, 0) == "rdx":
				print "[+] rdx got clobbered %s" % GetDisasm(i)
				rdx_flag = 1
			# irp_reg got clobbered
			elif GetMnem(i) == "mov" and GetOpnd(i, 0) == irp_reg:
				irp_reg_flag = 1
			else:
				"[-] Something weird happened %s" % GetDisasm(i)
		elif "rcx" in disasm and rcx_flag != 1:
			# Check for DEVICE_OBJECT.Extension
			if "rcx+40h" in disasm:
				if "rcx+40h" in src:
					OpStroffEx(i, 1, device_object_id, 0)
				else:
					OpStroffEx(i, 0, device_object_id, 0)
				print "[+] Made struct DEVICE_OBJECT.Extension"
			# Need to keep track of where DEVICE_OBJECT is being moved
			elif GetMnem(i) == "mov" and src == "rcx":
				device_object_reg = GetOpnd(i, 0)
				print "[+] Stored DEVICE_OBJECT in %s" % device_object_reg
			# rcx got clobbered
			elif GetMnem(i) == "mov" and GetOpnd(i, 0) == "rcx":
				rcx_flag = 1
		elif io_stack_reg in disasm and io_stack_flag != 1:
			print "[+] io_stack_reg= %s in %s" % (io_stack_reg, GetDisasm(i))
			# Check for DeviceIoControlCode which is IO_STACK_LOCATION+18h
			if io_stack_reg + "+18h" in disasm:
				if io_stack_reg + "+18h" in src:
					OpStroffEx(i, 1, io_stack_location_id, 0)
				else:
					OpStroffEx(i, 0, io_stack_location_id, 0)
				print "[+] Made struct IO_STACK_LOCATION+DeviceIoControlCode"
			# Check for InputBufferLength which is IO_STACK_LOCATION+10h
			elif io_stack_reg in "+10h" in disasm:
				if io_stack_reg + "+10h" in src:
					OpStroffEx(i, 1, io_stack_location_id, 0)
				else:
					OpStroffEx(i, 1, io_stack_location_id, 0)
				print "[+] Made struct IO_STACK_LOCATION+InputBufferLength"
			# Check for OutputBufferLength which is IO_STACK_LOCATION+8
			elif io_stack_reg + "+8" in disasm:
				if io_stack_reg + "+8" in src:
					OpStroffEx(i, 1, io_stack_location_id, 0)
				else:
					OpStroffEx(i, 0, io_stack_location_id, 0)
				print "[+] Made struct IO_STACK_LOCATION+OutputBufferLength"
			# io_stack_reg is being clobbered
			elif GetMnem(i) == "mov" and GetOpnd(i, 0) == io_stack_reg:
				io_stack_flag = 1
		else:
			continue
			#print "[+] nothing interesting in %08x\nInstruction: %s" % (i, GetDisasm(i))
