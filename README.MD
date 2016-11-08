## Quickstart

### DriverBuddy Installation Instructions
1. Copy DriverBuddy folder and DriverBuddy.py file into the IDA plugins folder C:\Program Files (x86)\IDA 6.8\plugins or wherever you installed IDA


### DriverBuddy Usage Instructions 
1. Start IDA and open a Windows kernel driver
2. Go to Edit->Plugins and select Driver Buddy or press ctrl-alt-d
3. Check Output window for DriverBuddy analysis results
4. To decode IOCTLs, highlight the suspected IOCTL and press ctrl-alt-i

## DriverBuddy 

DriverBuddy is an IDAPython plugin that helps automate some of the tedium
surrounding the reverse engineering of Windows Kernel Drivers. It has a number
of handy features, such as:

* Identifying the type of driver
* Locating DispatchDeviceControl and DispatchInternalDeviceControl functions
* Populating common structs for WDF and WDM drivers
	* Attempts to identify and label structs like the IRP and IO_STACK_LOCATION
	* Labels calls to WDF functions that would normally be unlabeled
* Finding known IOCTL codes and decoding them
* Flagging functions prone to misuse


### Finding DispatchDeviceControl

Being able to automatically locate and identify the DispatchDeviceControl
function is a time saving task during driver reverse engineering. This function
is used to route all incoming DeviceIoControl codes to the specific driver
function associated with that code. Automatically identifying this function
makes finding the valid DeviceIoControl codes for each driver much quicker.
Additionally, when investigating possible vulnerabilities in a driver due to a
crash, knowing the location of this function helps narrow the focus to the
specific function call associated with the crashing DeviceIoControl code.


### Labeling WDM Structs

Several driver structures are shared among all WDM drivers. Being able to
automatically identify these structures, such as the IO_STACK_LOCATION, IRP,
and DeviceObject structures, can help save time during the reverse engineering
process. DriverBuddy attempts to locate and identify many of these structs.


### Labeling WDF Functions

As with WDM drivers, there are several functions and structures that are shared
among all WDF drivers. Automatically identifying these functions and structures
will save time during the reverse engineering process and provide context to
unindentified areas of the driver where these functions are in use.

### Decoding DeviceIoControl Codes 

While reversing drivers, it is common to come across IOCTL codes as part of the 
analysis. These codes, when decoded, reveal useful information to reverse 
engineers and may draw focus to specific parts of the driver where 
vulnerabilities are more likely to exist.  


### Future things:

1. Add obref and deref checks of some sort to help find refcount issues
2. Polish output, gui? 
3. Strengthen/polish current features
    - Improve reliablity of DispatchDeviceControl finder
    - Write short blurbs about why things are flagged
    - MSDN doc importer

Stretch Goals:
1. Find IOCTLs automatically
2. IRP taint analysis aka follow aliasing of sysbuf/inbuf, size
3. Identify other common structures
4. Uninitialized variables, etc


### Credits

* We are using Satoshi Tanda's IOCTL decoder, originally found here https://github.com/tandasat/WinIoCtlDecoder.
* The WDF functions struct is based on Red Plait's work (http://redplait.blogspot.ru/2012/12/wdffunctionsidc.html) and was ported to IDA Python by Nicolas Guigo, later updated by us.


### License

This software is released under the MIT License, see LICENSE.
