// Includes
#include <ntifs.h> // For ZWQueryVirtualMemory and other types (PEPROCESS)
#include <ntstrsafe.h> // For RtlUnicodeStringInit
#include <windef.h> // For FLOATS
extern int _fltused = 1; // Signal that our driver is using FLOATING POINT (because games often use floats and when we edit an address' value, we have to do FP arithmetic)

// Definitions
#define DBG_PREFIX "sevenF_Drv: " // Prefix to be added in all DbgPrint calls in this project
#define DbgPrintLine(s, ...) DbgPrint(DBG_PREFIX s "\n", __VA_ARGS__) // Concatenate prefix, str, and newline
#define BUFSIZE 100 // Used for storing temporary values such as user input
#define NUM_ADDRESSES 700000000LL // THIS METHOD EATS UP MEMORY. If you don't have 16 gb you're done for
#define NUM_ULONG   700000000LL // We will map a giant section of memory to the target process and the driver process that will store the addresses found and their values
#define SECTION_SIZE (((NUM_ADDRESSES * sizeof(PULONG)) + (NUM_ULONG * sizeof(ULONG)))) // After testing (on only one game), the average values found were 640-660 million
// Cast to LL (long long) because of large value (5.6 billion bytes)

// Structs
NTSTATUS NTAPI MmCopyVirtualMemory // Used for writing to target process memory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

// Global variables
LARGE_INTEGER byteOffset = { 0 }; // Offset to start reading/writing file at (we want 0). Reason we have this global is because multiple funcs use this
OBJECT_ATTRIBUTES objAttr = { 0 }; // Multiple functions (when writing/reading to the target file) need the initialized object attributes
PEPROCESS target = { 0 }; // Targeted PEPROCESS to read memory from

PULONG* procAddressArr = 0; // Start of the addresses array in the TARGET process (stored addresses of values)
ULONG* procUlongArr = 0; // Start of the Ulong/value array in the TARGET process (stored values)

PULONG* drvAddressArr = 0;  // Start of the addresses array in the DRIVER process (stored addresses of values)
ULONG* drvUlongArr = 0;  // Start of the Ulong/value array in the DRIVER process (stored values)

PVOID drvSecBaseAddr = NULL; // Base address of the mapped section of memory in the driver process
PVOID procSecBaseAddr = NULL; // Base address of the mapped section of memory in the target process

HANDLE procHandle = { 0 }; // Actual handle to the process that we will use for ZwQueryVirtualMemory
HANDLE sectionHandle = { 0 }; // Handle to the created section of memory that will be mapped to the driver and the target

long long allFound = 0; // All 4-byte values and their addresses (readable, writable, & committed) scanned
long long allCounter = 0; // Will be used when we use the change() and nochange() functions to weed out values we don't want
int mapFlag = 0; // Check if we've created a section of memory and successfully mapped it already

// Functions
static NTSTATUS KernelReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;

	return MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetAddress, Size, KernelMode, &Bytes);
}

static NTSTATUS KernelWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes; // We could just KeStackAttachProcess, but this a simpler method
	// Only reason this isn't used when scanning is because THIS IS SLOW for many values
	return MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, &Bytes);
}

void NTAPI DriverUnload(PDRIVER_OBJECT DriverObject)
{
	// Routine that is called when driver is unloaded

	NTSTATUS status = 0;

	DbgPrintLine("DriverUnload(0x%p), Status=0x%x", DriverObject, status);
}

static void drawback()
{ // Used for writing a default value to the file so that the previous command won't be re-executed repeatedly
	IO_STATUS_BLOCK ioStatusBlock;
	char* buffer = "init"; // "init" will be our default value
	HANDLE writeHandle; // Create a handle for writing to the file

	NTSTATUS status = ZwCreateFile( // We're not "Creating a FILE" but we can use this to open a FILE
		&writeHandle,
		GENERIC_WRITE, // Instead of reading we will be WRITING
		&objAttr, // Use our previously initialized object attributes in DriverEntry that includes path
		&ioStatusBlock, // Not used
		NULL, // Optional don't need allocation size
		FILE_ATTRIBUTE_NORMAL, // Normal attributes
		FILE_SHARE_READ | FILE_SHARE_WRITE, // Make it so that we can read and write freely 
		FILE_OPEN, // We're opening file
		FILE_SYNCHRONOUS_IO_NONALERT, // Synchronize (whatever that means)
		NULL, // Should be NULL
		0 // Should be 0
	);

	if (!(NT_SUCCESS(status))) { DbgPrintLine("CRITICAL: ZwCreateFile"); return; }
	else {
		status = ZwWriteFile(
			writeHandle, // Handle to the file
			NULL, // Should be NULL
			NULL, // Should be NULL
			NULL, // Should be NULL
			&ioStatusBlock, // Status & info about requested write that we don't need
			buffer,// Data to write to file "init"
			sizeof(char) * 4, // 4 bytes for init
			&byteOffset, // At the beginning
			NULL // Should be NULL
		);
		if (!(NT_SUCCESS(status))) { DbgPrintLine("CRITICAL: (0x%X) ZwWriteFile", status); }
	}
	ZwClose(writeHandle);
}

static void* getAddr(char* buffer) // Convert the address passed by the user to the buffer to an actual addr
{ // Addresses are 64 bits, so the intuition is to split the addr and use RtlCharToInteger and then combine the two integers
	ULONG upper_32 = 0;
	ULONG lower_32 = 0;

	// Suppose we have an address 0000031ACDFE1EB4 
	// Then split them into two 0000031A CDFE1EB4
	// The format of the fadd call is fadd 64bitADDR (in hex) val
	RtlCharToInteger(buffer + 13, 16, &lower_32); // First the lower 32 because we need to place a null terminator
	buffer[13] = '\0'; // Used for getting the upper 32 bits. Note that the characters are BASE 16

	RtlCharToInteger(buffer + 5, 16, &upper_32); // Address begins at byte 5 (0-3 for incr, 4 for space)

	ULONG_PTR address = ((ULONG_PTR)upper_32 << 32) | lower_32; // Shift the upper part 32 bits and then bitwise OR the lower part (or add)

	return((void*)address);
}

static void link(char* buffer) // Get the EPROCESS struct of the target so we can get a handle later
{
	ULONG pid = 0; // Link to the target using the supplied pid

	RtlCharToInteger(buffer + 5, 10, &pid); // Our command is from bytes 0-3, space is byte 4, and pid is byte 5 onwards. 10 means BASE 10
	DbgPrintLine("Link %lu", pid);
	if (pid != 0) // If RtlCharToInt failed earlier for some reason (no supplied PID)
	{
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &target); // Get EPROCESS
		if (!(NT_SUCCESS(status))) { DbgPrintLine("Error: PsLookupProcessByProcessId");  target = NULL; } // getHandle will fail later if this NULL
	}
	else { DbgPrintLine("Error: PID, RtlCharToInt"); target = NULL; } // getHandle will fail later if this NULL

	drawback(); // MAKE SURE WHENEVER WE RUN A COMMAND WE DON'T RUN IT AGAIN
}

static void resetBuffer(char* buffer)
{
	for (int i = 0; i < BUFSIZE; i++) { buffer[i] = '\0'; } // Zero out the buffer so it doesn't potentially mess with our next command
}

static NTSTATUS getHandle(PEPROCESS Process, PHANDLE pHandle) // Actually get a handle to the target 
{
	NTSTATUS status = ObOpenObjectByPointer(
		Process, // EPROCESS struct we got earlier when linking
		OBJ_KERNEL_HANDLE, // This is a kernel handle
		NULL, // Optional, don't need access state
		PROCESS_ALL_ACCESS, // All access to target
		NULL, // Optional because of KERNEL MODE
		KernelMode, // Access mode
		pHandle // Out, handle to object
	);

	return status;
}

static NTSTATUS mapSection()
{

	LARGE_INTEGER sectionSize = { 0 }; // We must specify the Section size/Maximum size as a LARGE_INTEGER
	SIZE_T viewSize = 0; // 0 means map the entire section

	sectionSize.QuadPart = SECTION_SIZE;

	NTSTATUS status = ZwCreateSection(
		&sectionHandle, // Out, Section Handle
		SECTION_ALL_ACCESS, // All access to the section
		NULL, // We don't need the object attributes
		&sectionSize, // Maximum size of section
		PAGE_READWRITE, // Page protection
		SEC_COMMIT, //  Commit the section (whatever this means)
		NULL // Don't need FileHandle
	);

	if (!(NT_SUCCESS(status)))
	{
		DbgPrintLine("ZwCreateSection failed: 0x%X", status);
		return status;
	}

	status = ZwMapViewOfSection(
		sectionHandle,// SEC HANDLE
		NtCurrentProcess(),// We must map to both the driver proc and target proc
		&drvSecBaseAddr,
		0, // I don't know, should be 0 I guess
		0, // Don't commit anything yet (committing ~5.6 billion bytes is a crime to the pagefile)
		NULL, // Don't need section offset
		&viewSize,// Maps view of the ENTIRE section into the drv process (if we specify 0)
		ViewUnmap, // Don't share with child processes
		0, // I don't know, MEM_COMMIT is implied
		PAGE_READWRITE // We can read/write to the section
	);

	if (!(NT_SUCCESS(status)))
	{
		DbgPrintLine("ZwMapViewOfSection to driver proc failed: 0x%X", status);
		ZwClose(sectionHandle);
		return status;
	}

	status = ZwMapViewOfSection(
		sectionHandle,
		procHandle, // Same as above except we map this to the target process
		&procSecBaseAddr, // Store base address of section that was mapped to target proc
		0,
		0,
		NULL,
		&viewSize,
		ViewUnmap,
		0,
		PAGE_READWRITE
	);

	if (!(NT_SUCCESS(status)))
	{ // If we can map to our current driver but not to target process, then free map
		ZwUnmapViewOfSection(NtCurrentProcess(), drvSecBaseAddr);
		DbgPrintLine("ZwMapViewOfSection to target proc failed: 0x%X", status);
		ZwClose(sectionHandle);
		return status;
	}

	// Setup our references to the parts of the section
	procAddressArr = (PULONG*)procSecBaseAddr; // Our addresses will be stored first
	procUlongArr = (ULONG*)((PUCHAR)procSecBaseAddr + (NUM_ADDRESSES * sizeof(PULONG)));
	// Then we will store the values immediately following the addresses. cast to puchar to add bytes

	drvAddressArr = (PULONG*)drvSecBaseAddr; // Same as above
	drvUlongArr = (ULONG*)((PUCHAR)drvSecBaseAddr + (NUM_ADDRESSES * sizeof(PULONG)));

	return status;
}

static void finish() // When we are done with everything and want to exit the driver
{  // If we need to initiate a new scan or we're closing our driver, we NEED to clear our mapping
	ZwUnmapViewOfSection(NtCurrentProcess(), drvSecBaseAddr); // Unmap from driver
	ZwUnmapViewOfSection(procHandle, procSecBaseAddr); // Unmap from process
	ZwClose(sectionHandle); // Close our created section handle
	ZwClose(procHandle);
}

static void nochange() // If some addresses DO CHANGE, and their value is not the same, we set the addr in the section to NULL
{
	KAPC_STATE apcState; // the apcState

	KeStackAttachProcess(target, &apcState); // Enter into the target's address space
	for (int i = 0; i < allFound; i++) // Go through all found
	{
		if (procAddressArr[i] != NULL) // If the current address we're looking at is not NULL
		{
			ULONG copied = 0; // The value we will test for the change
			int valid_flag = 1; // The flag to test if the operation was successful

			PULONG addr = procAddressArr[i]; // the address will retrieve the value at

			__try { // Try dereferencing the value at the address
				copied = *addr;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				valid_flag = 0; // If not successful, set the flag
			}

			if (valid_flag) // If the dereferenced value is not the same as the stored val, then set this to NULL since we are no longer interested
			{
				if (copied != procUlongArr[i]) { allCounter -= 1; procAddressArr[i] = NULL; } // Update counter
			}
			else { allCounter -= 1; procAddressArr[i] = NULL; } // Update counter if the address is no longer valid
		}
	}
	KeUnstackDetachProcess(&apcState);

	DbgPrintLine("New Total (NoChange): %llu", allCounter); // Print the new amount of potential addresses that we're interested in
	drawback(); // MAKE SURE WHENEVER WE RUN A COMMAND WE DON'T RUN IT AGAIN
}

static void change() // If some addresses DO NOT CHANGE, and their value is the same, we set the addr in the section to NIL
{
	KAPC_STATE apcState; // the apcState

	KeStackAttachProcess(target, &apcState); // Enter into the target's address space
	for (int i = 0; i < allFound; i++) // Go through all found
	{
		if (procAddressArr[i] != NULL) // If the current address we're looking at is not NULL
		{
			ULONG copied = 0; // The value we will test for the change
			int valid_flag = 1; // The flag to test if the operation was successful

			PULONG addr = procAddressArr[i]; // the address will retrieve the value at

			__try { // Try dereferencing the value at the address
				copied = *addr;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				valid_flag = 0; // If not successful, set the flag
			}

			if (valid_flag)
			{ // If the dereferenced value is the same as the stored val (the val has not changed), then set this to NIL since we are no longer interested
				if (copied == procUlongArr[i]) { allCounter -= 1; procAddressArr[i] = NULL; }
				else { procUlongArr[i] = copied; } // Make sure we update the value with the new value if its CHANGED!

			}
			else { allCounter -= 1; procAddressArr[i] = NULL; } // Update counter if the address is no longer valid
		}
	}
	KeUnstackDetachProcess(&apcState);

	DbgPrintLine("New Total (Change): %llu", allCounter); // Print the new amount of potential addresses that we're interested in
	drawback(); // MAKE SURE WHENEVER WE RUN A COMMAND WE DON'T RUN IT AGAIN
}

static void print_addr()
{
	for (int i = 0; i < allFound; i++) // Go through all found addresses/values
	{
		if (drvAddressArr[i] != NULL) // If we didn't set the address to NULL earlier then
		{
			DbgPrintLine("Address: %p, Value: %lu", drvAddressArr[i], drvUlongArr[i]); // Print the address and value
		}
	}
	drawback(); // MAKE SURE WHENEVER WE RUN A COMMAND WE DON'T RUN IT AGAIN
}

static void fadd(char* buffer) // Note that this does not handle FP because of RtlCharToInt, so you will only basically increment the FP value
{
	buffer[21] = '\0'; // Separate the address from the increment
	void* trueAddress = getAddr(buffer); // bytes 0-3 are fadd, byte 4 is space, bytes 5-20 are the address

	ULONG increment = 0;
	RtlCharToInteger(buffer + 22, 10, &increment); // Get the value to "add" (increment)

	XSTATE_SAVE saveMe;

	if (NT_SUCCESS(KeSaveExtendedProcessorState(XSTATE_MASK_LEGACY_FLOATING_POINT, &saveMe)))
	{ // I don't know, but we use this to avoid interfering with the floating-point state of other applications running

		FLOAT orig = 0.0f;
		KernelReadVirtualMemory(target, trueAddress, &orig, 4); // Get the current value at the address specified & save it as a float

		orig += (FLOAT)increment; // Add the increment as a float to orig

		KernelWriteVirtualMemory(target, &orig, trueAddress, 4); // Finally write back to the address with the increased float
		KeRestoreExtendedProcessorState(&saveMe); // Restore the FPU state after
	}
	else { DbgPrintLine("Error: KeSaveExtendedProcessorState"); }
	drawback(); // MAKE SURE WHENEVER WE RUN A COMMAND WE DON'T RUN IT AGAIN
}

static void actually_scan() // Perform the actual scanning of the target process
{
	MEMORY_BASIC_INFORMATION memInfo; // Used to store the memory state of the process when QueryVirtualMemory is called
	void* currentScanAddress = 0x0; // We will always look for commited, readable, writable pages starting from VA addr 0

	while (NT_SUCCESS(ZwQueryVirtualMemory(procHandle, currentScanAddress, MemoryBasicInformation, &memInfo, sizeof(MEMORY_BASIC_INFORMATION), NULL)))
	{ // While there are still contiguous pages/page region beginning at the current scan address 

		currentScanAddress = (char*)memInfo.BaseAddress + memInfo.RegionSize; // We increment this early on so we can use it as bound when iterating through addrs 

		if (memInfo.State == MEM_COMMIT && memInfo.Protect == PAGE_READWRITE && memInfo.Type != MEM_MAPPED)
		{  // Because we map the section we created earlier into the target process (for faster scanning), don't want to rescan

			DbgPrintLine("Page Region At: %p, Region Size: %zu", memInfo.BaseAddress, memInfo.RegionSize);
			ULONG* advancer = (ULONG*)memInfo.BaseAddress; // We will scan values that are 4 bytes only (float, int, etc)

			KAPC_STATE apcState;
			KeStackAttachProcess(target, &apcState); // We will attach to the address space of the process when we scan the current region for quicker scanning.
			while (advancer < (ULONG*)currentScanAddress) // If we were to use MmCopyVM here, it would be extremely slow
			{
				ULONG copied = 0;
				int valid_flag = 1;

				__try {
					copied = *advancer; // Attempt to dereference the value at the current address in advancer/walker
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					valid_flag = 0;
					//DbgPrintLine("Memory access violation!");
				}

				if (valid_flag) // If we didn't get a mem access violation, then we can safely store this in our mapped section
				{
					procAddressArr[allFound] = advancer; // We have to make sure we're storing it in the section address of the TARGET PROCESS
					procUlongArr[allFound] = copied; // If we stored it in the section address of the driver process then bad things would happen
					allFound++; // Because the target process section is likely not mapped to the same address as the driver section 
				}
				else { break; } // The page is a lost cause and long gone... break
				advancer++; // Increment our pointer to the next 4 bytes in the region
			}
			KeUnstackDetachProcess(&apcState); // Detach from address space of target process

		}
	}

	DbgPrintLine("Total: %lld", allFound); // All 4 byte values committed, readable, writable values found
	allCounter = allFound; // Used when we have to weed down our addresses when using change/no change
}

static void scan() // The core functionality of our driver
{
	allFound = 0; // We reset these to 0 just in case the user initiated a previous scan
	allCounter = 0; // allFound is the total amount we found on the initial scan, and then allCounter will decrease as we scan for changes/no changes

	if (mapFlag) { finish(); } // If already mapped, don't create another mapping or bad things will happen

	if (!NT_SUCCESS(getHandle(target, &procHandle)))
	{
		DbgPrintLine("Failed to open handle for EPROCESS"); return;
	}
	if (!NT_SUCCESS(mapSection()))
	{
		DbgPrintLine("FAILED TO CREATE MAPPINGS"); return;
	}
	// Create a memory section and map it to both the target process and our driver process

	mapFlag = 1; // So we can free the mapping later, if we dont acquire mapping then map = 0
	actually_scan();

	drawback(); // MAKE SURE WHENEVER WE RUN A COMMAND WE DON'T RUN IT AGAIN
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	// Main driver entry routine
	UNREFERENCED_PARAMETER(DriverObject); // Not in use
	UNREFERENCED_PARAMETER(RegistryPath); // Not in use

	DbgPrintLine("DriverLoad(0x%p, %wZ)", DriverObject, RegistryPath); // Driver has loaded

	DriverObject->DriverUnload = DriverUnload; // Unload function

	UNICODE_STRING uniName; // Unicode name we can pass to initialize object attributes and then to create file
	NTSTATUS status = RtlUnicodeStringInit(&uniName, L"\\SystemRoot\\userInput.txt"); // This will be stored in the Windows folder

	if (NT_SUCCESS(status))
	{
		InitializeObjectAttributes(&objAttr, &uniName, // Used for setting up/helping to create handle to object 
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, // Case insensitive path, and specify that the handle can only be accessed in kernel mode
			NULL, NULL); // Don't need RootDirectory appended nor security descriptor (uniName absolute)

		if (KeGetCurrentIrql() != PASSIVE_LEVEL) // ZwCreateFile and other methods require PASSIVE_LEVEL
		{
			DbgPrintLine("CRITICAL: NOT PASSIVE LEVEL");
			return STATUS_INVALID_DEVICE_STATE;
		}
		else
		{
			IO_STATUS_BLOCK ioStatusBlock;
			HANDLE readHandle;
			status = ZwCreateFile( // Construct a handle to the user input file
				&readHandle, // Store handle
				GENERIC_READ, // We will only read
				&objAttr, // Earlier created object attributes
				&ioStatusBlock, // Not optional, store completion status and other info
				NULL, // Allocation size, don't need
				FILE_ATTRIBUTE_NORMAL,// Default file attributes
				FILE_SHARE_READ | FILE_SHARE_WRITE, // Allow the user to read and write to the file while driver is reading
				FILE_OVERWRITE, // Open the file, overwrite it. User must create the file themselves in Win directory or else it would require elevated privs to edit
				FILE_SYNCHRONOUS_IO_NONALERT, // Operations are performed synchronously (whatever that means)
				NULL,// Should be NULL
				0 // Should be 0
			);

			if (NT_SUCCESS(status))
			{
				DbgPrintLine("SUCCESS! File opened");

				LARGE_INTEGER interval; // Sleep for a little so we don't constantly run the while loop
				interval.QuadPart = -10000 * 1000; // (Negative for relative time) 1,000,000,000 nanoseconds or 1 second

				byteOffset.QuadPart = 0; // Manipulate ALL bits
				char buffer[BUFSIZE] = { 0 }; // Buffer of 100 bytes for chars

				drawback(); // Writes "init" to the file initially so ZwReadFile doesn't fail
				while (strcmp(buffer, "quit") != 0) // While the user hasn't exited the application by typing "quit" and unload hasn't been called
				{
					resetBuffer(buffer); // Reset the buffer with zeros every time we're about to read from the file
					KeDelayExecutionThread(KernelMode, FALSE, &interval); // Sleep the driver for a second
					status = ZwReadFile(
						readHandle, // Handle we constructed earlier
						NULL, // Should be NULL
						NULL, // Should be NULL
						NULL, // Should be NULL
						&ioStatusBlock, // Useless completion status
						buffer, // Place to read to
						BUFSIZE, // Size in length, of buffer
						&byteOffset, // Byte offset of file to read from (always read from 0 since we only read one line)
						NULL // Should be NULL
					);
					if (!(NT_SUCCESS(status))) { DbgPrintLine("CRITICAL: (0x%X) ZwReadFile", status);  break; }

					buffer[BUFSIZE - 96] = '\0'; // Our commands are only 4 characters, so separate buffer into command and args (anything after null terminator)

					// COMMANDS
					if (strcmp(buffer, "link") == 0) { link(buffer); } // Links the driver to a target process using a PID argument
					else if (strcmp(buffer, "scan") == 0) { scan(); } // Scans the target processes working (committed) memory for writable and readable pages
					else if (strcmp(buffer, "chan") == 0) { change(); } // If any of the values we scanned earlier have "changed" (not the same value), keep them
					else if (strcmp(buffer, "noch") == 0) { nochange(); } // If any of the values we scanned earlier have not changed (the same value), keep them
					else if (strcmp(buffer, "prin") == 0) { print_addr(); } // Print the non-null addresses in the mapped section and their associated values
					else if (strcmp(buffer, "fadd") == 0) { fadd(buffer); } // Add a floating point 

					DbgPrintLine("%s", buffer); // For debugging purposes and see what was put in the buffer
				}

				if (mapFlag) { finish(); } // If mapping set earlier, finish and cleanup our resources used
				ZwClose(readHandle); // Close the readHandle
			}
			else { DbgPrintLine("CRITICAL: ZwCreateFile"); }

		}
	}
	else
	{
		DbgPrintLine("CRITICAL: (0x%X) RtlUnicodeStringInit", status);
	}

	return 0;
}