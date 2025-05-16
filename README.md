# MinimalDriverMemScanner

Demonstration video: https://www.youtube.com/watch?v=hdolCuyAewA

The following commands are supported below. PLEASE use them as intended or else bad things will happen.

Link MUST be called before you perform any memory operations (scan, change, nochange).

Additionally, when you call "fadd", the fadd method relies on the assumption that you provide a full-length, 64-bit, hexadecimal address with leading zeros. For example: 0000031ACDFE1EB4. Do NOT include the leading hex prefix 0x.

You MUST call "quit" when you are done using the driver or else the section of memory (which is mapped to the driver and the target process) that is created when calling "scan" will REMAIN in memory and consume resources.

Commands are interpreted by the first 4 characters.

link [pid] /* Tells the driver the target process to get a handle to based on the supplied PID. */

scan /* Actually performs the memory scan. Note that this relies on mapping a section of memory and this absolutely consumes RAM depending on the application. I would not recommend running this on anything less than 16GB. */

chan (change) /* Searches through the stored addresses and evaluates the current value at the address VS the stored value. If they are NOT different (no change occurred), then we remove the address from the list. */

noch (nochange) /* Same as above, except if the stored value and the current value ARE different (a change occurred), then we remove the address from the list. */

prin (print) /* You have to use Dbgview, or an alternate method to view DbgPrint calls, because this function prints the current addresses in the list and their associated values using DbgPrint. */

fadd [address] [value] /* Stands for float add. Floats are commonly used in video games for values such as positional coordinates, health, etc, and this driver was developed to target those values. As stated above, when you supply the address, please make sure it follows the format 0000031ACDFE1EB4. Also, the value you supply will be parsed by RtlCharToInteger, so only non-negative whole numbers will be recognized. That value will then be casted to a FLOAT and added to the current value stored at the address. */

quit /* Successfully exits the driver. */

Before starting the driver via command line, make sure you have created the input file called "userInput.txt" and placed it into the C:\Windows folder (or wherever your Windows directory is). This is because the driver searches through the SystemRoot directory for "userInput.txt".

Please enter your commands at the beginning line of this file.