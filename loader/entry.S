/* Entry trampoline for the loader shellcode.
 *
 * exe2h extracts .text from its first byte, and the generated payload
 * calls that address. DonutLoader must therefore be reachable at .text
 * offset 0. It is not the first function in the source anymore (static
 * helpers precede it), so this object is linked first and jumps to it.
 * All registers are preserved, including the instance pointer in RCX. */

	.text

#if defined(__x86_64__)
	jmp	DonutLoader
#else
	jmp	_DonutLoader
#endif
