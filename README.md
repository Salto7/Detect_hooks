# Detect_hooks
detects EDR hooks and identify the "hooking" module, the code assumes the EDR (more than one actually does this) patch consists of a relative jump to a function in ntdll that is stomped with a trampoline.
