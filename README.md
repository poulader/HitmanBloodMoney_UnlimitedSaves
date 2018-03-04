# HitmanBloodMoney_UnlimitedSaves
Removes save limit for latest version of hitman blood money.

I added pattern matching to find target address, should work on non-steam and non-english now as well. I've only tested on steam though, make a new ticket if it fails on a non steam please.

You can now save and load on pro, plus unlimited saves on all difficulties.

I wrote this because I want to play harder difficulty in hitman blood money without being limited by saves.
I do not patch the hitman image on disk because they are using a packer which I'm working on atm; although they do not appear
to have any checksum checking for the part this modifies in the running process, there may be an initial checksum check before or while
unpacking as well. So this modifies an opcode in the hitman process in memory to always jmp to the "ok do a save" condition, instead of
a conditional jl based on number of saves so far. For load, it patches some opcodes to clear zf so it works for pro as well.

If you want to build yourself, you must use the compiler and linker settings included in the project file, "Minimal x86". If you do not, the size of the exported thread routine
may change, you will need to check disassembly and change the WPM size. Also, an earlier version had the exported function pointing to an entry in a jmp
table, so if you change compile/link options, watch out for that as well. I had to parse the instructions at the exported function address to get the
actual offset to the exported function, which is a pain. So change options at your own risk!
I am not responsible for the effectiveness, safety, or anything else of this software, blah blah blah, use at your own risk.
This does not modify any copyrighted files, it makes a change in your PCs memory, and this is for educational and research purposes.
Also I wrote this late at night so the code is sloppy, so sue me. I'll refactor later.
INstructions: Start hitman blood money, wait for it to reach main menu ("profile manager") or later. Run the program. It will tell you if it fails
or succeeds.
