# HitmanBloodMoney_UnlimitedSaves
Removes save limit for steam hitman blood money 1.2. 

Edit: For "Pro" difficulty, which has no saves allowed, saving works, but the load menu item needs to be patched. Will update soonish. For hard mode and below, eg the 3 saves or easier, it works fine.

Edit2: Steam has screwed up my two accounts with hitman blood money, I have the fix for pro but cannot test it. I'll put a second version up labelled as "untested" until someone with steam 1.2 tries it.

/*
I wrote this because I want to play harder difficulty in hitman blood money without being limited by saves.
I do not patch the hitman image on disk because they are using a packer which I'm working on atm; although they do not appear
to have any checksum checking for the part this modifies in the running process, there may be an initial checksum check before or while
unpacking as well. So this modifies an opcode in the hitman process in memory to always jmp to the "ok do a save" condition, instead of
a conditional jl based on number of saves so far.
This has been tested on the steam version, 1.2. It might not work on a non-steam version, as the offset from module base to opcode we want may 
be different. RPM does not appear to work on the steam 1.2 version, so as of right now I cannot dynamically find the instruction. I will
keep tinkering and see what is what for a future version.
You must use the compiler and linker settings included in the project file, "Minimal x86". If you do not, the size of the exported thread routine
may change, you will need to check disassembly and change the WPM size. Also, an earlier version had the exported function pointing to an entry in a jmp
table, so if you change compile/link options, watch out for that as well. I had to parse the instructions at the exported function address to get the
actual offset to the exported function, which is a pain. So change options at your own risk!
I am not responsible for the effectiveness, safety, or anything else of this software, blah blah blah, use at your own risk.
This does not modify any copyrighted files, it makes a change in your PCs memory, and this is for educational and research purposes.
Also I wrote this late at night so the code is sloppy, so sue me. I'll refactor later.
INstructions: Start hitman blood money 1.2 steam version, wait for it to reach main menu ("profile manager") or later. Run the program. It will tell you if it fails
or succeeds.
*/
