# [ WriteUp/Notes ] | More RAM | Forensic - Cyber League 2025

## By: Haalloobim as [HCS](https://ctftime.org/team/70159)

## Description 
1. Desc: 
Little John thought he could download galvanised steel squares from the internet :O

2. Tools:
- [volatility3](https://github.com/volatilityfoundation/volatility3)

3. File: 
- [memory.zip](https://drive.google.com/file/d/14SrUWo9JF9oOa8glfRfzfk8ZUw7g-yBU/view?usp=sharing)

## How to solve? 

#### ;tldr 

1. We've been provided a memory.lime, and we analyze it using volatility3
2. Using banners plugin, we can see that a linux memory and now the kernel version system map
3. And based on the system map, we look up the kernel system map to make it as a custom profile, and put that custom profile in this path `[vol-download]/volatility3/symbol/linux/`
4. After put that custom profile, use linux.bash as a plugin and get the flag. 

#### Flag: `CYBERLEAGUE{its_2025_whos_still_downloading_more_ram?!?!_34effo}`