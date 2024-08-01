# Quickstart




## Usage
`notpacked++ --help`
```
    _   __      __  ____             __            __          
   / | / ____  / /_/ __ \____ ______/ /_____  ____/ / __    __ 
  /  |/ / __ \/ __/ /_/ / __ `/ ___/ //_/ _ \/ __  __/ /___/ /_
 / /|  / /_/ / /_/ ____/ /_/ / /__/ ,< /  __/ /_/ /_  __/_  __/
/_/ |_/\____/\__/_/    \__,_/\___/_/|_|\___/\__,_/ /_/   /_/   
                                                               

 Authors      :   Jaber RAMHANI, Alexandre D'Hondt
 Version      :   0.1
 Copyright    :   © 2021-2024 Alexandre D'Hondt, Jaber Ramhani
 License      :   GNU General Public License v3.0
======================================================

Description: This program applies some alterations to a PE file. 
 Note that when no alteration is specified ALL of them will be applied, if at least one is specified only selected ones will be applied

Usage: ./notpacked++ <input_file> [OPTIONS]

    -o <output_file>  : Set the output file name. (default:<input_file>_out.exe)
    --help            : Display this help message.

Other options: (by default the behavior is --permissions --raw-size)
    --add-api         : Add 20 common API imports to the PE file. (Rebuilding a functional file not working yet)
    --fill-sections   : Fill sections with zeros from their raw size to their virtual size.
    --move-ep         : Move the entry point to a new low entropy section.
    --rename-sections : Rename packer sections to standard section names.
    --permissions      : Update the permissions of all sections to standard ones (rwx/rw-/..), moves the EP to a new section and renames sections.
    --raw-size    : Edit the raw size value in the header of sections having a 0 raw size (without adding real data bytes).

```

### Use case 1: All alterations
`notpacked++ input.exe`
This will apply the following alterations to the input file : 

- `--permissions`: Update the permissions of the sections to standard permissions (read, write, execute). This alteration also moves the entry point to a new section and renames sections.
- `--raw-size`: Edit the raw size value in the header of sections having a 0 raw size (without adding real data bytes).

### Use case 2: Selected alterations
`notpacked++ input.exe --rename-sections --move-ep`

This will only apply the following :

- `--rename-sections`: Rename packer sections to standard section names.
- `--move-ep`: Move the entry point to a new low entropy section.

### Use case 3: Output file
`notpacked++ input.exe -o output.exe`

> Note: If no output file is specified, the output file will be named `<inputFilename>_out.exe`

