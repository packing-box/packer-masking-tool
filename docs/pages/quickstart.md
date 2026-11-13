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

Other options: (by default the behavior is --fill-sections --permissions)
    --add-api         : Add up to 20 common API imports to inflate the import table. Use on its own (not with --permissions).
    --fill-sections   : Fill sections with zeros from their raw size to their virtual size.
    --rename-sections : Rename packer sections to standard section names.
    --permissions     : Update the permissions of all sections to standard ones (rwx/rw-/..), moves the EP to a new section and renames sections.
    --raw-size    : Edit the raw size value in the header of sections having a 0 raw size (without adding real data bytes).

```

### Use case 1: Default alterations
`notpacked++ input.exe`
When no alteration is specified, the default behavior applies the following to the input file :

- `--fill-sections`: Fill each section's slack up to its virtual size, lowering the entropy of packed sections.
- `--permissions`: Update the permissions of the sections to standard permissions (read, write, execute). This alteration also moves the entry point to a new section and renames sections.

> Note: a few header-level normalizations (checksum recomputation, zeroed-timestamp fix) are applied on every run, whatever the selected alterations. See [Alterations](alterations.md).

### Use case 2: Selected alterations
`notpacked++ input.exe --rename-sections --fill-sections`

This will only apply the following :

- `--rename-sections`: Rename packer sections to standard section names.
- `--fill-sections`: Fill sections with zeros from their raw size to their virtual size.

### Use case 3: Output file
`notpacked++ input.exe -o output.exe`

> Note: If no output file is specified, the output file will be named `<inputFilename>_out.exe`

