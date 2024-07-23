# Quickstart
~TODO~


## Usage
`notpacked++ --help`
```
    _   __      __  ____             __            __          
   / | / ____  / /_/ __ \____ ______/ /_____  ____/ / __    __ 
  /  |/ / __ \/ __/ /_/ / __ `/ ___/ //_/ _ \/ __  __/ /___/ /_
 / /|  / /_/ / /_/ ____/ /_/ / /__/ ,< /  __/ /_/ /_  __/_  __/
/_/ |_/\____/\__/_/    \__,_/\___/_/|_|\___/\__,_/ /_/   /_/   
                                                               

 Author       :   J. RAMHANI
 Contributor  :   A. D'Hondt
 Version      :   0.1
 Copyright    :   © 2024
 License      :   GNU General Public License v3.0
======================================================


Description: This program applies some alterations to a PE file. 
 Note that when no alteration is specified ALL of them will be applied, if at least one is specified only selected ones will be applied

Usage: ./notpacked++ <input_file>

    -o <output_file>  : Set the output file name.
    --help            : Display this help message.

Other options: (by default all of them applies)
    --add-api         : Add 20 common API imports to the PE file.
    --fill-zero       : Fill sections with zeros from their raw size to their virtual size.
    --move-ep         : Move the entry point to a new low entropy section.
    --rename-sections : Rename packer sections to standard section names.

```

### Use case 1: All alterations
`notpacked++ input.exe`
This will apply all alterations to the input file.

### Use case 2: Selected alterations
`notpacked++ input.exe --add-api --fill-zero`

This will only apply the following :

- `--add-api`: Add 20 common API imports
- `--fill-zero`: Fill sections with zeros from their raw size to their virtual size.

### Use case 3: Output file
`notpacked++ input.exe -o output.exe`

> Note: If no output file is specified, the output file will be named `output_<inputFilename>.exe`

### Soon to come
- Support for input via pipe
`ls | notpacked++`