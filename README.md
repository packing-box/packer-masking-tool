
<p align="center"><img src="src/logo.png" width="150" height="150" style="border-radius:50%;"></p>
<h1 align="center">NotPacked++</h1>
<h3 align="center">Adversarial tool for breaking static detection of packed executable</h3>

<div align="center">

[![NotPacked++](https://img.shields.io/badge/NotPacked++-v0.1-blue.svg)](https://github.com/packing-box/packer-masking-tool)
[![Read The Docs](https://readthedocs.org/projects/docker-packing-box/badge/?version=latest)](http://packer-masking-tool.readthedocs.io/en/latest/?badge=latest)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-orange.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Status](https://img.shields.io/badge/status-bêta-red.svg)

</div>

---

NotPacked++, is an adversarial weaponized tool to alter a packed executable to evade static packing detection. It is designed to be used by malware analysts to test the effectiveness of their detection mechanisms and to improve their detection capabilities. It is also useful for red teamers to test the effectiveness of their evasion techniques, and highlight potential weaknesses of a target's security mechanisms.

In the current version, the tool focuses on the PE file format and the most common packers used in the wild. The tool is designed to be modular and extensible, so that it can be easily extended to support other file formats and packers.



### Usage
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




---
## Example of usage

`notpacked++ input.exe`

```
<<snipped>>

[INFO]   Updating the permissions of all sections to standard ones (rwx/rw-/..), moving the entry point to a new section and Renaming sections to standard ones...
[+] Renaming section UPX0 to .data
[+] Renaming section UPX1 to .rdata

[INFO]   Editing the raw size value in the header of sections having a 0 raw size (without adding real data bytes)...
[+]  Section .data raw size updated to 0x9285
[+] Section raw size updated successfully!

[SUCCESS]  File saved as: input_out.exe
```

### Detectors evasion

```bash
$ manalyze input_out.exe
-

$ peid input_out.exe
-

$ peframe input_out.exe
-

$ reminder input_out.exe
False

$ retdec input_out.exe
-

$ pepack input_out.exe
-

$ bintropy input_out.exe -b -v
[DEBUG] Average entropy criterion (>6.677): False (5.945434314305998)
[DEBUG] Highest entropy criterion (>7.199): True (7.222037048843471)
[DEBUG] Output:
False

False 0.030065735045354813

```




## Installation

To install NotPacked++, you can either download the latest release from the [releases page](https://github.com/packing-box/packer-masking-tool/releases) or build it from source. 

> Please refer to the [documentation](https://packer-masking-tool.readthedocs.io/en/latest/?badge=latest) for a full guide to build the tool from source.


---
## Supporters


[![Stargazers repo roster for @packing-box/packer-masking-tool](https://reporoster.com/stars/dark/packing-box/packer-masking-tool)](https://github.com/packing-box/packer-masking-tool/stargazers)
