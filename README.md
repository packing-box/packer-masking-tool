
<p align="center"><img src="logo.webp" width="150" height="150" style="border-radius:50%;"></p>
<h1 align="center">NotPacked++</h1>
<h3 align="center">Adversarial tool for breaking static detection of packed executable</h3>

&nbsp;

![NotPacked++](https://img.shields.io/badge/NotPacked++-v0.1-blue.svg)
![Version](https://img.shields.io/badge/Black%20Hat%20Arsenal-EU%202024-1E90FF)
![License](https://img.shields.io/badge/license-GNU-red.svg)
![Status](https://img.shields.io/badge/status-bêta-red.svg)

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




---
## Building your version

```sh
make
```

### Dependencies

- LIEF

### Installation of LIEF
> It may ask for ROOT privileges to install the dependencies
```sh
./install.sh
```

