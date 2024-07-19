
# NotPacked++

```
    _   __      __  ____             __            __          
   / | / ____  / /_/ __ \____ ______/ /_____  ____/ / __    __ 
  /  |/ / __ \/ __/ /_/ / __ `/ ___/ //_/ _ \/ __  __/ /___/ /_
 / /|  / /_/ / /_/ ____/ /_/ / /__/ ,< /  __/ /_/ /_  __/_  __/
/_/ |_/\____/\__/_/    \__,_/\___/_/|_|\___/\__,_/ /_/   /_/   
                                                               
```

![NotPacked++](https://img.shields.io/badge/NotPacked++-v0.0.1-blue.svg)
![Version](https://img.shields.io/badge/Black%20Hat%20Arsenal-EU%202024-1E90FF)
![License](https://img.shields.io/badge/license-GNU-red.svg)
![Status](https://img.shields.io/badge/status-bêta-red.svg)

---
NotPacked++, is an adversarial weaponized tool to alter a packed executable to evade static packing detection. It is designed to be used by malware analysts to test the effectiveness of their detection mechanisms and to improve their detection capabilities. It is also useful for red teamers to test the effectiveness of their evasion techniques, and highlight potential weaknesses of a target's security mechanisms.

In the current version, the tool focuses on the PE file format and the most common packers used in the wild. The tool is designed to be modular and extensible, so that it can be easily extended to support other file formats and packers.


### Dependencies

- LIEF
- objdump / cut / grep 

### Installation
> It may ask for ROOT privileges to install the dependencies
```sh
./install.sh
```

