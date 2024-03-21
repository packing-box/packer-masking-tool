
# NotPacked++ | PackerMask | BoringPE | BoringPacker

![PackerMask](https://img.shields.io/badge/PackerMask-v0.0.1-blue.svg)
![Version](https://img.shields.io/badge/Black%20Hat%20Arsenal-EU%202024-1E90FF)
![License](https://img.shields.io/badge/license-GNU-red.svg)
![Status](https://img.shields.io/badge/status-bêta-red.svg)

---
PackingMasking, is an adversarial weaponized tool to alter a packed executable to evade static packing detection. It is designed to be used by malware analysts to test the effectiveness of their detection mechanisms and to improve their detection capabilities. It is also useful for red teamers to test the effectiveness of their evasion techniques, and highlight potential weaknesses of a target's security mechanisms.

In the current version, the tool focuses on the PE file format and the most common packers used in the wild. The tool is designed to be modular and extensible, so that it can be easily extended to support other file formats and packers.


### Other name ideas
- PE-Mask
- MaskPE
- MaskExe
- MaskPack
- BoringPE
- PackerMask
- MalwareMask
- PMask
- MMasker
- PhantomX
- RaptorX
- RwX
- CleanPE
- JustAMaskForPE
- PE-Stealth
- JustXpack
- NothingToSeeHere
- NotPacked++
- MasterOfDisguise



### Dependencies

- LIEF
- objdump / cut / grep 

### Installation
> It may ask for ROOT privileges to install the dependencies
```sh
./install.sh
```

