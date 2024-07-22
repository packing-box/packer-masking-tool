# Installation

To install NotPacked++, you can either download the latest release from the [releases page](https://github.com/packing-box/packer-masking-tool/releases) or build it from source.

## Building from Source

To build NotPacked++ from source, you will need to have the following dependencies:

- [LIEF](https://lief.re/) - Library to Instrument Executable Formats
- [g++](https://gcc.gnu.org/) - GNU Compiler Collection


### LIEF Installation
You can install LIEF by running the following command:
```bash
./install_lief.sh
```
Or you can use the Dockerfile provided in the repository to build the tool, it will install all the dependencies for you.

### Building NotPacked++
Once you have installed the dependencies, you can build the tool by running the following command:
```bash
make
```

