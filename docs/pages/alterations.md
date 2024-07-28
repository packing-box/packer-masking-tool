# Alterations


NotPacked++ can perform the following alterations on the input binary:

- `--add-api`: Add 20 common API imports to the PE file.
- `--move-ep`: Move the entry point to a new low entropy section.
- `--rename-sections`: Rename packer sections to standard section names.
- `--permissions`: Change the permissions of the sections to standard permissions (read, write, execute).
- `--edit-raw-size`: Edit the raw size value in the header of sections having a 0 raw size (without adding real data bytes).



### Add API imports

The `--add-api` option adds 20 API imports commonly found in not packed executables to the input PE file, as many packers only have a few imports in the IAT. The LIEF library we use adds a new section named '.l1' when adding the API imports, thus we recommend using it along with the `--permissions` or the `--rename-sections` option to rename that section to a standard name.

>**NOTE** : This option is still under development and does not yet rebuild a functional file (because of LIEF current implementation). Thus the resulting file will not be functional.



### Move entry point

The `--move-ep` option moves the entry point to a new low entropy section. It creates a new section with low entropy and injects a trampoline code to jump back to the original entry point. This ensures the file remains functional after the alteration. This alteration targets detectors relying on the bytes of the entry point to detect packers.


### Rename sections

The `--rename-sections` option renames packer sections to standard section names. It will rename sections names such as 'UPX0', 'UPX1', 'UPX2', etc. to standard names such as '.text', '.data', '.rsrc', etc. If the file contains standard sections, they will not be renamed. 


### Permissions

The `--permissions` option updates the permissions of all sections to standard ones (rwx/rw-/..). It starts by moving the EP to a new section named '.text', and renaming other sections to standard names such as '.data' and '.rdata'. It then updates the permissions of the sections not matching the standard permissions linked to their names. For example: 'UPX0' will be renamed to '.rdata' and its permissions updated from 'rwx' to 'r--'. In order to keep the file functional, the permissions are reverted to their original values at runtime, to do this we inject code that uses the VirtualProtect function to change the permissions of the sections.


### Edit raw size

The `--edit-raw-size` option edits the raw size value in the header for sections having a 0 raw size value. This alteration does not add real data bytes to the sections, it only changes the raw size value in the section header. This alteration maintains the file's functionality and can be used to confuse detectors that rely on the raw size value equal to 0 to detect packers.




