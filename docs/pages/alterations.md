# Alterations


NotPacked++ can perform the following alterations on the input binary:

- `--rename-sections`: Rename packer sections to standard section names.
- `--permissions`: Change the permissions of the sections to standard permissions (read, write, execute).
- `--raw-size`: Edit the raw size value in the header of sections having a 0 raw size (without adding real data bytes).
- `--fill-sections`: Fill sections with zeros from their raw size to their virtual size.



### Rename sections

The `--rename-sections` option renames packer sections to standard section names. It will rename sections names such as 'UPX0', 'UPX1', 'UPX2', etc. to standard names such as '.text', '.data', '.rsrc', etc. If the file contains standard sections, they will not be renamed. 


### Permissions

The `--permissions` option updates the permissions of all sections to standard ones (rwx/rw-/..). It starts by moving the EP to a new section named '.text', and renaming other sections to standard names such as '.data' and '.rdata'. It then updates the permissions of the sections not matching the standard permissions linked to their names. For example: 'UPX0' will be renamed to '.rdata' and its permissions updated from 'rwx' to 'r--'. In order to keep the file functional, the permissions are reverted to their original values at runtime, to do this we inject code that uses the VirtualProtect function to change the permissions of the sections.


### Edit raw size

The `--raw-size` option edits the raw size value in the header for sections having a 0 raw size value. This alteration does not add real data bytes to the sections, it only changes the raw size value in the section header without increasing the file size. This alteration maintains the file's functionality and can be used to confuse detectors that rely on the raw size value equal to 0 to detect packers.


### Fill sections

The `--fill-sections` option fills sections with zeros from their raw size to their virtual size. The resulting sections will have the same raw and virtual size values. 




