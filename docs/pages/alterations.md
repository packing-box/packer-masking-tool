# Alterations
~TODO~

NotPacked++ can perform the following alterations on the input binary:

- `--add-api`: Add 20 common API imports to the PE file.
- `--fill-zero`: Fill sections with zeros from their raw size to their virtual size.
- `--move-ep`: Move the entry point to a new low entropy section.
- `--rename-sections`: Rename packer sections to standard section names.

To apply all alterations to the input file, run the following command:

```bash
notpacked++ input.exe
```
