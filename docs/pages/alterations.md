# Alterations

NotPacked++ can perform the following alterations on the input binary:

- `--add-api`: Add up to 20 common API imports to inflate the import table.
- `--rename-sections`: Rename packer sections to standard section names.
- `--permissions`: Change the permissions of the sections to standard permissions (read, write, execute).
- `--raw-size`: Edit the raw size value in the header of sections having a 0 raw size (without adding real data bytes).
- `--fill-sections`: Fill the slack of sections up to their virtual size, lowering the entropy of packed sections.

When no alteration is specified, the default behavior is `--fill-sections --permissions`.

Beyond the per-option behavior below, every run also applies a few
[header-level normalizations](#normalizations-applied-on-every-write) and keeps
the [injected code and filler non-signaturable](#anti-signature-and-realism).


### Add API imports

The `--add-api` option adds up to 20 common API imports (benign functions from
standard libraries such as `KERNEL32.DLL`) to the import table. A very small
import table is one of the strongest "packed" signals, both for heuristics and
for machine-learning classifiers, so inflating it with ordinary APIs makes the
file look more like a regular build.

Particularities:

- Imports are added to the existing library descriptor when one is already
  present (matched case-insensitively, e.g. an existing `kernel32.dll`), rather
  than creating a duplicate descriptor, and APIs already imported are skipped.
- Adding imports requires LIEF to rebuild the import directory when writing, so
  this option is meant to be **used on its own, not together with
  `--permissions`**: the import-table relocation would move the IAT and
  invalidate the `VirtualProtect` address that `--permissions` bakes into its
  injected code.


### Rename sections

The `--rename-sections` option renames packer sections to standard section names. It will rename sections names such as 'UPX0', 'UPX1', 'UPX2', etc. to standard names such as '.text', '.data', '.rsrc', etc. If the file contains standard sections, they will not be renamed.


### Permissions

The `--permissions` option updates the permissions of all sections to standard ones (rwx/rw-/..). It starts by moving the EP to a new section named '.text', and renaming other sections to standard names such as '.data' and '.rdata'. It then updates the permissions of the sections not matching the standard permissions linked to their names. For example: 'UPX0' will be renamed to '.rdata' and its permissions updated from 'rwx' to 'r--'. In order to keep the file functional, the permissions are reverted to their original values at runtime, to do this we inject code that uses the VirtualProtect function to change the permissions of the sections.

Particularities:

- The new `.text` section wraps the injected trampoline in filler. That filler
  is **data-like**: it is sampled from the byte distribution of a genuine
  low-entropy section of the same file (see
  [Anti-signature and realism](#anti-signature-and-realism)), so it resembles
  real data instead of an obviously synthetic repeating pattern.
- The small stub that recovers the image base at runtime is emitted in one of
  several equivalent instruction encodings, chosen per run, so the trampoline
  does not carry a fixed byte signature of the tool.
- Because this option injects code that runs at startup, you should validate
  that the altered file still runs on the target platform.


### Edit raw size

The `--raw-size` option edits the raw size value in the header for sections having a 0 raw size value. This alteration does not add real data bytes to the sections, it only changes the raw size value in the section header without increasing the file size. This alteration maintains the file's functionality and can be used to confuse detectors that rely on the raw size value equal to 0 to detect packers.


### Fill sections

The `--fill-sections` option fills each section's slack (the gap from its raw
size up to its virtual size) so that the raw and virtual sizes match, and it
uses that slack to lower entropy where it matters:

- The entropy of each section is measured. A **packed** section (above ~7.0
  bits/byte) has its slack filled with zero bytes, which give the largest drop
  in measured entropy per added byte and read like ordinary tail/BSS padding.
  The entropy before and after is reported.
- A **low-entropy** section has nothing to gain from flattening, so its slack is
  filled with [data-like filler](#anti-signature-and-realism) instead of a
  constant run.

Particularity / limitation: filling happens **within the existing slack** only.
A packed section whose raw size already equals its virtual size has no slack to
fill, so its entropy cannot be reduced this way; such a case is reported.


## Normalizations applied on every write

Independently of the selected options, every output file is normalized when it
is written:

- **Checksum**: the PE header checksum is recomputed on the written file and
  patched in place, so the file does not carry a stale (now invalid) checksum.
  This is a no-op when the original file had a zero checksum, which is normal
  for user-mode executables.
- **Timestamp**: a zeroed `TimeDateStamp` (a weak "non-standard build" signal
  that packers often leave behind) is replaced with a plausible build time,
  drawn at random from a past window (2015-2024) so the value is not itself a
  constant NotPacked++ signature. A non-zero timestamp is left untouched.


## Anti-signature and realism

Two cross-cutting concerns shape the bytes NotPacked++ writes:

- **No fixed signature of the tool.** Anything NotPacked++ injects (the
  image-base recovery stub, filler, overlay padding) is randomized per run.
  A single YARA/AV rule should not be able to fingerprint NotPacked++ itself
  from a constant byte pattern.
- **Filler that looks like data.** A perfectly periodic run (for example a
  constant byte, or a 3-byte pattern repeated) reads as low entropy but looks
  like nothing real, which is itself a signal. Instead, filler is drawn i.i.d.
  from the byte histogram of a genuine low-entropy section of the same file, so
  it shares a real section's byte profile and low entropy while being aperiodic
  and not a verbatim copy. When no suitable donor section exists, a plausible
  zeros-plus-ASCII distribution is used.
