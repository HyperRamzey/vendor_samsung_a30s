#!/usr/bin/env python
"""
Correct the over-tall stream configuration in libexynoscamera3.so.

    stream-config record {5760, 4320, 50000000}  ->  {5760, 4312, 50000000}

Why
---
The IMX576's real active array is 5760x4312, but the ROM's camera HAL
advertises a 5760x4320 stream configuration.  The framework then clamps AGC's
SCALER_CROP_REGION to a size the sensor physically cannot deliver, and the HAL
logs, once per frame:

    ExynosCamera: m_updateCropRegion[4214]: FT(n) Invalid Crop Size(5760, 4320),
                                                         sensorMax(5760, 4312)

Measured on-device on stock: 1386-1535 occurrences per session.

This is a data-table correction, not a logic change: it makes the advertised
max size agree with the sensor, so the clamp becomes a no-op.

Evidence (32-bit /vendor/lib, the object the camera provider actually maps -
the provider is a 32-bit process):

  stock  2f02355beef3106e...  Invalid Crop Size: 1386
  patched 2b34261e06c85ad0...  Invalid Crop Size: 0
          still 3,409,288 B / HDR+ 3,454,844 B / video 59,283,268 B, all OK

Usage
-----
    python patch_crop_table.py <in.so> [out.so] [--all] [--expect-sha HEX]

  default   patch only the first (back-camera) record - this is the site that
            was runtime-verified
  --all     patch every 5760x4320@50fps record found (for blobs whose live
            site has not been identified)

The script is idempotent: an already-corrected blob is reported and left
untouched, so it is safe to re-run over a build tree.
"""
import hashlib
import struct
import sys

# The IMX576 active array.
TRUE_W, TRUE_H = 5760, 4312
# The value the ROM wrongly advertises.
BOGUS_H = 4320
# 50 fps expressed in the interval units the table uses.
INTERVAL = 50000000


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5(data):
    return hashlib.md5(data).hexdigest()


def find_sites(d):
    """Return file offsets of every {5760, h, 50000000} record."""
    w_pat = struct.pack("<I", TRUE_W)
    f_pat = struct.pack("<I", INTERVAL)
    out = []
    off = 0
    while True:
        i = d.find(w_pat, off)
        if i < 0:
            break
        off = i + 1
        if d[i + 8:i + 12] == f_pat:
            h, = struct.unpack_from("<I", d, i + 4)
            if h in (BOGUS_H, TRUE_H):
                out.append((i, h))
    return out


def main(argv):
    argv = list(argv)
    expect = None
    patch_all = False
    positional = []
    it = iter(range(1, len(argv)))
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok == "--all":
            patch_all = True
        elif tok == "--expect-sha":
            if i + 1 >= len(argv):
                sys.exit("--expect-sha needs a value")
            expect = argv[i + 1].lstrip("#")
            i += 1
        elif tok.startswith("--"):
            sys.exit("unknown option %s" % tok)
        else:
            positional.append(tok)
        i += 1

    if not positional:
        sys.exit(__doc__)

    src = positional[0]
    dst = positional[1] if len(positional) > 1 else src

    before = sha256(src)
    print("input   %s" % src)
    print("        sha256 %s" % before)
    if expect and before != expect:
        sys.exit("input hash mismatch\n  expected %s\n  got      %s" % (expect, before))

    data = bytearray(open(src, "rb").read())
    sites = find_sites(data)
    if not sites:
        print("no {5760, ?, 50000000} stream records found - nothing to do")
        print("output  sha256 %s (unchanged)" % before)
        return 0

    print("records found:")
    for off, h in sites:
        verdict = "OK (already correct)" if h == TRUE_H else "WRONG (%d -> %d)" % (h, TRUE_H)
        print("  file 0x%06X  h=%-6d %s" % (off, h, verdict))

    targets = sites if patch_all else sites[:1]
    if not patch_all and len(sites) > 1:
        print("        (patching the first record only; --all would patch %d)"
              % len(sites))

    changed = 0
    for off, h in targets:
        if h == TRUE_H:
            continue
        struct.pack_into("<I", data, off + 4, TRUE_H)
        changed += 1
        print("patch   file 0x%06X  height %d -> %d  (1 byte: 0x%02X -> 0x%02X)"
              % (off + 4, h, TRUE_H, h & 0xFF, TRUE_H & 0xFF))

    if changed == 0:
        print("result  already correct, no bytes changed")
        print("output  sha256 %s" % before)
        return 0

    # Re-verify only the records this run was asked to correct.  The blob
    # legitimately keeps other 5760x4320 records (there are three groups of
    # three); the back-camera one is the site that was runtime-verified.
    patched_offsets = {off for off, _ in targets}
    after = {off: h for off, h in find_sites(data)}
    for off in sorted(patched_offsets):
        if after.get(off) != TRUE_H:
            sys.exit("post-patch check failed at 0x%06X (h=%s)"
                     % (off, after.get(off)))
    for off, h in after.items():
        if off not in patched_offsets and h == BOGUS_H:
            print("note    file 0x%06X left at %d (not a target of this run)"
                  % (off, h))

    if dst != src:
        open(dst, "wb").write(data)
    else:
        open(src, "wb").write(data)

    print("result  %d byte(s) changed across %d record(s)" % (changed, len(targets)))
    print("output  %s" % dst)
    print("        sha256 %s" % sha256(dst))
    print("        md5    %s" % md5(data))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
