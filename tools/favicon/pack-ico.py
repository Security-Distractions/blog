#!/usr/bin/env python3
"""Pack PNGs into a multi-resolution .ico. Pillow is not installed here and is not needed:
the ICO format has allowed whole PNG files as entries since Vista, so this is just a header
plus the PNG bytes. Sizes must be <= 256.

Usage: pack-ico.py out.ico in16.png in32.png in48.png
"""
import struct
import sys

out, srcs = sys.argv[1], sys.argv[2:]
imgs = []
for p in srcs:
    d = open(p, "rb").read()
    assert d[:8] == b"\x89PNG\r\n\x1a\n", "%s is not a PNG" % p
    w, h = struct.unpack(">II", d[16:24])       # IHDR width/height
    assert w <= 256 and h <= 256, "%s is %dx%d; ICO entries max at 256" % (p, w, h)
    imgs.append((w, h, d))

offset = 6 + 16 * len(imgs)                      # ICONDIR + one ICONDIRENTRY each
hdr = struct.pack("<HHH", 0, 1, len(imgs))       # reserved, type 1 = icon, count
entries, blobs = b"", b""
for w, h, d in imgs:
    entries += struct.pack(
        "<BBBBHHII",
        0 if w == 256 else w, 0 if h == 256 else h,  # 0 means 256
        0, 0,                                        # palette count, reserved
        1, 32,                                       # colour planes, bits per pixel
        len(d), offset,
    )
    blobs += d
    offset += len(d)
open(out, "wb").write(hdr + entries + blobs)
print("%s: %d entries (%s), %d bytes"
      % (out, len(imgs), " ".join("%dx%d" % (w, h) for w, h, _ in imgs), len(hdr + entries + blobs)))
