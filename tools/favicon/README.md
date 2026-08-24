# Site icons

`static/favicon.ico`, `favicon-16x16.png`, `favicon-32x32.png`, `apple-touch-icon.png` and
`icon-512.png` are generated from `assets/img/logo.png` — they are committed, so a normal build
needs nothing from this directory.

The wordmark is 1.78:1 and unusable as a tab icon, so the icon is the glitched **S** lifted out of
it, clipped to the glyph and centred. An `SD` monogram was tried and rejected: two letters in a
16px box are indistinguishable.

Regenerate only if the logo changes:

```sh
cp tools/favicon/build.mjs /opt/compromise-canvas/
cd /opt/compromise-canvas && node build.mjs /opt/blog/site   # prints the copy commands
```

`build.mjs` needs Playwright, which this repo does not depend on; `/opt/compromise-canvas` has it.
`pack-ico.py` writes the multi-resolution `.ico` (16/32/48) with the standard library alone —
Pillow is not needed, because ICO entries may be whole PNG files.
