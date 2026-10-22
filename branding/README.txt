NodeWatch startup branding
==========================

The native Windows launcher displays `startup.bmp` while the private runtime and local backend start.

To trial a different startup image later:
1. Prepare a 420 x 420 pixel, 24-bit RGB BMP.
2. Name it `startup.bmp`.
3. Replace this file in `_internal\branding` before launching NodeWatch.

`startup.png` is retained as the reference/source preview for the current artwork.

This file-based design is intentional: the splash artwork can change without modifying the application code.

v0.10.27: `icon.png` (256 x 256, rounded) is the same artwork cropped to its tile. It is the source of
every icon: the Windows launcher (.ico), the Mac app (.icns), the window/taskbar icon and the sidebar
logo (app/static/brand/*.png). Release packages ship `startup.bmp` (splash) and `icon.png`; `startup.png`
stays in the source tree as the full-size reference.
