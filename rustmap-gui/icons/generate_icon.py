"""Generate a minimal 32x32 blue square .ico file without external dependencies."""
import struct

width = 32
height = 32

# Blue color in BGRA format
blue = b'\xFF\x80\x00\xFF'  # B=255, G=128, R=0, A=255 (blue)

# Build the BMP image data (bottom-up row order for BMP)
# 32-bit BGRA pixel data
pixel_data = blue * (width * height)

# AND mask: 1 bit per pixel, rows padded to 4 bytes
# All zeros = fully opaque (no transparency via AND mask)
and_mask_row_bytes = (width + 7) // 8  # 4 bytes for 32 pixels
and_mask_row_padded = ((and_mask_row_bytes + 3) // 4) * 4  # pad to 4 bytes
and_mask = b'\x00' * and_mask_row_padded * height

# BMP Info Header (BITMAPINFOHEADER) - 40 bytes
bmp_header = struct.pack('<I', 40)            # biSize
bmp_header += struct.pack('<i', width)         # biWidth
bmp_header += struct.pack('<i', height * 2)    # biHeight (doubled for ICO format: XOR + AND)
bmp_header += struct.pack('<H', 1)             # biPlanes
bmp_header += struct.pack('<H', 32)            # biBitCount (32-bit BGRA)
bmp_header += struct.pack('<I', 0)             # biCompression (BI_RGB)
bmp_header += struct.pack('<I', len(pixel_data) + len(and_mask))  # biSizeImage
bmp_header += struct.pack('<i', 0)             # biXPelsPerMeter
bmp_header += struct.pack('<i', 0)             # biYPelsPerMeter
bmp_header += struct.pack('<I', 0)             # biClrUsed
bmp_header += struct.pack('<I', 0)             # biClrImportant

image_data = bmp_header + pixel_data + and_mask
image_size = len(image_data)

# ICO Header - 6 bytes
ico_header = struct.pack('<HHH', 0, 1, 1)  # reserved=0, type=1 (ICO), count=1

# ICO Directory Entry - 16 bytes
ico_entry = struct.pack('<B', width if width < 256 else 0)   # bWidth (0 means 256)
ico_entry += struct.pack('<B', height if height < 256 else 0) # bHeight
ico_entry += struct.pack('<B', 0)              # bColorCount (0 for 32-bit)
ico_entry += struct.pack('<B', 0)              # bReserved
ico_entry += struct.pack('<H', 1)              # wPlanes
ico_entry += struct.pack('<H', 32)             # wBitCount
ico_entry += struct.pack('<I', image_size)     # dwBytesInRes
ico_entry += struct.pack('<I', 6 + 16)        # dwImageOffset (after header + 1 entry)

output_path = r'c:\Users\stell\OneDrive\Projects\RustMap\rustmap-gui\icons\icon.ico'

with open(output_path, 'wb') as f:
    f.write(ico_header)
    f.write(ico_entry)
    f.write(image_data)

print(f"Icon written to: {output_path}")
print(f"Total file size: {6 + 16 + image_size} bytes")
