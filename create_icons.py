from PIL import Image, ImageDraw, ImageFont
import os

# Create icons folder
os.makedirs("icons", exist_ok=True)

# Create 128x128 icon
size = 128
img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Draw shield
draw.rectangle([20, 30, 108, 98], fill='#2c3e50', outline='#3498db', width=3)
draw.polygon([(64, 10), (40, 50), (88, 50)], fill='#e74c3c')

# Draw network lines
for i in range(5):
    y = 60 + i*8
    draw.line([(30, y), (98, y)], fill='#3498db', width=2)

# Save
img.save("icons/icon-128.png")
img.save("icons/icon.ico", format='ICO', sizes=[(128, 128)])

# Create smaller versions
for s in [64, 32, 16]:
    small = img.resize((s, s), Image.Resampling.LANCZOS)
    small.save(f"icons/icon-{s}.png")

print("✅ Icons created in icons/ folder")