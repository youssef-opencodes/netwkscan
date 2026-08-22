"""Script to generate NMD application icons (resources/icon.ico and resources/icon.png)."""
import os
from PIL import Image, ImageDraw

def create_shield_icon():
    os.makedirs("resources", exist_ok=True)
    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    
    img = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Outer dark circle background
    draw.ellipse([10, 10, 246, 246], fill=(15, 23, 42, 255), outline=(59, 130, 246, 255), width=6)
    
    # Shield shape points
    shield_points = [
        (128, 40),   # Top center
        (200, 70),   # Top right
        (190, 160),  # Mid right
        (128, 220),  # Bottom point
        (66, 160),   # Mid left
        (56, 70),    # Top left
    ]
    draw.polygon(shield_points, fill=(30, 41, 59, 255), outline=(59, 130, 246, 255), width=5)
    
    # Inner accent (cyan glow)
    inner_shield = [
        (128, 55),
        (185, 80),
        (176, 150),
        (128, 205),
        (80, 150),
        (71, 80),
    ]
    draw.polygon(inner_shield, fill=(15, 23, 42, 255), outline=(6, 182, 212, 255), width=3)

    # Center radar / search icon (crosshair with circle)
    draw.ellipse([100, 95, 156, 151], outline=(59, 130, 246, 255), width=4)
    draw.line([(128, 85), (128, 161)], fill=(6, 182, 212, 255), width=3)
    draw.line([(90, 123), (166, 123)], fill=(6, 182, 212, 255), width=3)
    draw.ellipse([120, 115, 136, 131], fill=(59, 130, 246, 255))
    
    # Save PNG
    png_path = os.path.join("resources", "icon.png")
    img.save(png_path, format="PNG")
    print(f"Saved {png_path}")

    # Save ICO with multiple sizes
    ico_path = os.path.join("resources", "icon.ico")
    img.save(ico_path, format="ICO", sizes=sizes)
    print(f"Saved {ico_path}")

if __name__ == "__main__":
    create_shield_icon()
