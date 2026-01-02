"""
Quick build script for PySecure Scanner
Run: python quick_build.py
"""

import os
import sys
import platform
import PyInstaller.__main__

def build_windows():
    print("Building Windows executable...")
    
    # Create Windows executable
    PyInstaller.__main__.run([
        'main.py',
        '--name=PySecureScanner',
        '--onefile',
        '--windowed',
        '--add-data=README.md;.',
        '--noconsole',
        '--clean'
    ])
    
    # Create batch file
    with open("dist/pysecure.bat", "w") as f:
        f.write('@echo off\n"%~dp0PySecureScanner.exe" %*\n')
    
    print("✅ Windows build complete!")
    return "dist/PySecureScanner.exe"

def build_linux():
    print("Building Linux executable...")
    
    PyInstaller.__main__.run([
        'main.py',
        '--name=pysecure',
        '--onefile',
        '--add-data=README.md:.',
        '--clean'
    ])
    
    # Make executable
    os.chmod("dist/pysecure", 0o755)
    print("✅ Linux build complete!")
    return "dist/pysecure"

def build_macos():
    print("Building macOS application...")
    
    PyInstaller.__main__.run([
        'main.py',
        '--name=PySecureScanner',
        '--onefile',
        '--windowed',
        '--add-data=README.md:.',
        '--clean'
    ])
    
    print("✅ macOS build complete!")
    return "dist/PySecureScanner"

def main():
    print("""
    ╔══════════════════════════════════╗
    ║   BUILD PYSECURE EXECUTABLES    ║
    ╚══════════════════════════════════╝
    """)
    
    system = platform.system()
    
    if system == "Windows":
        exe_path = build_windows()
        print(f"\n📦 Executable: {exe_path}")
        print("📦 Batch file: dist/pysecure.bat")
        
    elif system == "Linux":
        exe_path = build_linux()
        print(f"\n📦 Executable: {exe_path}")
        
    elif system == "Darwin":
        exe_path = build_macos()
        print(f"\n📦 Executable: {exe_path}")
        
    else:
        print(f"❌ Unsupported platform: {system}")
        return
    
    print("\n🎯 Next steps:")
    print("1. ZIP the 'dist' folder")
    print("2. Upload to GitHub Releases")
    print("3. Name it: PySecureScanner-YourPlatform.zip")

if __name__ == "__main__":
    main()