"""
Build PySecure Scanner as standalone executable
Run: python build_exe.py
"""

import PyInstaller.__main__
import os
import platform
import shutil
import sys

def cleanup():
    """Clean build artifacts"""
    folders = ['build', 'dist']
    files = ['pysecure.spec']
    
    for folder in folders:
        if os.path.exists(folder):
            shutil.rmtree(folder)
    
    for file in files:
        if os.path.exists(file):
            os.remove(file)

def build_windows():
    """Build for Windows"""
    print("Building Windows executable...")
    
    PyInstaller.__main__.run([
        'main.py',
        '--name=PySecureScanner',
        '--onefile',
        '--windowed',
        '--icon=assets/icon.ico',  # Create this icon file
        '--add-data=config.json;.',
        '--add-data=README.md;.',
        '--hidden-import=tensorflow',
        '--hidden-import=torch',
        '--noconsole',  # No terminal window for GUI
        '--clean'
    ])
    
    # Create batch file for CLI
    with open("dist/pysecure.bat", "w") as f:
        f.write('@echo off\n"%~dp0PySecureScanner.exe" %*\n')
    
    # Package as ZIP
    shutil.make_archive("PySecureScanner-Windows", 'zip', "dist")
    print("✅ Windows build complete: PySecureScanner-Windows.zip")

def build_linux():
    """Build for Linux"""
    print("Building Linux executable...")
    
    PyInstaller.__main__.run([
        'main.py',
        '--name=pysecure',
        '--onefile',
        '--add-data=config.json:.',
        '--add-data=README.md:.',
        '--hidden-import=tensorflow',
        '--hidden-import=torch',
        '--clean'
    ])
    
    # Make executable
    os.chmod("dist/pysecure", 0o755)
    
    # Create installer script
    installer = '''#!/bin/bash
echo "Installing PySecure Scanner..."
sudo cp pysecure /usr/local/bin/pysecure
sudo chmod +x /usr/local/bin/pysecure
echo "Installation complete! Run with: pysecure --gui"
'''
    
    with open("dist/install.sh", "w") as f:
        f.write(installer)
    os.chmod("dist/install.sh", 0o755)
    
    shutil.make_archive("PySecureScanner-Linux", 'zip', "dist")
    print("✅ Linux build complete: PySecureScanner-Linux.zip")

def build_macos():
    """Build for macOS"""
    print("Building macOS application...")
    
    PyInstaller.__main__.run([
        'main.py',
        '--name=PySecureScanner',
        '--windowed',
        '--onefile',
        '--icon=assets/icon.icns',  # macOS icon
        '--add-data=config.json:.',
        '--add-data=README.md:.',
        '--osx-bundle-identifier=com.pysecure.scanner',
        '--hidden-import=tensorflow',
        '--hidden-import=torch',
        '--clean'
    ])
    
    # Create DMG if needed (optional)
    shutil.make_archive("PySecureScanner-macOS", 'zip', "dist")
    print("✅ macOS build complete: PySecureScanner-macOS.zip")

def main():
    print("""
    ╔══════════════════════════════════════════╗
    ║      PYSECURE SCANNER BUILDER           ║
    ╚══════════════════════════════════════════╝
    """)
    
    # Clean previous builds
    cleanup()
    
    # Detect platform and build
    system = platform.system()
    
    if system == "Windows":
        build_windows()
    elif system == "Linux":
        build_linux()
    elif system == "Darwin":
        build_macos()
    else:
        print(f"❌ Unsupported platform: {system}")
        return
    
    print("\n✨ Build complete! Upload to GitHub Releases.")

if __name__ == "__main__":
    main()