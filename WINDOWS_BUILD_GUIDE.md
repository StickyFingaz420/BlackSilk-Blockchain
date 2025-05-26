# Windows Build Guide for BlackSilk Miner

## Fixing "LNK1181: cannot open input file 'randomx.lib'" Error

This guide helps Windows developers resolve the RandomX linking issue in the BlackSilk miner.

## Prerequisites

1. **Visual Studio 2022** (Community, Professional, or Enterprise)
   - Install "Desktop development with C++" workload
   - Ensure "CMake tools for Visual Studio" is selected
2. **Rust** (latest stable version) - Download from https://rustup.rs/
3. **Git** - Download from https://git-scm.com/

## Quick Fix - Automated (RECOMMENDED)

### Option 1: PowerShell Script
```powershell
# Run from BlackSilk root directory in PowerShell as Administrator
.\build_randomx_windows.ps1
```

### Option 2: Batch Script
```cmd
# Run from BlackSilk root directory in Command Prompt as Administrator
build_randomx_windows.bat
```

Both scripts will automatically:
- Detect Visual Studio 2022
- Configure and build RandomX with optimal settings
- Copy `randomx.lib` and `randomx.dll` to the miner directory
- Prepare everything for Rust compilation

After running either script, build the miner:
```cmd
cargo build --release -p blacksilk-miner
```

## Alternative: Pre-built Libraries

### Quick Fix (If Automated Scripts Fail)

1. **Download pre-built RandomX libraries** from the official releases:
   ```
   https://github.com/tevador/RandomX/releases
   ```

2. **Extract and copy files** to your miner directory:
   ```
   copy randomx.dll miner\
   copy randomx.lib miner\
   ```

3. **Build the miner**:
   ```cmd
   cd miner
   cargo build --release
   ```

### Build from Source (Advanced)

If you need to build RandomX from source:

#### Prerequisites
- Visual Studio 2019 or later with C++ tools
- CMake 3.15+
- Git

#### Steps

1. **Clone RandomX repository**:
   ```cmd
   git clone https://github.com/tevador/RandomX.git
   cd RandomX
   ```

2. **Create build directory**:
   ```cmd
   mkdir build
   cd build
   ```

3. **Configure with CMake**:
   ```cmd
   cmake .. -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release
   ```

4. **Build the library**:
   ```cmd
   cmake --build . --config Release
   ```

5. **Copy output files**:
   ```cmd
   copy Release\randomx.lib ..\..\miner\
   copy Release\randomx.dll ..\..\miner\
   ```

6. **Build BlackSilk miner**:
   ```cmd
   cd ..\..\miner
   cargo build --release
   ```

### Verification

Test that everything works:

```cmd
target\release\blacksilk-miner.exe benchmark
```

You should see RandomX initialization and hashrate output.

### Troubleshooting

#### Error: "randomx.lib not found"
- Ensure `randomx.lib` is in the `miner\` directory
- Check file permissions (not read-only)

#### Error: "randomx.dll not found" (runtime)
- Copy `randomx.dll` to the same directory as `blacksilk-miner.exe`
- Or add the miner directory to your PATH

#### Error: "MSVCR140.dll missing"
- Install Visual C++ Redistributable for Visual Studio 2019+

#### Performance Issues
- Enable huge pages in Windows for better performance
- Run as Administrator for optimal RandomX performance

### Performance Optimization

#### Enable Huge Pages (Windows 10/11)
1. Run `gpedit.msc` as Administrator
2. Navigate to: Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment
3. Find "Lock pages in memory"
4. Add your user account
5. Restart your computer

#### Build with Native CPU Optimizations
```cmd
set RUSTFLAGS=-C target-cpu=native
cargo build --release
```

### Support

If you continue experiencing issues:
1. Check that all dependencies are correctly installed
2. Verify your Visual Studio installation includes C++ tools
3. Ensure you're using 64-bit architecture throughout
4. Review the build logs for specific error messages

For additional help, refer to the RandomX documentation or the BlackSilk project issues.
