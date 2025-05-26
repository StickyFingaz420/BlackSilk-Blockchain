# BlackSilk Windows Build Solution

## Your Current Issue
You're getting `LNK1181: cannot open input file 'randomx.lib'` because the Windows linker needs both `randomx.dll` AND `randomx.lib` files, but you only have the DLL.

## SOLUTION: Use the Automated Build Scripts

Since you have Visual Studio 2022, I've created automated scripts to build RandomX and solve this issue.

### Step 1: Run the Automated Build Script

Open **Command Prompt as Administrator** in your BlackSilk directory and run:

```cmd
build_randomx_windows.bat
```

OR open **PowerShell as Administrator** and run:

```powershell
.\build_randomx_windows.ps1
```

### Step 2: Build the Miner

After the script completes successfully, run:

```cmd
cargo build --release -p blacksilk-miner
```

## What the Script Does

1. **Detects Visual Studio 2022** automatically
2. **Sets up the build environment** (vcvars64.bat)
3. **Configures RandomX** with CMake for Visual Studio 17 2022
4. **Builds the RandomX library** in Release mode
5. **Copies both files** to your miner directory:
   - `randomx.lib` (import library for linking)
   - `randomx.dll` (runtime library)

## Expected Output

After running the script, you should see:
```
SUCCESS! RandomX libraries have been built and copied to miner directory.
You can now run: cargo build --release -p blacksilk-miner
```

And in your `miner\` directory you'll have:
- `randomx.lib` - ~200 KB (import library)
- `randomx.dll` - ~1.5 MB (runtime library)

## If the Automated Script Fails

### Manual Build Steps:

1. **Open Developer Command Prompt for VS 2022**
2. **Navigate to your BlackSilk directory**
3. **Build RandomX manually**:
   ```cmd
   cd RandomX
   mkdir build
   cd build
   cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
   cmake --build . --config Release
   ```
4. **Copy the files**:
   ```cmd
   copy Release\randomx.lib ..\..\miner\
   copy Release\randomx.dll ..\..\miner\
   ```
5. **Build the miner**:
   ```cmd
   cd ..\..\
   cargo build --release -p blacksilk-miner
   ```

## Verification

Test that everything works:
```cmd
target\release\blacksilk-miner.exe --help
target\release\blacksilk-miner.exe benchmark
```

## Why This Happens

Windows uses a different linking model than Linux:
- **Linux**: Uses `librandomx.a` (static library) or `librandomx.so` (shared library)
- **Windows**: Needs both `randomx.lib` (import library) and `randomx.dll` (dynamic library)

The import library (`randomx.lib`) contains stubs that tell the linker how to call functions in the DLL at runtime.

## Performance Notes

For optimal mining performance on Windows:
1. **Enable Huge Pages** (requires Administrator privileges)
2. **Run as Administrator** for best RandomX performance
3. **Use Release build** (not Debug) for maximum speed

The BlackSilk miner should achieve similar performance to other RandomX miners like XMRig when properly configured.

## Need Help?

If you still encounter issues:
1. Make sure Visual Studio 2022 is properly installed with C++ tools
2. Run the script as Administrator
3. Check that you have enough disk space (~500 MB for build)
4. Verify your internet connection for downloading dependencies

The automated scripts should handle 99% of cases. This solution preserves all the great work in the BlackSilk project while making it accessible to Windows developers!
