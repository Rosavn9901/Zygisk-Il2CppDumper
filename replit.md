# Zygisk-Il2CppDumper

A Magisk module that dumps Il2Cpp data from Unity Android games at runtime using Zygisk (Magisk in Zygote). It can bypass protection, encryption, and obfuscation that static dumpers fail against.

## Project Type

This is a **native Android/Magisk module** — not a web application. There is no frontend or backend server. The project compiles to a flashable `.zip` file for rooted Android devices.

## Tech Stack

- **Languages:** C++20, C
- **Build System:** Gradle + CMake
- **Toolchain:** Android NDK (v25.2.9519653)
- **Target:** Android (minSdk 23, targetSdk 32)

## How to Build

This project requires the Android SDK and NDK to build. The recommended approaches are:

1. **GitHub Actions** — Fork the repo, go to the Actions tab, run the **Build** workflow, input the game package name, and download the artifact.
2. **Android Studio** — Edit `module/src/main/cpp/game.h` to set `GamePackageName`, then run the Gradle task `:module:assembleRelease`. Output zip is placed in `out/`.

## How to Use

1. Install [Magisk](https://github.com/topjohnwu/Magisk) v24+ with Zygisk enabled
2. Build the module (see above)
3. Flash the generated zip in Magisk
4. Start the target game — `dump.cs` will be generated at `/data/data/<GamePackageName>/files/`

## Key Files

- `module/src/main/cpp/game.h` — Set `GamePackageName` here before building
- `module/src/main/cpp/main.cpp` — Zygisk module entry point
- `module/src/main/cpp/il2cpp_dump.cpp` — Core dump logic
- `template/magisk_module/` — Magisk module skeleton files

## User Preferences
