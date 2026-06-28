#!/usr/bin/env python3
"""
APK Patcher for Il2CppDumper
Injects libil2cpp-dump.so into a game APK and patches the smali to load it.

Requirements:
  - Python 3.6+
  - apktool  (https://apktool.io) in PATH
  - apksigner or jarsigner in PATH (part of Android SDK build-tools)
  - zipalign in PATH (part of Android SDK build-tools)

Usage:
  python3 apk_patch.py <input.apk> <libil2cpp-dump.so> [options]

Options:
  --arch       arm64-v8a | armeabi-v7a | all   (default: all)
  --out        output APK path                  (default: <input>_patched.apk)
  --ks         keystore path for apksigner      (default: auto-generate debug key)
  --ks-pass    keystore password                (default: android)
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd, check=True, capture=False):
    print(f"[*] {' '.join(cmd)}")
    result = subprocess.run(cmd,
                            capture_output=capture,
                            text=True)
    if check and result.returncode != 0:
        print(f"[!] Command failed: {' '.join(cmd)}")
        if capture:
            print(result.stderr)
        sys.exit(1)
    return result


def which_required(tool):
    path = shutil.which(tool)
    if not path:
        print(f"[!] '{tool}' not found in PATH. Please install it first.")
        sys.exit(1)
    return path


# ---------------------------------------------------------------------------
# Keystore generation
# ---------------------------------------------------------------------------

def ensure_debug_keystore(ks_path):
    if os.path.exists(ks_path):
        return
    keytool = shutil.which("keytool")
    if not keytool:
        print("[!] keytool not found — cannot generate debug keystore.")
        sys.exit(1)
    print(f"[*] Generating debug keystore at {ks_path}")
    run([keytool,
         "-genkey", "-v",
         "-keystore", ks_path,
         "-alias", "debug",
         "-keyalg", "RSA",
         "-keysize", "2048",
         "-validity", "10000",
         "-storepass", "android",
         "-keypass", "android",
         "-dname", "CN=Debug,O=Debug,C=US"])


# ---------------------------------------------------------------------------
# Smali injection
# ---------------------------------------------------------------------------

LOADLIB_SMALI = '    invoke-static {{}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V'
STRING_CONST  = '    const-string v0, "il2cpp-dump"'

# Regex to find the beginning of a method body in smali
METHOD_START_RE = re.compile(r'^\.method\s+.*\s+(?:attachBaseContext|onCreate)\s*\(.*\).*$')
SUPER_CALL_RE   = re.compile(r'^\s+invoke-\w+\s+\{[^}]*\},\s+L.*?;->(?:attachBaseContext|onCreate)\(')


def inject_loadlib_into_smali_file(smali_path):
    """
    Looks for attachBaseContext or onCreate in a smali file and inserts
    System.loadLibrary("il2cpp-dump") right after the super call.
    Returns True if the file was modified.
    """
    with open(smali_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    # Check if already injected
    if 'il2cpp-dump' in ''.join(lines):
        return False

    new_lines = []
    i = 0
    injected = False
    in_target_method = False

    while i < len(lines):
        line = lines[i]
        new_lines.append(line)

        # Detect entry into a target method
        if METHOD_START_RE.match(line.strip()):
            in_target_method = True

        # Detect end of method
        if line.strip() == '.end method':
            in_target_method = False

        # After the super call inside the target method, inject loadLibrary
        if in_target_method and not injected and SUPER_CALL_RE.match(line):
            # Find the 'return-void' or next instruction after super call
            # Insert right after this line
            new_lines.append('\n')
            new_lines.append('    # --- il2cpp-dump injection ---\n')
            new_lines.append('    const-string v0, "il2cpp-dump"\n')
            new_lines.append('    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n')
            new_lines.append('    # --- end injection ---\n')
            injected = True
            print(f"    [+] Injected loadLibrary into {smali_path}")

        i += 1

    if injected:
        with open(smali_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

    return injected


def find_and_inject_smali(decompile_dir):
    """
    Walk all smali directories, find Application subclass or main Activity,
    and inject System.loadLibrary("il2cpp-dump").
    Priority: Application > Activity > any .smali with onCreate
    """
    smali_dirs = [d for d in os.listdir(decompile_dir)
                  if d.startswith('smali') and os.path.isdir(os.path.join(decompile_dir, d))]

    candidates_app = []
    candidates_activity = []

    for smali_dir in smali_dirs:
        base = os.path.join(decompile_dir, smali_dir)
        for root, dirs, files in os.walk(base):
            for fname in files:
                if not fname.endswith('.smali'):
                    continue
                fpath = os.path.join(root, fname)
                with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                # Application subclass: extends Landroid/app/Application;
                if 'Landroid/app/Application;' in content and 'attachBaseContext' in content:
                    candidates_app.append(fpath)
                elif 'Landroid/app/Application;' in content and 'onCreate' in content:
                    candidates_app.append(fpath)
                elif 'Landroid/app/Activity;' in content and 'onCreate' in content:
                    candidates_activity.append(fpath)

    injected_count = 0
    for path in (candidates_app or candidates_activity):
        if inject_loadlib_into_smali_file(path):
            injected_count += 1
            break  # Inject into only one class is enough

    if injected_count == 0:
        print("[!] Warning: could not find a suitable Application/Activity class to inject into.")
        print("    You may need to manually add System.loadLibrary(\"il2cpp-dump\") to your game's startup code.")
    else:
        print(f"[+] Smali injection done ({injected_count} file(s) modified)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def patch_apk(input_apk, so_path, arch, output_apk, ks_path, ks_pass):
    apktool   = which_required("apktool")
    zipalign  = which_required("zipalign")

    # Prefer apksigner; fall back to jarsigner
    apksigner = shutil.which("apksigner")
    jarsigner = shutil.which("jarsigner")
    if not apksigner and not jarsigner:
        print("[!] Neither apksigner nor jarsigner found in PATH.")
        sys.exit(1)

    # Verify .so file exists
    if not os.path.isfile(so_path):
        print(f"[!] .so file not found: {so_path}")
        sys.exit(1)

    with tempfile.TemporaryDirectory(prefix="il2cpp_patch_") as tmpdir:
        decompile_dir = os.path.join(tmpdir, "decompiled")
        unsigned_apk  = os.path.join(tmpdir, "unsigned.apk")
        aligned_apk   = os.path.join(tmpdir, "aligned.apk")

        # 1. Decompile APK
        print("\n[1/5] Decompiling APK with apktool...")
        run([apktool, "d", input_apk, "-o", decompile_dir, "--force"])

        # 2. Inject .so into lib/<abi>/
        print("\n[2/5] Injecting .so library...")
        abis = []
        if arch == "all":
            # Only inject into ABIs already present in the APK
            lib_dir = os.path.join(decompile_dir, "lib")
            if os.path.isdir(lib_dir):
                abis = os.listdir(lib_dir)
            if not abis:
                abis = ["arm64-v8a", "armeabi-v7a"]
        else:
            abis = [arch]

        for abi in abis:
            dest_dir = os.path.join(decompile_dir, "lib", abi)
            os.makedirs(dest_dir, exist_ok=True)
            dest = os.path.join(dest_dir, "libil2cpp-dump.so")
            shutil.copy2(so_path, dest)
            print(f"    [+] Copied to lib/{abi}/libil2cpp-dump.so")

        # 3. Inject System.loadLibrary into smali
        print("\n[3/5] Patching smali to load library...")
        find_and_inject_smali(decompile_dir)

        # 4. Rebuild APK
        print("\n[4/5] Rebuilding APK...")
        run([apktool, "b", decompile_dir, "-o", unsigned_apk])

        # 5. Zipalign + Sign
        print("\n[5/5] Aligning and signing APK...")
        run([zipalign, "-f", "-p", "4", unsigned_apk, aligned_apk])

        if apksigner:
            ensure_debug_keystore(ks_path)
            run([apksigner, "sign",
                 "--ks", ks_path,
                 "--ks-pass", f"pass:{ks_pass}",
                 "--out", output_apk,
                 aligned_apk])
        else:
            # jarsigner fallback
            ensure_debug_keystore(ks_path)
            shutil.copy2(aligned_apk, output_apk)
            run([jarsigner, "-verbose",
                 "-sigalg", "SHA1withRSA",
                 "-digestalg", "SHA1",
                 "-keystore", ks_path,
                 "-storepass", ks_pass,
                 output_apk, "debug"])

    print(f"\n[✓] Done! Patched APK saved to: {output_apk}")
    print("    Install with: adb install -r \"" + output_apk + "\"")
    print("    Output files will be at: /sdcard/dump/dump.cs and /sdcard/dump/script.json")


def main():
    parser = argparse.ArgumentParser(
        description="Inject Il2CppDumper .so into a game APK"
    )
    parser.add_argument("apk",    help="Path to the original game APK")
    parser.add_argument("so",     help="Path to libil2cpp-dump.so (built from this project)")
    parser.add_argument("--arch", default="all",
                        choices=["arm64-v8a", "armeabi-v7a", "all"],
                        help="Target ABI (default: all — matches ABIs already in APK)")
    parser.add_argument("--out",  default=None,
                        help="Output APK path (default: <input>_patched.apk)")
    parser.add_argument("--ks",   default=os.path.join(os.path.expanduser("~"), ".debug.keystore"),
                        help="Keystore path (default: ~/.debug.keystore, auto-created)")
    parser.add_argument("--ks-pass", default="android", dest="ks_pass",
                        help="Keystore password (default: android)")
    args = parser.parse_args()

    output_apk = args.out
    if output_apk is None:
        base, ext = os.path.splitext(args.apk)
        output_apk = base + "_patched" + ext

    patch_apk(
        input_apk=os.path.abspath(args.apk),
        so_path=os.path.abspath(args.so),
        arch=args.arch,
        output_apk=os.path.abspath(output_apk),
        ks_path=args.ks,
        ks_pass=args.ks_pass,
    )


if __name__ == "__main__":
    main()
