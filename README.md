# CVE-2019-2215
Temproot for Bravia TV via CVE-2019-2215.

## Overview
Demonstration of a kernel memory R/W-only privilege escalation attack resulting in a temporary root shell.

It works on Sony Bravia TV devices running the Android 8 (PKG6.0724) firmware with kernel version 4.9.51.

For this tool to work on other devices and/or kernels affected by the same vulnerability, some offsets need to be found and changed. As mentioned on the [Project Zero bugtracker](https://bugs.chromium.org/p/project-zero/issues/detail?id=1942), this isn't terribly difficult.

## Disclaimers
This tool and its source code are made available for documentary and educational purposes only.

USING THIS TOOL MAY BRICK YOUR DEVICE. DO NOT TRY UNLESS YOU KNOW WHAT YOU ARE DOING.

## Compilation

```console
# Download the Android NDK.
user@host:~$ wget https://dl.google.com/android/repository/android-ndk-r20b-linux-x86_64.zip

# Extract the NDK and set its path as $ANDROID_NDK_HOME.
user@host:~$ unzip android-ndk-r20b-linux-x86_64.zip
user@host:~$ export ANDROID_NDK_HOME=~/android-ndk-r20b

# Clone the `CVE-2019-2215` git repository and `cd` into it.
user@host:~$ git clone https://github.com/LIznzn/CVE-2019-2215.git
user@host:~$ cd CVE-2019-2215

# Compile the binary.
user@host:~/CVE-2019-2215$ $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang poc-bravia.c -static -o poc-bravia

```

## Usage

```console
# Push binary to device.
user@host:~/CVE-2019-2215$ adb push ./poc-bravia /data/local/tmp/

# Use ADB Shell.
user@host:~/CVE-2019-2215$ adb shell

# Run it.
BRAVIA_4K_UR1:/ $ cd /data/local/tmp
BRAVIA_4K_UR1:/data/local/tmp $ chmod 755 poc-bravia
BRAVIA_4K_UR1:/data/local/tmp $ ./poc-bravia

```
