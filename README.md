# Root My Device

A fork of [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy),
the work of [BuSung-dev](https://github.com/BuSung-dev). This repository keeps
the original Apache License 2.0 — see [LICENSE](LICENSE). The payload side is a
fork of [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads).

<img width="108" height="108" alt="sprout_icon_108" src="https://github.com/user-attachments/assets/2ba0e360-0876-489c-b256-f75df7589785" />


Root My Device is a one-click installer for explicitly
supported firmware builds. The application itself is kept separate
from device offsets, native exploit payloads, and KernelSU build artifacts.


[Latest release](https://github.com/Witaqua-tools/Root-My-Device/releases)

The device feed and native payloads are maintained in
[Root-My-Device-Payloads](https://github.com/Witaqua-tools/Root-My-Device-Payloads).
Every push to its `main` branch builds the payloads and publishes them as a
GitHub release under a tag unique to that run. The app resolves that
repository's `releases/latest`, reads the `targets-v2.json` asset from it, and
downloads every artifact named in it — so the set of payloads it installs is
immutable once published, and nothing is committed as a binary.

## Application


<img width="200" alt="KakaoTalk_20260718_170922353" src="https://github.com/user-attachments/assets/3f562ea4-8c39-4ade-bfd3-93eea1a1cc24" />
<img width="200" alt="KakaoTalk_20260718_171127319" src="https://github.com/user-attachments/assets/8dde0443-12cf-4058-ba76-0337aefb92a0" />
<img width="200" alt="KakaoTalk_20260718_171030202" src="https://github.com/user-attachments/assets/f656e8af-60a6-4fcb-a3db-d4232bede613" />

The app automatically selects an exact match for the kernel release,
full build display ID, SDK, ABI, and page size. Advanced mode can select a
profile manually and presents separate kernel-release and build warnings.

## Build

Requirements:

- Android Studio JBR 21
- Android SDK 37
- Android NDK 28 or newer
- CMake 3.22.1

The APK contains one native program that is not built from this repository's
own source, so clone with submodules:

```powershell
git clone --recurse-submodules https://github.com/Witaqua-tools/Root-My-Device
# or, in an existing checkout
git submodule update --init payloads
```

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat :app:assembleDebug
```

Output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

### The bootstrap helper

`lib/arm64-v8a/libcve43499root.so` in the APK is not a library — it is the
bootstrap helper, an executable the app runs with `ProcessBuilder` out of
`nativeLibraryDir`. It is what loads a downloaded payload, and afterwards what
serves `su` over a socket once the payload has made it root.

It is compiled from source by [`app/src/main/cpp/CMakeLists.txt`](app/src/main/cpp/CMakeLists.txt),
not committed as a binary. The source is not here, though: the payload's
standalone route execs the same program from a fixed path, so the payload
repository has to build it too, and it stays the one copy. This repository
reaches it through the `payloads` submodule, whose pinned commit is the record
of exactly which revision an APK was built from.

That means two builds of one source, deliberately. The payload repository pins
NDK 29 at API 35 because its exploit payload is a fixed-size blob whose
toolchain is part of its identity; here CMake uses this module's `ndkVersion`
at `minSdk`. The helper depends on neither — it is the same program either way,
and the copy the app ships is the one built here.

Two things about it are load-bearing and easy to undo by accident: it must be
an **executable** (`add_executable` plus `-pie`, so it has a `PT_INTERP` that a
shared library would not), and it must be **named `lib*.so`** with
`jniLibs.useLegacyPackaging = true`, because that is what gets extracted into
`nativeLibraryDir` as a real file with the execute bit set. Both are commented
where they are set.

Use only on devices you own or are explicitly authorized to test.
