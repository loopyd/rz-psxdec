# rz-psxdec

`rz-psxdec` is a PlayStation 1 focused RetDec plugin for
[Rizin](https://github.com/rizinorg/rizin). It loads as `rz-psxdec.so` and uses
the customized [retdec-psx](https://github.com/loopyd/retdec-psx) backend.

## Scope

The fork develops decompilation of little-endian, 32-bit PS1 MIPS code for the
BOF3 reverse-engineering workspace. It keeps ordinary Rizin function commands and
adds `pdzar` for bounded generation from verified original bytes.

The two repositories have separate roles:

| Repository | Workspace path | Role |
| --- | --- | --- |
| [rz-psxdec](https://github.com/loopyd/rz-psxdec) | `third_party/rz-psxdec` | Rizin plugin and console commands |
| [retdec-psx](https://github.com/loopyd/retdec-psx) | `third_party/retdec-psx` | Customized RetDec backend linked into the plugin |

## Build

The supported build described here uses Linux, a C++17 compiler, CMake 3.13 or
newer, Make, Git, Python 3, Autotools, pkg-config, OpenSSL and zlib. Use an existing
Rizin installation with its CMake package metadata.

Clone both forks into the same parent directory:

```sh
git clone --branch dev https://github.com/loopyd/rz-psxdec.git rz-psxdec
git clone --branch master https://github.com/loopyd/retdec-psx.git retdec-psx
```

Prepare disposable source trees from these pinned archives. Verify their SHA-256
values before extraction:

| Dependency | Revision | Archive SHA-256 |
| --- | --- | --- |
| LLVM | `a776c2a976ef64d9cd84d7ee71d0e4a04aa117a1` | `b5879b30768135e5fce84ccd8be356d2c55c940ab32ceb22d278b228e88c4c60` |
| Capstone | `5.0-rc2` | `c47acdabb9ba4922a6d68b96eb7e14a431bfef7d7c57cea1e5881f87776228b2` |
| YARA | `v4.2.0-rc1` | `ae1adad2ae33106f4c296cef32ddba2c93867010ef853028d30cad42548d0474` |

Archive URLs and pins are in the backend's
[cmake/deps.cmake](https://github.com/loopyd/retdec-psx/blob/master/cmake/deps.cmake).
Keep executable modes when extracting. YARA's build patches and writes its source
tree, so use a disposable copy.

Set `rizin_prefix` to the absolute Rizin installation prefix. Set `llvm_source`,
`capstone_source` and `yara_source` to the absolute extracted source roots. Set
`stdcxxfs_directory` to the directory containing the selected compiler's
`libstdc++fs.a`, located with `/usr/bin/c++ -print-file-name=libstdc++fs.a`.
If the compiler needs no separate filesystem library, omit `CMAKE_LIBRARY_PATH`.

Run these commands from the parent of both clones:

```sh
build_attempt="$PWD/build/rz-psxdec"
plugin_revision="$(git -C rz-psxdec rev-parse HEAD)"
backend_revision="$(git -C retdec-psx rev-parse HEAD)"
cmake -S rz-psxdec -B "$build_attempt/build" -G "Unix Makefiles" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX="$build_attempt/prefix" \
	-DCMAKE_C_COMPILER=/usr/bin/cc -DCMAKE_CXX_COMPILER=/usr/bin/c++ \
	-DCMAKE_MAKE_PROGRAM=/usr/bin/make \
	-DCMAKE_PREFIX_PATH="$rizin_prefix" \
	-DCMAKE_LIBRARY_PATH="$stdcxxfs_directory" \
	-DBUILD_BUNDLED_RETDEC=ON -DBUILD_CUTTER_PLUGIN=OFF \
	-DRETDEC_ENABLE_ALL=OFF -DRETDEC_ENABLE_RETDEC=ON -DRETDEC_TESTS=OFF \
	-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
	-DRETDEC_SOURCE_DIR="$PWD/retdec-psx" \
	-DRZ_PSXDEC_REVISION="$plugin_revision" \
	-DRETDEC_PSX_REVISION="$backend_revision" \
	-DLLVM_LOCAL_DIR="$llvm_source" -DCAPSTONE_LOCAL_DIR="$capstone_source" \
	-DYARA_LOCAL_DIR="$yara_source"
cmake --build "$build_attempt/build" --parallel 24 --target rz-psxdec
```

The DSO is `$build_attempt/build/src/rz-plugin/rz-psxdec.so`. The local install
prefix confines RetDec's configure-time support cleanup to this build attempt.
These commands do not run a top-level install or copy the DSO into an installed
plugin directory. Keep the DSO with its build dependencies.

This fork requires `BUILD_BUNDLED_RETDEC=ON`; it refuses an installed external
backend. CMake reads both actual Git HEADs and rejects a mismatched explicit
revision. The generated plugin version is
`rz-psxdec@<plugin-40-SHA>+retdec-psx@<backend-40-SHA>`. Keep both source trees
unchanged through the build. The Rizin ABI version remains Rizin's own version.

In the BOF3 workspace, the existing lifecycle supplies the pinned sources and
records a verified build receipt:

```sh
bin/harness setup --component rz-psxdec --force
bin/harness doctor --component rz-psxdec
```

Setup prints the verified DSO and `native-build.json` paths under a fresh
`build/third_party/rz-psxdec/attempt-*` directory. Its maintained guide is
`tools/retdec-psx/README.md` in that workspace.

## Use

Set `rizin_binary` to the Rizin executable from the configured installation.
Set `dso` to the built `rz-psxdec.so`, or the verified path printed by setup.
For an extracted raw payload, set `payload` to its file and `load_address` to its
proven runtime address:

```sh
RZ_NOPLUGINS=1 "$rizin_binary" \
	-N -n -a mips -b 32 -E little -m "$load_address" \
	-l "$dso" "$payload"
```

`RZ_NOPLUGINS=1` disables automatic plugin discovery. `-l` explicitly loads this
DSO. For a PS-X EXE, extract its payload and use the header's reviewed load address.
For an overlay, prove its base before mapping it.

Use `Lcj` to inspect the loaded `rz-psxdec` registration and build version.
Use `pdz?` and `pdza?` to inspect its commands:

| Command | Result |
| --- | --- |
| `pdz` | Decompile the current Rizin function |
| `pdzo` | Show decompiled code with offsets |
| `pdzj` | Print the current decompilation as JSON |
| `pdz*` | Print commands that add the decompilation as comments |
| `pdza [start [end]]` | Analyze and import functions in a range |
| `pdzaa` | Analyze and import all functions |
| `pdzar /absolute/workspace` | Generate from the fixed original-only workspace request |
| `pdze` | Show the plugin's output-directory environment setting |

`DEC_SAVE_DIR` selects the ordinary decompilation output directory. Interactive
`pdz` uses the current Rizin analysis and supplied context. For original-only
generation, pass an absolute workspace to `pdzar`. That workspace must contain a
validated `input/request.json`, `input/image.raw` and the release's fixed
`native/fixed-config.json`.

The BOF3 harness prepares those inputs and preserves the generation boundary.
Its guides are `tools/retdec-psx/preparation.md` and
`tools/retdec-psx/reconstruction.md`. Ordinary function commands do not establish
original-only input provenance.

## Evidence limits

Generated C and inferred declarations require independent review. A successful
plugin invocation, compilation or preservation comparison does not prove original
bytes, calling contracts, associated data or placement. Full PS1 instruction and
GTE behavior, runtime fidelity and the 118-function reconstruction milestone remain
unproved. Held call-contract production retains its separate admission gates.

Keep private original images, authored evaluator references and byte-bearing
captures local. Original-only generation withholds authored answers, names, maps
and source-specific compiler profiles.

## Provenance and license

This fork derives from [rizinorg/rz-retdec](https://github.com/rizinorg/rz-retdec).
Upstream credits include RizinOrg, copyright 2022, and Avast Software,
copyright 2020. Plugin source retains `LGPL-3.0-only` notices. See
[COPYING](COPYING) and the [GNU licenses](https://www.gnu.org/licenses/).

The backend derives from [Avast RetDec](https://github.com/avast/retdec), copyright
2017 Avast Software, under the MIT license. The plugin also retains provenance
from [retdec-r2plugin](https://github.com/avast/retdec-r2plugin), copyright 2020
Avast Software. Backend and dependency licenses remain separate. See the
[backend license](https://github.com/loopyd/retdec-psx/blob/master/LICENSE),
[PeLib notice](https://github.com/loopyd/retdec-psx/blob/master/LICENSE-PELIB) and
[third-party notices](https://github.com/loopyd/retdec-psx/blob/master/LICENSE-THIRD-PARTY).
