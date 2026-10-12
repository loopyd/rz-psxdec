# rz-psxdec

`rz-psxdec` is a PlayStation 1 focused RetDec plugin for
[Rizin](https://github.com/rizinorg/rizin). It loads as `rz-psxdec.so` and uses
the customized [retdec-psx](https://github.com/loopyd/retdec-psx) backend.

## Scope

The fork develops decompilation of little-endian, 32-bit PS1 MIPS code.
It keeps ordinary Rizin function commands and
adds `pdzar` for bounded generation from verified original bytes.

The two repositories have separate roles:

| Repository | Sibling directory | Role |
| --- | --- | --- |
| [rz-psxdec](https://github.com/loopyd/rz-psxdec) | `rz-psxdec` | Rizin plugin and console commands |
| [retdec-psx](https://github.com/loopyd/retdec-psx) | `retdec-psx` | Customized RetDec backend linked into the plugin |

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

## Use

Set `rizin_binary` to the Rizin executable from the configured installation.
Set `dso` to the built `rz-psxdec.so`.
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
| `pdzaom /absolute/metadata.json image-id...` | Mount original images in the supplied order |
| `pdzaou image-id...` | Dismount images |
| `pdzao` | Print the active native memory context as JSON |
| `pdze` | Show the plugin's output-directory environment setting |

`DEC_SAVE_DIR` selects the ordinary decompilation output directory. Interactive
`pdz` uses the current Rizin analysis and supplied context. For original-only
generation, pass an absolute workspace to `pdzar`. That workspace must contain a
validated `input/request.json`, `input/image.raw` and the release's fixed
`native/fixed-config.json`.

Ordinary function commands do not establish original-only input provenance.

## Overlay state

Mount the executable first, then the overlays needed for the selected static
state. Each image must have original bytes and explicit load metadata:

```text
pdzaom /absolute/metadata.json executable overlay-a overlay-b
pdzao
pdzaou overlay-a overlay-b
```

Later mounts replace overlapping bytes. Mounting an unchanged image again keeps
its position. Dismount it before mounting it again to change that position.
Dismounting reveals an earlier mounted image, or leaves an unmapped gap. It models
static image selection, not the bytes a running game leaves in RAM after unloading.
Each command batch either succeeds in full or preserves the previous context.

Metadata accepts `psx.overlay-images/v1` with an `images` array. Each image has a
unique `image_id` and these fields:

| Fields | Meaning |
| --- | --- |
| `target`, `file_path` | Image label and absolute original-file path |
| `file_sha256`, `file_bytes` | Complete file identity and size |
| `payload_offset`, `payload_sha256`, `payload_bytes` | Payload slice and its identity |
| `load_address`, `mapping_kind` | Explicit RAM address and placement evidence kind |

Digests are lowercase SHA-256 strings. Offsets, sizes and addresses are JSON
integers. `psx-exe-header` placement must agree with the original PS-X EXE header.
For a raw image, use `original-catalog` and supply `mapping_path` and
`mapping_sha256` for a catalog that records the exact image, slice and load address.
The existing `retdec118.original-image-catalog/v1` catalog is also accepted
directly, with its sibling `images/NNN.image` files.

The native loader checks file and payload hashes before mounting. Mappings must
fit PS1's 2 MiB RAM. KUSEG, KSEG0 and KSEG1 aliases share byte ownership. A context
supports at most 128 mounted images and 64 MiB of payloads. `pdzao` records mount
order, placement evidence, visible intervals and a context digest. Mounted
decompilation requires raw little-endian MIPS input. It uses the native context
for instruction and data reads and keeps its results separate from Rizin's
inferred functions and globals. Decompilation caches include the context digest.

Original-only requests use `retdec118.native-request/v5`, or v6 when binding a
checked runtime entry observation, and declare the ordered
`overlay_mounts` image IDs. The request binds the staged catalog and generator input
with `image_catalog_sha256` and `problem_sha256`. An existing interactive context
must match that request. Earlier request versions reject ambient mounts. This path
requires canonical KSEG0 load and
function addresses. Mounted direct callees can be discovered from
original instructions within the native bounds. Their output records remain
separate from reviewed functions and retain unresolved obligations.
Discovery admits at most 32 callees, 256 instruction words per callee and 4096
words in total.

V6 adds an `entry_observation` descriptor with the function and image identity,
entry PC, state hash and size, and capture file records. The workspace stages
the passed native target receipt, CPU-query receipt, register capture, CPU query
and complete RAM capture at the descriptor's `input/entry-*` paths. Native parsing
checks their hashes, linked state identity and settled CPU state. Discovery must
match the observed function's original instruction bytes before it can use the
captured SP for saved-frame analysis.

The resulting `scopedRestoration` metadata records saved words, store and load
instructions, crossed calls and covered exits. Its conditions require normal
instruction and memory completion, active original instructions, stable RAM
mapping and cache mode, and no asynchronous or external state interference.
These relationships retain unresolved
universal control, effects and declaration obligations.

## Evidence limits

Generated C and inferred declarations require independent review. A successful
plugin invocation, compilation or preservation comparison does not prove original
bytes, calling contracts, associated data or placement. Unsupported instruction,
control or memory facts remain explicit obligations. Inferred machine values
alone do not establish source C declarations.

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
