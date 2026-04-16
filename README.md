# Bakery

Cake archive extraction/builder tool for .cak archives.

## Support

Supports extracting files from all known games/cake archives.
* v6.7
* v6.8
* v8.1 (use force no enc flag)
* v8.2
* v8.3
* v8.7
* v9.1
* v9.2
* v9.3
* v9.9 (not currently public)

## Usage

### Download in [Releases](https://github.com/Nenkai/CakeTool/releases).

Some batch (`.bat`) scripts are included which can be used by dropping files or folders into them. Otherwise:

* Unpacking cakes: `CakeTool.exe unpack-cak -i <path to .cak>` - **make sure the cake file name hasn't been renamed**.
* Unpacking a specific file from a cake archive: `CakeTool.exe unpack-file -i <path to .cak> -f <game file path> [-o output path]`
* Packing a cake: `CakeTool.exe pack -i <path to folder> -v <version>` version is 9.2 (24) or 9.3 (25). Earlier is untested.

> [!NOTE]  
> Arguments wrapped in `<>` are required and `[]` are optional.

## Modding

A hook is provided in releases. Please read the release notes.

## Building

.NET 9.0 and Visual Studio 2022.

## License

MIT License.

Beyond licensing please credit if you're going to use any of the work & research this took.
