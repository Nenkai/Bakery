using CakeTool.Compression;
using CakeTool.GameFiles.Textures;
using CakeTool.Hashing;

using CommunityToolkit.HighPerformance;
using CommunityToolkit.HighPerformance.Buffers;

using Microsoft.Extensions.Logging;

using Pfim;

using Syroot.BinaryData;
using Syroot.BinaryData.Memory;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool;

public class CakeFileBuilder
{
    private readonly ILoggerFactory? _loggerFactory;
    private readonly ILogger? _logger;

    private List<CakeFileEntry> _files = [];
    private List<CakeDirInfo> _dirs = [];
    private SortedDictionary<ulong, CakeEntryLookup> _dirLookup = [];
    private SortedDictionary<ulong, CakeEntryLookup> _fileLookup = [];
    private byte[] _stringTable;
    private List<CakeFileHeaderSection> _sections = [];

    public uint TotalChunkCount { get; set; } = 0;

    public byte VersionMajor { get; set; } = 9;
    public byte VersionMinor { get; set; } = 3;

    public bool EncryptHeader { get; set; } = false;
    public ushort NumSectorsPerChunk { get; set; } = 1024;

    private string OriginalDirName { get; set; } = string.Empty;

    private BinaryStream _cakeStream;

    private CakeRegistryType RegistryType { get; set; } = CakeRegistryType.Regular;
    private TextureDatabase _tdb;

    private string _tempDir = "temp";

    public CakeFileBuilder(byte versionMajor, byte versionMinor, CakeRegistryType registryType = CakeRegistryType.Regular, 
        ILoggerFactory? loggerFactory = null)
    {
        VersionMajor = versionMajor;
        VersionMinor = versionMinor;

        RegistryType = registryType;

        if (loggerFactory is not null)
            _logger = loggerFactory.CreateLogger(GetType().ToString());
    }

    /// <summary>
    /// Registers all files from a directory.
    /// </summary>
    /// <param name="mainDir"></param>
    public void RegisterFiles(string mainDir)
    {
        _logger?.LogInformation("Indexing '{mainDir}' for a new cake...", mainDir);

        if (IsAtLeastVersion(9, 1))
        {
            byte version = 5;
            if (IsAtLeastVersion(9, 3))
                version = 6;

            _tdb = new TextureDatabase(version);
        }

        BuildFileTree(mainDir, mainDir);
    }

    /// <summary>
    /// Adds a new file to the cake.
    /// </summary>
    /// <param name="localPath"></param>
    /// <param name="relativePath"></param>
    public void AddFile(string localPath, string relativePath)
    {
        relativePath = relativePath.Replace('\\', '/');

        CakeDirInfo parentDir = _dirs[0];
        ReadOnlySpan<char> pathSpan = relativePath.AsSpan();
        foreach (var part in pathSpan.Split('/'))
        {
            if (part.End.Value == pathSpan.Length)
                break;

            ReadOnlySpan<char> piece = pathSpan[part];
            ulong dirHash = FNV1A64.FNV64StringI(piece);
            if (_dirLookup.TryGetValue(dirHash, out CakeEntryLookup lookup))
                continue;

            var newDir = new CakeDirInfo()
            {
                DirIndex = (uint)_dirs.Count,
                Path = piece.ToString(),
                Hash = dirHash,
            };

            parentDir.SubFolderIndices.Add(newDir.DirIndex);
            _dirs.Add(newDir);

            _dirLookup.Add(newDir.Hash, new CakeEntryLookup()
            {
                EntryIndex = newDir.DirIndex,
                NameHash = newDir.Hash,
            });

            parentDir = newDir;
        }

        RegisterFileForFolder(parentDir, localPath, relativePath);
    }

    private CakeDirInfo BuildFileTree(string mainDir, string currentDir)
    {
        var dirEntry = new CakeDirInfo();
        string parentRelative = Path.GetRelativePath(mainDir, currentDir);
        if (parentRelative == ".")
            parentRelative = "";
        else
            dirEntry.Hash = FNV1A64.FNV64StringI(parentRelative.Replace('\\', '/'));

        dirEntry.Path = parentRelative;

        _dirs.Add(dirEntry);
        dirEntry.DirIndex = (uint)(_dirs.Count - 1);

        _dirLookup.Add(dirEntry.Hash, new CakeEntryLookup()
        {
            NameHash = !string.IsNullOrEmpty(parentRelative) ? dirEntry.Hash : 0,
            EntryIndex = dirEntry.DirIndex,
        });

        foreach (var fileSysPath in Directory.EnumerateFileSystemEntries(currentDir, "*"))
        {
            string relativeSubEntryPath = Path.GetRelativePath(mainDir, fileSysPath).Replace('\\', '/');

            var info = new FileInfo(fileSysPath);
            if (info.Attributes.HasFlag(FileAttributes.Directory))
            {
                CakeDirInfo child = BuildFileTree(mainDir, fileSysPath);

                dirEntry.SubFolderIndices.Add(child.DirIndex);
            }
            else
            {
                if (relativeSubEntryPath.Equals("_textures.tdb"))
                {
                    _logger?.LogWarning("Skipping _textures.tdb in folder as we're rebuilding it");
                    continue;
                }

                RegisterFileForFolder(dirEntry, fileSysPath, relativeSubEntryPath);
            }
        }

        return dirEntry;
    }

    private void RegisterFileForFolder(CakeDirInfo dirEntry, string localPath, string relativeSubEntryPath)
    {
        CakeFileEntry cakeFileEntry;
        if (localPath.EndsWith(".dds"))
        {
            if (!IsAtLeastVersion(9))
            {
                _logger?.LogWarning("Texture packing is not yet supported for cakes <9.1. Skipping '{path}'", relativeSubEntryPath);
                return;
            }

            cakeFileEntry = CreateTexFromDds(localPath, relativeSubEntryPath);
        }
        else
        {
            var info = new FileInfo(localPath);
            cakeFileEntry = CreateFileEntry(localPath, relativeSubEntryPath, info.Length);
        }

        cakeFileEntry.ParentDirIndex = dirEntry.DirIndex;

        _files.Add(cakeFileEntry);
        cakeFileEntry.FileEntryIndex = (uint)(_files.Count - 1);
        dirEntry.FileIndices.Add(cakeFileEntry.FileEntryIndex);

        ulong hash = FNV1A64.FNV64StringI(cakeFileEntry.RelativePath);
        _fileLookup.TryAdd(hash, new CakeEntryLookup()
        {
            NameHash = hash,
            EntryIndex = cakeFileEntry.FileEntryIndex,
            IsEmptyFile = cakeFileEntry.ExpandedSize == 0,
        });

        _logger?.LogInformation("Registered {gamePath} ({sizeString})...", cakeFileEntry.RelativePath, Utils.BytesToString(cakeFileEntry.ExpandedSize));
    }

    private CakeFileEntry CreateFileEntry(string localPath, string relativePath, long fileSize)
    {
        bool shouldCompress = ShouldCompress(relativePath, fileSize);

        var cakeFileEntry = new CakeFileEntry()
        {
            CompressedSize = (uint)fileSize,
            ExpandedSize = (uint)fileSize,
            CRCChecksum = 0,
            FileName = Path.GetFileName(relativePath),
            RelativePath = relativePath.Replace('\\', '/'),
            LocalPath = localPath,
        };

        if (ResourceIds.ExtensionToResourceId.TryGetValue(Path.GetExtension(cakeFileEntry.RelativePath), out var resourceId))
            cakeFileEntry.ResourceTypeSignature = resourceId;

        if (shouldCompress)
        {
            SetupCompressedEntry(cakeFileEntry);
        }
        else
        {
            cakeFileEntry.ChunkEndOffsets.Add(cakeFileEntry.CompressedSize);
        }

        TotalChunkCount += (uint)cakeFileEntry.ChunkEndOffsets.Count;

        return cakeFileEntry;
    }

    private void SetupCompressedEntry(CakeFileEntry cakeFileEntry)
    {
        cakeFileEntry.ShouldCompress = true;
        cakeFileEntry.CompressedBits = 1;
        cakeFileEntry.NumSectorsPerChunk = NumSectorsPerChunk;

        long size = cakeFileEntry.ExpandedSize;
        while (size > 0)
        {
            cakeFileEntry.ChunkEndOffsets.Add(0);
            size -= Math.Min(size, cakeFileEntry.NumSectorsPerChunk * CakeRegistryFile.SECTOR_SIZE_BYTES);
        }

        if (_tdb.TryGetTexture(cakeFileEntry.RelativePath, out TextureMeta textureMeta) && !IsAtLeastVersion(9, 3))
            textureMeta.SetCompressed(true);
    }

    private bool ShouldCompress(string relativePath, long fileSize)
    {
        return fileSize >= 0x100 && !ShouldNotCompressFileWithExtension(relativePath);
    }

    private bool ShouldNotCompressFileWithExtension(string ext)
    {
        switch (Path.GetExtension(ext))
        {
            case ".tdb": // _textures.tdb
            case ".bk2": // Bink video, already compressed
            case ".adefs":
            case ".hkt":
            case ".bdy":
            case ".idx":
            case ".bin":
            case ".audioquery":
            case ".adb2":
            case ".iff":
            case ".pck":
            case ".bgnt":
            case ".ini":
            case ".dds":
            case ".db":
                return true;
        }

        return false;
    }

    private CakeFileEntry CreateTexFromDds(string localPath, string relativePath)
    {
        _logger?.LogInformation("Converting '{localPath}' to .tex...", relativePath);

        using var ddsFileStream = File.OpenRead(localPath);
        if (ddsFileStream.Length < 4 + 0x7C)
            throw new IOException("Invalid dds file, file is smaller than a regular dds header.");

        var header = new Pfim.DdsHeader(ddsFileStream);

        // https://learn.microsoft.com/en-us/windows/win32/direct3ddds/dx-graphics-dds-pguide
        DXGI_FORMAT format = 0;
        if (header.PixelFormat.FourCC.HasFlag(CompressionAlgorithm.DX10))
        {
            var dx10Header = new DdsHeaderDxt10(ddsFileStream);
            format = (DXGI_FORMAT)dx10Header.DxgiFormat;

            if (dx10Header.ResourceDimension != D3D10ResourceDimension.D3D10_RESOURCE_DIMENSION_TEXTURE2D)
                throw new IOException("Non 2d textures are not supported.");
        }
        else
        {
            if (header.PixelFormat.FourCC == CompressionAlgorithm.D3DFMT_DXT1)
                format = DXGI_FORMAT.DXGI_FORMAT_BC1_UNORM;
            else if (header.PixelFormat.FourCC == CompressionAlgorithm.D3DFMT_DXT2 || header.PixelFormat.FourCC == CompressionAlgorithm.D3DFMT_DXT3)
                format = DXGI_FORMAT.DXGI_FORMAT_BC2_UNORM;
            else if (header.PixelFormat.FourCC == CompressionAlgorithm.D3DFMT_DXT4 || header.PixelFormat.FourCC == CompressionAlgorithm.D3DFMT_DXT5)
                format = DXGI_FORMAT.DXGI_FORMAT_BC3_UNORM;
            else if (header.PixelFormat.FourCC == CompressionAlgorithm.BC4U || (uint)header.PixelFormat.FourCC == 0x20344342) // 'BC4 '
                format = DXGI_FORMAT.DXGI_FORMAT_BC4_UNORM;
            else if (header.PixelFormat.FourCC == CompressionAlgorithm.BC4S)
                format = DXGI_FORMAT.DXGI_FORMAT_BC4_SNORM;
            else if (header.PixelFormat.FourCC == CompressionAlgorithm.ATI2 || header.PixelFormat.FourCC == CompressionAlgorithm.BC5U || (uint)header.PixelFormat.FourCC == 0x20354342) // 'BC5 '
                format = DXGI_FORMAT.DXGI_FORMAT_BC5_UNORM;
            else if (header.PixelFormat.FourCC == CompressionAlgorithm.BC5S)
                format = DXGI_FORMAT.DXGI_FORMAT_BC5_SNORM;
            else if ((uint)header.PixelFormat.FourCC == 0x48364342) // 'BC6H'
                format = DXGI_FORMAT.DXGI_FORMAT_BC6H_UF16;
            else if ((uint)header.PixelFormat.FourCC == 0x48364342) // 'BC7 '
                format = DXGI_FORMAT.DXGI_FORMAT_BC7_UNORM;
            else if ((uint)header.PixelFormat.FourCC == 0x70)
                format = DXGI_FORMAT.DXGI_FORMAT_R16G16_FLOAT;
            else if ((uint)header.PixelFormat.FourCC == 0x71)
                format = DXGI_FORMAT.DXGI_FORMAT_R16G16B16A16_FLOAT;
            else if ((uint)header.PixelFormat.FourCC == 0x72)
                format = DXGI_FORMAT.DXGI_FORMAT_R32_FLOAT;
            else if ((uint)header.PixelFormat.FourCC == 0x74)
                format = DXGI_FORMAT.DXGI_FORMAT_R32G32B32A32_FLOAT;
            else if (header.PixelFormat.FourCC == CompressionAlgorithm.None)
                format = DXGI_FORMAT.DXGI_FORMAT_R8G8B8A8_UNORM;
        }

        byte version = 0;
        if (IsVersion(9, 3))
            version = 14;
        else if (IsVersion(9, 1) || IsVersion(9, 2))
            version = 13;

        TextureUtils.DXGIFormatToGE(format, out GEBaseFmt geFormat, out GEType geType, out bool isSRGB);

        string texPath = Path.ChangeExtension(relativePath, ".tex");
        TextureMeta texMeta = _tdb.Add(texPath, new TextureMeta()
        {
            Version = version,
            DimensionType = TextureMeta.TextureDimension.Texture_2D,

            Width = (ushort)header.Width,
            Height = (ushort)header.Height,
            Depth = 0,
            Format = geFormat,
            Type = geType,
            IsSRGB = isSRGB,
            NumMipmaps = (byte)header.MipMapCount,
            ExpandedFileSize = (uint)(ddsFileStream.Length - ddsFileStream.Position),
            CompressedFileSize = (uint)(ddsFileStream.Length - ddsFileStream.Position),
        });

        _logger?.LogInformation("Converted {gamePath} ({w}x{h}, {format}-{type})", relativePath, texMeta.Width, texMeta.Height, texMeta.Format, texMeta.Type);

        string tempPath = Path.GetFullPath(Path.Combine(_tempDir, texPath));
        Directory.CreateDirectory(Path.GetDirectoryName(tempPath)!);

        CakeFileEntry fileEntry = CreateFileEntry(tempPath, texPath, fileSize: texMeta.CompressedFileSize);
        if (IsAtLeastVersion(9))
        {
            texMeta.UnkBitflags_0x24 |= TextureMeta.TexMetaFlags.Unk1;

            using var imageDataStream = File.Create(tempPath);
            if (IsAtLeastVersion(9, 3))
            {
                // Copy image data
                // 9.3 (25) only stores the data as files. No header or anything.
                // The metadata is in _textures.tdb.
                ddsFileStream.CopyTo(imageDataStream);
            }
            else if (IsVersion(9, 1) || IsVersion(9, 2)) // 9.1 and 9.2 has _textures.tdb, but the file data also has the header.
            {
                // 9.1/9.2 uses _textures.tdb, but the file still has a header.
                bool shouldCompress = ShouldCompress(texPath, texMeta.ExpandedFileSize);

                uint headerSize = TextureMeta.GetSize(texMeta.Version);
                texMeta.Write(imageDataStream);

                if (shouldCompress)
                {
                    fileEntry.ShouldCompress = false;
                    fileEntry.CompressedBits = 0; // Compression is handled on the tex side.
                    CompressChunked(fileEntry, ddsFileStream, imageDataStream, baseOffset: headerSize);
                }
                else
                {
                    // Include header.
                    fileEntry.CompressedSize += headerSize;
                    fileEntry.NumSectorsPerChunk = NumSectorsPerChunk;
                    ddsFileStream.CopyTo(imageDataStream);
                }
            }
        }
        else
            throw new UnreachableException();

        return fileEntry;
    }

    private void BuildStringTable()
    {
        _stringTable = SerializeStringTable();
    }

    private byte[] SerializeStringTable()
    {
        using var ms = new MemoryStream();
        using var bs = new BinaryStream(ms);

        if (IsAtLeastVersion(9))
            WriteString(bs, OriginalDirName);

        foreach (CakeDirInfo dirInfo in _dirs)
        {
            dirInfo.PathStringOffset = (uint)bs.Position;
            WriteString(bs, dirInfo.Path);
        }

        foreach (CakeFileEntry fileInfo in _files)
        {
            fileInfo.StringOffset = (uint)bs.Position;
            WriteString(bs, fileInfo.FileName);
        }

        return ms.ToArray();
    }

    public void Bake(string path)
    {
        _logger?.LogInformation("Baking cake started.");
        _logger?.LogInformation("Version: {vMajor}.{vMinor}", VersionMajor, VersionMinor);
        _logger?.LogInformation("Registry Type: {type}", RegistryType);
        _logger?.LogInformation("Number of files: {numFiles}", _files.Count);

        if (IsAtLeastVersion(9, 1) && _tdb.TextureInfos.Count > 0)
        {
            _logger?.LogInformation("Creating _textures.tdb with {numTextures} (>=V9.1)...", _tdb.TextureInfos.Count);

            string texDbPath = "_textures.tdb";
            string localTexDbPath = Path.Combine(_tempDir, texDbPath);
            Directory.CreateDirectory(Path.GetDirectoryName(localTexDbPath));

            using (var tdbStream = File.Create(localTexDbPath))
                _tdb.Write(tdbStream);

            AddFile(localTexDbPath, texDbPath);
        }

        BuildStringTable();

        // FilesysDirHeader
        using var fs = File.Create(path);
        _cakeStream = new BinaryStream(fs);
        _cakeStream.Write("FDIR"u8);
        _cakeStream.WriteByte(VersionMajor);
        _cakeStream.WriteByte(VersionMinor);

        if (IsAtLeastVersion(8, 7))
            _cakeStream.WriteUInt16((ushort)((byte)RegistryType << 8));
        else
            _cakeStream.WriteUInt16((ushort)(byte)RegistryType);

        uint tocSize = GetFullHeaderSize();
        _cakeStream.Position = Utils.AlignValue(tocSize, 0x04);

        // Skip header & section toc for now.
        if (RegistryType != CakeRegistryType.External)
        {
            _logger?.LogInformation("Writing {numFiles} files.", _files.Count);
            WriteFiles();
        }

        // Write sections.
        _cakeStream.Position = GetHeaderAndSectionInfoSize();
        {
            WriteSection((BinaryStream bs) =>
            {
                foreach (var dirLookupEntry in _dirLookup)
                    dirLookupEntry.Value.Write(bs, VersionMajor, VersionMinor);
            });

            WriteSection((BinaryStream bs) =>
            {
                foreach (var fileLookupEntry in _fileLookup)
                    fileLookupEntry.Value.Write(bs, VersionMajor, VersionMinor);
            });

            WriteSection((BinaryStream bs) =>
            {
                foreach (var fileEntry in _files)
                    fileEntry.Write(bs, VersionMajor, VersionMinor);
            });

            WriteSection((BinaryStream bs) =>
            {
                foreach (var dirEntry in _dirs)
                    dirEntry.Write(bs, VersionMajor, VersionMinor);
            });

            WriteSection((BinaryStream bs) => bs.WriteBytes(_stringTable));
            Debug.Assert(_cakeStream.Position == Utils.AlignValue(tocSize, 0x04));
        }

        _cakeStream.Position = 0x08;

        var sectionInfoBytes = new byte[GetHeaderAndSectionInfoSize() - 0x08];
        SpanWriter sectionInfoWriter = new SpanWriter(sectionInfoBytes);
        sectionInfoWriter.WriteUInt32((uint)_files.Count);
        sectionInfoWriter.WriteUInt32((uint)_dirs.Count);
        if (IsAtLeastVersion(9))
            sectionInfoWriter.WriteUInt32(TotalChunkCount);

        // Write section infos.
        for (int i = 0; i < _sections.Count; i++)
        {
            sectionInfoWriter.WriteUInt32(_sections[i].Size);
            sectionInfoWriter.WriteUInt32(_sections[i].Checksum);
            sectionInfoWriter.WriteUInt32(_sections[i].Offset);
        }
        sectionInfoWriter.WriteUInt32(0);
        sectionInfoWriter.WriteUInt32(0);
        sectionInfoWriter.WriteUInt32(tocSize);

        if (EncryptHeader)
        {
            throw new NotImplementedException($"{nameof(Bake)} Header encryption not yet implemented.");
        }

        _cakeStream.Write(sectionInfoBytes);

        _logger?.LogInformation("Finished. Cake size: {sizeString}", Utils.BytesToString((ulong)_cakeStream.Length));

        if (RegistryType == CakeRegistryType.External)
            _logger?.LogWarning("Cake is built as external, make sure the contents are present in the game root.");

        if (Directory.Exists(_tempDir))
        {
            try
            {
                Directory.Delete(_tempDir, recursive: true);
            }
            catch (Exception)
            {
                _logger?.LogWarning( "Failed to delete leftover temp directory ({dir}).", _tempDir);
            }
        }
    }

    private void WriteSection(Action<BinaryStream> writeCallback)
    {
        uint sectionOffset = (uint)_cakeStream.Position;

        using var ms = new MemoryStream();
        using var bs = new BinaryStream(ms);

        writeCallback(bs);
        uint sectionSize = (uint)bs.Length;

        bs.Align(0x04, grow: true);

        uint sectionCrc = 1;
        byte[] bytes = ms.ToArray();

        if (EncryptHeader)
        {
            throw new NotImplementedException($"{nameof(Bake)}: Header encryption not yet implemented.");

            sectionCrc = CRC32C.Hash(bytes);
        }

        _cakeStream.Write(bytes);
        _cakeStream.Align(0x04, grow: true);

        _sections.Add(new CakeFileHeaderSection(sectionSize, sectionCrc, sectionOffset));
    }

    private int _counter;
    private void WriteFiles()
    {
        for (_counter = 0; _counter < _files.Count; _counter++)
        {
            CakeFileEntry? file = _files[_counter];
            WriteFile(file, file.LocalPath);
        }
    }

    private void WriteFile(CakeFileEntry fileEntry, string path)
    {
        fileEntry.DataOffset = (ulong)_cakeStream.Position;

        using var fileStream = File.OpenRead(path);
        if (fileEntry.ShouldCompress)
        {
            _logger?.LogInformation("[{index}/{numFiles}] Compressing {file}...", _counter + 1, _files.Count, fileEntry.RelativePath);
            CompressChunked(fileEntry, fileStream, _cakeStream, 0);
        }
        else
        {
            // TODO: encryption (?).
            _logger?.LogInformation("[{index}/{numFiles}] Writing {file}...", _counter + 1, _files.Count, fileEntry.RelativePath);
            fileStream.CopyTo(_cakeStream);
        }

        _cakeStream.Align(0x04, grow: true);
    }

    private void CompressChunked(CakeFileEntry fileEntry, Stream inputStream, Stream outputStream, long baseOffset)
    {
        // Note that outputStream may have some sort of header (i.e v9.1 textures).
        // CompressedSize will include it, same for the first chunk, even if it's not inherently compressed.

        long size = fileEntry.ExpandedSize;
        uint decChunkSize = fileEntry.NumSectorsPerChunk * CakeRegistryFile.SECTOR_SIZE_BYTES;

        using MemoryOwner<byte> decBuffer = MemoryOwner<byte>.Allocate((int)decChunkSize);
        using MemoryOwner<byte> compBuffer = MemoryOwner<byte>.Allocate((int)decChunkSize);

        int chunkIndex = 0;
        while (size > 0)
        {
            int chunkSize = (int)Math.Min(size, decChunkSize);

            var decChunk = decBuffer.Span.Slice(0, chunkSize);
            inputStream.ReadExactly(decChunk);

            long compSize = Oodle.Compress(OodleFormat.Kraken,
                decChunk,
                chunkSize,
                compBuffer.Span,
                OodleCompressionLevel.Normal);

            if (compSize == 0)
                throw new IOException("Failed to compress oodle chunk?");
            else if (compSize > decChunkSize)
                throw new IOException("Compressed file is larger than decompressed file. Compressing an already compressed file?");

            Span<byte> compChunk = compBuffer.Span.Slice(0, (int)compSize);
            outputStream.Write(compChunk);

            size -= chunkSize;
            baseOffset += compSize;

            fileEntry.ChunkEndOffsets[chunkIndex++] = (uint)baseOffset;
        }

        fileEntry.CompressedSize = (uint)baseOffset;
    }

    private uint GetFullHeaderSize()
    {
        uint tocSize = GetHeaderAndSectionInfoSize();
        foreach (var dirLookupEntry in _dirLookup)
            tocSize += dirLookupEntry.Value.GetSize(VersionMajor, VersionMinor);
        tocSize = Utils.AlignValue(tocSize, 0x04);

        foreach (var fileLookupEntry in _fileLookup)
            tocSize += fileLookupEntry.Value.GetSize(VersionMajor, VersionMinor);
        tocSize = Utils.AlignValue(tocSize, 0x04);

        foreach (var fileEntry in _files)
            tocSize += fileEntry.GetSize(VersionMajor, VersionMinor);
        tocSize = Utils.AlignValue(tocSize, 0x04);

        foreach (var dirEntry in _dirs)
            tocSize += dirEntry.GetSize(VersionMajor, VersionMinor);
        tocSize = Utils.AlignValue(tocSize, 0x04);

        tocSize += (uint)_stringTable.Length;
        // alignment for string table to data does not count towards size.

        return tocSize;
    }

    private uint GetHeaderAndSectionInfoSize()
    {
        if (IsAtLeastVersion(9))
            return 0x5Cu;
        else
            return 0x58u;
    }

    private void WriteString(BinaryStream bs, string str)
    {
        if (IsAtLeastVersion(8))
        {
            if (EncryptHeader)
                throw new NotImplementedException($"{nameof(WriteString)}: String encryption (>=V8) not yet implemented.");
            else
            {
                bs.WriteString(str, StringCoding.ByteCharCount);
                bs.WriteByte(0);
            }
        }
        else
        {
            if (EncryptHeader)
                throw new NotImplementedException($"{nameof(WriteString)}: String encryption (<V8) not yet implemented.");
            else
                bs.WriteString(str, StringCoding.ZeroTerminated);
        }
    }

    private bool IsVersion(byte versionMajor, byte versionMinor)
    {
        return VersionMajor == versionMajor && VersionMinor == versionMinor;
    }

    private bool IsAtLeastVersion(byte versionMajor, byte versionMinor = 0)
    {
        if (VersionMajor < versionMajor)
            return false;

        return VersionMajor > versionMajor || (VersionMajor == versionMajor && VersionMinor >= versionMinor);
    }
}
