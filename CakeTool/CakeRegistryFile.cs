using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

using Microsoft.Extensions.Logging;
using Microsoft.IO;

using CommunityToolkit.HighPerformance;
using CommunityToolkit.HighPerformance.Buffers;

using CakeTool.Crypto;
using CakeTool.Hashing;
using CakeTool.Compression;
using CakeTool.PRNG;
using CakeTool.GameFiles.Textures;

using Syroot.BinaryData;
using Syroot.BinaryData.Memory;
using System.Text.Json;

namespace CakeTool;

/// <summary>
/// Cake registry file (disposable object).
/// </summary>
public class CakeRegistryFile : AbstractVersionableCakeEntity, IDisposable
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;

    public const uint FILESYS_DIR_SIGNATURE = 0x52494446; // 'FDIR'
    public const int FILESYS_DIR_HEADER_SIZE = 0x08;

    public const int DIR_LOOKUP_TABLE_SECTION_INDEX = 0;
    public const int FILE_LOOKUP_TABLE_SECTION_INDEX = 1;
    public const int FILE_INFO_TABLE_SECTION_INDEX = 2;
    public const int DIR_INFO_TABLE_SECTION_INDEX = 3;
    public const int STRING_TABLE_SECTION_INDEX = 4;

    public const uint SECTOR_SIZE_BYTES = 0x400;

    public string FileName { get; set; } = string.Empty;

    public CakeRegistryType TypeOrParam { get; set; }

    /// <summary>
    /// Whether the cake is encrypted, at least the header and toc.
    /// </summary>
    public bool IsHeaderEncrypted { get; set; }

    /// <summary>
    /// For V6 through 8.3, otherwise look into <see cref="CakeFileEntry"/> for later versions
    /// </summary>
    public bool IsFileDataEncrypted { get; set; }

    public uint MainCryptoKey { get; set; }

    // Sections
    private List<CakeFileHeaderSection> _sections = [];

    /// <summary>
    /// Lookup table for actual file entries. Should always be sorted by hash for binary search.
    /// </summary>
    private Dictionary<ulong, CakeEntryLookup> _dirLookupTable = [];

    /// <summary>
    /// Lookup table for actual directory entries. Should always be sorted by hash for binary search.
    /// </summary>
    private Dictionary<ulong, CakeEntryLookup> _fileLookupTable = [];

    /// <summary>
    /// List of all directories and their information.
    /// </summary>
    private List<CakeDirInfo> _dirEntries = [];

    /// <summary>
    /// List of all files and their information.
    /// </summary>
    private List<CakeFileEntry> _fileEntries = [];

    /// <summary>
    /// String/path table.
    /// </summary>
    private Dictionary<uint, string> _strings = [];

    /// <summary>
    /// File stream handle for the cake
    /// </summary>
    private FileStream _fileStream;

    // This is needed for certain cakes that do not have encryption despite their headers marked as such.
    // Game basically correctly checks the header and goes into a function for handling encryption, but they're stubbed in those builds.
    private bool _forceNoEncryption;
    private bool _noConvertDds;

    private CakeCryptor _cakeCryptor;

    // For 9.3
    private TextureDatabase _textureDb;

    private static readonly RecyclableMemoryStreamManager manager = new RecyclableMemoryStreamManager();

    private CakeRegistryFile(string fileName, FileStream fs, ILoggerFactory? loggerFactory = null, bool forceNoEncryption = false,
        bool noConvertDds = false)
    {
        _fileStream = fs;
        FileName = Path.GetFileName(fileName);
        _forceNoEncryption = forceNoEncryption;
        _noConvertDds = noConvertDds;

        if (loggerFactory is not null)
            _logger = loggerFactory.CreateLogger(GetType().ToString());
    }

    public static CakeRegistryFile Open(string file, ILoggerFactory? loggerFactory = null, bool forceNoEncryption = false,
        bool noConvertDds = false)
    {
        var fs = File.OpenRead(file);
        if (fs.Length < 0x58)
            throw new InvalidDataException("Invalid cake file. Header is too small, corrupted?");

        var cake = new CakeRegistryFile(file, fs, loggerFactory, forceNoEncryption, noConvertDds);
        cake.OpenInternal();
        return cake;
    }

    public uint GetHeaderAndSectionInfoSize()
    {
        if (IsAtLeastVersion(9))
            return 0x5Cu;
        else
            return 0x58u;
    }

    // UI/Projects/ShowAssets/superstar_nameplates
    public CakeDirInfo? GetDirEntry(string dir)
    {
        ulong hash = FNV1A64.FNV64StringI(dir);
        if (_dirLookupTable.TryGetValue(hash, out CakeEntryLookup? dirLookupEntry))
        {
            return _dirEntries[(int)dirLookupEntry.EntryIndex];
        }

        return null;
    }

    public CakeFileEntry? GetFileEntry(string file, out bool isEmpty)
    {
        isEmpty = true;

        ulong hash = FNV1A64.FNV64StringI(file);
        if (_fileLookupTable.TryGetValue(hash, out CakeEntryLookup? fileLookupEntry))
        {
            isEmpty = fileLookupEntry.IsEmptyFile;
            return _fileEntries[(int)fileLookupEntry.EntryIndex];
        }

        return null;
    }

    public void ExtractAll(string outputDir)
    {
        foreach (CakeFileEntry? fileEntry in _fileEntries)
        {
            var name = _strings[fileEntry.StringOffset];

            try
            {
                ExtractFileData(fileEntry, name, outputDir);
            }
            catch (Exception ex)
            {
                string gamePath = GetGamePathForEntry(fileEntry);
                _logger?.LogError(ex, "Failed to extract '{gamePath}'", gamePath);
            }
        }
    }

    public bool FileExists(string file)
    {
        ulong hash = FNV1A64.FNV64StringI(file);
        return _fileLookupTable.TryGetValue(hash, out _);
    }

    public bool ExtractFile(string file, string outputDir)
    {
        ulong hash = FNV1A64.FNV64StringI(file);
        if (!_fileLookupTable.TryGetValue(hash, out CakeEntryLookup? lookupEntry))
            return false;

        CakeFileEntry fileEntry = _fileEntries[(int)lookupEntry.EntryIndex];
        ExtractFileData(fileEntry, file, outputDir);
        return true;
    }

    public bool ExtractFile(string file, Stream stream)
    {
        ulong hash = FNV1A64.FNV64StringI(file);
        if (!_fileLookupTable.TryGetValue(hash, out CakeEntryLookup? lookupEntry))
            return false;

        CakeFileEntry fileEntry = _fileEntries[(int)lookupEntry.EntryIndex];

        using RecyclableMemoryStream fileDataStream = manager.GetStream(tag: null, fileEntry.ExpandedSize);
        ExtractFileData(fileEntry, file, fileDataStream);

        string gamePath = GetGamePathForEntry(fileEntry);
        PostProcessFileData(fileEntry, fileDataStream, gamePath, stream);
        return true;
    }

    private void OpenInternal()
    {
        BinaryStream bs = new BinaryStream(_fileStream);
        if (bs.Length < 0x58)
            throw new InvalidDataException("Invalid cake file. file is too small to contain main header, corrupted?");

        Span<byte> headerBytes = stackalloc byte[0x08]; 
        bs.ReadExactly(headerBytes);
        FilesysDirHeader header = MemoryMarshal.Cast<byte, FilesysDirHeader>(headerBytes)[0];

        if (header.Signature != FILESYS_DIR_SIGNATURE)
            throw new InvalidDataException("Not a valid cake file, signature did not match 'FDIR'.");

        VersionMajor = (byte)(header.Version & 0xFF);
        VersionMinor = (byte)(header.Version >> 8);

        _cakeCryptor = new CakeCryptor(VersionMajor, VersionMinor);

        _logger?.LogInformation("Cake Version: v{major}.{minor}", VersionMajor, VersionMinor);

        if (VersionMajor == 6 || (VersionMajor == 8 && VersionMinor < 7)) // v6, v8.1 thru 6? maybe?
        {
            TypeOrParam = (CakeRegistryType)(header.Flags & 0b11_1111_1111_1111); // Is it 8 and 6 bits split?

            // is bit 14 header/toc encryption, and bit 15 file encryption maybe?
            // needs further testing tbh.
            IsHeaderEncrypted = ((header.Flags >> 14) & 1) == 1;
            IsFileDataEncrypted = (header.Flags >> 15) == 1;
        }
        else if (IsAtLeastVersion(8, 7)) // >=v8.7 - encryption flag on files moved to entry infos.
        {
            byte unk = (byte)(header.Flags & 0b11111111);
            TypeOrParam = (CakeRegistryType)((header.Flags >> 8) & 0b1111111);
            IsHeaderEncrypted = (header.Flags >> 15) == 1; // 1 bit
        }

        _logger?.LogInformation("Type: {type} ({typeNumber})", TypeOrParam, (int)TypeOrParam);

        if (IsHeaderEncrypted)
            MainCryptoKey = _cakeCryptor.GenerateCryptoXorKey(FileName);

        _logger?.LogInformation("Crypto Key: {key:X8}", MainCryptoKey);

        uint headerPlusSectionTocSize = GetHeaderAndSectionInfoSize();
        if (bs.Length < headerPlusSectionTocSize)
            throw new InvalidDataException("Invalid cake file. file is too small to contain main header + section, corrupted?");

        byte[] sectionHeaderBytes = new byte[headerPlusSectionTocSize];
        bs.Position = 0;
        bs.ReadExactly(sectionHeaderBytes);

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            _logger?.LogInformation("Decrypting header.");
            Span<byte> sectionInfoBytes = sectionHeaderBytes.AsSpan(FILESYS_DIR_HEADER_SIZE,
                (int)(headerPlusSectionTocSize - FILESYS_DIR_HEADER_SIZE));

            _cakeCryptor.CryptHeaderData(sectionInfoBytes, MainCryptoKey);
        }

        SpanReader sectionReader = new SpanReader(sectionHeaderBytes, Syroot.BinaryData.Core.Endian.Little);
        sectionReader.Position = FILESYS_DIR_HEADER_SIZE;
        ReadSections(bs, sectionReader);

        if (TypeOrParam == CakeRegistryType.External)
        {
            _logger?.LogInformation("External Entries ({count}):", _fileEntries.Count);
            foreach (CakeFileEntry? fileEntry in _fileEntries)
            {
                var name = _strings[fileEntry.StringOffset];

                CakeDirInfo parentDir = _dirEntries[(int)fileEntry.ParentDirIndex];
                string dirName = _strings[parentDir.PathStringOffset];

                _logger?.LogInformation("- {file}", Path.Combine(dirName, name));
            }
        }

        OnCakeEntriesLoaded();

        _logger?.LogInformation("Cake initialized.");
    }

    /// <summary>
    /// Post-processing on cake file entries loaded.
    /// </summary>
    private void OnCakeEntriesLoaded()
    {
        if (IsAtLeastVersion(9, 3) && !_noConvertDds)
        {
            if (FileExists("_textures.tdb"))
            {
                _logger?.LogInformation("Loading texture database from cake.. (_textures.tdb)");
                using var ms = new MemoryStream();
                ExtractFile("_textures.tdb", ms);
                ms.Position = 0;

                _textureDb = new TextureDatabase();
                _textureDb.Read(ms);

                _logger?.LogInformation("Texture database loaded with {textureCount} entries.", _textureDb.TextureInfos.Count);
            }
            else
            {
                _logger?.LogInformation("Not loading texture database (_textures.tdb is not present in cake).");
            }
        }
    }

    private void ExtractFileData(CakeFileEntry entry, string fileName, string outputDir)
    {
        string gamePath = GetGamePathForEntry(entry);
        string outputPath = Path.Combine(outputDir, gamePath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        _logger?.LogInformation("Extracting: {file}", gamePath);

        using RecyclableMemoryStream fileDataStream = manager.GetStream(tag: null, entry.ExpandedSize);
        ExtractFileData(entry, fileName, fileDataStream);

        if (entry.ResourceTypeSignature == ResourceIds.Texture && !_noConvertDds)
            outputPath = Path.ChangeExtension(outputPath, ".dds");

        using var outputFileStream = File.Create(outputPath);
        PostProcessFileData(entry, fileDataStream, gamePath, outputFileStream);
    }

    private void ExtractFileData(CakeFileEntry entry, string fileName, Stream outputStream)
    {
        if (entry.CompressedSize == 0)
            return;

        string gamePath = GetGamePathForEntry(entry);
        _fileStream.Position = (long)entry.DataOffset;

        using var inputBuffer = MemoryOwner<byte>.Allocate((int)entry.CompressedSize);
        _fileStream.ReadExactly(inputBuffer.Span);

        if ((VersionMajor == 6 && IsFileDataEncrypted) ||
            ((IsVersion(8, 2) || IsVersion(8, 3)) && IsFileDataEncrypted) ||
            (IsVersion(8, 7) && entry.RawBitFlags != 0) ||
            (VersionMajor >= 9 && (entry.UnkBits2EncryptedMaybe & 1) != 0))
        {
            uint key = _cakeCryptor.GetFileManglingKey(entry, MainCryptoKey);
            _cakeCryptor.CryptFileDataAndCheck(inputBuffer.Span, entry, key);
        }

        if (entry.CompressedSize >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(inputBuffer.Span) == ResourceIds.Resource) // RES!
        {
            ExtractResource(fileName, gamePath, inputBuffer, outputStream);
        }
        else if (entry.ResourceTypeSignature == ResourceIds.Texture && (IsVersion(9, 1) || IsVersion(9, 2)))
        {
            // Will need to be post-processed in PostProcessFileData. File contains texture meta & compressed data
            outputStream.Write(inputBuffer.Span);
        }
        else
        {
            // 9.0 introduced chunked decompression.
            if (IsAtLeastVersion(9, 0))
                ExtractChunked(entry, gamePath, inputBuffer.Span, outputStream);
            else
                ExtractRaw(entry, gamePath, inputBuffer, outputStream);
        }
    }

    private void PostProcessFileData(CakeFileEntry entry, Stream fileDataStream, string gamePath, Stream outputStream)
    {
        fileDataStream.Position = 0;

        if (entry.ResourceTypeSignature == ResourceIds.Texture && !_noConvertDds)
        {
            if (IsAtLeastVersion(9, 3)) // 9.3's tex only store image data. We need to refer to the .tdb file for conversion.
            {
                if (_textureDb.TryGetTexture(gamePath, out TextureMeta texMeta))
                {
                    PrintTextureInfo(gamePath, texMeta);

                    TextureUtils.ConvertToDDS(texMeta, fileDataStream, outputStream);
                    return;
                }
            }
            else if (IsVersion(9, 1) || IsVersion(9, 2)) // 9.1 & 9.2 stores the metadata before the compressed data.
            {
                // Texture meta is embedded.
                ProcessEmbededTextureResource(entry, gamePath, fileDataStream, outputStream);
                return;
            }
            else if (fileDataStream.Length >= 4) // Earlier tex actually has metadata in them. Check for file's TEX! magic for conversion.
            {
                uint magic = fileDataStream.ReadUInt32();
                if (magic == ResourceIds.Texture)
                {
                    var texMeta = new TextureMeta();
                    texMeta.Read(fileDataStream);

                    PrintTextureInfo(gamePath, texMeta);

                    if ((texMeta.Version == 9 || texMeta.Version == 10) && texMeta.IsCompressedTexture()) // V9/V10 (20) Crunched
                    {
                        if (texMeta.IsCompressedTexture())
                        {
                            // Note/todo: end of buffer may have format name
                            using var inputBuffer = MemoryOwner<byte>.Allocate((int)texMeta.CompressedFileSize);
                            fileDataStream.ReadExactly(inputBuffer.Span);

                            if (Crunch2.DecompressToDds(inputBuffer.Span, texMeta.CompressedFileSize, out MemoryOwner<byte>? uncompressed))
                            {
                                outputStream.Write(uncompressed.Span);
                                uncompressed.Dispose();
                            }
                        }
                    }
                    else if (texMeta.Version == 11 && texMeta.IsCompressedTexture()) // V11 (23) can be compressed in-place with oodle
                    {
                        using var inputBuffer = MemoryOwner<byte>.Allocate((int)texMeta.CompressedFileSize);
                        fileDataStream.ReadExactly(inputBuffer.Span);

                        using var outputBuffer = MemoryOwner<byte>.Allocate((int)texMeta.ExpandedFileSize);
                        long decoded = Oodle.Decompress(in MemoryMarshal.GetReference(inputBuffer.Span), texMeta.CompressedFileSize,
                                                        in MemoryMarshal.GetReference(outputBuffer.Span), texMeta.ExpandedFileSize);

                        TextureUtils.ConvertToDDS(texMeta, outputBuffer.AsStream(), outputStream);
                    }
                    else
                    {
                        TextureUtils.ConvertToDDS(texMeta, fileDataStream, outputStream);
                    }
                    return;
                }
            }
        }

        fileDataStream.Position = 0;
        fileDataStream.CopyTo(outputStream);
    }

    private void ExtractChunked(CakeFileEntry entry, string gamePath, Span<byte> inputBuffer, Stream outputStream, bool isEmbeddedTextureResource = false)
    {
        if (entry.CompressedBits != 0)
        {
            uint chunkOffset = 0;
            long decOffset = 0;

            uint decChunkSize = entry.NumSectorsPerChunk * SECTOR_SIZE_BYTES;
            using var outputBuffer = MemoryOwner<byte>.Allocate((int)decChunkSize);

            for (int i = 0; i < entry.ChunkEndOffsets.Count; i++)
            {
                uint chunkSize = entry.ChunkEndOffsets[i] - (i != 0 ? entry.ChunkEndOffsets[i - 1] : 0);
                if (isEmbeddedTextureResource && i == 0)
                    chunkSize -= 0x28;

                Span<byte> chunk = inputBuffer.Slice((int)chunkOffset, (int)chunkSize);

                // There's probably a better way to calculate this.
                long decSize = Math.Min(decOffset + decChunkSize, entry.ExpandedSize) - decOffset;

                // The last chunk may not be compressed if it's too small to have been worth it.
                // The game probably detects this better
                if (decSize != chunkSize)
                {
                    long decoded = Oodle.Decompress(in MemoryMarshal.GetReference(chunk),
                                                    chunkSize,
                                                    in MemoryMarshal.GetReference(outputBuffer.Span),
                                                    decSize);

                    if (decoded != decSize)
                    {
                        _logger?.LogError("ERROR: Failed to decompress oodle data ({file}), skipping!", gamePath);
                        return;
                    }

                    outputStream.Write(outputBuffer.Span.Slice(0, (int)decSize));
                }
                else
                {
                    outputStream.Write(chunk);
                }

                decOffset += decSize;
                chunkOffset += chunkSize;
            }

            if (decOffset != entry.ExpandedSize)
                _logger?.LogError("ERROR: Failed to decompress oodle data ({file}), skipping!", gamePath);
        }
        else
        {
            outputStream.Write(inputBuffer);
        }
    }

    private void ExtractRaw(CakeFileEntry entry, string gamePath, MemoryOwner<byte> inputBuffer, Stream outputStream)
    {
        if (entry.ExpandedSize != entry.CompressedSize)
        {
            using var outputBuffer = MemoryOwner<byte>.Allocate((int)entry.ExpandedSize);
            long decoded = Oodle.Decompress(in MemoryMarshal.GetReference(inputBuffer.Span), entry.CompressedSize,
                                            in MemoryMarshal.GetReference(outputBuffer.Span), entry.ExpandedSize);
            if (decoded != entry.ExpandedSize)
                _logger?.LogError("ERROR: Failed to decompress oodle data ({file}), skipping!", gamePath);
            else
                outputStream.Write(outputBuffer.Span);
        }
        else
        {
            outputStream.Write(inputBuffer.Span);
        }
    }

    // Mostly used in Version 6/8.
    private void ExtractResource(string fileName, string dirName, MemoryOwner<byte> inputBuffer, Stream outputStream)
    {
        const int ResourceHeaderSize = 0x18;

        SpanReader resReader = new SpanReader(inputBuffer.Span);
        uint resourceSignature = resReader.ReadUInt32();
        uint versionMaybe = resReader.ReadUInt32(); // version? this doesn't appear to be read
        uint resourceType = resReader.ReadUInt32();
        uint compressedSize = resReader.ReadUInt32();
        uint compressionType = resReader.ReadUInt32();
        uint decompressedSize = resReader.ReadUInt32();

        switch (compressionType)
        {
            case 0:
                {
                    ReadOnlySpan<byte> resourceData = inputBuffer.Span.Slice(ResourceHeaderSize, (int)compressedSize);
                    outputStream.Write(resourceData);
                }
                break;

            case 0x4C444F4F: // 'OODL'
            case 0x214B524B: // 'KRK!'
                {
                    ReadOnlySpan<byte> resourceData = inputBuffer.Span.Slice(ResourceHeaderSize, (int)compressedSize);

                    using var outputBuffer = MemoryOwner<byte>.Allocate((int)decompressedSize);
                    long decoded = Oodle.Decompress(in MemoryMarshal.GetReference(resourceData), compressedSize,
                                                    in MemoryMarshal.GetReference(outputBuffer.Span), decompressedSize);
                    if (decoded != decompressedSize)
                        _logger?.LogError("ERROR: Failed to decompress oodle data ({file}), skipping!", Path.Combine(dirName, fileName));
                    else
                        outputStream.Write(outputBuffer.Span);
                }
                break;

            default:
                throw new NotSupportedException($"Resource compression type {compressionType:X8} not supported for file {Path.Combine(dirName, fileName)}");
        }
    }

    private void ProcessEmbededTextureResource(CakeFileEntry fileEntry, string gamePath, Stream fileDataStream, Stream outputStream)
    {
        var texMeta = new TextureMeta();
        texMeta.Read(fileDataStream);

        PrintTextureInfo(gamePath, texMeta);

        int currentOffset = (int)fileDataStream.Position;
        if (texMeta.IsCompressedTexture())
        {
            int compressedSize = (int)(fileDataStream.Length - currentOffset);
            byte[] compressed = fileDataStream.ReadBytes(compressedSize);

            using RecyclableMemoryStream decompressedImageDataStream = manager.GetStream(tag: null, fileEntry.ExpandedSize);
            ExtractChunked(fileEntry, gamePath, compressed, decompressedImageDataStream, true);

            decompressedImageDataStream.Position = 0;
            TextureUtils.ConvertToDDS(texMeta, decompressedImageDataStream, outputStream);
        }
        else
        {
            TextureUtils.ConvertToDDS(texMeta, fileDataStream, outputStream);
        }
    }

    private void PrintTextureInfo(string gamePath, TextureMeta texMeta)
    {
        string formatStr = $"{texMeta.Format}-{texMeta.Type}" + (texMeta.IsSRGB ? "-SRGB" : string.Empty);

        _logger?.LogInformation("Converting '{gamePath}' to .dds... ({dimType}, {width}x{height}, {formatStr}, depth={depth}, {sizes})", gamePath,
                         texMeta.DimensionType,
                         texMeta.Width, texMeta.Height,
                         formatStr,
                         texMeta.Depth,
                         string.Join(",", texMeta.UnkSizes));
    }

    public string GetGamePathForEntry(CakeFileEntry entry)
    {
        string gamePath;
        if (IsAtLeastVersion(8))
        {
            CakeDirInfo parentDir = _dirEntries[(int)entry.ParentDirIndex];
            string dirName = _strings[parentDir.PathStringOffset];
            string fileName = _strings[entry.StringOffset];
            gamePath = Path.Combine(dirName, fileName).Replace('\\', '/');
        }
        else
            gamePath = _strings[entry.StringOffset]; // Old versions has the full path.

        return gamePath;
    }

    private void ReadSections(BinaryStream bs, SpanReader hdrReader)
    {
        _logger?.LogInformation("Reading Sections..");

        uint fileCount = hdrReader.ReadUInt32();
        uint dirCount = hdrReader.ReadUInt32();

        _logger?.LogInformation("Num Files: {fileCount}", fileCount);
        _logger?.LogInformation("Num Folders: {folderCount}", dirCount);

        if (IsAtLeastVersion(9))
        {
            uint chunkCount = hdrReader.ReadUInt32(); // Sum of all number of chunks from each file entry
            _logger?.LogInformation("Num Chunks: {chunkCount}", chunkCount);
        }

        for (int i = 0; i < 5; i++)
        {
            uint secSize = hdrReader.ReadUInt32();
            uint secCrc = hdrReader.ReadUInt32(); // always 1 in 2K21 where there's no encryption
            uint secOffset = hdrReader.ReadUInt32();
            _sections.Add(new CakeFileHeaderSection(secSize, secCrc, secOffset));
        }

        // These two seem to be always empty.
        uint pad1 = hdrReader.ReadUInt32();
        uint pad2 = hdrReader.ReadUInt32();
        uint totalTocSize = hdrReader.ReadUInt32(); // aka header (0x5C) + all sections

        if (bs.Length < totalTocSize)
            throw new InvalidDataException($"Stream/file size is smaller than expected header+toc size. stream: 0x{bs.Length:X} < expected: {totalTocSize:X}");

        ReadDirLookupTable(bs, dirCount);
        ReadFileLookupTable(bs, fileCount);
        ReadFileEntries(bs, fileCount);
        ReadDirEntries(bs, dirCount);
        ReadStringTable(bs);

        Debug.Assert(bs.Position == totalTocSize);

        _logger?.LogInformation("Done reading sections.");
    }

    private void ReadFileLookupTable(BinaryStream bs, uint numFiles)
    {
        bs.Position = _sections[FILE_LOOKUP_TABLE_SECTION_INDEX].Offset;
        byte[] sectionData = new byte[_sections[FILE_LOOKUP_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(sectionData);

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            _logger?.LogInformation("Decrypting file LUT section.");

            uint crc = _cakeCryptor.CryptHeaderData(sectionData, MainCryptoKey);
            if (crc != _sections[FILE_LOOKUP_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("File lookup section checksum did not match. Invalid or corrupted?");

            _logger?.LogInformation("File LUT section checksum OK.");
        }

        SpanReader sectionReader = new SpanReader(sectionData);
        for (int i = 0; i < numFiles; i++)
        {
            var fileEntry = new CakeEntryLookup();
            fileEntry.Read(ref sectionReader);
            _fileLookupTable.Add(fileEntry.NameHash, fileEntry);
        }
    }

    private void ReadDirEntries(BinaryStream bs, uint dirCount)
    {
        bs.Position = _sections[DIR_INFO_TABLE_SECTION_INDEX].Offset;
        byte[] sectionData = new byte[_sections[DIR_INFO_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(sectionData);

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            _logger?.LogInformation("Decrypting dir entries section.");

            uint crc = _cakeCryptor.CryptHeaderData(sectionData, MainCryptoKey);
            if (crc != _sections[DIR_INFO_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("Dir entries section checksum did not match. Invalid or corrupted?");

            _logger?.LogInformation("Dir entries section checksum OK.");
        }

        SpanReader sectionReader = new SpanReader(sectionData);
        for (int i = 0; i < dirCount; i++)
        {
            var dirEntry = new CakeDirInfo();
            dirEntry.Read(ref sectionReader);
            _dirEntries.Add(dirEntry);
        }
    }

    private void ReadDirLookupTable(BinaryStream bs, uint numFolders)
    {
        bs.Position = _sections[DIR_LOOKUP_TABLE_SECTION_INDEX].Offset;
        byte[] sectionData = new byte[_sections[DIR_LOOKUP_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(sectionData);

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            _logger?.LogInformation("Decrypting dir section.");

            uint crc = _cakeCryptor.CryptHeaderData(sectionData, MainCryptoKey);
            if (crc != _sections[DIR_LOOKUP_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("Dir section checksum did not match. Invalid or corrupted?");

            _logger?.LogInformation("Dir section checksum OK.");
        }

        SpanReader srr = new SpanReader(sectionData);
        for (int i = 0; i < numFolders; i++)
        {
            var dirEntry = new CakeEntryLookup();
            dirEntry.Read(ref srr);
            _dirLookupTable.Add(dirEntry.NameHash, dirEntry);
        }
    }

    private void ReadFileEntries(BinaryStream bs, uint numFiles)
    {
        bs.Position = _sections[FILE_INFO_TABLE_SECTION_INDEX].Offset;
        byte[] entries = new byte[_sections[FILE_INFO_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(entries);

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            _logger?.LogInformation("Decrpyting file entries section.");

            uint crc = _cakeCryptor.CryptHeaderData(entries, MainCryptoKey);
            if (crc != _sections[FILE_INFO_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("File info section checksum did not match. Invalid or corrupted?");

            _logger?.LogInformation("File entries section checksum OK.");
        }

        SpanReader entriesReader = new SpanReader(entries);
        for (int i = 0; i < numFiles; i++)
        {
            var fileEntry = new CakeFileEntry();
            fileEntry.Read(ref entriesReader, VersionMajor, VersionMinor);
            _fileEntries.Add(fileEntry);
        }
    }

    private void ReadStringTable(BinaryStream bs)
    {
        // String table section
        bs.Position = _sections[STRING_TABLE_SECTION_INDEX].Offset;
        byte[] stringTableSection = new byte[_sections[STRING_TABLE_SECTION_INDEX].Size];
        bs.ReadExactly(stringTableSection);

        if (!_forceNoEncryption && IsHeaderEncrypted)
        {
            _logger?.LogInformation("Decrpyting string table section.");

            uint crc = _cakeCryptor.CryptHeaderData(stringTableSection, MainCryptoKey);
            if (crc != _sections[STRING_TABLE_SECTION_INDEX].Checksum)
                throw new InvalidCastException("String table checksum did not match. Invalid or corrupted?");

            _logger?.LogInformation("String table section checksum OK.");
        }

        ReadStringEntries(stringTableSection);
    }

    private void ReadStringEntries(byte[] stringTableSection)
    {
        SpanReader sr = new SpanReader(stringTableSection);

        if (IsAtLeastVersion(9))
        {
            string mainDirMaybe = _cakeCryptor.ReadScrambledString(ref sr);
            _logger?.LogInformation("Original or Base Dir (?): {mainDir}", !string.IsNullOrEmpty(mainDirMaybe) ? mainDirMaybe : "<none>");
        }

        while (!sr.IsEndOfSpan)
        {
            uint strOffset = (uint)sr.Position;
            string str;
            if (IsAtLeastVersion(8))
            {
                // This has a length, but is still null terminated
                if (!_forceNoEncryption && IsHeaderEncrypted)
                    str = _cakeCryptor.ReadScrambledString(ref sr);
                else
                {
                    str = sr.ReadString1();
                    sr.ReadByte(); // zero termination
                }
            }
            else
                str = sr.ReadString0();

            _strings.Add(strOffset, str);
        }
    }



    public void Dispose()
    {
        ((IDisposable)_fileStream).Dispose();
        _cakeCryptor?.Dispose();
        GC.SuppressFinalize(this);
    }
}

public enum CakeRegistryType : byte
{
    Regular = 1,
    Unk2 = 2,
    Unk3 = 3,
    
    /// <summary>
    /// rs.cak
    /// </summary>
    /// RSPatch
    RegistryPatch = 4,

    /// <summary>
    /// For tiny packs, refering to files outside the cake
    /// </summary>
    External = 5,
}
