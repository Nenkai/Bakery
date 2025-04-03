using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace CakeTool.Compression;

public partial class Oodle
{
    /// <summary>
    /// Oodle Library Path
    /// </summary>
    private const string OodleLibraryPath = "oo2core_9_win64";

    [LibraryImport(OodleLibraryPath, EntryPoint = "OodleLZ_Compress"), UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private unsafe static partial long OodleLZ_Compress(OodleFormat format, byte* rawBuf, long rawSize, byte* compBuf, OodleCompressionLevel level, 
        nint options, nint dictionaryBase, nint lrm, nint scratchMem, long scratchSize);

    /// <summary>
    /// Oodle64 Decompression Method 
    /// </summary>
    [LibraryImport(OodleLibraryPath, EntryPoint = "OodleLZ_Decompress"), UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    public static partial long OodleLZ_Decompress(in byte compBuf, long bufferSize, in byte decodeTo, long outputBufferSize, int fuzz,
        int crc, int verbose, long dst_base, long e, long cb, long cb_ctx, long scratch, long scratch_size, int threadPhase);

    public static uint GetCompressedBounds(uint BufferSize)
        => BufferSize + 274 * ((BufferSize + 0x3FFFF) / 0x400000);

    /// <summary>
    /// Compresses a byte array of Oodle Compressed Data (Requires Oodle DLL)
    /// </summary>
    /// <param name="input">Input Compressed Data</param>
    /// <param name="decompressedLength">Decompressed Size</param>
    /// <returns>Resulting Array if success, otherwise null.</returns>
    public static long Compress(OodleFormat format, Span<byte> input, long inputLength, Span<byte>output, OodleCompressionLevel level)
    {
        // Decode the data (other parameters such as callbacks not required)
        unsafe
        {
            // Using in parameters seems to cause issues somehow when compiled as release.
            // Do this for now.
            fixed (byte* inputPtr = input)
            {
                fixed (byte* outputPtr = output)
                {
                    return OodleLZ_Compress(format, inputPtr, inputLength, outputPtr, level, 0, 0, 0, 0, 0);
                }
            }
        }
    }

    /// <summary>
    /// Decompresses a byte array of Oodle Compressed Data (Requires Oodle DLL)
    /// </summary>
    /// <param name="input">Input Compressed Data</param>
    /// <param name="decompressedLength">Decompressed Size</param>
    /// <returns>Resulting Array if success, otherwise null.</returns>
    public static long Decompress(in byte input, long inputLength, in byte output, long decompressedLength)
    {
        // Decode the data (other parameters such as callbacks not required)
        return OodleLZ_Decompress(input, inputLength, output, decompressedLength, 1, 0, 0, 0, 0, 0, 0, 0, 0, 3);
    }
}

public enum OodleFormat
{
    LZH,
    LZHLW,
    LZNIB,
    None,
    LZB16,
    LZBLW,
    LZA,
    LZNA,
    Kraken,
    Mermaid,
    BitKnit,
    Selkie,
    Akkorokamui
}

public enum OodleCompressionLevel : ulong
{
    None,
    Fastest,
    Faster,
    Fast,
    Normal,
    Level1,
    Level2,
    Level3,
    Level4,
    Level5
}
