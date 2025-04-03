using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Numerics;
using System.Buffers.Binary;

using Syroot.BinaryData.Memory;

using CakeTool.Hashing;
using CakeTool.PRNG;

namespace CakeTool.Crypto;

public class CakeCryptor : AbstractVersionableCakeEntity, IDisposable
{
    /***************************************
    * 
    * Welcome to the crypto zone!
    * 
    ***************************************/

    private ChaCha20? _chaCha20Ctx;

    public const string ConstantKeyV9_3 = "W?#i]}UvfXzW[iQx;QbLzJH3j}ct/KZ[";
    public const string ConstantIVV9_3 = "+e{*;_hX";

    public const string ConstantKeyV9_1 = "V9w0ooTmKK'{z!mg6b$E%1,s2)nj2o_";
    public const string ConstantIVV9_1 = "XC;JQm8";

    public const string ConstantKeyV8 = "r-v4WVyWOprRr7Qw9kN0myq5KCXGaaf";
    public const string ConstantIVV8 = "xTKmfw_";

    public CakeCryptor(byte versionMajor, byte versionMinor)
    {
        VersionMajor = versionMajor;
        VersionMinor = versionMinor;
    }

    /// <summary>
    /// Generates the header encryption key for the specified cake file name.
    /// </summary>
    /// <param name="fileName"></param>
    /// <returns></returns>
    /// <exception cref="NotSupportedException"></exception>
    public uint GenerateCryptoXorKey(string fileName)
    {
        if (IsVersion(6, 7))
            return GenerateCryptoKeyV6_7(fileName);
        if (IsVersion(6, 8) || IsVersion(8, 1))
            return GenerateCryptoKeyV6_8(fileName);
        else if (IsVersion(8, 2))
            return GenerateCryptoKeyV8_2(fileName);
        else if (IsVersion(8, 3))
            return GenerateCryptoKeyV8_3(fileName);
        else if (IsVersion(8, 7))
            return GenerateCryptoKeyV8_7(fileName);
        else if (IsVersion(9, 1))
            return GenerateCryptoKeyV9_1(fileName);
        else if (IsVersion(9, 2))
            return GenerateCryptoKeyV9_2(fileName);
        else if (IsVersion(9, 3))
            return GenerateCryptoKeyV9_3(fileName);
        throw new NotSupportedException($"Cake v{VersionMajor}.{VersionMinor} are not yet supported.");
    }

    public uint CryptHeaderData(Span<byte> data, uint key)
    {
        if (VersionMajor == 6) // 6.x
        {
            return XORCRCData(data, key);
        }
        else if (IsVersion(8, 2)) // 8.2
        {
            byte[] bytes = BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(key));
            for (int i = 0; i < data.Length; i++)
                data[i] ^= (byte)((byte)i + bytes[i % 4]);
            return CRC32C.Hash(data);
        }
        else if (IsVersion(8, 3)) // 8.3
        {
            RotateCrypt(data, key);
            return CRC32C.Hash(data);
        }
        else if (IsAtLeastVersion(8, 7)) // >= 8.7
        {
            return XORCRCData(data, key);
        }
        else
            throw new NotImplementedException();
    }

    public string ReadScrambledString(ref SpanReader sr)
    {
        uint key;
        if (IsVersion(8, 2))
            key = (uint)BinaryPrimitives.ReverseEndianness(sr.Position);
        else
            key = (uint)sr.Position;

        byte strLen = sr.ReadByte();
        byte[] bytes = sr.ReadBytes(strLen + 1);

        if (IsVersion(8, 3))
        {
            RotateCrypt(bytes.AsSpan(0, bytes.Length - 1), key);
        }
        else // v6, >=8.7
        {
            ScrambleBytes(bytes.AsSpan(0, bytes.Length - 1), key);
        }

        return Encoding.ASCII.GetString(bytes.AsSpan(0, bytes.Length - 1));
    }

    // SysCore::BakedDataFile::GetFileManglingKey
    /// <summary>
    /// Generates the data encryption key for the specified file entry.
    /// </summary>
    /// <param name="entry"></param>
    /// <param name="mainCryptoKey"></param>
    /// <returns></returns>
    /// <exception cref="NotSupportedException"></exception>
    public uint GetFileManglingKey(CakeFileEntry entry, uint mainCryptoKey)
    {
        if (IsVersion(6, 7))
        {
            return ~(entry.CompressedSize ^ mainCryptoKey);
        }
        else if (IsVersion(6, 8))
        {
            return entry.CompressedSize ^ mainCryptoKey;
        }
        else if (IsVersion(8, 2))
        {
            return BinaryPrimitives.ReverseEndianness(entry.CRCChecksum);
        }
        else if (IsVersion(8, 3))
        {
            Span<byte> toHash = stackalloc byte[3 * sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x00..], mainCryptoKey);
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x08..], entry.CompressedSize);
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x10..], entry.DataOffset);

            ulong val = 0xCBF29CE484222325;
            for (int i = 0; i < 0x18; i++)
                val = 0x100000001B3L * (ulong)((sbyte)toHash[i] ^ (long)val);

            return (uint)((val & 0xFFFFFFFF) ^ (val >> 32));
        }
        else if (IsVersion(8, 7) || IsVersion(9, 1))
        {
            Span<byte> toHash = stackalloc byte[4 + 4 + 8 + 4 + 4];
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x00..], mainCryptoKey);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x04..], ~mainCryptoKey);
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x08..], entry.DataOffset);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x10..], entry.CompressedSize);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x14..], ~entry.CompressedSize);

            ulong val = 0xCBF29CE484222325;
            for (int i = 0; i < 0x18; i++)
                val = 0x100000001B3L * (ulong)((sbyte)toHash[i] ^ (long)val);

            return (uint)((val & 0xFFFFFFFF) ^ (val >> 32));
        }
        else if (IsVersion(9, 2))
        {
            // Order was changed a bit.
            Span<byte> toHash = stackalloc byte[4 + 4 + 4 + 4 + 8];
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x00..], ~entry.CompressedSize);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x04..], entry.CompressedSize);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x08..], ~mainCryptoKey);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x0C..], mainCryptoKey);
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x10..], ~entry.DataOffset);

            ulong val = 0xCBF29CE484222325;
            for (int i = 0; i < 0x18; i++)
                val = 0x100000001B3L * (ulong)((sbyte)toHash[i] ^ (long)val);

            return (uint)((val & 0xFFFFFFFF) ^ ~(val >> 32)); // We also flip bits of the higher 32.
        }
        else if (IsVersion(9, 3))
        {
            Span<byte> toHash = stackalloc byte[4 + 4 + 8 + 4 + 4 + 4 + 4];
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x00..], mainCryptoKey);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x04..], ~entry.CompressedSize);
            BinaryPrimitives.WriteUInt64LittleEndian(toHash[0x08..], ~(entry.DataOffset ^ mainCryptoKey));
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x10..], entry.CompressedSize);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x14..], ~mainCryptoKey);

            ulong combined = ~(entry.DataOffset ^ mainCryptoKey);
            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x18..], BitOperations.Crc32C((uint)(combined >> 32), (uint)(combined & 0xFFFFFFFF)));

            BinaryPrimitives.WriteUInt32LittleEndian(toHash[0x1C..], BitOperations.Crc32C(~mainCryptoKey, entry.CompressedSize));

            ulong fnv1a = 0xCBF29CE484222325;
            for (int i = 0; i < toHash.Length; i++)
                fnv1a = 0x100000001B3L * (ulong)((sbyte)toHash[i] ^ (long)fnv1a);

            uint final = ScrambleGenSeed(BitConverter.GetBytes(fnv1a));
            return ~final;
        }

        throw new NotSupportedException();
    }

    /// <summary>
    /// Decrypts file data and CRC checks it (when CRC is available).
    /// </summary>
    /// <param name="data"></param>
    /// <param name="fileEntry"></param>
    /// <param name="key"></param>
    /// <exception cref="Exception"></exception>
    public void CryptFileDataAndCheck(Span<byte> data, CakeFileEntry fileEntry, uint key)
    {
        if (VersionMajor == 6)
        {
            uint crc = XORCRCData(data, key);
            if (crc != fileEntry.CRCChecksum)
                throw new Exception("V6 File decryption checksum failed.");
        }
        else if (IsVersion(8, 2))
        {
            ScrambleBytes(data, key);
            if (CRC32C.Hash(data) != fileEntry.CRCChecksum)
                throw new Exception("V8.2 File decryption checksum failed.");

        }
        else if (IsVersion(8, 3))
        {
            for (int i = 0; i < data.Length; i++)
            {
                byte val = byte.RotateRight(data[i], (i - 1) % 8 ^ 0xD);
                val = byte.RotateLeft((byte)(val ^ (i - 1 + Utils.ExtractU8_U32(key, (i + 1) % 4))), (i + 1) % 8);
                data[i] = val;
            }

            if (CRC32C.Hash(data) != fileEntry.CRCChecksum)
                throw new Exception("V8.3 File decryption checksum failed.");
        }
        else if (IsAtLeastVersion(8, 7))
        {
            // only the first 0x100 bytes are ever encrypted.
            for (int i = 0; i < Math.Min(fileEntry.CompressedSize, 0x100); i++)
            {
                byte val = byte.RotateRight(data[i], (i - 1) % 8 ^ 0xD);
                val = byte.RotateLeft((byte)(val ^ (i - 1 + Utils.ExtractU8_U32(key, (i + 1) % 4))), (i + 1) % 8);
                data[i] = val;
            }
        }
    }

    private static void RotateCrypt(Span<byte> bytes, uint key)
    {
        byte[] keyBytes = BitConverter.GetBytes(key);
        for (int i = 0; i < bytes.Length; i++)
        {
            byte rotated = byte.RotateRight(bytes[i], (i - 1) ^ 5);
            bytes[i] = byte.RotateLeft((byte)(rotated ^ (i + keyBytes[((byte)i + 1) % 4] - 1)), i + 1);
        }
    }

    private static void ScrambleBytes(Span<byte> data, uint key)
    {
        for (int i = 0; i < data.Length; i++)
        {
            int byteOffset = (int)Utils.ExtractU8_U32(key, i);
            data[i] ^= (byte)(i + byteOffset);
        }
    }

    /// <summary>
    /// En/Decrypts data and CRC32C it in one go.
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    private static uint XORCRCData(Span<byte> data, uint key)
    {
        uint lastkey = key;
        uint crc = ~0u;
        while (data.Length >= 8)
        {
            Span<uint> asUints = MemoryMarshal.Cast<byte, uint>(data);
            uint v1 = asUints[0];
            uint v2 = asUints[1];
            asUints[0] ^= lastkey;
            asUints[1] ^= v1;
            lastkey = v2;

            crc = BitOperations.Crc32C(crc, BinaryPrimitives.ReadUInt64LittleEndian(data));
            data = data[8..];
        }

        // NOTE: remaining bytes xor the key. therefore remaining 7 bytes should always be processed separately
        while (data.Length > 0)
        {
            data[0] ^= (byte)lastkey;
            lastkey ^= data[0];

            crc = BitOperations.Crc32C(crc, data[0]);
            data = data[1..];
        }

        return ~crc;
    }

    private static uint ScrambleGenSeed(Span<byte> bytes)
    {
        uint val = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            val = (val << 4) + bytes[i];
            val = (val ^ ((val & 0xF0000000) >> 24)) & 0x0FFFFFFF;
        }
        return val;
    }

    private uint GenerateCryptoKeyV6_7(string fileName)
    {
        ulong hash = FNV1A64.FNV64StringI(fileName);
        return (uint)((hash & 0xFFFFFFFF) ^ (hash >> 32));
    }

    // SysCore::BuildKey63FromName
    // SysCore::GenerateEncryptionKey
    private uint GenerateCryptoKeyV6_8(string fileName)
    {
        Memory<byte> keyOne = CreateInitialKeyTableFromNameSeed(fileName, 0x40);
        Span<byte> outHash = stackalloc byte[0x10];
        MetroHash.Metrohash128crc_1(keyOne.Span.Slice(0, 0x3F), 0x3F, 0, outHash);

        Span<uint> hashInts = MemoryMarshal.Cast<byte, uint>(outHash);
        uint key = hashInts[0] ^ hashInts[1] ^ hashInts[2] ^ hashInts[3];
        return key;
    }

    private uint GenerateCryptoKeyV8_2(string fileName)
    {
        string nameSeed = $"{fileName.ToLower()}{VersionMajor:D2}{VersionMinor:D2}";
        Memory<byte> table = CreateInitialKeyTableFromNameSeed(nameSeed, 0x40);
        Chacha20Crypt(table.Span);

        Span<byte> metroHash = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(table.Span.Slice(0, 0x3F), 0x3F, 0, metroHash);

        Span<uint> hashInts = MemoryMarshal.Cast<byte, uint>(metroHash);
        uint key = hashInts[0] ^ hashInts[1] ^ hashInts[2] ^ hashInts[3];
        return key;
    }

    private uint GenerateCryptoKeyV8_3(string fileName)
    {
        string nameSeed = $"{fileName.ToLower()}{VersionMajor:D2}{VersionMinor:D2}";
        Memory<byte> table = CreateInitialKeyTableFromNameSeed(nameSeed, 0x40);
        Chacha20Crypt(table.Span.Slice(0, 0x3F));

        // Alter table by putting a metrohash in it
        Span<byte> metroHash = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(table.Span.Slice(0, 0x3F), 0x3F, 0, metroHash);

        Span<uint> tableInts = MemoryMarshal.Cast<byte, uint>(table.Span);
        Span<uint> hashInts = MemoryMarshal.Cast<byte, uint>(metroHash);
        uint seed = hashInts[0] ^ hashInts[1] ^ hashInts[2] ^ hashInts[3];
        for (int i = 0; i < 14; i++)
        {
            tableInts[i] ^= seed;
            seed = tableInts[i];
        }

        seed = table.Span[52];
        for (int i = 56; i < 63; i++)
        {
            table.Span[i] ^= (byte)seed;
            seed = table.Span[i];
        }

        Span<byte> metroHash2 = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(table.Span.Slice(0, 0x3F), 0x3F, 0, metroHash2);

        Span<uint> hashInts2 = MemoryMarshal.Cast<byte, uint>(metroHash2);
        uint key = hashInts2[0] ^ hashInts2[1] ^ hashInts2[2] ^ hashInts2[3];

        return key;
    }

    private uint GenerateCryptoKeyV8_7(string fileName)
    {
        string nameSeed = $"{fileName.ToLower()}{VersionMajor:D2}{VersionMinor:D2}";
        Memory<byte> table = CreateInitialKeyTableFromNameSeed(nameSeed, 0x80);
        Chacha20Crypt(table.Span);

        Span<byte> metroHash = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(table.Span, 0x80, BinaryPrimitives.ReadUInt32LittleEndian(table.Span), metroHash);

        uint crcSeed = ~0u;

        byte[] keyOneCopy = table.ToArray();
        Span<uint> keyOneUints = MemoryMarshal.Cast<byte, uint>(keyOneCopy);
        Span<ulong> keyOneUlongs = MemoryMarshal.Cast<byte, ulong>(keyOneCopy);
        for (int i = 0; i < keyOneUlongs.Length; i++)
            crcSeed = BitOperations.Crc32C(crcSeed, keyOneUlongs[i]);
        crcSeed = ~crcSeed;

        Span<uint> metroHashInts = MemoryMarshal.Cast<byte, uint>(metroHash);
        uint seed = metroHashInts[0] ^ metroHashInts[1] ^ metroHashInts[2] ^ metroHashInts[3];
        for (int i = 0; i < 32; i++)
        {
            keyOneUints[i] ^= seed;
            seed = keyOneUints[i];
        }

        _chaCha20Ctx.ResetCounter();
        _chaCha20Ctx.DecryptBytes(keyOneCopy, 0x40); // lower 0x40 bytes only

        Span<byte> metroHash2 = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(keyOneCopy, 0x80, crcSeed, metroHash2);
        Span<uint> metroHash2Ints = MemoryMarshal.Cast<byte, uint>(metroHash2);

        uint key = metroHash2Ints[0] ^ metroHash2Ints[1] ^ metroHash2Ints[2] ^ metroHash2Ints[3];
        return key;
    }

    private uint GenerateCryptoKeyV9_1(string fileName)
    {
        // Same as 8.7, but we use D3 this time
        string nameSeed = $"{fileName.ToLower()}{VersionMajor:D3}{VersionMinor:D3}";
        Memory<byte> table = CreateInitialKeyTableFromNameSeed(nameSeed, 0x80);
        Chacha20Crypt(table.Span);

        Span<byte> metroHash = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(table.Span, 0x80, BinaryPrimitives.ReadUInt32LittleEndian(table.Span), metroHash);

        byte[] keyOneCopy = table.ToArray();
        Span<uint> keyOneUints = MemoryMarshal.Cast<byte, uint>(keyOneCopy);
        Span<ulong> keyOneUlongs = MemoryMarshal.Cast<byte, ulong>(keyOneCopy);

        uint crcSeed = ~0u;
        for (int i = 0; i < keyOneUlongs.Length; i++)
            crcSeed = BitOperations.Crc32C(crcSeed, keyOneUlongs[i]);
        crcSeed = ~crcSeed;

        Span<uint> metroHashInts = MemoryMarshal.Cast<byte, uint>(metroHash);
        uint seed = metroHashInts[0] ^ metroHashInts[1] ^ metroHashInts[2] ^ metroHashInts[3];
        for (int i = 0; i < 32; i++)
        {
            keyOneUints[i] ^= seed;
            seed = keyOneUints[i];
        }

        Chacha20Crypt(keyOneCopy.AsSpan(0, 0x40)); // lower 0x40 bytes only

        Span<byte> metroHash2 = stackalloc byte[0x10];
        MetroHash.MetroHashUnkCustomV9_1(keyOneCopy, 0x80, crcSeed, metroHash2);
        Span<uint> metroHash2Ints = MemoryMarshal.Cast<byte, uint>(metroHash2);

        uint key = metroHash2Ints[0] ^ metroHash2Ints[1] ^ metroHash2Ints[2] ^ metroHash2Ints[3];
        return key;
    }

    private uint GenerateCryptoKeyV9_2(string fileName)
    {
        // Step 1: Generate seed
        string nameSeed = $"{fileName}-{VersionMajor}-{VersionMinor}".ToUpper();

        // Step 2: Generate hash table from name seed
        Memory<byte> keyOne = CreateInitialKeyTableFromNameSeed(nameSeed, 0x80);

        // Step 3: Generate a mt seed (lower 32) before hashing hash table
        uint mtSeed1 = ScrambleGenSeed(keyOne.Span);

        // Step 4: Crypt hash table
        Chacha20Crypt(keyOne.Span);

        // Step 5: Generate a mt seed (upper 32) before hashing hash table
        uint mtSeed2 = ScrambleGenSeed(keyOne.Span);

        // Step 6: SFMT/CRC table
        Span<ulong> keyUlongs = MemoryMarshal.Cast<byte, ulong>(keyOne.Span);

        // NOTE: Higher 32bit is effectively useless. But that's what the game does so
        var sfmtRand = new SFMT(mtSeed2);
        ulong baseVal = ((ulong)mtSeed2 << 32) | mtSeed1;
        for (int i = 0; i < 8; i++)
            baseVal = BitOperations.Crc32C((uint)baseVal, keyUlongs[(int)(sfmtRand.Nextuint() % 16)]);

        // Step 7: SFMT XOR & Metro hash part 1
        ulong metroHashSeed = baseVal ^ sfmtRand.Nextuint();
        ulong[] outMetroHash = new ulong[2];
        MetroHash.Metrohash128crc_2(keyOne.Span, (ulong)keyOne.Length, metroHashSeed, MemoryMarshal.Cast<ulong, byte>(outMetroHash));

        // Step 8: SFMT XOR & Metro hash part 2
        ulong metroHashSeed2 = BitOperations.Crc32C(BitOperations.Crc32C((uint)baseVal, outMetroHash[0]), ~outMetroHash[1]) ^ sfmtRand.Nextuint();
        ulong[] outMetroHash2 = new ulong[2];
        MetroHash.Metrohash128crc_2(keyOne.Span, (ulong)keyOne.Length, metroHashSeed2, MemoryMarshal.Cast<ulong, byte>(outMetroHash2));

        // Step 9: Gen seed from final metrohash data
        uint finalSeed = ScrambleGenSeed(MemoryMarshal.Cast<ulong, byte>(outMetroHash2));

        // Step 10: Gen crc (again), many details here are unused
        uint crc = 0;
        byte mask = 0xFF;
        for (int i = 0; i < 0x80; i++)
        {
            var data = keyOne.Span[i];
            crc = BitOperations.Crc32C(crc, data);

            // Not really used
            int byteIndex = (i + 1) % 4;
            byte piece = (byte)(mask + (byte)Utils.ExtractU8_U32(finalSeed, byteIndex));
            byte rotated = byte.RotateRight(data, i + 1);
            keyOne.Span[i] = byte.RotateLeft((byte)(piece ^ rotated), mask ^ 5);

            mask++;
        }

        // Step 11: XOR CRC and SFMT to create final key.
        uint key = crc ^ sfmtRand.Nextuint();
        return key;
    }

    private uint GenerateCryptoKeyV9_3(string fileName)
    {
        // Step 1: Generate seed
        string nameSeed = $"{fileName}-{VersionMajor}-{VersionMinor}".ToUpper();

        // Step 2: Generate hash table from name seed (OK)
        Memory<byte> tableBytes = CreateInitialKeyTableFromNameSeed(nameSeed, 0x80);
        Span<ulong> tableULongs = MemoryMarshal.Cast<byte, ulong>(tableBytes.Span);

        // Step 3: Generate a mt seed (lower 32 then higher) before hashing hash table
        uint mtSeed1 = ScrambleGenSeed(tableBytes.Span);
        uint crc = 0xFFFFFFFF;
        for (int i = 0; i < 0x80; i++)
            crc = BitOperations.Crc32C(crc, tableBytes.Span[i]);

        uint loSeed = ~(mtSeed1 ^ crc);
        var sfmtRand = new SFMT(loSeed);
        uint count = sfmtRand.Nextuint() % 8;
        for (int i = 0; i < count; i++)
            loSeed = BitOperations.Crc32C(loSeed, tableULongs[(int)(sfmtRand.Nextuint() % 16)]);
        uint hiSeed = BitOperations.Crc32C(sfmtRand.Nextuint(), sfmtRand.Nextuint());

        // Step 5: Chacha
        Chacha20Crypt(tableBytes.Span);

        // Step 6: MurmurHash3 X64
        ulong u64Seed = (ulong)hiSeed << 32 | loSeed;
        Span<byte> hash = stackalloc byte[16];

        // Step 7: New unknown hashing
        UnkHash.Hash(tableBytes.Span, hash, u64Seed);
        Span<ulong> hashLongs = MemoryMarshal.Cast<byte, ulong>(hash);

        // Step 8: more crcing.. Game passes combined in full into the crc32 instruction, only the lower 32 will be used.
        uint seed = BitOperations.Crc32C(BitOperations.Crc32C((uint)u64Seed, ~hashLongs[0]), hashLongs[1]);

        // Step 9: Mt skip (Equivalent to calling Nextuint twice)
        sfmtRand.Next();

        // Step 10: Chacha again (that will essentially decrypt)
        Chacha20Crypt(tableBytes.Span);

        // Step 11: Unk hash again
        UnkHash.Hash(tableBytes.Span, hash, seed);

        // Step 12: MT
        seed = sfmtRand.Nextuint() ^ sfmtRand.Nextuint();

        // Step 13: Scramble
        uint seed2 = ScrambleGenSeed(MemoryMarshal.Cast<ulong, byte>(hashLongs));

        // Step 14: xor both seeds & not them into final key
        uint key = ~(seed ^ seed2);
        return key;
    }

    private Memory<byte> CreateInitialKeyTableFromNameSeed(string nameSeed, int length)
    {
        byte[] k = new byte[length];
        if (VersionMajor == 6)
        {
            // Repeat string till we have 64 bytes
            // "hello" = "hellohellohello..."
            int j = 0;
            for (int i = 0; i < 0x3F + 1; i++)
            {
                if (j == nameSeed.Length)
                    j = 0;

                k[i] = (byte)nameSeed[j++];
            }
            k[0x3F] = 0; // Null termination, not needed, but that's what happens
        }
        else if (IsVersion(8, 2) || IsVersion(8, 3))
        {
            // same, but this time go in reverse everytime we reach the start or end of the string
            // hello = "helloollehhello..."

            int seedIndex = 0;
            int incDirection = 1;
            for (int i = 0; i < length; i++)
            {
                k[i] = (byte)nameSeed[seedIndex];

                seedIndex += incDirection;
                if (seedIndex == nameSeed.Length - 1 || seedIndex == 0)
                    incDirection = -incDirection; // Increment the other way around
            }
            k[length - 1] = 0;

        }
        else if (IsVersion(8, 7))
        {
            int i = 0;
            while (i < length)
            {
                for (int j = 0; j < nameSeed.Length && i < length; j++)
                    k[i++] = (byte)(nameSeed[j] ^ 0x32);

                for (int j = nameSeed.Length - 2; j > 0 && i < length; j--)
                    k[i++] = (byte)(nameSeed[j] ^ 0x32);
            }
        }
        else if (IsVersion(9, 1))
        {
            // same, but flip bits
            int seedIndex = 0;
            int incDirection = 1;
            for (int i = 0; i < length; i++)
            {
                k[i] = (byte)(~nameSeed[seedIndex] ^ (i + 0x1C));

                seedIndex += incDirection;
                if (seedIndex == nameSeed.Length - 1 || seedIndex == 0)
                    incDirection = -incDirection; // Increment the other way around
            }
        }
        else if (IsVersion(9, 2))
        {
            int i = 0;
            while (i < length)
            {
                for (int j = 0; j < nameSeed.Length && i < length; j++)
                    k[i] = (byte)(nameSeed[j] ^ (nameSeed[j] + (i++ ^ 0x1C)));

                for (int j = nameSeed.Length - 2; j > 0 && i < length; j--)
                    k[i] = (byte)(nameSeed[j] ^ (nameSeed[j] + (i++ ^ 0x1C)));
            }
        }
        else if (IsVersion(9, 3))
        {
            int seedIndex = 0;
            int incDirection = 1;
            for (byte i = 0; i < length; i++)
            {
                k[i] = (byte)(nameSeed[seedIndex] ^ ((byte)((byte)~nameSeed[seedIndex] + (byte)(i ^ 0xBC))));

                seedIndex += incDirection;
                if (seedIndex == nameSeed.Length - 1 || seedIndex == 0)
                    incDirection = -incDirection; // Increment the other way around
            }
        }

        return k.AsMemory(0, length);
    }

    private void Chacha20Crypt(Span<byte> keyOne)
    {
        if (_chaCha20Ctx is null)
        {
            byte[] key = new byte[32];
            byte[] iv = new byte[12];

            if (IsVersion(9, 3))
            {
                Encoding.ASCII.GetBytes(ConstantKeyV9_3, key);
                Encoding.ASCII.GetBytes(ConstantIVV9_3, iv.AsSpan(4));
                ChaCha20.sigma = Encoding.ASCII.GetBytes("Tf!UM*18EWf]$X_&");
            }
            else if (IsVersion(9,1) || IsVersion(9, 2))
            {
                Encoding.ASCII.GetBytes(ConstantKeyV9_1, key);
                Encoding.ASCII.GetBytes(ConstantIVV9_1, iv.AsSpan(4));
                ChaCha20.sigma = Encoding.ASCII.GetBytes("Ym<q}it&('oU^}t_"); // yeah that was also changed for some reason
            }
            else
            {
                Encoding.ASCII.GetBytes(ConstantKeyV8, key);
                Encoding.ASCII.GetBytes(ConstantIVV8, iv.AsSpan(4));
            }

            _chaCha20Ctx = new ChaCha20(key, iv, 0);
        }
        else
        {
            _chaCha20Ctx.ResetCounter();
        }

        _chaCha20Ctx.DecryptBytes(keyOne, keyOne.Length);

    }

    public void Dispose()
    {
        _chaCha20Ctx?.Dispose();
        GC.SuppressFinalize(this);
    }
}
