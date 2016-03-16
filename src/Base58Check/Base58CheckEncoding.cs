using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace Base58Check
{
  /// <summary>
  /// Base58Check Encoding / Decoding (Bitcoin-style)
  /// </summary>
  /// <remarks>
  /// See here for more details: https://en.bitcoin.it/wiki/Base58Check_encoding
  /// </remarks>
  public static class Base58CheckEncoding
  {
    private const int CHECK_SUM_SIZE = 4;

    /// <summary>
    /// Encodes data with a 4-byte checksum
    /// </summary>
    /// <param name="data">Data to be encoded</param>
    /// <returns></returns>
    public static string Encode(byte[] data)
    {
      return EncodePlain(_AddCheckSum(data));
    }

    /// <summary>
    /// Encodes data in plain Base58, without any checksum.
    /// </summary>
    /// <param name="data">The data to be encoded</param>
    /// <returns></returns>
    public static string EncodePlain(byte[] data)
    {
      // Decode byte[] to BigInteger
      var intData = data.Aggregate<byte, BigInteger>(0, (current, t) => current*256 + t);

      // Encode BigInteger to Base58 string
      var result = string.Empty;
      while (intData > 0)
      {
        var remainder = (int)(intData % 58);
        intData /= 58;
        result = IntToBase58Char(remainder) + result;
      }

      // Append `1` for each leading 0 byte
      for (var i = 0; i < data.Length && data[i] == 0; i++)
      {
        result = '1' + result;
      }

      return result;
    }

    /// <summary>
    /// Decodes data in Base58Check format (with 4 byte checksum)
    /// </summary>
    /// <param name="data">Data to be decoded</param>
    /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
    public static byte[] Decode(string data)
    {
      var dataWithCheckSum = DecodePlain(data);
      var dataWithoutCheckSum = _VerifyAndRemoveCheckSum(dataWithCheckSum);

      if (dataWithoutCheckSum == null)
      {
        throw new FormatException("Base58 checksum is invalid");
      }

      return dataWithoutCheckSum;
    }

    /// <summary>
    /// Decodes data in plain Base58, without any checksum.
    /// </summary>
    /// <param name="data">Data to be decoded</param>
    /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
    public static byte[] DecodePlain(string data)
    {
      // Decode Base58 string to BigInteger 
      BigInteger intData = 0;
      for (var i = 0; i < data.Length; i++)
      {
        var digit = CharToRawBinaryInt(data[i]); //Slow

        if (digit < 0)
        {
          throw new FormatException(string.Format("Invalid Base58 character `{0}` at position {1}", data[i], i));
        }

        intData = intData * 58 + digit;
      }

      // Encode BigInteger to byte[]
      // Leading zero bytes get encoded as leading `1` characters
      var leadingZeroCount = data.TakeWhile(c => c == '1').Count();
      var leadingZeros = Enumerable.Repeat((byte)0, leadingZeroCount);
      var bytesWithoutLeadingZeros =
        intData.ToByteArray()
        .Reverse()// to big endian
        .SkipWhile(b => b == 0);//strip sign byte
      var result = leadingZeros.Concat(bytesWithoutLeadingZeros).ToArray();

      return result;
    }

    private static byte[] _AddCheckSum(byte[] data)
    {
      var checkSum = _GetCheckSum(data);
      var dataWithCheckSum = ArrayHelpers.ConcatArrays(data, checkSum);

      return dataWithCheckSum;
    }

    //Returns null if the checksum is invalid
    private static byte[] _VerifyAndRemoveCheckSum(byte[] data)
    {
      var result = ArrayHelpers.SubArray(data, 0, data.Length - CHECK_SUM_SIZE);
      var givenCheckSum = ArrayHelpers.SubArray(data, data.Length - CHECK_SUM_SIZE);
      var correctCheckSum = _GetCheckSum(result);

      return givenCheckSum.SequenceEqual(correctCheckSum) ? result : null;
    }

    private static byte[] _GetCheckSum(byte[] data)
    {
      SHA256 sha256 = new SHA256Managed();
      var hash1 = sha256.ComputeHash(data);
      var hash2 = sha256.ComputeHash(hash1);

      var result = new byte[CHECK_SUM_SIZE];
      Buffer.BlockCopy(hash2, 0, result, 0, result.Length);

      return result;
    }
    
    // Should be constant time
    private static char IntToBase58Char(int value)
    {
      value += 0x31;
      
      // Start with 1 through 9...
      
      // if (value > 0x39) value += 0x41 - 0x31; // 16
      value += ((0x39 - value) >> 8) & 16;
      
      // Skip I (0x48)
      
      // if (value > 0x48) value += 0x49 - 0x48; // 1
      value += ((0x48 - value) >> 8) & 1;
      
      // Skip O (0x4f)
      
      // if (value > 0x4f) value += 0x50 - 0x4f; // 1
      value += ((0x4f - value) >> 8) & 1;
      
      // if (value > 0x5a) value += 0x61 - 0x5b; // 6
      value += ((0x5a - value) >> 8) & 6;
      
      // Skip l (0x6c)
      
      // if (value > 0x4f) value += 0x6d - 0x6c; // 1
      value += ((0x6c - value) >> 8) & 1;
      
      return (char)value;
    }
    
    // Should be constant time
    private static int CharToRawBinaryInt(char value)
    {
      int src = (int)value;
      int ret = -1;
      
      // Start with 1 through 9...
      // if (src > 0x30 && src < 0x3a) ret += src - 0x31 + 1; // -47
      ret += (((0x30 - src) & (src - 0x3a)) >> 8) & (src - 47);
      
      // A-H
      // if (src > 0x40 && src < 0x49) ret += $src - 0x41 + 9 + 1; // -55
      ret += (((0x40 - src) & (src - 0x49)) >> 8) & (src - 55);
      
      // J-N
      // if (src > 0x49 && src < 0x4f) ret += $src - 0x49 + 18 + 1; // -54
      ret += (((0x49 - src) & (src - 0x4f)) >> 8) & (src - 54);
      
      // P-Z
      // if (src > 0x4f && src < 0x5b) ret += $src - 0x50 + 22 + 1; // -57
      ret += (((0x4f - src) & (src - 0x5b)) >> 8) & (src - 57);
      
      // a-k
      // if ($src > 0x60 && $src < 0x6c) ret += $src - 0x61 + 33 + 1; // -63
      ret += (((0x60 - src) & (src - 0x6c)) >> 8) & (src - 63);
      
      // l-z
      // if ($src > 0x6d && $src < 0x7b) ret += $src - 0x6e + 44 + 1; // -65
      int += (((0x6d - src) & (src - 0x7b)) >> 8) & (src - 65);
      
      return (char)ret;
    }
  }
}
