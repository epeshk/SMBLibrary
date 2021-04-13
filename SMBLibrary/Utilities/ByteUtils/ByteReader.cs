using System;
using System.Buffers;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using MemoryPools.Memory;
using SMBLibrary;

namespace Utilities
{
    public class ByteReader
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte ReadByte(IMemoryOwner<byte> buffer, int offset) =>
            ReadByte(buffer.Memory.Span, offset);
        
        public static byte ReadByte(Span<byte> buffer, int offset)
        {
            return buffer[offset];
        }

        public static byte ReadByte(IMemoryOwner<byte> buffer, ref int offset) =>
            ReadByte(buffer.Memory.Span, ref offset);
        
        public static byte ReadByte(Span<byte> buffer, ref int offset)
        {
            offset++;
            return buffer[offset - 1];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ReadBytes(Span<byte> target, Span<byte> buffer, ref int offset, int length)
        {
            buffer.Slice(offset, length).CopyTo(target);
            offset += length;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ReadBytes(Span<byte> target, Span<byte> buffer, int offset, int length)
        {
            buffer.Slice(offset, length).CopyTo(target);
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] ReadBytes_RentArray(Span<byte> buffer, int offset, int length)
        {
            var result = ExactArrayPool.Rent(length);
            buffer.Slice(offset, length).CopyTo(result);
            return result;
        }
       
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] ReadBytes_RentArray(Span<byte> buffer, ref int offset, int length)
        {
            offset += length;
            return ReadBytes_RentArray(buffer, offset - length, length);
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static IMemoryOwner<byte> ReadBytes_Rent(Span<byte> buffer, int offset, int length)
        {
            var result = Arrays.Rent(length);
            buffer.Slice(offset, length).CopyTo(result.Memory.Span);
            return result;
        }
       
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static IMemoryOwner<byte> ReadBytes_Rent(Span<byte> buffer, ref int offset, int length)
        {
            offset += length;
            return ReadBytes_Rent(buffer, offset - length, length);
        }

        /// <summary>
        /// Will return the ANSI string stored in the buffer
        /// </summary>
        public static void ReadAnsiString(Span<char> target, Span<byte> buffer, int offset, int count)
        {
            // ASCIIEncoding.ASCII.GetString will convert some values to '?' (byte value of 63)
            // Any codepage will do, but the only one that Mono supports is 28591.
            Encoding.GetEncoding(28591).GetChars(buffer.Slice(offset, count), target);
        }

        /// <summary>
        /// Will return the ANSI string stored in the buffer
        /// </summary>
        public static string ReadAnsiString(Span<byte> buffer, int offset, int count)
        {
            // ASCIIEncoding.ASCII.GetString will convert some values to '?' (byte value of 63)
            // Any codepage will do, but the only one that Mono supports is 28591.
            return Encoding.GetEncoding(28591).GetString(buffer.Slice(offset, count));
        }

        public static void ReadAnsiString(Span<char> target, Span<byte> buffer, ref int offset, int count)
        {
            offset += count;
            ReadAnsiString(target, buffer, offset - count, count);
        }
        
        public static string ReadAnsiString(Span<byte> buffer, ref int offset, int count)
        {
            offset += count;
            return ReadAnsiString(buffer, offset - count, count);
        }

        [Obsolete]
        public static string ReadUTF16String(Span<byte> buffer, int offset, int numberOfCharacters)
        {
            var numberOfBytes = numberOfCharacters * 2;
            return Encoding.Unicode.GetString(buffer.Slice(offset, numberOfBytes));
        }

        [Obsolete]
        public static string ReadUTF16String(Span<byte> buffer, ref int offset, int numberOfCharacters)
        {
            var numberOfBytes = numberOfCharacters * 2;
            offset += numberOfBytes;
            return Encoding.Unicode.GetString(buffer.Slice(offset - numberOfBytes, numberOfBytes));
        }

        public static void ReadUTF16String(Span<char> target, Span<byte> buffer, int offset, int numberOfCharacters)
        {
            var numberOfBytes = numberOfCharacters * 2;
            Encoding.Unicode.GetChars(buffer.Slice(offset, numberOfBytes), target);
        }

        public static void ReadUTF16String(Span<char> target, Span<byte> buffer, ref int offset, int numberOfCharacters)
        {
            var numberOfBytes = numberOfCharacters * 2;
            offset += numberOfBytes;
            ReadUTF16String(target, buffer, offset - numberOfBytes, numberOfCharacters);
        }
        
        [Obsolete]

        public static string ReadNullTerminatedAnsiString(Span<byte> buffer, int offset)
        {
            var builder = new StringBuilder();
            var c = (char)ReadByte(buffer, offset);
            while (c != '\0')
            {
                builder.Append(c);
                offset++;
                c = (char)ReadByte(buffer, offset);
            }
            return builder.ToString();
        }

        public static string ReadNullTerminatedUTF16String(Span<byte> buffer, int offset)
        {
            var builder = new StringBuilder();
            var c = (char)LittleEndianConverter.ToUInt16(buffer, offset);
            while (c != 0)
            {
                builder.Append(c);
                offset += 2;
                c = (char)LittleEndianConverter.ToUInt16(buffer, offset);
            }
            return builder.ToString();
        }

        public static string ReadNullTerminatedAnsiString(Span<byte> buffer, ref int offset)
        {
            var result = ReadNullTerminatedAnsiString(buffer, offset);
            offset += result.Length + 1;
            return result;
        }

        public static string ReadNullTerminatedUTF16String(Span<byte> buffer, ref int offset)
        {
            var result = ReadNullTerminatedUTF16String(buffer, offset);
            offset += result.Length * 2 + 2;
            return result;
        }

        public static byte[] ReadBytes(Stream stream, int count)
        {
            var temp = new MemoryStream();
            ByteUtils.CopyStream(stream, temp, count);
            return temp.ToArray();
        }

        /// <summary>
        /// Return all bytes from current stream position to the end of the stream
        /// </summary>
        public static byte[] ReadAllBytes(Stream stream)
        {
            var temp = new MemoryStream();
            ByteUtils.CopyStream(stream, temp);
            return temp.ToArray();
        }
    }
}
