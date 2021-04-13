/* Copyright (C) 2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.IO;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.Authentication.GSSAPI
{
    /// <summary>
    /// [MS-SPNG] - NegTokenInit2
    /// </summary>
    public class SimpleProtectedNegotiationTokenInit2 : SimpleProtectedNegotiationTokenInit
    {
        public const byte NegHintsTag = 0xA3;
        new public const byte MechanismListMICTag = 0xA4;

        public const byte HintNameTag = 0xA0;
        public const byte HintAddressTag = 0xA1;

        public string HintName;
        public byte[] HintAddress;

        public SimpleProtectedNegotiationTokenInit2()
        {
            HintName = "not_defined_in_RFC4178@please_ignore";
        }

        public override void Dispose()
        {
            base.Dispose();
            if (HintAddress != null) ExactArrayPool.Return(HintAddress);
        }

        /// <param name="offset">The offset following the NegTokenInit2 tag</param>
        /// <exception cref="System.IO.InvalidDataException"></exception>
        public SimpleProtectedNegotiationTokenInit2(Span<byte> buffer, int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte)DerEncodingTag.Sequence)
            {
                throw new InvalidDataException();
            }
            var sequenceLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var sequenceEndOffset = offset + sequenceLength;
            while (offset < sequenceEndOffset)
            {
                tag = ByteReader.ReadByte(buffer, ref offset);
                if (tag == MechanismTypeListTag)
                {
                    MechanismTypeList = ReadMechanismTypeList(buffer, ref offset);
                }
                else if (tag == RequiredFlagsTag)
                {
                    throw new NotImplementedException("negTokenInit.ReqFlags is not implemented");
                }
                else if (tag == MechanismTokenTag)
                {
                    MechanismToken = ReadMechanismToken(buffer, ref offset);
                }
                else if (tag == NegHintsTag)
                {
                    HintName = ReadHints(buffer, ref offset, out HintAddress);
                }
                else if (tag == MechanismListMICTag)
                {
                    MechanismListMIC = ReadMechanismListMIC(buffer, ref offset);
                }
                else
                {
                    throw new InvalidDataException("Invalid negTokenInit structure");
                }
            }
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            var sequenceLength = GetTokenFieldsLength();
            var sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
            var constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
            var constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
            var bufferSize = 1 + constructionLengthFieldSize + 1 + sequenceLengthFieldSize + sequenceLength;
            var buffer = Arrays.Rent(bufferSize);
            var offset = 0;
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, NegTokenInitTag);
            DerEncodingHelper.WriteLength(buffer.Memory.Span, ref offset, constructionLength);
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, (byte)DerEncodingTag.Sequence);
            DerEncodingHelper.WriteLength(buffer.Memory.Span, ref offset, sequenceLength);
            if (MechanismTypeList.Count > 0)
            {
                WriteMechanismTypeList(buffer.Memory.Span, ref offset, ref MechanismTypeList);
            }
            if (MechanismToken != null)
            {
                WriteMechanismToken(buffer.Memory.Span, ref offset, MechanismToken.Memory.Span);
            }
            if (HintName != null || HintAddress != null)
            {
                WriteHints(buffer.Memory.Span, ref offset, HintName, HintAddress);
            }
            if (MechanismListMIC != null)
            {
                WriteMechanismListMIC(buffer.Memory.Span, ref offset, MechanismListMIC.Memory.Span);
            }
            return buffer;
        }

        protected override int GetTokenFieldsLength()
        {
            var result = base.GetTokenFieldsLength();
            if (HintName != null || HintAddress != null)
            {
                var hintsSequenceLength = GetHintsSequenceLength(HintName, HintAddress);
                var hintsSequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintsSequenceLength);
                var hintsSequenceConstructionLength = 1 + hintsSequenceLengthFieldSize + hintsSequenceLength;
                var hintsSequenceConstructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintsSequenceConstructionLength);
                var entryLength = 1 + hintsSequenceConstructionLengthFieldSize + 1 + hintsSequenceLengthFieldSize + hintsSequenceLength;
                result += entryLength;
            }
            return result;
        }

        protected static string ReadHints(Span<byte> buffer, ref int offset, out byte[] hintAddress)
        {
            string hintName = null;
            hintAddress = null;
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte)DerEncodingTag.Sequence)
            {
                throw new InvalidDataException();
            }
            var sequenceLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var sequenceEndOffset = offset + sequenceLength;
            while (offset < sequenceEndOffset)
            {
                tag = ByteReader.ReadByte(buffer, ref offset);
                if (tag == HintNameTag)
                {
                    hintName = ReadHintName(buffer, ref offset);
                }
                else if (tag == HintAddressTag)
                {
                    hintAddress = ReadHintAddress_Rental(buffer, ref offset);
                }
                else
                {
                    throw new InvalidDataException();
                }
            }
            return hintName;
        }

        protected static string ReadHintName(Span<byte> buffer, ref int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte)DerEncodingTag.GeneralString)
            {
                throw new InvalidDataException();
            }
            var hintLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var hintNameBytes = ByteReader.ReadBytes_RentArray(buffer, ref offset, hintLength);
            var res= DerEncodingHelper.DecodeGeneralString(hintNameBytes);
            ExactArrayPool.Return(hintNameBytes);
            return res;
        }

        protected static byte[] ReadHintAddress_Rental(Span<byte> buffer, ref int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte)DerEncodingTag.ByteArray)
            {
                throw new InvalidDataException();
            }
            var hintLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            return ByteReader.ReadBytes_RentArray(buffer, ref offset, hintLength);
        }

        protected static int GetHintsSequenceLength(string hintName, byte[] hintAddress)
        {
            var sequenceLength = 0;
            if (hintName != null)
            {
                var hintNameBytes = DerEncodingHelper.EncodeGeneralString(hintName);
                var lengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintNameBytes.Length);
                var constructionLength = 1 + lengthFieldSize + hintNameBytes.Length;
                var constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
                var entryLength = 1 + constructionLengthFieldSize + 1 + lengthFieldSize + hintNameBytes.Length;
                sequenceLength += entryLength;
            }
            if (hintAddress != null)
            {
                var lengthFieldSize = DerEncodingHelper.GetLengthFieldSize(hintAddress.Length);
                var constructionLength = 1 + lengthFieldSize + hintAddress.Length;
                var constructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(constructionLength);
                var entryLength = 1 + constructionLengthFieldSize + 1 + lengthFieldSize + hintAddress.Length;
                sequenceLength += entryLength;
            }
            return sequenceLength;
        }

        private static void WriteHints(Span<byte> buffer, ref int offset, string hintName, byte[] hintAddress)
        {
            var sequenceLength = GetHintsSequenceLength(hintName, hintAddress);
            var sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
            var constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
            BufferWriter.WriteByte(buffer, ref offset, NegHintsTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            BufferWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.Sequence);
            DerEncodingHelper.WriteLength(buffer, ref offset, sequenceLength);
            if (hintName != null)
            {
                WriteHintName(buffer, ref offset, hintName);
            }
            if (hintAddress != null)
            {
                WriteHintAddress(buffer, ref offset, hintAddress);
            }
        }

        private static void WriteHintName(Span<byte> buffer, ref int offset, string hintName)
        {
            var hintNameBytes = DerEncodingHelper.EncodeGeneralString(hintName);
            var constructionLength = 1 + DerEncodingHelper.GetLengthFieldSize(hintNameBytes.Length) + hintNameBytes.Length;
            BufferWriter.WriteByte(buffer, ref offset, HintNameTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            BufferWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.GeneralString);
            DerEncodingHelper.WriteLength(buffer, ref offset, hintNameBytes.Length);
            BufferWriter.WriteBytes(buffer, ref offset, hintNameBytes);
        }

        private static void WriteHintAddress(Span<byte> buffer, ref int offset, byte[] hintAddress)
        {
            var constructionLength = 1 + DerEncodingHelper.GetLengthFieldSize(hintAddress.Length) + hintAddress.Length;
            BufferWriter.WriteByte(buffer, ref offset, HintAddressTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            BufferWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.ByteArray);
            DerEncodingHelper.WriteLength(buffer, ref offset, hintAddress.Length);
            BufferWriter.WriteBytes(buffer, ref offset, hintAddress);
        }

        new protected static void WriteMechanismListMIC(Span<byte> buffer, ref int offset, byte[] mechanismListMIC)
        {
            var mechanismListMICLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismListMIC.Length);
            BufferWriter.WriteByte(buffer, ref offset, MechanismListMICTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, 1 + mechanismListMICLengthFieldSize + mechanismListMIC.Length);
            BufferWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.ByteArray);
            DerEncodingHelper.WriteLength(buffer, ref offset, mechanismListMIC.Length);
            BufferWriter.WriteBytes(buffer, ref offset, mechanismListMIC);
        }
    }
}
