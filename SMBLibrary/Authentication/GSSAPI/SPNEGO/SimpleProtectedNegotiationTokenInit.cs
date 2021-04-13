/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.IO;
using MemoryPools.Collections.Specialized;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.Authentication.GSSAPI
{
    /// <summary>
    /// RFC 4178 - negTokenInit
    /// </summary>
    public class SimpleProtectedNegotiationTokenInit : SimpleProtectedNegotiationToken
    {
        public const byte NegTokenInitTag = 0xA0;
        public const byte MechanismTypeListTag = 0xA0;
        public const byte RequiredFlagsTag = 0xA1;
        public const byte MechanismTokenTag = 0xA2;
        public const byte MechanismListMICTag = 0xA3;

        /// <summary>
        /// Contains one or more security mechanisms available for the initiator, in decreasing preference order.
        /// </summary>
        public LongLocalList<IMemoryOwner<byte>> MechanismTypeList; // Optional
        // reqFlags - Optional, RECOMMENDED to be left out
        public IMemoryOwner<byte> MechanismToken; // Optional
        public IMemoryOwner<byte> MechanismListMIC; // Optional

        public SimpleProtectedNegotiationTokenInit()
        {
        }

        public override void Dispose()
        {
            base.Dispose();
            if (MechanismToken != null) MechanismToken.Dispose(); MechanismToken = null;
            if (MechanismListMIC != null) MechanismListMIC.Dispose(); MechanismListMIC = null;
            
            if (MechanismTypeList.Count > 0)
                for (int i = 0, len = MechanismTypeList.Count; i < len; i++)
                {
                    MechanismTypeList[i].Dispose();
                }
            MechanismTypeList.Clear();
        }

        /// <param name="offset">The offset following the NegTokenInit tag</param>
        /// <exception cref="System.IO.InvalidDataException"></exception>
        public SimpleProtectedNegotiationTokenInit(Span<byte> buffer, int offset)
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
            if (MechanismListMIC != null)
            {
                WriteMechanismListMIC(buffer.Memory.Span, ref offset, MechanismListMIC.Memory.Span);
            }
            return buffer;
        }

        protected virtual int GetTokenFieldsLength()
        {
            var result = 0;
            if (MechanismTypeList.Count > 0)
            {
                var typeListSequenceLength = GetMechanismTypeListSequenceLength(ref MechanismTypeList);
                var typeListSequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(typeListSequenceLength);
                var typeListConstructionLength = 1 + typeListSequenceLengthFieldSize + typeListSequenceLength;
                var typeListConstructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(typeListConstructionLength);
                var entryLength = 1 + typeListConstructionLengthFieldSize + 1 + typeListSequenceLengthFieldSize + typeListSequenceLength;
                result += entryLength;
            }
            if (MechanismToken != null)
            {
                var mechanismTokenLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(MechanismToken.Length());
                var mechanismTokenConstructionLength = 1 + mechanismTokenLengthFieldSize + MechanismToken.Length();
                var mechanismTokenConstructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismTokenConstructionLength);
                var entryLength = 1 + mechanismTokenConstructionLengthFieldSize + 1 + mechanismTokenLengthFieldSize + MechanismToken.Length();;
                result += entryLength;
            }
            if (MechanismListMIC != null)
            {
                var mechanismListMICLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(MechanismListMIC.Length());
                var mechanismListMICConstructionLength = 1 + mechanismListMICLengthFieldSize + MechanismListMIC.Length();
                var mechanismListMICConstructionLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismListMICConstructionLength);
                var entryLength = 1 + mechanismListMICConstructionLengthFieldSize + 1 + mechanismListMICLengthFieldSize + MechanismListMIC.Length();
                result += entryLength;
            }
            return result;
        }

        protected static LongLocalList<IMemoryOwner<byte>> ReadMechanismTypeList(Span<byte> buffer, ref int offset)
        {
            var result = new LongLocalList<IMemoryOwner<byte>>();
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
                if (tag != (byte)DerEncodingTag.ObjectIdentifier)
                {
                    throw new InvalidDataException();
                }
                var mechanismTypeLength = DerEncodingHelper.ReadLength(buffer, ref offset);
                var mechanismType = ByteReader.ReadBytes_Rent(buffer, ref offset, mechanismTypeLength);
                result.Add(mechanismType);
            }
            return result;
        }

        protected static IMemoryOwner<byte> ReadMechanismToken(Span<byte> buffer, ref int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte)DerEncodingTag.ByteArray)
            {
                throw new InvalidDataException();
            }
            var mechanismTokenLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var token = ByteReader.ReadBytes_Rent(buffer, ref offset, mechanismTokenLength);
            return token;
        }

        protected static IMemoryOwner<byte> ReadMechanismListMIC(Span<byte> buffer, ref int offset)
        {
            var constructionLength = DerEncodingHelper.ReadLength(buffer, ref offset);
            var tag = ByteReader.ReadByte(buffer, ref offset);
            if (tag != (byte)DerEncodingTag.ByteArray)
            {
                throw new InvalidDataException();
            }
            var length = DerEncodingHelper.ReadLength(buffer, ref offset);
            return ByteReader.ReadBytes_Rent(buffer, ref offset, length);
        }

        protected static int GetMechanismTypeListSequenceLength(ref LongLocalList<IMemoryOwner<byte>> mechanismTypeList)
        {
            var sequenceLength = 0;
            for (var index = 0; index < mechanismTypeList.Count; index++)
            {
                var mechanismType = mechanismTypeList[index];
                var lengthFieldSize = DerEncodingHelper.GetLengthFieldSize(mechanismType.Length());
                var entryLength = 1 + lengthFieldSize + mechanismType.Length();
                sequenceLength += entryLength;
            }

            return sequenceLength;
        }

        protected static void WriteMechanismTypeList(Span<byte> buffer, ref int offset, ref LongLocalList<IMemoryOwner<byte>> mechanismTypeList)
        {
            var sequenceLength = GetMechanismTypeListSequenceLength(ref mechanismTypeList);
            var sequenceLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(sequenceLength);
            var constructionLength = 1 + sequenceLengthFieldSize + sequenceLength;
            BufferWriter.WriteByte(buffer, ref offset, MechanismTypeListTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            BufferWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.Sequence);
            DerEncodingHelper.WriteLength(buffer, ref offset, sequenceLength);
            for (var index = 0; index < mechanismTypeList.Count; index++)
            {
                var mechanismType = mechanismTypeList[index];
                BufferWriter.WriteByte(buffer, ref offset, (byte) DerEncodingTag.ObjectIdentifier);
                DerEncodingHelper.WriteLength(buffer, ref offset, mechanismType.Length());
                BufferWriter.WriteBytes(buffer, ref offset, mechanismType.Memory.Span);
            }
        }

        protected static void WriteMechanismToken(Span<byte> buffer, ref int offset, Span<byte> mechanismToken)
        {
            var constructionLength = 1 + DerEncodingHelper.GetLengthFieldSize(mechanismToken.Length) + mechanismToken.Length;
            BufferWriter.WriteByte(buffer, ref offset, MechanismTokenTag);
            DerEncodingHelper.WriteLength(buffer, ref offset, constructionLength);
            BufferWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.ByteArray);
            DerEncodingHelper.WriteLength(buffer, ref offset, mechanismToken.Length);
            BufferWriter.WriteBytes(buffer, ref offset, mechanismToken);
        }

        protected static void WriteMechanismListMIC(Span<byte> buffer, ref int offset, Span<byte> mechanismListMIC)
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
