/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_NEGOTIATE Request
    /// </summary>
    public class NegotiateRequest : SMB1Command
    {
        public const int SupportedBufferFormat = 0x02;
        // Data:
        public List<string> Dialects = new List<string>();
        
        public override SMB1Command Init()
        {
            base.Init();
            Dialects.Clear();
            return this;
        }

        public NegotiateRequest Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            
            var dataOffset = 0;
            while (dataOffset < SmbData.Length())
            {
                var bufferFormat = ByteReader.ReadByte(SmbData.Memory.Span, ref dataOffset);
                if (bufferFormat != SupportedBufferFormat)
                {
                    throw new InvalidDataException("Unsupported Buffer Format");
                }
                var dialect = ByteReader.ReadNullTerminatedAnsiString(SmbData.Memory.Span, dataOffset);
                Dialects.Add(dialect);
                dataOffset += dialect.Length + 1;
            }

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            var length = 0;
            for (var index = 0; index < Dialects.Count; index++)
            {
                var dialect = Dialects[index];
                length += 1 + dialect.Length + 1;
            }

            SmbParameters = MemoryOwner<byte>.Empty;
            SmbData = Arrays.Rent(length);
            var offset = 0;
            for (var index = 0; index < Dialects.Count; index++)
            {
                var dialect = Dialects[index];
                BufferWriter.WriteByte(SmbData.Memory.Span, offset, 0x02);
                BufferWriter.WriteAnsiString(SmbData.Memory.Span, offset + 1, dialect, dialect.Length);
                BufferWriter.WriteByte(SmbData.Memory.Span, offset + 1 + dialect.Length, 0x00);
                offset += 1 + dialect.Length + 1;
            }

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_NEGOTIATE;
    }
}
