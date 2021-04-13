/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_WRITE_ANDX Response
    /// SMB 1.0: The 2 reserved bytes at offset 8 become CountHigh (used when the CAP_LARGE_WRITEX capability has been negotiated)
    /// </summary>
    public class WriteAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 12;
        // Parameters:
        public uint Count; // The number of bytes written to the file, 2 bytes + 2 'CountHigh' bytes
        public ushort Available;
        public ushort Reserved;

        public override SMB1Command Init()
        {
            base.Init();
            
            Count = default;
            Available = default;
            Reserved = default;
            
            return this;
        }

        public virtual SMB1Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            
            Count = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);
            Available = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 6);
            var countHigh = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 8);
            Reserved = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 10);
            Count |= (uint)(countHigh << 16);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            var counthHigh = (ushort)(Count >> 16);

            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, (ushort)(Count & 0xFFFF));
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 6, Available);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 8, counthHigh);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 10, Reserved);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_WRITE_ANDX;
    }
}
