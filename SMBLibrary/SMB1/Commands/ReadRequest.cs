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
    /// SMB_COM_READ Request
    /// </summary>
    public class ReadRequest : SMB1Command
    {
        public const int ParametersLength = 10;
        // Parameters:
        public ushort FID;
        public ushort CountOfBytesToRead;
        public uint ReadOffsetInBytes;
        public ushort EstimateOfRemainingBytesToBeRead;

        public override SMB1Command Init()
        {
            base.Init();
            FID = default;
            CountOfBytesToRead = default;
            ReadOffsetInBytes = default;
            EstimateOfRemainingBytesToBeRead = default;
            return this;
        }

        public ReadRequest Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            
            FID = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            CountOfBytesToRead = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 2);
            ReadOffsetInBytes = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 4);
            CountOfBytesToRead = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 8);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, FID);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 2, CountOfBytesToRead);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 4, ReadOffsetInBytes);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 8, CountOfBytesToRead);
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_READ;
    }
}
