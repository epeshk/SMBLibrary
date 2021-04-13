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
    /// SMB_COM_FLUSH Request
    /// </summary>
    public class FlushRequest : SMB1Command
    {
        public const int ParametersLength = 2;
        // Parameters:
        public ushort FID;

        public FlushRequest Init()
        {
            base.Init();
            FID = default;
            return this;
        }

        public FlushRequest Init(Span<byte> buffer, int offset) 
        {
            base.Init(buffer, offset, false);
            FID = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);
            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, FID);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_FLUSH;
    }
}
