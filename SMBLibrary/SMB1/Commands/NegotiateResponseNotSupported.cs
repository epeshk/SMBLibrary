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
    /// SMB_COM_NEGOTIATE Response
    /// </summary>
    public class NegotiateResponseNotSupported : SMB1Command
    {
        public const int ParametersLength = 2;
        public const ushort DialectsNotSupported = 0xFFFF;

        public override SMB1Command Init()
        {
            base.Init();

            return this;
        }

        public NegotiateResponseNotSupported Init(Span<byte> buffer, int offset)
        {
            throw new NotImplementedException();
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, DialectsNotSupported);

            SmbData = MemoryOwner<byte>.Empty;

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_NEGOTIATE;
    }
}
