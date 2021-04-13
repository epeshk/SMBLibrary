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
    /// SMB_COM_WRITE_RAW Interim Response
    /// </summary>
    public class WriteRawInterimResponse : SMB1Command
    {
        public const int ParametersLength = 2;
        // Parameters;
        public ushort Available;

        public override SMB1Command Init()
        {
            base.Init();
            return this;
        }

        public virtual SMB1Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            Available = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 0);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 0, Available);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_WRITE_RAW;
    }
}
