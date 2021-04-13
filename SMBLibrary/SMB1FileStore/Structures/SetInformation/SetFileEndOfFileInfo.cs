/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// SMB_SET_FILE_END_OF_FILE_INFO
    /// </summary>
    public class SetFileEndOfFileInfo : SetInformation
    {
        public const int Length = 8;

        public long EndOfFile;

        public SetFileEndOfFileInfo()
        {
        }

        public SetFileEndOfFileInfo(Span<byte> buffer) : this(buffer, 0)
        {
        }

        public SetFileEndOfFileInfo(Span<byte> buffer, int offset)
        {
            EndOfFile = LittleEndianConverter.ToInt64(buffer, offset);
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            var buffer = Arrays.Rent(Length);
            LittleEndianWriter.WriteInt64(buffer.Memory.Span, 0, EndOfFile);
            return buffer;
        }

        public override SetInformationLevel InformationLevel => SetInformationLevel.SMB_SET_FILE_END_OF_FILE_INFO;
    }
}
