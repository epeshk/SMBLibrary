/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// [MS-SMB2] 2.2.14.1 - SMB2_FILEID
    /// </summary>
    public class FileID : IDisposable
    {
        public const int Length = 16;

        public ulong Persistent;
        public ulong Volatile;

        public FileID()
        {
            
        }
        public FileID Init()
        {
            Persistent = default;
            Volatile = default;
            return this;
        }
        
        public FileID Init(Span<byte> buffer, int offset)
        {
            Persistent = LittleEndianConverter.ToUInt64(buffer, offset + 0);
            Volatile = LittleEndianConverter.ToUInt64(buffer, offset + 8);
            return this;
        }

        public void WriteBytes(Span<byte> buffer, int offset)
        {
            LittleEndianWriter.WriteUInt64(buffer, offset + 0, Persistent);
            LittleEndianWriter.WriteUInt64(buffer, offset + 8, Volatile);
        }

        public void Dispose()
        {
            ObjectsPool<FileID>.Return(this);
        }
    }
}
