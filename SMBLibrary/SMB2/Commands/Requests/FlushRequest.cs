/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 FLUSH Request
    /// </summary>
    public class FlushRequest : SMB2Request
    {
        public const int DeclaredSize = 24;

        private ushort StructureSize;
        public ushort Reserved1;
        public uint Reserved2;
        public FileID FileId;

        public FlushRequest() : base(SMB2CommandName.Flush)
        {
            StructureSize = DeclaredSize;
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved1);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, Reserved2);
            FileId.WriteBytes(buffer, offset + 8);
        }

        public override int CommandLength
        {
            get
            {
                return DeclaredSize;
            }
        }
    }
}
