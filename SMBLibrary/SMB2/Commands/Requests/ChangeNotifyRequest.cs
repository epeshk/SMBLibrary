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
    /// SMB2 CHANGE_NOTIFY Request
    /// </summary>
    public class ChangeNotifyRequest : SMB2Request
    {
        public const int DeclaredSize = 32;

        private ushort StructureSize;
        public ChangeNotifyFlags Flags;
        public uint OutputBufferLength;
        public FileID FileId;
        public NotifyChangeFilter CompletionFilter;
        public uint Reserved;

        public ChangeNotifyRequest() : base(SMB2CommandName.ChangeNotify)
        {
            StructureSize = DeclaredSize;
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort)Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, OutputBufferLength);
            FileId.WriteBytes(buffer, offset + 8);
            LittleEndianWriter.WriteUInt32(buffer, offset + 24, (uint)CompletionFilter);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, Reserved);
        }

        public bool WatchTree
        {
            get
            {
                return ((Flags & ChangeNotifyFlags.WatchTree) > 0);
            }
            set
            {
                if (value)
                {
                    Flags |= ChangeNotifyFlags.WatchTree;
                }
                else
                {
                    Flags &= ~ChangeNotifyFlags.WatchTree;
                }
            }
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
