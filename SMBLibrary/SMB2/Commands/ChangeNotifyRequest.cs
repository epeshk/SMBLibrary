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
    /// SMB2 CHANGE_NOTIFY Request
    /// </summary>
    public class ChangeNotifyRequest : SMB2Command
    {
        public const int DeclaredSize = 32;

        private ushort StructureSize;
        public ChangeNotifyFlags Flags;
        public uint OutputBufferLength;
        public FileID FileId;
        public NotifyChangeFilter CompletionFilter;
        public uint Reserved;

        public ChangeNotifyRequest()
        {
            Init(SMB2CommandName.ChangeNotify);
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Flags = (ChangeNotifyFlags)LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            FileId = ObjectsPool<FileID>.Get().Init(buffer, offset + Smb2Header.Length + 8);
            CompletionFilter = (NotifyChangeFilter)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 24);
            Reserved = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 28);
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, (ushort)Flags);
            LittleEndianWriter.WriteUInt32(buffer, 4, OutputBufferLength);
            FileId.WriteBytes(buffer, 8);
            LittleEndianWriter.WriteUInt32(buffer, 24, (uint)CompletionFilter);
            LittleEndianWriter.WriteUInt32(buffer, 28, Reserved);
        }

        public bool WatchTree
        {
            get => ((Flags & ChangeNotifyFlags.WatchTree) > 0);
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

        public override void Dispose()
        {
            base.Dispose();
            
            //FileId.Dispose(); - fileId handle is frequently used for multiple requests and can be disposed via ISMBFileStore.CloseFile(...) method.  
            FileId = default;

            ObjectsPool<ChangeNotifyRequest>.Return(this);
        }

        public override int CommandLength => DeclaredSize;
    }
}
