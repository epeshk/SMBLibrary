/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary
{
    public enum FileAction : uint
    {
        Added = 0x00000001,               // FILE_ACTION_ADDED
        Removed = 0x00000002,             // FILE_ACTION_REMOVED
        Modified = 0x00000003,            // FILE_ACTION_MODIFIED
        RenamedOldName = 0x00000004,      // FILE_ACTION_RENAMED_OLD_NAME
        RenamedNewName = 0x00000005,      // FILE_ACTION_RENAMED_NEW_NAME
        AddedStream = 0x00000006,         // FILE_ACTION_ADDED_STREAM
        RemovedStream = 0x00000007,       // FILE_ACTION_REMOVED_STREAM
        ModifiedStream = 0x00000008,      // FILE_ACTION_MODIFIED_STREAM
        RemovedByDelete = 0x00000009,     // FILE_ACTION_REMOVED_BY_DELETE
        IDNotTunneled = 0x0000000A,       // FILE_ACTION_ID_NOT_TUNNELLED
        TunneledIDCollision = 0x0000000B, // FILE_ACTION_TUNNELLED_ID_COLLISION
    }

    /// <summary>
    /// [MS-FSCC] 2.4.42 - FileNotifyInformation
    /// </summary>
    public class FileNotifyInformation
    {
        public const int FixedLength = 12;

        public uint NextEntryOffset;
        public FileAction Action;
        private uint FileNameLength;
        public IMemoryOwner<char> FileName;

        public FileNotifyInformation()
        {
            FileName = MemoryOwner<char>.Empty;
        }

        public FileNotifyInformation(Span<byte> buffer, int offset)
        {
            NextEntryOffset = LittleEndianConverter.ToUInt32(buffer, offset + 0);
            Action = (FileAction)LittleEndianConverter.ToUInt32(buffer, offset + 4);
            FileNameLength = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            FileName = Arrays.Rent<char>((int) (FileNameLength / 2)); 
            ByteReader.ReadUTF16String(FileName.Memory.Span, buffer, offset + 12, (int)(FileNameLength / 2));
        }

        public void WriteBytes(Span<byte> buffer, int offset)
        {
            FileNameLength = (uint)(FileName.Memory.Length * 2);
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, NextEntryOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint)Action);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, FileNameLength);
            BufferWriter.WriteUTF16String(buffer, offset + 12, FileName.Memory.Span);
        }

        public int Length => FixedLength + FileName.Memory.Length * 2;

        public static List<FileNotifyInformation> ReadList(Span<byte> buffer, int offset)
        {
            var result = new List<FileNotifyInformation>();
            FileNotifyInformation entry;
            do
            {
                entry = new FileNotifyInformation(buffer, offset);
                result.Add(entry);
                offset += (int)entry.NextEntryOffset;
            }
            while (entry.NextEntryOffset != 0);
            return result;
        }

        public static IMemoryOwner<byte> GetBytes(List<FileNotifyInformation> notifyInformationList)
        {
            var listLength = GetListLength(notifyInformationList);
            var buffer = Arrays.Rent<byte>(listLength);
            var offset = 0;
            for (var index = 0; index < notifyInformationList.Count; index++)
            {
                var entry = notifyInformationList[index];
                var length = entry.Length;
                var paddedLength = (int)Math.Ceiling((double)length / 4) * 4;
                if (index < notifyInformationList.Count - 1)
                {
                    entry.NextEntryOffset = (uint)paddedLength;
                }
                else
                {
                    entry.NextEntryOffset = 0;
                }
                entry.WriteBytes(buffer.Memory.Span, offset);
                offset += paddedLength;
            }
            return buffer;
        }

        public static int GetListLength(List<FileNotifyInformation> notifyInformationList)
        {
            var result = 0;
            for (var index = 0; index < notifyInformationList.Count; index++)
            {
                var entry = notifyInformationList[index];
                var length = entry.Length;
                // [MS-FSCC] NextEntryOffset MUST always be an integral multiple of 4.
                // The FileName array MUST be padded to the next 4-byte boundary counted from the beginning of the structure.
                if (index < notifyInformationList.Count - 1)
                {
                    // No padding is required following the last data element.
                    var paddedLength = (int)Math.Ceiling((double)length / 4) * 4;
                    result += paddedLength;
                }
                else
                {
                    result += length;
                }
            }
            return result;
        }
    }
}
