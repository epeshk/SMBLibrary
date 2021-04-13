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
    public abstract class QueryDirectoryFileInformation : FileInformation, IDisposable
    {
        public uint NextEntryOffset;
        public uint FileIndex;

        public virtual QueryDirectoryFileInformation Init(Span<byte> buffer, int offset)
        {
            NextEntryOffset = LittleEndianConverter.ToUInt32(buffer, offset + 0);
            FileIndex = LittleEndianConverter.ToUInt32(buffer, offset + 4);
            return this;
        }

        public override void WriteBytes(Span<byte> buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, NextEntryOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, FileIndex);
        }

        public static QueryDirectoryFileInformation ReadFileInformation(Span<byte> buffer, int offset, FileInformationClass fileInformationClass)
        {
            return fileInformationClass switch
            {
                FileInformationClass.FileDirectoryInformation => ObjectsPool<FileDirectoryInformation>.Get().Init(buffer, offset),
                FileInformationClass.FileFullDirectoryInformation => ObjectsPool<FileFullDirectoryInformation>.Get().Init(buffer, offset),
                FileInformationClass.FileBothDirectoryInformation => ObjectsPool<FileBothDirectoryInformation>.Get().Init(buffer, offset),
                FileInformationClass.FileNamesInformation => ObjectsPool<FileNamesInformation>.Get().Init(buffer, offset),
                FileInformationClass.FileIdBothDirectoryInformation => ObjectsPool<FileIdBothDirectoryInformation>.Get().Init(buffer, offset),
                FileInformationClass.FileIdFullDirectoryInformation => ObjectsPool<FileIdFullDirectoryInformation>.Get().Init(buffer, offset),
                _ => throw new NotImplementedException(String.Format("File information class {0} is not supported.", (int) fileInformationClass))
            };
        }

        public static IMemoryOwner<QueryDirectoryFileInformation> ReadFileInformationList(Span<byte> buffer, int offset, FileInformationClass fileInformationClass)
        {
            // `using` - because Slice makes count++ 
            using var result = Arrays.Rent<QueryDirectoryFileInformation>(1042*10);
            var index = 0;
            QueryDirectoryFileInformation entry;
            do
            {
                entry = ReadFileInformation(buffer, offset, fileInformationClass);
                result.Memory.Span[index] = entry;
                offset += (int)entry.NextEntryOffset;
                index++;
            }
            while (entry.NextEntryOffset != 0);
            return result.Slice(0, index);
        }

        public static IMemoryOwner<byte> GetBytes(List<QueryDirectoryFileInformation> fileInformationList)
        {
            var listLength = GetListLength(fileInformationList);
            var buffer = Arrays.Rent(listLength);
            var offset = 0;
            for (var index = 0; index < fileInformationList.Count; index++)
            {
                var entry = fileInformationList[index];
                var length = entry.Length;
                var paddedLength = (int)Math.Ceiling((double)length / 8) * 8;
                if (index < fileInformationList.Count - 1)
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

        public static int GetListLength(List<QueryDirectoryFileInformation> fileInformationList)
        {
            var result = 0;
            for(var index = 0; index < fileInformationList.Count; index++)
            {
                var entry = fileInformationList[index];
                var length = entry.Length;
                // [MS-FSCC] each [entry] MUST be aligned on an 8-byte boundary.
                if (index < fileInformationList.Count - 1)
                {
                    // No padding is required following the last data element.
                    var paddedLength = (int)Math.Ceiling((double)length / 8) * 8;
                    result += paddedLength;
                }
                else
                {
                    result += length;
                }
            }
            return result;
        }

        public abstract void Dispose();
    }
}
