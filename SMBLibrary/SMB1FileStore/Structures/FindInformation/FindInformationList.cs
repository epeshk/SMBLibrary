/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;
using MemoryPools.Memory;

namespace SMBLibrary.SMB1
{
    public class FindInformationList : List<FindInformation>, IDisposable
    {
        public FindInformationList()
        {
        }

        public FindInformationList(Span<byte> buffer, FindInformationLevel informationLevel, bool isUnicode)
        {
            var offset = 0;
            FindInformation entry;
            do
            {
	            entry = FindInformation.ReadEntry(buffer, offset, informationLevel, isUnicode);
                Add(entry);
                offset += (int) entry.NextEntryOffset;
            } while (entry.NextEntryOffset != 0 && offset < buffer.Length);
        }

        public IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            for(var index = 0; index < Count - 1; index++)
            {
                var entry = this[index];
                var entryLength = entry.GetLength(isUnicode);
                entry.NextEntryOffset = (uint)entryLength;

            }
            var length = GetLength(isUnicode);
            var buffer = Arrays.Rent(length);
            var offset = 0;
            foreach (var entry in this)
            {
                entry.WriteBytes(buffer.Memory.Span, ref offset, isUnicode);
            }
            return buffer;
        }

        public int GetLength(bool isUnicode)
        {
            var length = 0;
            for (var index = 0; index < Count; index++)
            {
                var entry = this[index];
                var entryLength = entry.GetLength(isUnicode);
                length += entryLength;
            }
            return length;
        }

        public void Dispose()
        {
            foreach (var entry in this)
            {
                entry.Dispose();
            }
            Clear();
        }
    }
}
