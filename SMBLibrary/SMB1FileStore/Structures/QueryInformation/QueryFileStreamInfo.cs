/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// <summary>
    /// SMB_QUERY_FILE_STREAM_INFO
    /// </summary>
    public class QueryFileStreamInfo : QueryInformation
    {
        private List<FileStreamEntry> m_entries = new List<FileStreamEntry>();

        public QueryFileStreamInfo()
        {
        }

        public QueryFileStreamInfo(Span<byte> buffer, int offset)
        {
            if (offset < buffer.Length)
            {
                FileStreamEntry entry;
                do
                {
                    entry = new FileStreamEntry(buffer, offset);
                    m_entries.Add(entry);
                    offset += (int)entry.NextEntryOffset;
                }
                while (entry.NextEntryOffset != 0);
            }
        }

        public override IMemoryOwner<byte> GetBytes()
        {
            var buffer = Arrays.Rent(Length);
            var offset = 0;
            for (var index = 0; index < m_entries.Count; index++)
            {
                var entry = m_entries[index];
                entry.WriteBytes(buffer.Memory.Span, offset);
                var entryLength = entry.Length;
                offset += entryLength;
                if (index < m_entries.Count - 1)
                {
                    // [MS-FSCC] When multiple FILE_STREAM_INFORMATION data elements are present in the buffer, each MUST be aligned on an 8-byte boundary
                    var padding = (8 - (entryLength % 8)) % 8;
                    offset += padding;
                }
            }
            return buffer;
        }

        public List<FileStreamEntry> Entries => m_entries;

        public override QueryInformationLevel InformationLevel => QueryInformationLevel.SMB_QUERY_FILE_STREAM_INFO;

        public int Length
        {
            get
            {
                var length = 0;
                for (var index = 0; index < m_entries.Count; index++)
                {
                    var entry = m_entries[index];
                    var entryLength = entry.Length;
                    length += entryLength;
                    if (index < m_entries.Count - 1)
                    {
                        // [MS-FSCC] When multiple FILE_STREAM_INFORMATION data elements are present in the buffer, each MUST be aligned on an 8-byte boundary
                        var padding = (8 - (entryLength % 8)) % 8;
                        length += padding;
                    }
                }
                return length;
            }
        }
    }
}
