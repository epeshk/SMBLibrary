/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.4.40 - FileStreamInformation
    /// </summary>
    public class FileStreamInformation : FileInformation
    {
        List<FileStreamEntry> m_entries = new List<FileStreamEntry>();

        public FileStreamInformation()
        {
        }

        public FileStreamInformation(Span<byte> buffer, int offset)
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

        public override void WriteBytes(Span<byte> buffer, int offset)
        {
            for (var index = 0; index < m_entries.Count; index++)
            {
                var entry = m_entries[index];
                var entryLength = entry.PaddedLength;
                entry.NextEntryOffset = (index < m_entries.Count - 1) ? (uint)entryLength : 0;
                entry.WriteBytes(buffer, offset);
                offset += entryLength;
            }
        }

        public List<FileStreamEntry> Entries => m_entries;

        public override FileInformationClass FileInformationClass => FileInformationClass.FileStreamInformation;

        public override int Length
        {
            get
            {
                var length = 0;
                for (var index = 0; index < m_entries.Count; index++)
                {
                    var entry = m_entries[index];
                    var entryLength = (index < m_entries.Count - 1) ? entry.PaddedLength : entry.Length;
                    length += entryLength;
                }
                return length;
            }
        }
    }
}
