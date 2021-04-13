/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.RPC
{
    /// <summary>
    /// p_rt_versions_supported_t
    /// </summary>
    public class VersionsSupported
    {
        public List<Version> Entries = new List<Version>(); // p_protocols

        public VersionsSupported()
        {
        }

        public VersionsSupported(Span<byte> buffer, int offset)
        {
            var protocols = ByteReader.ReadByte(buffer, offset + 0);
            Entries = new List<Version>();
            for (var index = 0; index < protocols; index++)
            {
                var version = new Version(buffer, offset + 1 + index * Version.Length);
                Entries.Add(version);
            }
        }

        public void WriteBytes(Span<byte> buffer, int offset)
        {
            BufferWriter.WriteByte(buffer, offset + 0, (byte)Count);
            for (var index = 0; index < Entries.Count; index++)
            {
                Entries[index].WriteBytes(buffer, offset + 1 + index * Version.Length);
            }
        }

        public int Count => Entries.Count;

        public int Length => 1 + Count * Version.Length;
    }
}
