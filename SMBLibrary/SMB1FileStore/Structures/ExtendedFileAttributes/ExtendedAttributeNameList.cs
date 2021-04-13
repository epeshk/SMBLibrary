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

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// [MS-CIFS] 2.2.1.2.1.1 - SMB_GEA_LIST
    /// </summary>
    public class ExtendedAttributeNameList : List<ExtendedAttributeName>
    {
        public ExtendedAttributeNameList()
        {
        }

        public ExtendedAttributeNameList(Span<byte> buffer, int offset)
        {
            // [MS-CIFS] length MUST contain the total size of the GEAList field, plus the size of the SizeOfListInBytes field
            var length = (int)LittleEndianConverter.ToUInt32(buffer, offset + 0);
            var position = offset + 4;
            var eof = offset + length;
            while (position < eof)
            {
                var attribute = new ExtendedAttributeName(buffer, position);
                Add(attribute);
                position += attribute.Length;
            }
        }

        public IMemoryOwner<byte> GetBytes()
        {
            var buffer = Arrays.Rent(Length);
            WriteBytes(buffer.Memory.Span, 0);
            return buffer;
        }

        public void WriteBytes(Span<byte> buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint)Length);
            foreach (var entry in this)
            {
                entry.WriteBytes(buffer, offset);
                offset += entry.Length;
            }
        }

        public int Length
        {
            get
            {
                var length = 4;
                foreach (var entry in this)
                {
                    length += entry.Length;
                }
                return length;
            }
        }
    }
}
