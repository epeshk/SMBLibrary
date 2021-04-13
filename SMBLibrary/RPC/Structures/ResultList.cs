/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// p_result_list_t
    /// </summary>
    public class ResultList : List<ResultElement>
    {
        //byte NumberOfResults;
        public byte Reserved;
        public ushort Reserved2;

        public ResultList()
        {}

        public ResultList(Span<byte> buffer, int offset)
        {
            var numberOfResults = ByteReader.ReadByte(buffer, offset + 0);
            Reserved = ByteReader.ReadByte(buffer, offset + 1);
            Reserved2 = LittleEndianConverter.ToUInt16(buffer, offset + 2);
            offset += 4;
            for (var index = 0; index < numberOfResults; index++)
            {
                var element = new ResultElement(buffer, offset);
                Add(element);
                offset += ResultElement.Length;
            }
        }

        public void WriteBytes(Span<byte> buffer, int offset)
        {
            var numberOfResults = (byte)Count;

            BufferWriter.WriteByte(buffer, offset + 0, numberOfResults);
            BufferWriter.WriteByte(buffer, offset + 1, Reserved);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved2);
            offset += 4;
            for (var index = 0; index < numberOfResults; index++)
            {
                this[index].WriteBytes(buffer, offset);
                offset += ResultElement.Length;
            }
        }

        public void WriteBytes(Span<byte> buffer, ref int offset)
        {
            WriteBytes(buffer, offset);
            offset += Length;
        }

        public int Length => 4 + ResultElement.Length * Count;
    }
}
