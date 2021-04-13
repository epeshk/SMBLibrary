/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// p_cont_elem_t
    /// </summary>
    public class ContextElement // Presentation Context Element
    {
        public ushort ContextID;
        // byte NumberOfTransferSyntaxItems;
        public byte Reserved;
        public SyntaxID AbstractSyntax;
        public List<SyntaxID> TransferSyntaxList = new List<SyntaxID>();

        public ContextElement()
        {
        }

        public ContextElement(Span<byte> buffer, int offset)
        {
            ContextID = LittleEndianConverter.ToUInt16(buffer, offset + 0);
            var numberOfTransferSyntaxItems = ByteReader.ReadByte(buffer, offset + 2);
            Reserved = ByteReader.ReadByte(buffer, offset + 3);
            AbstractSyntax = new SyntaxID(buffer, offset + 4);
            offset += 4 + SyntaxID.Length;
            for (var index = 0; index < numberOfTransferSyntaxItems; index++)
            {
                var syntax = new SyntaxID(buffer, offset);
                TransferSyntaxList.Add(syntax);
                offset += SyntaxID.Length;
            }
        }

        public void WriteBytes(Span<byte> buffer, int offset)
        {
            var numberOfTransferSyntaxItems = (byte)TransferSyntaxList.Count;

            LittleEndianWriter.WriteUInt16(buffer, offset + 0, ContextID);
            BufferWriter.WriteByte(buffer, offset + 2, numberOfTransferSyntaxItems);
            BufferWriter.WriteByte(buffer, offset + 3, Reserved);
            AbstractSyntax.WriteBytes(buffer, offset + 4);
            offset += 4 + SyntaxID.Length;

            for (var index = 0; index < numberOfTransferSyntaxItems; index++)
            {
                TransferSyntaxList[index].WriteBytes(buffer, offset);
                offset += SyntaxID.Length;
            }
        }

        public int Length => 4 + SyntaxID.Length * (TransferSyntaxList.Count + 1);
    }
}
