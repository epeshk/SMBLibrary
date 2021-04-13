/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 ERROR Response
    /// </summary>
    public class ErrorResponse : SMB2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        public byte ErrorContextCount;
        public byte Reserved;
        private uint ByteCount;
        public IMemoryOwner<byte> ErrorData = MemoryOwner<byte>.Empty;
        
        public override SMB2Command Init(SMB2CommandName commandName)
        {
            base.Init(commandName);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
            ErrorContextCount = default;
            Reserved = default;
            ByteCount = default;
            return this;
        }

        public SMB2Command Init(SMB2CommandName commandName, NTStatus status)
        {
            Init(commandName);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
            Header.Status = status;
            return this;
        }

        public SMB2Command Init(SMB2CommandName commandName, NTStatus status, IMemoryOwner<byte> errorData)
        {
            Init(commandName);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
            Header.Status = status;
            ErrorData = errorData;
            return this;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            ErrorContextCount = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            Reserved = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            ByteCount = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);

            if (ByteCount != 0)
            {
	            ErrorData = Arrays.Rent((int) ByteCount);
	            buffer.Slice(offset + Smb2Header.Length + 8).CopyTo(ErrorData.Memory.Span);
            }

            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            ByteCount = (uint)ErrorData.Memory.Length;
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            BufferWriter.WriteByte(buffer, 2, ErrorContextCount);
            BufferWriter.WriteByte(buffer, 3, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, 4, ByteCount);
            if (ErrorData.Memory.Length > 0)
            {
                BufferWriter.WriteBytes(buffer, 8, ErrorData.Memory.Span);
            }
            else
            {
                // If the ByteCount field is zero then the server MUST supply an ErrorData field that is one byte in length, and SHOULD set that byte to zero
                BufferWriter.WriteBytes(buffer, 8, new byte[1]);
            }
        }

        public override void Dispose()
        {
            if (ErrorData != null)
            {
                ErrorData.Dispose();
                base.Dispose();
                ErrorData = null;
                ObjectsPool<ErrorResponse>.Return(this);
            }
        }

        public override int CommandLength =>
            // If the ByteCount field is zero then the server MUST supply an ErrorData field that is one byte in length
            FixedSize + Math.Max(ErrorData.Memory.Length, 1);
    }
}
