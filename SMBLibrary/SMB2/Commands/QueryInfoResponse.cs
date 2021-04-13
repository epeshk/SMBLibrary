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
    /// SMB2 QUERY_INFO Response
    /// </summary>
    public class QueryInfoResponse : SMB2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        private ushort OutputBufferOffset;
        private uint OutputBufferLength;
        public IMemoryOwner<byte> OutputBuffer = MemoryOwner<byte>.Empty;

        public QueryInfoResponse()
        {
            Init(SMB2CommandName.QueryInfo);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            OutputBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            OutputBuffer = Arrays.RentFrom<byte>(buffer.Slice(offset + OutputBufferOffset, (int)OutputBufferLength));
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            OutputBufferOffset = 0;
            OutputBufferLength = (uint)OutputBuffer.Length();
            if (OutputBuffer.Length() > 0)
            {
                OutputBufferOffset = Smb2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, OutputBufferOffset);
            LittleEndianWriter.WriteUInt32(buffer, 4, OutputBufferLength);
            BufferWriter.WriteBytes(buffer, FixedSize, OutputBuffer.Memory.Span);
        }

        public FileInformation GetFileInformation(FileInformationClass informationClass)
        {
            return FileInformation.GetFileInformation(OutputBuffer.Memory.Span, 0, informationClass);
        }

        public FileSystemInformation GetFileSystemInformation(FileSystemInformationClass informationClass)
        {
            return FileSystemInformation.GetFileSystemInformation(OutputBuffer.Memory.Span, 0, informationClass);
        }

        public SecurityDescriptor GetSecurityInformation()
        {
            return new SecurityDescriptor(OutputBuffer.Memory.Span, 0);
        }

        public void SetFileInformation(FileInformation fileInformation)
        {
            OutputBuffer = fileInformation.GetBytes();
        }

        public void SetFileSystemInformation(FileSystemInformation fileSystemInformation)
        {
            OutputBuffer = fileSystemInformation.GetBytes();
        }

        public void SetSecurityInformation(SecurityDescriptor securityDescriptor)
        {
            OutputBuffer = securityDescriptor.GetBytes();
        }

        public override void Dispose()
        {
            base.Dispose();
            OutputBuffer.Dispose();
            ObjectsPool<QueryInfoResponse>.Return(this);
        }

        public override int CommandLength => FixedSize + OutputBuffer.Length();
    }
}
