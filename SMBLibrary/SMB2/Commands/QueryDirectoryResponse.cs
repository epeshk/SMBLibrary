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

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 QUERY_DIRECTORY Response
    /// </summary>
    public class QueryDirectoryResponse : SMB2Command
    {
        public const int FixedLength = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        private ushort OutputBufferOffset;
        private uint   OutputBufferLength;
        
        public IMemoryOwner<byte> OutputBuffer = MemoryOwner<byte>.Empty;

        public QueryDirectoryResponse()
        {
            Init(SMB2CommandName.QueryDirectory);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            OutputBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            OutputBuffer = Arrays.Rent((int)OutputBufferLength);
            buffer.Slice(offset + OutputBufferOffset).CopyTo(OutputBuffer.Memory.Span);
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            OutputBufferOffset = 0;
            OutputBufferLength = (uint)OutputBuffer.Memory.Length;
            if (OutputBuffer.Memory.Length > 0)
            {
                OutputBufferOffset = Smb2Header.Length + FixedLength;
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, OutputBufferOffset);
            LittleEndianWriter.WriteUInt32(buffer, 4, OutputBufferLength);
            
            OutputBuffer.Memory.Span.CopyTo(buffer.Slice(FixedLength));
        }

        public IMemoryOwner<QueryDirectoryFileInformation> GetFileInformationList(FileInformationClass fileInformationClass)
        {
            if (OutputBuffer.Memory.Length > 0)
            {
                return QueryDirectoryFileInformation.ReadFileInformationList(OutputBuffer.Memory.Span, 0, fileInformationClass);
            }

            return MemoryOwner<QueryDirectoryFileInformation>.Empty;
        }

        public void SetFileInformationList(List<QueryDirectoryFileInformation> fileInformationList)
        {
            OutputBuffer?.Dispose();
            OutputBuffer = QueryDirectoryFileInformation.GetBytes(fileInformationList);
        }

        public override void Dispose()
        {
            if (OutputBuffer != null)
            {
                OutputBuffer.Dispose();
                OutputBuffer = null;
                base.Dispose();
                ObjectsPool<QueryDirectoryResponse>.Return(this);
            }
        }

        public override int CommandLength => FixedLength + OutputBuffer.Memory.Length;
    }
}
