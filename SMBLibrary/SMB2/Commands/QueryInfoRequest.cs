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
    /// SMB2 QUERY_INFO Request
    /// </summary>
    public class QueryInfoRequest : SMB2Command
    {
        public const int FixedSize = 40;
        public const int DeclaredSize = 41;

        private ushort StructureSize;
        public InfoType InfoType;
        private byte FileInfoClass;
        public uint OutputBufferLength;
        private ushort InputBufferOffset;
        public ushort Reserved;
        private uint InputBufferLength;
        public uint AdditionalInformation;
        public uint Flags;
        public FileID FileId;
        public IMemoryOwner<byte> InputBuffer = MemoryOwner<byte>.Empty;

        public QueryInfoRequest()
        {
            Init(SMB2CommandName.QueryInfo);
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            InfoType = (InfoType)ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            FileInfoClass = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            InputBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 8);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 10);
            InputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 12);
            AdditionalInformation = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 16);
            Flags = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 20);
            FileId = ObjectsPool<FileID>.Get().Init(buffer, offset + Smb2Header.Length + 24);
            InputBuffer = Arrays.RentFrom<byte>(buffer.Slice(offset + InputBufferOffset, (int)InputBufferLength));
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            InputBufferOffset = 0;
            InputBufferLength = (uint)InputBuffer.Length();
            if (InputBuffer.Length() > 0)
            {
                InputBufferOffset = Smb2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            BufferWriter.WriteByte(buffer, 2, (byte)InfoType);
            BufferWriter.WriteByte(buffer, 3, FileInfoClass);
            LittleEndianWriter.WriteUInt32(buffer, 4, OutputBufferLength);
            LittleEndianWriter.WriteUInt16(buffer, 8, InputBufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, 10, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, 12, InputBufferLength);
            LittleEndianWriter.WriteUInt32(buffer, 16, AdditionalInformation);
            LittleEndianWriter.WriteUInt32(buffer, 20, Flags);
            FileId.WriteBytes(buffer, 24);
            BufferWriter.WriteBytes(buffer, FixedSize, InputBuffer.Memory.Span);
        }

        public FileInformationClass FileInformationClass
        {
            get => (FileInformationClass)FileInfoClass;
            set => FileInfoClass = (byte)value;
        }

        public FileSystemInformationClass FileSystemInformationClass
        {
            get => (FileSystemInformationClass)FileInfoClass;
            set => FileInfoClass = (byte)value;
        }

        public SecurityInformation SecurityInformation
        {
            get => (SecurityInformation)AdditionalInformation;
            set => AdditionalInformation = (uint)value;
        }

        public void SetFileInformation(FileInformation fileInformation)
        {
            InputBuffer = fileInformation.GetBytes();
        }

        public override void Dispose()
        {
            base.Dispose();
            InputBuffer.Dispose();

            //FileId.Dispose(); - fileId handle is frequently used for multiple requests and can be disposed via ISMBFileStore.CloseFile(...) method.  
            FileId = default;

            ObjectsPool<QueryInfoRequest>.Return(this);
        }

        public override int CommandLength => FixedSize + InputBuffer.Length();
    }
}
