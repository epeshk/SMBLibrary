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
    /// SMB2 SET_INFO Request
    /// </summary>
    public class SetInfoRequest : SMB2Command
    {
        public const int FixedSize = 32;
        public const int DeclaredSize = 33;

        private ushort StructureSize;
        public InfoType InfoType;
        private byte FileInfoClass;
        public uint BufferLength;
        private ushort BufferOffset;
        public ushort Reserved;
        public uint AdditionalInformation;
        public FileID FileId;
        public IMemoryOwner<byte> Buffer = MemoryOwner<byte>.Empty;

        public SetInfoRequest Init()
        {
            InfoType = default;
            FileInfoClass = default;
            BufferLength = default;
            BufferOffset = default;
            Reserved = default;
            AdditionalInformation = default;
            FileId = default;
            Init(SMB2CommandName.SetInfo);
            StructureSize = DeclaredSize;
            return this;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            InfoType = (InfoType)ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            FileInfoClass = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            BufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            BufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 8);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 10);
            AdditionalInformation = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 12);
            FileId = ObjectsPool<FileID>.Get().Init(buffer, offset + Smb2Header.Length + 16);
            Buffer = Arrays.RentFrom<byte>(buffer.Slice(offset + BufferOffset, (int) BufferLength));
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            BufferOffset = 0;
            BufferLength = (uint)Buffer.Length();
            if (Buffer.Length() > 0)
            {
                BufferOffset = Smb2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            BufferWriter.WriteByte(buffer, 2, (byte)InfoType);
            BufferWriter.WriteByte(buffer, 3, FileInfoClass);
            LittleEndianWriter.WriteUInt32(buffer, 4, BufferLength);
            LittleEndianWriter.WriteUInt16(buffer, 8, BufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, 10, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, 12, AdditionalInformation);
            FileId.WriteBytes(buffer, 16);
            BufferWriter.WriteBytes(buffer, FixedSize, Buffer.Memory.Span);
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
            Buffer = fileInformation.GetBytes();
        }

        public void SetFileSystemInformation(FileSystemInformation fileSystemInformation)
        {
            Buffer = fileSystemInformation.GetBytes();
        }

        public void SetSecurityInformation(SecurityDescriptor securityDescriptor)
        {
            Buffer = securityDescriptor.GetBytes();
        }

        public override void Dispose()
        {
            base.Dispose();
            Buffer.Dispose();

            //FileId.Dispose(); - fileId handle is frequently used for multiple requests and can be disposed via ISMBFileStore.CloseFile(...) method.  
            FileId = default;

            ObjectsPool<SetInfoRequest>.Return(this);
        }

        public override int CommandLength => FixedSize + Buffer.Length();
    }
}
