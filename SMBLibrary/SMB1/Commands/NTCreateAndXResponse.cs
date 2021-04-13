/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_NT_CREATE_ANDX Response
    /// </summary>
    public class NTCreateAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 68;
        // Parameters:
        //CommandName AndXCommand;
        //byte AndXReserved;
        //ushort AndXOffset;
        public OpLockLevel OpLockLevel;
        public ushort FID;
        public CreateDisposition CreateDisposition;
        public DateTime? CreateTime;
        public DateTime? LastAccessTime;
        public DateTime? LastWriteTime;
        public DateTime? LastChangeTime;
        public ExtendedFileAttributes ExtFileAttributes;
        public long AllocationSize;
        public long EndOfFile;
        public ResourceType ResourceType;
        public NamedPipeStatus NMPipeStatus;
        public bool Directory;

        public override SMB1Command Init()
        {
            base.Init();
            OpLockLevel = default;
            FID = default;
            CreateDisposition = default;
            CreateTime = default;
            LastAccessTime = default;
            LastWriteTime = default;
            LastChangeTime = default;
            ExtFileAttributes = default;
            AllocationSize = default;
            EndOfFile = default;
            ResourceType = default;
            NMPipeStatus = default;
            Directory = default;

            return this;
        }

        public NTCreateAndXResponse Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            
            var parametersOffset = 4;
            OpLockLevel = (OpLockLevel)ByteReader.ReadByte(SmbParameters.Memory.Span, ref parametersOffset);
            FID = LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            CreateDisposition = (CreateDisposition)LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);
            CreateTime = SMB1Helper.ReadNullableFileTime(SmbParameters.Memory.Span, ref parametersOffset);
            LastAccessTime = SMB1Helper.ReadNullableFileTime(SmbParameters.Memory.Span, ref parametersOffset);
            LastWriteTime = SMB1Helper.ReadNullableFileTime(SmbParameters.Memory.Span, ref parametersOffset);
            LastChangeTime = SMB1Helper.ReadNullableFileTime(SmbParameters.Memory.Span, ref parametersOffset);
            ExtFileAttributes = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);
            AllocationSize = LittleEndianReader.ReadInt64(SmbParameters.Memory.Span, ref parametersOffset);
            EndOfFile = LittleEndianReader.ReadInt64(SmbParameters.Memory.Span, ref parametersOffset);
            ResourceType = (ResourceType)LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            NMPipeStatus = NamedPipeStatus.Read(SmbParameters.Memory.Span, ref parametersOffset);
            Directory = (ByteReader.ReadByte(SmbParameters.Memory.Span, ref parametersOffset) > 0);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            var parametersOffset = 4;
            BufferWriter.WriteByte(SmbParameters.Memory.Span, ref parametersOffset, (byte)OpLockLevel);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, FID);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, (uint)CreateDisposition);
            FileTimeHelper.WriteFileTime(SmbParameters.Memory.Span, ref parametersOffset, CreateTime);
            FileTimeHelper.WriteFileTime(SmbParameters.Memory.Span, ref parametersOffset, LastAccessTime);
            FileTimeHelper.WriteFileTime(SmbParameters.Memory.Span, ref parametersOffset, LastWriteTime);
            FileTimeHelper.WriteFileTime(SmbParameters.Memory.Span, ref parametersOffset, LastChangeTime);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, (uint)ExtFileAttributes);
            LittleEndianWriter.WriteInt64(SmbParameters.Memory.Span, ref parametersOffset, AllocationSize);
            LittleEndianWriter.WriteInt64(SmbParameters.Memory.Span, ref parametersOffset, EndOfFile);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, (ushort)ResourceType);
            NMPipeStatus.WriteBytes(SmbParameters.Memory.Span, ref parametersOffset);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, ref parametersOffset, Convert.ToByte(Directory));
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_NT_CREATE_ANDX;
    }
}
