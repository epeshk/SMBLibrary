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
    /// SMB_COM_NT_CREATE_ANDX Extended Response
    /// </summary>
    public class NTCreateAndXResponseExtended : SMBAndXCommand
    {
        public const int ParametersLength = 100;
        // [MS-SMB] Section 2.2.4.9.2 and Note <49>:
        // Windows-based SMB servers send 50 (0x32) words in the extended response although they set the WordCount field to 0x2A.
        public const int DeclaredParametersLength = 84;
        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
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
        public ushort NMPipeStatus_or_FileStatusFlags;
        public bool Directory;
        public Guid VolumeGuid;
        public ulong FileID;
        public AccessMask MaximalAccessRights;
        public AccessMask GuestMaximalAccessRights;
        
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
            NMPipeStatus_or_FileStatusFlags = default;
            Directory = default;
            VolumeGuid = default;
            FileID = default;
            MaximalAccessRights = default;
            GuestMaximalAccessRights = default;
            return this;
        }

        public NTCreateAndXResponseExtended Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            var parametersOffset = 4;
            OpLockLevel = (OpLockLevel)ByteReader.ReadByte(SmbParameters.Memory.Span, ref parametersOffset);
            FID = LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            CreateDisposition = (CreateDisposition)LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);
            CreateTime = FileTimeHelper.ReadNullableFileTime(SmbParameters.Memory.Span, ref parametersOffset);
            LastAccessTime = FileTimeHelper.ReadNullableFileTime(SmbParameters.Memory.Span, ref parametersOffset);
            LastWriteTime = FileTimeHelper.ReadNullableFileTime(SmbParameters.Memory.Span, ref parametersOffset);
            LastChangeTime = FileTimeHelper.ReadNullableFileTime(SmbParameters.Memory.Span, ref parametersOffset);
            ExtFileAttributes = LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);
            AllocationSize = LittleEndianReader.ReadInt64(SmbParameters.Memory.Span, ref parametersOffset);
            EndOfFile = LittleEndianReader.ReadInt64(SmbParameters.Memory.Span, ref parametersOffset);
            ResourceType = (ResourceType)LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            NMPipeStatus_or_FileStatusFlags = LittleEndianReader.ReadUInt16(SmbParameters.Memory.Span, ref parametersOffset);
            Directory = (ByteReader.ReadByte(SmbParameters.Memory.Span, ref parametersOffset) > 0);
            VolumeGuid = LittleEndianReader.ReadGuid(SmbParameters.Memory.Span, ref parametersOffset);
            FileID = LittleEndianReader.ReadUInt64(SmbParameters.Memory.Span, ref parametersOffset);
            MaximalAccessRights = (AccessMask)LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);
            GuestMaximalAccessRights = (AccessMask)LittleEndianReader.ReadUInt32(SmbParameters.Memory.Span, ref parametersOffset);
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
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, ref parametersOffset, NMPipeStatus_or_FileStatusFlags);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, ref parametersOffset, Convert.ToByte(Directory));
            LittleEndianWriter.WriteGuidBytes(SmbParameters.Memory.Span, ref parametersOffset, VolumeGuid);
            LittleEndianWriter.WriteUInt64(SmbParameters.Memory.Span, ref parametersOffset, FileID);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, (uint)MaximalAccessRights);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, ref parametersOffset, (uint)GuestMaximalAccessRights);
            return base.GetBytes(isUnicode);
        }

        public NamedPipeStatus NMPipeStatus
        {
            get => new NamedPipeStatus(NMPipeStatus_or_FileStatusFlags);
            set => NMPipeStatus_or_FileStatusFlags = value.ToUInt16();
        }

        public FileStatusFlags FileStatusFlags
        {
            get => (FileStatusFlags)NMPipeStatus_or_FileStatusFlags;
            set => NMPipeStatus_or_FileStatusFlags = (ushort)value;
        }

        public override CommandName CommandName => CommandName.SMB_COM_NT_CREATE_ANDX;
    }
}
