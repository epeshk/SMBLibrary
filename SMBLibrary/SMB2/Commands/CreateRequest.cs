/* Copyright (C) 2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// SMB2 CREATE Request
    /// </summary>
    public class CreateRequest : SMB2Command
    {
        public const int FixedLength = 56;
        public const int DeclaredSize = 57;

        private ushort StructureSize;
        public byte SecurityFlags; // Reserved
        public OplockLevel RequestedOplockLevel;
        public ImpersonationLevel ImpersonationLevel;
        public ulong SmbCreateFlags;
        public ulong Reserved;
        public AccessMask DesiredAccess;
        public FileAttributes FileAttributes;
        public ShareAccess ShareAccess;
        public CreateDisposition CreateDisposition;
        public CreateOptions CreateOptions;
        private ushort NameOffset;
        private ushort NameLength;
        private uint CreateContextsOffset; // 8-byte aligned
        private uint CreateContextsLength;
        public IMemoryOwner<char> Name;
        public List<CreateContext> CreateContexts = new List<CreateContext>();

        public CreateRequest Init()
        {
            SecurityFlags = default;
            RequestedOplockLevel = default;
            ImpersonationLevel = default;
            SmbCreateFlags = default;
            Reserved = default;
            DesiredAccess = default;
            FileAttributes = default;
            ShareAccess = default;
            CreateDisposition = default;
            CreateOptions = default;
            NameOffset = default;
            NameLength = default;
            CreateContextsOffset = default; 
            CreateContextsLength = default;
        
            Init(SMB2CommandName.Create);
            StructureSize = DeclaredSize;
            return this;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            SecurityFlags = ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 2);
            RequestedOplockLevel = (OplockLevel)ByteReader.ReadByte(buffer, offset + Smb2Header.Length + 3);
            ImpersonationLevel = (ImpersonationLevel)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            SmbCreateFlags = LittleEndianConverter.ToUInt64(buffer, offset + Smb2Header.Length + 8);
            Reserved = LittleEndianConverter.ToUInt64(buffer, offset + Smb2Header.Length + 16);
            DesiredAccess = (AccessMask)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 24);
            FileAttributes = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 28);
            ShareAccess = (ShareAccess)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 32);
            CreateDisposition = (CreateDisposition)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 36);
            CreateOptions = (CreateOptions)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 40);
            NameOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 44);
            NameLength = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 46);
            CreateContextsOffset = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 48);
            CreateContextsLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 52);
            Name = Arrays.Rent<char>(NameLength / 2); 
            
            ByteReader.ReadUTF16String(Name.Memory.Span, buffer, offset + NameOffset, NameLength / 2);
            if (CreateContextsLength > 0)
            {
                CreateContexts = CreateContext.ReadCreateContextList(buffer, (int)CreateContextsOffset);
            }
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            // [MS-SMB2] The NameOffset field SHOULD be set to the offset of the Buffer field from the beginning of the SMB2 header.
            // Note: Windows 8.1 / 10 will return STATUS_INVALID_PARAMETER if NameOffset is set to 0.
            NameOffset = Smb2Header.Length + FixedLength;
            NameLength = (ushort)(Name.Memory.Length * 2);
            CreateContextsOffset = 0;
            CreateContextsLength = 0;
            var paddedNameLength = (int)Math.Ceiling((double)(Name.Memory.Length * 2) / 8) * 8;
            if (CreateContexts.Count > 0)
            {
                CreateContextsOffset = (uint)(Smb2Header.Length + FixedLength + paddedNameLength);
                CreateContextsLength = (uint)CreateContext.GetCreateContextListLength(CreateContexts);
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            BufferWriter.WriteByte(buffer, 2, SecurityFlags);
            BufferWriter.WriteByte(buffer, 3, (byte)RequestedOplockLevel);
            LittleEndianWriter.WriteUInt32(buffer, 4, (uint)ImpersonationLevel);
            LittleEndianWriter.WriteUInt64(buffer, 8, SmbCreateFlags);
            LittleEndianWriter.WriteUInt64(buffer, 16, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, 24, (uint)DesiredAccess);
            LittleEndianWriter.WriteUInt32(buffer, 28, (uint)FileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, 32, (uint)ShareAccess);
            LittleEndianWriter.WriteUInt32(buffer, 36, (uint)CreateDisposition);
            LittleEndianWriter.WriteUInt32(buffer, 40, (uint)CreateOptions);
            LittleEndianWriter.WriteUInt16(buffer, 44, NameOffset);
            LittleEndianWriter.WriteUInt16(buffer, 46, NameLength);
            LittleEndianWriter.WriteUInt32(buffer, 48, CreateContextsOffset);
            LittleEndianWriter.WriteUInt32(buffer, 52, CreateContextsLength);
            BufferWriter.WriteUTF16String(buffer, 56, Name.Memory.Span);
            CreateContext.WriteCreateContextList(buffer, 56 + paddedNameLength, CreateContexts);
        }

        public override int CommandLength
        {
            get
            {
                int bufferLength;
                if (CreateContexts.Count == 0)
                {
                    bufferLength = Name.Memory.Length * 2;
                }
                else
                {
                    var paddedNameLength = (int)Math.Ceiling((double)(Name.Memory.Length * 2) / 8) * 8;
                    bufferLength = paddedNameLength + CreateContext.GetCreateContextListLength(CreateContexts);
                }
                // [MS-SMB2] The Buffer field MUST be at least one byte in length.
                return FixedLength + Math.Max(bufferLength, 1);
            }
        }

        public override void Dispose()
        {
            if (Name != null)
            {
                Name.Dispose();
                base.Dispose();
                Name = null;
                ObjectsPool<CreateRequest>.Return(this);
            }
        }
    }
}
