/* Copyright (C) 2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 CREATE Request
    /// </summary>
    public class CreateRequest : SMB2Request
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
        public string Name;
        public List<CreateContext> CreateContexts = new List<CreateContext>();

        public CreateRequest() : base(SMB2CommandName.Create)
        {
            StructureSize = DeclaredSize;
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            // [MS-SMB2] The NameOffset field SHOULD be set to the offset of the Buffer field from the beginning of the SMB2 header.
            // Note: Windows 8.1 / 10 will return STATUS_INVALID_PARAMETER if NameOffset is set to 0.
            NameOffset = SMB2Header.Length + FixedLength;
            NameLength = (ushort)(Name.Length * 2);
            CreateContextsOffset = 0;
            CreateContextsLength = 0;
            int paddedNameLength = (int)Math.Ceiling((double)(Name.Length * 2) / 8) * 8;
            if (CreateContexts.Count > 0)
            {
                CreateContextsOffset = (uint)(SMB2Header.Length + FixedLength + paddedNameLength);
                CreateContextsLength = (uint)CreateContext.GetCreateContextListLength(CreateContexts);
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            ByteWriter.WriteByte(buffer, offset + 2, SecurityFlags);
            ByteWriter.WriteByte(buffer, offset + 3, (byte)RequestedOplockLevel);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, (uint)ImpersonationLevel);
            LittleEndianWriter.WriteUInt64(buffer, offset + 8, (ulong)SmbCreateFlags);
            LittleEndianWriter.WriteUInt64(buffer, offset + 16, (ulong)Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 24, (uint)DesiredAccess);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, (uint)FileAttributes);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, (uint)ShareAccess);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, (uint)CreateDisposition);
            LittleEndianWriter.WriteUInt32(buffer, offset + 40, (uint)CreateOptions);
            LittleEndianWriter.WriteUInt16(buffer, offset + 44, NameOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 46, NameLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 48, CreateContextsOffset);
            LittleEndianWriter.WriteUInt32(buffer, offset + 52, CreateContextsLength);
            ByteWriter.WriteUTF16String(buffer, offset + 56, Name);
            CreateContext.WriteCreateContextList(buffer, offset + 56 + paddedNameLength, CreateContexts);
        }

        public override int CommandLength
        {
            get
            {
                int bufferLength;
                if (CreateContexts.Count == 0)
                {
                    bufferLength = Name.Length * 2;
                }
                else
                {
                    int paddedNameLength = (int)Math.Ceiling((double)(Name.Length * 2) / 8) * 8;
                    bufferLength = paddedNameLength + CreateContext.GetCreateContextListLength(CreateContexts);
                }
                // [MS-SMB2] The Buffer field MUST be at least one byte in length.
                return FixedLength + Math.Max(bufferLength, 1);
            }
        }
    }
}
