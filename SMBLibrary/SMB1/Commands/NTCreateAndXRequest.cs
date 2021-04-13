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
    /// SMB_COM_NT_CREATE_ANDX Request
    /// </summary>
    public class NTCreateAndXRequest : SMBAndXCommand
    {
        public const int ParametersLength = 48;
        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
        public byte Reserved;
        // ushort NameLength; // in bytes
        public NTCreateFlags Flags;
        public uint RootDirectoryFID;
        public AccessMask DesiredAccess;
        public long AllocationSize;
        public ExtendedFileAttributes ExtFileAttributes;
        public ShareAccess ShareAccess;
        public CreateDisposition CreateDisposition;
        public CreateOptions CreateOptions;
        public ImpersonationLevel ImpersonationLevel;
        public SecurityFlags SecurityFlags;
        // Data:
        public string FileName; // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)

        public override SMB1Command Init()
        {
            base.Init();

            return this;
        }

        public override SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            base.Init(buffer, offset, isUnicode);
            Reserved = ByteReader.ReadByte(SmbParameters.Memory.Span, 4);
            var nameLength = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 5);
            Flags = (NTCreateFlags)LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 7);
            RootDirectoryFID = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 11);
            DesiredAccess = (AccessMask)LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 15);
            AllocationSize = LittleEndianConverter.ToInt64(SmbParameters.Memory.Span, 19);
            ExtFileAttributes = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 27);
            ShareAccess = (ShareAccess)LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 31);
            CreateDisposition = (CreateDisposition)LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 35);
            CreateOptions = (CreateOptions)LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 39);
            ImpersonationLevel = (ImpersonationLevel)LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 43);
            SecurityFlags = (SecurityFlags)ByteReader.ReadByte(SmbParameters.Memory.Span, 47);

            var dataOffset = 0;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                dataOffset = 1;
            }
            FileName = SMB1Helper.ReadSMBString(SmbData.Memory.Span, dataOffset, isUnicode);

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            var nameLength = (ushort)FileName.Length;
            if (isUnicode)
            {
                nameLength *= 2;
            }
            SmbParameters = Arrays.Rent(ParametersLength);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 4, Reserved);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 5, nameLength);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 7, (uint)Flags);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 11, RootDirectoryFID);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 15, (uint)DesiredAccess);
            LittleEndianWriter.WriteInt64(SmbParameters.Memory.Span, 19, AllocationSize);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 27, (uint)ExtFileAttributes);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 31, (uint)ShareAccess);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 35, (uint)CreateDisposition);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 39, (uint)CreateOptions);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 43, (uint)ImpersonationLevel);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 47, (byte)SecurityFlags);

            var padding = 0;
            if (isUnicode)
            {
                padding = 1;
                SmbData = Arrays.Rent(padding + FileName.Length * 2 + 2);
            }
            else
            {
                SmbData = Arrays.Rent(FileName.Length + 1);
            }
            SMB1Helper.WriteSMBString(SmbData.Memory.Span, padding, isUnicode, FileName);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_NT_CREATE_ANDX;
    }
}