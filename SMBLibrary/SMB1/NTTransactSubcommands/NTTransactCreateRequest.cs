/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// NT_TRANSACT_CREATE Request
    /// </summary>
    public class NTTransactCreateRequest : NTTransactSubcommand
    {
        public const int ParametersFixedLength = 53;
        // Parameters:
        public NTCreateFlags Flags;
        public uint RootDirectoryFID;
        public AccessMask DesiredAccess;
        public long AllocationSize;
        public ExtendedFileAttributes ExtFileAttributes;
        public ShareAccess ShareAccess;
        public CreateDisposition CreateDisposition;
        public CreateOptions CreateOptions;
        // uint SecurityDescriptiorLength;
        // uint EALength;
        // uint NameLength;
        public ImpersonationLevel ImpersonationLevel;
        public SecurityFlags SecurityFlags;
        public string Name; // OEM / Unicode. NOT null terminated. (MUST be aligned to start on a 2-byte boundary from the start of the NT_Trans_Parameters)
        // Data:
        public SecurityDescriptor SecurityDescriptor;
        public List<FileFullEAEntry> ExtendedAttributes;

        public NTTransactCreateRequest()
        {
        }

        public NTTransactCreateRequest(IMemoryOwner<byte> parameters, IMemoryOwner<byte> data, bool isUnicode)
        {
            var parametersOffset = 0;
            Flags = (NTCreateFlags)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            RootDirectoryFID = LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            DesiredAccess = (AccessMask)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            AllocationSize = LittleEndianReader.ReadInt64(parameters, ref parametersOffset);
            ExtFileAttributes = LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            ShareAccess = (ShareAccess)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            CreateDisposition = (CreateDisposition)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            CreateOptions = (CreateOptions)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            var securityDescriptiorLength = LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            var eaLength = LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            var nameLength = LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            ImpersonationLevel = (ImpersonationLevel)LittleEndianReader.ReadUInt32(parameters, ref parametersOffset);
            SecurityFlags = (SecurityFlags)ByteReader.ReadByte(parameters, ref parametersOffset);

            if (isUnicode)
            {
                parametersOffset++;
            }
            Name = SMB1Helper.ReadFixedLengthString(parameters.Memory.Span, ref parametersOffset, isUnicode, (int)nameLength);
            if (securityDescriptiorLength > 0)
            {
                SecurityDescriptor = new SecurityDescriptor(data.Memory.Span, 0);
            }
            ExtendedAttributes = FileFullEAInformation.ReadList(data.Memory.Span, (int)securityDescriptiorLength);
        }

        public override IMemoryOwner<byte> GetParameters(bool isUnicode)
        {
            throw new NotImplementedException();
        }

        public override IMemoryOwner<byte> GetData()
        {
            throw new NotImplementedException();
        }

        public override NTTransactSubcommandName SubcommandName => NTTransactSubcommandName.NT_TRANSACT_CREATE;
    }
}
