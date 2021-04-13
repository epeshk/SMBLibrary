/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// TRANS2_OPEN2 Request
    /// </summary>
    public class Transaction2Open2Request : Transaction2Subcommand
    {
        // Parameters:
        public Open2Flags Flags;
        public AccessModeOptions AccessMode;
        public ushort Reserved1;
        public SMBFileAttributes FileAttributes;
        public DateTime? CreationTime; // UTIME (seconds since Jan 1, 1970)
        public OpenMode OpenMode;
        public uint AllocationSize;
        public IMemoryOwner<byte> Reserved; // 10 bytes
        public string FileName; // SMB_STRING
        // Data:
        public FullExtendedAttributeList ExtendedAttributeList;

        public Transaction2Open2Request()
        {
            Reserved = Arrays.Rent(10);
        }

        public Transaction2Open2Request(IMemoryOwner<byte> parameters, IMemoryOwner<byte> data, bool isUnicode)
        {
            Flags = (Open2Flags)LittleEndianConverter.ToUInt16(parameters, 0);
            AccessMode = new AccessModeOptions(parameters.Memory.Span, 2);
            Reserved1 = LittleEndianConverter.ToUInt16(parameters, 4);
            FileAttributes = (SMBFileAttributes)LittleEndianConverter.ToUInt16(parameters, 6);
            CreationTime = UTimeHelper.ReadNullableUTime(parameters, 8);
            OpenMode = new OpenMode(parameters.Memory.Span, 12);
            AllocationSize = LittleEndianConverter.ToUInt32(parameters, 14);
            Reserved = Arrays.RentFrom<byte>(parameters.Memory.Span.Slice(18, 10));
            FileName = SMB1Helper.ReadSMBString(parameters, 28, isUnicode);

            ExtendedAttributeList = new FullExtendedAttributeList(data.Memory.Span, 0);
        }

        public override void GetSetupInto(Span<byte> target)
        {
            LittleEndianConverter.GetBytes(target, (ushort)SubcommandName);
        }

        public override IMemoryOwner<byte> GetParameters(bool isUnicode)
        {
            var length = 28;
            if (isUnicode)
            {
                length += FileName.Length * 2 + 2;
            }
            else
            {
                length += FileName.Length + 1;
            }

            var parameters = Arrays.Rent(length);
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 0, (ushort)Flags);
            AccessMode.WriteBytes(parameters.Memory.Span, 2);
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 4, Reserved1);
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 6, (ushort)FileAttributes);
            UTimeHelper.WriteUTime(parameters.Memory.Span, 8, CreationTime);
            OpenMode.WriteBytes(parameters.Memory.Span, 12);
            LittleEndianWriter.WriteUInt32(parameters.Memory.Span, 14, AllocationSize);
            BufferWriter.WriteBytes(parameters.Memory.Span, 18, Reserved.Memory.Span, 10);
            SMB1Helper.WriteSMBString(parameters.Memory.Span, 28, isUnicode, FileName);
            return parameters;
        }

        public override IMemoryOwner<byte> GetData(bool isUnicode)
        {
            return ExtendedAttributeList.GetBytes();
        }

        public override Transaction2SubcommandName SubcommandName => Transaction2SubcommandName.TRANS2_OPEN2;

        public override void Dispose()
        {
            base.Dispose();
            Reserved.Dispose();
        }
    }
}
