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
    /// TRANS2_FIND_NEXT2 Request
    /// </summary>
    public class Transaction2FindNext2Request : Transaction2Subcommand
    {
        // Parameters:
        public ushort SID; // Search handle
        public ushort SearchCount;
        public FindInformationLevel InformationLevel;
        public uint ResumeKey;
        public FindFlags Flags;
        public string FileName; // SMB_STRING
        // Data:
        public ExtendedAttributeNameList GetExtendedAttributeList; // Used with FindInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST

        public Transaction2FindNext2Request()
        {
            GetExtendedAttributeList = new ExtendedAttributeNameList();
        }

        public Transaction2FindNext2Request(IMemoryOwner<byte> parameters, IMemoryOwner<byte> data, bool isUnicode)
        {
            SID = LittleEndianConverter.ToUInt16(parameters.Memory.Span, 0);
            SearchCount = LittleEndianConverter.ToUInt16(parameters.Memory.Span, 2);
            InformationLevel = (FindInformationLevel)LittleEndianConverter.ToUInt16(parameters.Memory.Span, 4);
            ResumeKey = LittleEndianConverter.ToUInt32(parameters.Memory.Span, 6);
            Flags = (FindFlags)LittleEndianConverter.ToUInt16(parameters.Memory.Span, 10);
            FileName = SMB1Helper.ReadSMBString(parameters.Memory.Span, 12, isUnicode);

            if (InformationLevel == FindInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST)
            {
                GetExtendedAttributeList = new ExtendedAttributeNameList(data.Memory.Span, 0);
            }
        }

        public override void GetSetupInto(Span<byte> target)
        {
            LittleEndianConverter.GetBytes(target, (ushort)SubcommandName);
        }

        public override IMemoryOwner<byte> GetParameters(bool isUnicode)
        {
            var length = 12;
            if (isUnicode)
            {
                length += FileName.Length * 2 + 2;
            }
            else
            {
                length += FileName.Length + 1;
            }

            var parameters = Arrays.Rent(length);
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 0, SID);
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 2, SearchCount);
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 4, (ushort)InformationLevel);
            LittleEndianWriter.WriteUInt32(parameters.Memory.Span, 6, ResumeKey);
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 10, (ushort)Flags);
            SMB1Helper.WriteSMBString(parameters.Memory.Span, 12, isUnicode, FileName);

            return parameters;
        }

        public override IMemoryOwner<byte> GetData(bool isUnicode)
        {
            if (InformationLevel == FindInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST)
            {
                return GetExtendedAttributeList.GetBytes();
            }

            return MemoryOwner<byte>.Empty;
        }

        public override Transaction2SubcommandName SubcommandName => Transaction2SubcommandName.TRANS2_FIND_NEXT2;
    }
}
