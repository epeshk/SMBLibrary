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
    /// TRANS2_QUERY_PATH_INFORMATION Request
    /// </summary>
    public class Transaction2QueryPathInformationRequest : Transaction2Subcommand
    {
        private const ushort SmbInfoPassthrough = 0x03E8;
        public const int ParametersFixedLength = 6;
        // Parameters:
        public ushort InformationLevel;
        public uint Reserved;
        public string FileName; // SMB_STRING
        // Data:
        public FullExtendedAttributeList GetExtendedAttributeList; // Used with QueryInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST

        public Transaction2QueryPathInformationRequest()
        {
            GetExtendedAttributeList = new FullExtendedAttributeList();
        }

        public Transaction2QueryPathInformationRequest(IMemoryOwner<byte> parameters, IMemoryOwner<byte> data, bool isUnicode)
        {
            InformationLevel = LittleEndianConverter.ToUInt16(parameters, 0);
            Reserved = LittleEndianConverter.ToUInt32(parameters, 4);
            FileName = SMB1Helper.ReadSMBString(parameters, 6, isUnicode);

            if (!IsPassthroughInformationLevel && QueryInformationLevel == QueryInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST)
            {
                GetExtendedAttributeList = new FullExtendedAttributeList(data.Memory.Span, 0);
            }
        }

        public override void GetSetupInto(Span<byte> target)
        {
            LittleEndianConverter.GetBytes(target, (ushort)SubcommandName);
        }

        public override IMemoryOwner<byte> GetParameters(bool isUnicode)
        {
            var length = ParametersFixedLength;
            if (isUnicode)
            {
                length += FileName.Length * 2 + 2;
            }
            else
            {
                length += FileName.Length + 1;
            }
            var parameters = Arrays.Rent(length);
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 0, InformationLevel);
            LittleEndianWriter.WriteUInt32(parameters.Memory.Span, 2, Reserved);
            SMB1Helper.WriteSMBString(parameters.Memory.Span, 6, isUnicode, FileName);
            return parameters;
        }

        public override IMemoryOwner<byte> GetData(bool isUnicode)
        {
            if (!IsPassthroughInformationLevel && QueryInformationLevel == QueryInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST)
            {
                return GetExtendedAttributeList.GetBytes();
            }

            return MemoryOwner<byte>.Empty;
        }

        public bool IsPassthroughInformationLevel => (InformationLevel >= SmbInfoPassthrough);

        public QueryInformationLevel QueryInformationLevel
        {
            get => (QueryInformationLevel)InformationLevel;
            set => InformationLevel = (ushort)value;
        }

        public FileInformationClass FileInformationClass
        {
            get => (FileInformationClass)(InformationLevel - SmbInfoPassthrough);
            set => InformationLevel = (ushort)((ushort)value + SmbInfoPassthrough);
        }

        public override Transaction2SubcommandName SubcommandName => Transaction2SubcommandName.TRANS2_QUERY_PATH_INFORMATION;
    }
}
