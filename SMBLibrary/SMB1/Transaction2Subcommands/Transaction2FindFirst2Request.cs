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
    /// TRANS2_FIND_FIRST2 Request
    /// </summary>
    public class Transaction2FindFirst2Request : Transaction2Subcommand
    {
        // Parameters:
        public SMBFileAttributes SearchAttributes;
        public ushort SearchCount;
        public FindFlags Flags;
        public FindInformationLevel InformationLevel;
        public SearchStorageType SearchStorageType;
        public string FileName; // SMB_STRING
        // Data:
        public ExtendedAttributeNameList GetExtendedAttributeList; // Used with FindInformationLevel.SMB_INFO_QUERY_EAS_FROM_LIST

        public Transaction2FindFirst2Request()
        {
            GetExtendedAttributeList = new ExtendedAttributeNameList();
        }

        public Transaction2FindFirst2Request(IMemoryOwner<byte> parameters, IMemoryOwner<byte> data, bool isUnicode)
        {
            SearchAttributes = (SMBFileAttributes)LittleEndianConverter.ToUInt16(parameters, 0);
            SearchCount = LittleEndianConverter.ToUInt16(parameters, 2);
            Flags = (FindFlags)LittleEndianConverter.ToUInt16(parameters, 4);
            InformationLevel = (FindInformationLevel)LittleEndianConverter.ToUInt16(parameters, 6);
            SearchStorageType = (SearchStorageType)LittleEndianConverter.ToUInt32(parameters, 8);
            FileName = SMB1Helper.ReadSMBString(parameters, 12, isUnicode);

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
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 0, (ushort)SearchAttributes);
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 2, SearchCount);
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 4, (ushort)Flags);
            LittleEndianWriter.WriteUInt16(parameters.Memory.Span, 6, (ushort)InformationLevel);
            LittleEndianWriter.WriteUInt32(parameters.Memory.Span, 8, (uint)SearchStorageType);
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

        public bool CloseAfterRequest
        {
            get => ((Flags & FindFlags.SMB_FIND_CLOSE_AFTER_REQUEST) > 0);
            set
            {
                if (value)
                {
                    Flags |= FindFlags.SMB_FIND_CLOSE_AFTER_REQUEST;
                }
                else
                {
                    Flags &= ~FindFlags.SMB_FIND_CLOSE_AFTER_REQUEST;
                }
            }
        }

        public bool CloseAtEndOfSearch
        {
            get => ((Flags & FindFlags.SMB_FIND_CLOSE_AT_EOS) > 0);
            set
            {
                if (value)
                {
                    Flags |= FindFlags.SMB_FIND_CLOSE_AT_EOS;
                }
                else
                {
                    Flags &= ~FindFlags.SMB_FIND_CLOSE_AT_EOS;
                }
            }
        }

        public override Transaction2SubcommandName SubcommandName => Transaction2SubcommandName.TRANS2_FIND_FIRST2;
    }
}
