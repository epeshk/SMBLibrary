/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using System.Collections.Generic;
using MemoryPools.Memory;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// NT_TRANSACT_NOTIFY_CHANGE Response
    /// </summary>
    public class NTTransactNotifyChangeResponse : NTTransactSubcommand
    {
        // Parameters:
        public IMemoryOwner<byte> FileNotifyInformationBytes;

        public NTTransactNotifyChangeResponse()
        {
        }

        public NTTransactNotifyChangeResponse(IMemoryOwner<byte> parameters)
        {
            FileNotifyInformationBytes = parameters.AddOwner();
        }

        public override IMemoryOwner<byte> GetParameters(bool isUnicode)
        {
            return FileNotifyInformationBytes;
        }

        public List<FileNotifyInformation> GetFileNotifyInformation()
        {
            return FileNotifyInformation.ReadList(FileNotifyInformationBytes.Memory.Span, 0);
        }

        public void SetFileNotifyInformation(List<FileNotifyInformation> notifyInformationList)
        {
            FileNotifyInformationBytes = FileNotifyInformation.GetBytes(notifyInformationList);
        }

        public override NTTransactSubcommandName SubcommandName => NTTransactSubcommandName.NT_TRANSACT_NOTIFY_CHANGE;

        public override void Dispose()
        {
            base.Dispose();
            FileNotifyInformationBytes.Dispose();
            FileNotifyInformationBytes = null;
        }
    }
}
