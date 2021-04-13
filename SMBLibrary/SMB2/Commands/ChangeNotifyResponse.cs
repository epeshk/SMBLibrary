/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// SMB2 CHANGE_NOTIFY Response
    /// </summary>
    public class ChangeNotifyResponse : SMB2Command
    {
        public const int FixedSize = 8;
        public const int DeclaredSize = 9;

        private ushort StructureSize;
        private ushort OutputBufferOffset;
        private uint OutputBufferLength;
        public IMemoryOwner<byte> OutputBuffer = MemoryOwner<byte>.Empty;

        public ChangeNotifyResponse()
        {
            Init(SMB2CommandName.ChangeNotify);
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            OutputBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            OutputBufferLength = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            OutputBuffer = Arrays.RentFrom<byte>(buffer.Slice(offset + OutputBufferOffset, (int)OutputBufferLength));
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            OutputBufferOffset = 0;
            OutputBufferLength = (uint)OutputBuffer.Length();
            if (OutputBuffer.Length() > 0)
            {
                OutputBufferOffset = Smb2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, OutputBufferOffset);
            LittleEndianWriter.WriteUInt32(buffer, 4, OutputBufferLength);
            BufferWriter.WriteBytes(buffer, FixedSize, OutputBuffer.Memory.Span);
        }

        public List<FileNotifyInformation> GetFileNotifyInformation()
        {
            return FileNotifyInformation.ReadList(OutputBuffer.Memory.Span, 0);
        }

        public void SetFileNotifyInformation(List<FileNotifyInformation> notifyInformationList)
        {
            OutputBuffer = FileNotifyInformation.GetBytes(notifyInformationList);
        }

        public override void Dispose()
        {
            base.Dispose();
            ObjectsPool<ChangeNotifyResponse>.Return(this);
        }

        public override int CommandLength => FixedSize + OutputBuffer.Length();
    }
}
