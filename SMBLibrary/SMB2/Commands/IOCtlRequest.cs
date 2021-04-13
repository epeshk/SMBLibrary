/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 IOCTL Request
    /// </summary>
    public class IOCtlRequest : SMB2Command
    {
        public const int FixedLength = 56;
        public const int DeclaredSize = 57;

        private ushort StructureSize;
        public ushort Reserved;
        public uint CtlCode;
        public FileID FileId;
        private uint InputOffset;
        private uint InputCount;
        public uint MaxInputResponse;
        private uint OutputOffset;
        private uint OutputCount;
        public uint MaxOutputResponse;
        public IOCtlRequestFlags Flags;
        public uint Reserved2;
        public IMemoryOwner<byte> Input = MemoryOwner<byte>.Empty;
        public IMemoryOwner<byte> Output = MemoryOwner<byte>.Empty;

        public IOCtlRequest()
        {
            Init(SMB2CommandName.IOCtl);
            StructureSize = DeclaredSize;
        }

        public override SMB2Command Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 2);
            CtlCode = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 4);
            FileId = ObjectsPool<FileID>.Get().Init(buffer, offset + Smb2Header.Length + 8);
            InputOffset = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 24);
            InputCount = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 28);
            MaxInputResponse = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 32);
            OutputOffset = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 36);
            OutputCount = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 40);
            MaxOutputResponse = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 44);
            Flags = (IOCtlRequestFlags)LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 48);
            Reserved2 = LittleEndianConverter.ToUInt32(buffer, offset + Smb2Header.Length + 52);
            Input = Arrays.RentFrom<byte>(buffer.Slice(offset + (int)InputOffset, (int)InputCount));
            Output = Arrays.RentFrom<byte>(buffer.Slice(offset + (int)OutputOffset, (int)OutputCount));
            return this;
        }

        public override void WriteCommandBytes(Span<byte> buffer)
        {
            InputOffset = 0;
            InputCount = (uint)Input.Length();
            OutputOffset = 0;
            OutputCount = (uint)Output.Length();
            if (Input.Length() > 0)
            {
                InputOffset = Smb2Header.Length + FixedLength;
            }
            if (Output.Length() > 0)
            {
                OutputOffset = Smb2Header.Length + FixedLength + (uint)Input.Length();
            }
            LittleEndianWriter.WriteUInt16(buffer, 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, 2, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, 4, CtlCode);
            FileId.WriteBytes(buffer, 8);
            LittleEndianWriter.WriteUInt32(buffer, 24, InputOffset);
            LittleEndianWriter.WriteUInt32(buffer, 28, InputCount);
            LittleEndianWriter.WriteUInt32(buffer, 32, MaxInputResponse);
            LittleEndianWriter.WriteUInt32(buffer, 36, OutputOffset);
            LittleEndianWriter.WriteUInt32(buffer, 40, OutputCount);
            LittleEndianWriter.WriteUInt32(buffer, 44, MaxOutputResponse);
            LittleEndianWriter.WriteUInt32(buffer, 48, (uint)Flags);
            LittleEndianWriter.WriteUInt32(buffer, 52, Reserved2);
            if (Input.Length() > 0)
            {
                BufferWriter.WriteBytes(buffer, FixedLength, Input.Memory.Span);
            }
            if (Output.Length() > 0)
            {
                BufferWriter.WriteBytes(buffer,  FixedLength + Input.Length(), Output.Memory.Span);
            }
        }

        public bool IsFSCtl
        {
            get => (Flags & IOCtlRequestFlags.IsFSCtl) > 0;
            set
            {
                if (value)
                {
                    Flags |= IOCtlRequestFlags.IsFSCtl;
                }
                else
                {
                    Flags &= ~IOCtlRequestFlags.IsFSCtl;
                }
            }
        }

        public override void Dispose()
        {
            base.Dispose();
            Input.Dispose();
            Output.Dispose();
            Input = Output = null;
            FileId = default;
            ObjectsPool<IOCtlRequest>.Return(this);
        }

        public override int CommandLength => FixedLength + Input.Length() + Output.Length();
    }
}
