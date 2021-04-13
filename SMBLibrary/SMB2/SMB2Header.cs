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
    public class Smb2Header : IDisposable
    {
        public const int Length = 64;
        public const int SignatureOffset = 48;

        public static readonly byte[] ProtocolSignature = { 0xFE, 0x53, 0x4D, 0x42 };

        private byte[] _protocolId; // 4 bytes, 0xFE followed by "SMB"
        private ushort StructureSize;
        public ushort CreditCharge;
        public NTStatus Status;
        public SMB2CommandName Command;
        public ushort Credits; // CreditRequest or CreditResponse (The number of credits granted to the client)
        public SMB2PacketHeaderFlags Flags;
        public uint NextCommand; // offset in bytes
        public ulong MessageId;
        public uint Reserved; // Sync
        public uint TreeId;   // Sync
        public ulong AsyncId; // Async
        public ulong SessionId;
        public IMemoryOwner<byte> Signature; // 16 bytes (present if SMB2_FLAGS_SIGNED is set)

        public Smb2Header Init(SMB2CommandName commandName, SMB2Command where)
        {
            CreditCharge = default;
            Status = default;
            Credits = default; 
            Flags = default;
            NextCommand = default;
            MessageId = default;
            Reserved = default;
            TreeId = default;  
            AsyncId = default; 
            SessionId = default;
            
            _protocolId = ProtocolSignature;
            StructureSize = Length;
            Command = commandName;
            
            Signature = Arrays.Rent(16);
            return this;
        }

        public Smb2Header Init(Span<byte> buffer, int offset, SMB2Command where)
        {
            Signature = Arrays.Rent<byte>(16);
            _protocolId = ProtocolSignature; //ByteReader.ReadBytes(buffer, offset + 0, 4);
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + 4);
            CreditCharge = LittleEndianConverter.ToUInt16(buffer, offset + 6);
            Status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
            Command = (SMB2CommandName)LittleEndianConverter.ToUInt16(buffer, offset + 12);
            Credits = LittleEndianConverter.ToUInt16(buffer, offset + 14);
            Flags = (SMB2PacketHeaderFlags)LittleEndianConverter.ToUInt32(buffer, offset + 16);
            NextCommand = LittleEndianConverter.ToUInt32(buffer, offset + 20);
            MessageId = LittleEndianConverter.ToUInt64(buffer, offset + 24);
            if ((Flags & SMB2PacketHeaderFlags.AsyncCommand) > 0)
            {
                AsyncId = LittleEndianConverter.ToUInt64(buffer, offset + 32);
            }
            else
            {
                Reserved = LittleEndianConverter.ToUInt32(buffer, offset + 32);
                TreeId = LittleEndianConverter.ToUInt32(buffer, offset + 36);
            }
            SessionId = LittleEndianConverter.ToUInt64(buffer, offset + 40);
            if ((Flags & SMB2PacketHeaderFlags.Signed) > 0)
            {
                ByteReader.ReadBytes(Signature.Memory.Span, buffer, offset + 48, 16);
            }

            return this;
        }

        public void Dispose()
        {
            Signature?.Dispose();
            Signature = null;
            ObjectsPool<Smb2Header>.Return(this);
        }

        public void WriteBytes(Span<byte> buffer, int offset)
        {
            BufferWriter.WriteBytes(buffer, offset + 0, _protocolId);
            LittleEndianWriter.WriteUInt16(buffer, offset + 4, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 6, CreditCharge);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, (uint)Status);
            LittleEndianWriter.WriteUInt16(buffer, offset + 12, (ushort)Command);
            LittleEndianWriter.WriteUInt16(buffer, offset + 14, Credits);
            LittleEndianWriter.WriteUInt32(buffer, offset + 16, (uint)Flags);
            LittleEndianWriter.WriteUInt32(buffer, offset + 20, NextCommand);
            LittleEndianWriter.WriteUInt64(buffer, offset + 24, MessageId);
            if ((Flags & SMB2PacketHeaderFlags.AsyncCommand) > 0)
            {
                LittleEndianWriter.WriteUInt64(buffer, offset + 32, AsyncId);
            }
            else
            {
                LittleEndianWriter.WriteUInt32(buffer, offset + 32, Reserved);
                LittleEndianWriter.WriteUInt32(buffer, offset + 36, TreeId);
            }
            LittleEndianWriter.WriteUInt64(buffer, offset + 40, SessionId);
            if ((Flags & SMB2PacketHeaderFlags.Signed) > 0)
            {
                BufferWriter.WriteBytes(buffer.Slice(offset + 48), Signature.Memory.Span);
            }
        }

        public bool IsResponse
        {
            get => (Flags & SMB2PacketHeaderFlags.ServerToRedir) > 0;
            set
            {
                if (value)
                {
                    Flags |= SMB2PacketHeaderFlags.ServerToRedir;
                }
                else
                {
                    Flags &= ~SMB2PacketHeaderFlags.ServerToRedir;
                }
            }
        }
        
        public bool IsAsync
        {
            get => (Flags & SMB2PacketHeaderFlags.AsyncCommand) > 0;
            set
            {
                if (value)
                {
                    Flags |= SMB2PacketHeaderFlags.AsyncCommand;
                }
                else
                {
                    Flags &= ~SMB2PacketHeaderFlags.AsyncCommand;
                }
            }
        }

        public bool IsRelatedOperations
        {
            get => (Flags & SMB2PacketHeaderFlags.RelatedOperations) > 0;
            set
            {
                if (value)
                {
                    Flags |= SMB2PacketHeaderFlags.RelatedOperations;
                }
                else
                {
                    Flags &= ~SMB2PacketHeaderFlags.RelatedOperations;
                }
            }
        }
        
        public bool IsSigned
        {
            get => (Flags & SMB2PacketHeaderFlags.Signed) > 0;
            set
            {
                if (value)
                {
                    Flags |= SMB2PacketHeaderFlags.Signed;
                }
                else
                {
                    Flags &= ~SMB2PacketHeaderFlags.Signed;
                }
            }
        }

        public static bool IsValidSmb2Header(Span<byte> buffer)
        {
            if (buffer.Length >= 4)
            {
                var protocol = ByteReader.ReadBytes_RentArray(buffer, 0, 4);
                return ByteUtils.AreByteArraysEqual(protocol, ProtocolSignature);
            }
            return false;
        }
    }
}
