/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// LOCKING_ANDX_RANGE32 (10-byte)
    /// or
    /// LOCKING_ANDX_RANGE64 (24-byte )
    /// </summary>
    public class LockingRange
    {
        public const int Length32 = 10;
        public const int Length64 = 20;

        public ushort PID;
        public ulong ByteOffset;
        public ulong LengthInBytes;

        public void Write32(Span<byte> buffer, ref int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, ref offset, PID);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint)ByteOffset);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint)LengthInBytes);
        }

        public void Write64(Span<byte> buffer, ref int offset)
        {
            LittleEndianWriter.WriteUInt16(buffer, ref offset, PID);
            offset += 2; // padding
            LittleEndianWriter.WriteUInt64(buffer, ref offset, ByteOffset);
            LittleEndianWriter.WriteUInt64(buffer, ref offset, LengthInBytes);
        }

        public static LockingRange Read32(Span<byte> buffer, ref int offset)
        {
            var entry = new LockingRange();
            entry.PID = LittleEndianReader.ReadUInt16(buffer, ref offset);
            entry.ByteOffset = LittleEndianReader.ReadUInt32(buffer, ref offset);
            entry.LengthInBytes = LittleEndianReader.ReadUInt32(buffer, ref offset);
            return entry;
        }

        public static LockingRange Read64(Span<byte> buffer, ref int offset)
        {
            var entry = new LockingRange();
            entry.PID = LittleEndianReader.ReadUInt16(buffer, ref offset);
            offset += 2; // padding
            entry.ByteOffset = LittleEndianReader.ReadUInt64(buffer, ref offset);
            entry.LengthInBytes = LittleEndianReader.ReadUInt64(buffer, ref offset);
            return entry;
        }
    }

    /// <summary>
    /// SMB_COM_LOCKING_ANDX Request
    /// </summary>
    public class LockingAndXRequest : SMBAndXCommand
    {
        public const int ParametersLength = 12;
        // Parameters:
        public ushort FID;
        public LockType TypeOfLock;
        public byte NewOpLockLevel;
        public uint Timeout;
        //ushort NumberOfRequestedUnlocks;
        //ushort NumberOfRequestedLocks;
        // Data:
        public List<LockingRange> Unlocks = new List<LockingRange>();
        public List<LockingRange> Locks = new List<LockingRange>();

        public override SMB1Command Init()
        {
            base.Init();
            
            Locks.Clear();
            Unlocks.Clear();
            FID = default;
            TypeOfLock = default;
            NewOpLockLevel = default;
            Timeout = default;

            return this;
        }

        public LockingAndXRequest Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            
            FID = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 4);
            TypeOfLock = (LockType)ByteReader.ReadByte(SmbParameters.Memory.Span, 6);
            NewOpLockLevel = ByteReader.ReadByte(SmbParameters.Memory.Span, 7);
            Timeout = LittleEndianConverter.ToUInt32(SmbParameters.Memory.Span, 8);
            var numberOfRequestedUnlocks = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 12);
            var numberOfRequestedLocks = LittleEndianConverter.ToUInt16(SmbParameters.Memory.Span, 14);

            var dataOffset = 0;
            if ((TypeOfLock & LockType.LARGE_FILES) > 0)
            {
                for (var index = 0; index < numberOfRequestedUnlocks; index++)
                {
                    var entry = LockingRange.Read64(SmbData.Memory.Span, ref dataOffset);
                    Unlocks.Add(entry);
                }

                for (var index = 0; index < numberOfRequestedLocks; index++)
                {
                    var entry = LockingRange.Read64(SmbData.Memory.Span, ref dataOffset);
                    Locks.Add(entry);
                }
            }
            else
            {
                for (var index = 0; index < numberOfRequestedUnlocks; index++)
                {
                    var entry = LockingRange.Read32(SmbData.Memory.Span, ref dataOffset);
                    Unlocks.Add(entry);
                }

                for (var index = 0; index < numberOfRequestedLocks; index++)
                {
                    var entry = LockingRange.Read32(SmbData.Memory.Span, ref dataOffset);
                    Locks.Add(entry);
                }
            }

            return this;
        }

        public override IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            SmbParameters = Arrays.Rent(ParametersLength);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 4, FID);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 6, (byte)TypeOfLock);
            BufferWriter.WriteByte(SmbParameters.Memory.Span, 7, NewOpLockLevel);
            LittleEndianWriter.WriteUInt32(SmbParameters.Memory.Span, 8, Timeout);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 12, (ushort)Unlocks.Count);
            LittleEndianWriter.WriteUInt16(SmbParameters.Memory.Span, 14, (ushort)Locks.Count);

            int dataLength;
            var isLargeFile = (TypeOfLock & LockType.LARGE_FILES) > 0;
            if (isLargeFile)
            {
                dataLength = (Unlocks.Count + Locks.Count) * LockingRange.Length64;
            }
            else
            {
                dataLength = (Unlocks.Count + Locks.Count) * LockingRange.Length32;
            }
            var dataOffset = 0;
            SmbData = Arrays.Rent(dataLength);
            for (var index = 0; index < Unlocks.Count; index++)
            {
                if (isLargeFile)
                {
                    Unlocks[index].Write64(SmbData.Memory.Span, ref dataOffset);
                }
                else
                {
                    Unlocks[index].Write32(SmbData.Memory.Span, ref dataOffset);
                }
            }

            for (var index = 0; index < Locks.Count; index++)
            {
                if (isLargeFile)
                {
                    Locks[index].Write64(SmbData.Memory.Span, ref dataOffset);
                }
                else
                {
                    Locks[index].Write32(SmbData.Memory.Span, ref dataOffset);
                }
            }
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName => CommandName.SMB_COM_LOCKING_ANDX;
    }
}
