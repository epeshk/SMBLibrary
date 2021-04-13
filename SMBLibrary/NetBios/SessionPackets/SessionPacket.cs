/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.IO;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.1. SESSION PACKET
    /// [MS-SMB2] 2.1 Transport - Direct TCP transport packet
    /// </summary>
    /// <remarks>
    /// We extend this implementation to support Direct TCP transport packet which utilize the unused session packet flags to extend the maximum trailer length.
    /// </remarks>
    public abstract class SessionPacket<T> : SessionPacketBase where T : SessionPacket<T>
    {
        public T Init()
        {
            TrailerLength = default;
            Trailer = MemoryOwner<byte>.Empty;
            return (T) this;
        }
    }
    
    public abstract class SessionPacketBase : IDisposable
    {
        public const int HeaderLength = 4;
        public const int MaxSessionPacketLength = 131075;
        public const int MaxDirectTcpPacketLength = 16777215;

        public SessionPacketTypeName Type;
        protected int TrailerLength; // Session packet: 17 bits, Direct TCP transport packet: 3 bytes
        public IMemoryOwner<byte> Trailer;
        
        public virtual void Init(Span<byte> buffer)
        {
            var offset = 0;
            Type = (SessionPacketTypeName)ByteReader.ReadByte(buffer, 0);
            TrailerLength = ByteReader.ReadByte(buffer, 1) << 16 | BigEndianConverter.ToUInt16(buffer, 2);

            var container = Arrays.Rent(TrailerLength);
            ByteReader.ReadBytes(container.Memory.Span, buffer, 4, TrailerLength);
            Trailer = container;
        }

        public virtual IMemoryOwner<byte> GetBytes()
        {
            TrailerLength = Trailer.Memory.Length;
            var bufOwner = Arrays.Rent(HeaderLength + TrailerLength);
            var span = bufOwner.Memory.Span;
            var pos = 0;
            
            BufferWriter.WriteByte(span, ref pos, (byte)Type);
            BufferWriter.WriteByte(span, ref pos, Convert.ToByte(TrailerLength >> 16));
            BigEndianWriter.WriteUInt16(span, ref pos, (ushort)(TrailerLength & 0xFFFF));
            BufferWriter.WriteBytes(span, ref pos, Trailer.Memory.Span);

            return bufOwner;
        }

        public virtual int Length => HeaderLength + Trailer.Memory.Length;

        public static int GetSessionPacketLength(Span<byte> buffer, int offset)
        {
            var trailerLength = ByteReader.ReadByte(buffer, offset + 1) << 16 | BigEndianConverter.ToUInt16(buffer, offset + 2);
            return 4 + trailerLength;
        }

        public static SessionPacketBase GetSessionPacket(Span<byte> buffer, int offset)
        {
            var type = (SessionPacketTypeName)ByteReader.ReadByte(buffer, offset);
            
            SessionPacketBase packet = type switch
            {
                SessionPacketTypeName.SessionMessage => ObjectsPool<SessionMessagePacket>.Get(),
                SessionPacketTypeName.SessionRequest => ObjectsPool<SessionRequestPacket>.Get(),
                SessionPacketTypeName.PositiveSessionResponse => ObjectsPool<PositiveSessionResponsePacket>.Get(),
                SessionPacketTypeName.NegativeSessionResponse => ObjectsPool<NegativeSessionResponsePacket>.Get(),
                SessionPacketTypeName.RetargetSessionResponse => ObjectsPool<SessionRetargetResponsePacket>.Get(),
                SessionPacketTypeName.SessionKeepAlive => ObjectsPool<SessionKeepAlivePacket>.Get(),
                _ => throw new InvalidDataException($"Invalid NetBIOS session packet type: 0x{(byte)type:X2}")
            };
            
            packet.Init(buffer.Slice(offset));
            return packet;
        }

        public virtual void Dispose()
        {
            Trailer?.Dispose();
            Trailer = null;
        }
    }
}
