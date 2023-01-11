/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * Copyright (C) 2023 Eugene Peshkov and SMBLibrary.Async contributors. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Buffers;
using System.IO;
using System.Linq;
using SMBLibrary.SMB2;
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
    public abstract class SessionPacket
    {
        public const int HeaderLength = 4;
        public const int MaxSessionPacketLength = 131075;
        public const int MaxDirectTcpPacketLength = 16777215;

        public SessionPacketTypeName Type;
        private int TrailerLength; // Session packet: 17 bits, Direct TCP transport packet: 3 bytes
        public ArraySegment<byte>[] Trailer;

        public byte[] TrailerBytes
        {
            get
            {
                if (Trailer == null || Trailer.Length == 0) return null;
                if (Trailer.Length > 1)
                    throw new Exception();
                return Trailer[0].Array;
            }
            set
            {
                if (Trailer != null && Trailer.Length > 1)
                    throw new Exception();
                Trailer = new ArraySegment<byte>[] { value };
            }
        }

        public SessionPacket()
        {
        }

        internal SessionPacket(byte[] buffer, int offset, ArrayPool<byte> pool, ITrailerDecryptor decryptor=null)
        {
            Type = (SessionPacketTypeName)ByteReader.ReadByte(buffer, offset + 0);
            TrailerLength = ByteReader.ReadByte(buffer, offset + 1) << 16 | BigEndianConverter.ToUInt16(buffer, offset + 2);

            var trailer = buffer.AsSpan(offset + 4, TrailerLength);
            if (decryptor != null)
                trailer = decryptor.DecryptTrailer(trailer);

            SMB2CommandName commandName = (SMB2CommandName)LittleEndianConverter.ToUInt16(trailer, 12);
            var structureSize = LittleEndianConverter.ToUInt16(trailer, SMB2Header.Length + 0);
            
            if (commandName == SMB2CommandName.Read && structureSize == ReadResponse.DeclaredSize)
            {
                var dataOffset = ByteReader.ReadByte(trailer, SMB2Header.Length + 2);
                var dataLength = (int)LittleEndianConverter.ToUInt32(trailer, SMB2Header.Length + 4);
                var beginningArray = pool.Rent(dataOffset);
                var array = pool.Rent(dataLength);

                trailer.Slice(0, dataOffset).CopyTo(beginningArray);
                trailer.Slice(dataOffset, dataLength).CopyTo(array);

                Trailer = new ArraySegment<byte>[]
                {
                    trailer.Slice(0, dataOffset).ToArray(),
                    array
                };
            }
            else
            {
                Trailer = new ArraySegment<byte>[] { trailer.ToArray() };
            }
        }

        public virtual ArraySegment<byte>[] GetBytes()
        {
            TrailerLength = this.Trailer.Sum(x => x.Count);

            byte flags = Convert.ToByte(TrailerLength >> 16);

            byte[] buffer = new byte[HeaderLength];
            ByteWriter.WriteByte(buffer, 0, (byte)Type);
            ByteWriter.WriteByte(buffer, 1, flags);
            BigEndianWriter.WriteUInt16(buffer, 2, (ushort)(TrailerLength & 0xFFFF));

            return Trailer.Prepend(buffer).ToArray();
        }

        public virtual int Length
        {
            get
            {
                return HeaderLength + Trailer.Length;
            }
        }

        public static int GetSessionPacketLength(byte[] buffer, int offset)
        {
            int trailerLength = ByteReader.ReadByte(buffer, offset + 1) << 16 | BigEndianConverter.ToUInt16(buffer, offset + 2);
            return 4 + trailerLength;
        }

        internal static SessionPacket GetSessionPacket(byte[] buffer, int offset, ArrayPool<byte> pool, ITrailerDecryptor decryptor)
        {
            SessionPacketTypeName type = (SessionPacketTypeName)ByteReader.ReadByte(buffer, offset);
            switch (type)
            {
                case SessionPacketTypeName.SessionMessage:
                    return new SessionMessagePacket(buffer, offset, pool, decryptor);
                case SessionPacketTypeName.SessionRequest:
                    return new SessionRequestPacket(buffer, offset, pool);
                case SessionPacketTypeName.PositiveSessionResponse:
                    return new PositiveSessionResponsePacket(buffer, offset, pool);
                case SessionPacketTypeName.NegativeSessionResponse:
                    return new NegativeSessionResponsePacket(buffer, offset, pool);
                case SessionPacketTypeName.RetargetSessionResponse:
                    return new SessionRetargetResponsePacket(buffer, offset, pool);
                case SessionPacketTypeName.SessionKeepAlive:
                    return new SessionKeepAlivePacket(buffer, offset, pool);
                default:
                    throw new InvalidDataException("Invalid NetBIOS session packet type: 0x" + ((byte)type).ToString("X2"));
            }
        }
    }
}
