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
    public class ConnectionReceiveBuffer : IDisposable
    {
        private IMemoryOwner<byte> _buffer;
        private int _readOffset;
        private int _bytesInBuffer;
        private int? _packetLength;

        public ConnectionReceiveBuffer Init()
        {
            Init(SessionPacketBase.MaxSessionPacketLength);
            return this;
        }

        /// <param name="bufferLength">Must be large enough to hold the largest possible NBT packet</param>
        public ConnectionReceiveBuffer Init(int bufferLength)
        {
            if (_buffer == null)
            {
                if (bufferLength < SessionPacketBase.MaxSessionPacketLength)
                {
                    throw new ArgumentException(
                        "bufferLength must be large enough to hold the largest possible NBT packet");
                }

                _buffer = Arrays.Rent(bufferLength);
            }

            _readOffset = 0;
            _bytesInBuffer = 0;
            _packetLength = null;
            
            return this;
        }

        public void IncreaseBufferSize(int bufferLength)
        {
            var buffer = Arrays.Rent(bufferLength);
            if (_bytesInBuffer > 0)
            {
                _buffer.Memory.Slice(_readOffset, _bytesInBuffer).CopyTo(buffer.Memory);
                _readOffset = 0;
            }
            _buffer?.Dispose();
            _buffer = buffer;
        }

        public void SetNumberOfBytesReceived(int numberOfBytesReceived)
        {
            _bytesInBuffer += numberOfBytesReceived;
        }

        public bool HasCompletePacket()
        {
            if (_bytesInBuffer >= 4)
            {
                if (!_packetLength.HasValue)
                {
                    _packetLength = SessionPacketBase.GetSessionPacketLength(_buffer.Memory.Span, _readOffset);
                }
                return _bytesInBuffer >= _packetLength.Value;
            }
            return false;
        }

        /// <summary>
        /// HasCompletePacket must be called and return true before calling DequeuePacket
        /// </summary>
        /// <exception cref="System.IO.InvalidDataException"></exception>
        public SessionPacketBase DequeuePacket()
        {
            SessionPacketBase packet;
            try
            {
                packet = SessionPacketBase.GetSessionPacket(_buffer.Memory.Span, _readOffset);
            }
            catch (IndexOutOfRangeException ex)
            {
                throw new InvalidDataException("Invalid NetBIOS session packet", ex);
            }
            RemovePacketBytes();
            return packet;
        }

        /// <summary>
        /// HasCompletePDU must be called and return true before calling DequeuePDUBytes
        /// </summary>
        public byte[] DequeuePacketBytes()
        {
            var packetBytes = ByteReader.ReadBytes_RentArray(_buffer.Memory.Span, _readOffset, _packetLength.Value);
            RemovePacketBytes();
            return packetBytes;
        }

        private void RemovePacketBytes()
        {
            _bytesInBuffer -= _packetLength.Value;
            if (_bytesInBuffer == 0)
            {
                _readOffset = 0;
                _packetLength = null;
            }
            else
            {
                _readOffset += _packetLength.Value;
                _packetLength = null;
                if (!HasCompletePacket())
                {
                    _buffer.Memory.Slice(_readOffset).CopyTo(_buffer.Memory);
                    _readOffset = 0;
                }
            }
        }

        public Memory<byte> Buffer => _buffer.Memory;

        public int WriteOffset => _readOffset + _bytesInBuffer;

        public int BytesInBuffer => _bytesInBuffer;

        public int AvailableLength => _buffer.Memory.Length - (_readOffset + _bytesInBuffer);

        public void Dispose()
        {
            _buffer?.Dispose();
            _buffer = null;
        }
    }
}
