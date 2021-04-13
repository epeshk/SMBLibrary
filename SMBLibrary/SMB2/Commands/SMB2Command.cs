/* Copyright (C) 2017-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB2
{
    public abstract class SMB2Command : IDisposable
    {
        public Smb2Header Header;

        public virtual SMB2Command Init(SMB2CommandName commandName)
        {
            Header = ObjectsPool<Smb2Header>.Get().Init(commandName, this);
            return this;
        }

        public virtual SMB2Command Init(Span<byte> buffer, int offset)
        {
            Header = ObjectsPool<Smb2Header>.Get().Init(buffer, offset, this);
            return this;
        }

        public virtual void Dispose()
        {
            Header?.Dispose();
            Header = null;
        }

        public void WriteBytes(Span<byte> buffer, int offset)
        {
            Header.WriteBytes(buffer, offset);
            WriteCommandBytes(buffer.Slice(offset + Smb2Header.Length));
        }

        public abstract void WriteCommandBytes(Span<byte> buffer);

        public IMemoryOwner<byte> GetBytes()
        {
            var buffer = Arrays.Rent(Length);
            WriteBytes(buffer.Memory.Span, 0);
            return buffer;
        }

        public SMB2CommandName CommandName => Header.Command;

        public int Length => Smb2Header.Length + CommandLength;

        public abstract int CommandLength
        {
            get;
        }

        public static SMB2Command ReadRequest(Span<byte> buffer, int offset)
        {
            var commandName = (SMB2CommandName)LittleEndianConverter.ToUInt16(buffer, offset + 12);
            switch (commandName)
            {
                case SMB2CommandName.Negotiate:
                    return ObjectsPool<NegotiateRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.SessionSetup:
                    return ObjectsPool<SessionSetupRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.Logoff:
                    return ObjectsPool<LogoffRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.TreeConnect:
                    return ObjectsPool<TreeConnectRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.TreeDisconnect:
                    return ObjectsPool<TreeDisconnectRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.Create:
                    return ObjectsPool<CreateRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.Close:
                    return ObjectsPool<CloseRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.Flush:
                    return ObjectsPool<FlushRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.Read:
                    return ObjectsPool<ReadRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.Write:
                    return ObjectsPool<WriteRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.Lock:
                    return ObjectsPool<LockRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.IOCtl:
                    return ObjectsPool<IOCtlRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.Cancel:
                    return ObjectsPool<CancelRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.Echo:
                    return ObjectsPool<EchoRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.QueryDirectory:
                    return ObjectsPool<QueryDirectoryRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.ChangeNotify:
                    return ObjectsPool<ChangeNotifyRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.QueryInfo:
                    return ObjectsPool<QueryInfoRequest>.Get().Init(buffer, offset);
                case SMB2CommandName.SetInfo:
                    return ObjectsPool<SetInfoRequest>.Get().Init(buffer, offset);
                default:
                    throw new InvalidDataException("Invalid SMB2 command 0x" + ((ushort)commandName).ToString("X4"));
            }
        }

        public static List<SMB2Command> ReadRequestChain(Span<byte> buffer, int offset)
        {
            var result = new List<SMB2Command>();
            SMB2Command command;
            do
            {
                command = ReadRequest(buffer, offset);
                result.Add(command);
                offset += (int)command.Header.NextCommand;
            }
            while (command.Header.NextCommand != 0);
            return result;
        }

        public static IMemoryOwner<byte> GetCommandChainBytes(List<SMB2Command> commands)
        {
            return GetCommandChainBytes(commands, null);
        }

        /// <param name="sessionKey">
        /// command will be signed using this key if (not null and) SMB2_FLAGS_SIGNED is set.
        /// </param>
        public static IMemoryOwner<byte> GetCommandChainBytes(List<SMB2Command> commands, byte[] sessionKey)
        {
            var totalLength = 0;
            for (var index = 0; index < commands.Count; index++)
            {
                // Any subsequent SMB2 header MUST be 8-byte aligned
                var length = commands[index].Length;
                if (index < commands.Count - 1)
                {
                    var paddedLength = (int)Math.Ceiling((double)length / 8) * 8;
                    totalLength += paddedLength;
                }
                else
                {
                    totalLength += length;
                }
            }
            var buffer = Arrays.Rent(totalLength);
            var offset = 0;
            Span<byte> hash = stackalloc byte[16];
            for (var index = 0; index < commands.Count; index++)
            {
                var command = commands[index];
                var commandLength = command.Length;
                int paddedLength;
                if (index < commands.Count - 1)
                {
                    paddedLength = (int)Math.Ceiling((double)commandLength / 8) * 8;
                    command.Header.NextCommand = (uint)paddedLength;
                }
                else
                {
                    paddedLength = commandLength;
                }
                command.WriteBytes(buffer.Memory.Span, offset);
                if (command.Header.IsSigned && sessionKey != null)
                {
                    // [MS-SMB2] Any padding at the end of the message MUST be used in the hash computation.
                    using var hasher = new HMACSHA256(sessionKey);
                    hasher.TryComputeHash(buffer.Memory.Span, hash, out _);
                    // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
                    BufferWriter.WriteBytes(buffer.Memory.Span, offset + Smb2Header.SignatureOffset, hash, 16);
                }
                offset += paddedLength;
            }
            return buffer;
        }

        public static SMB2Command ReadResponse(Span<byte> buffer, int offset)
        {
            var commandName = (SMB2CommandName)LittleEndianConverter.ToUInt16(buffer, offset + 12);
            var structureSize = LittleEndianConverter.ToUInt16(buffer, offset + Smb2Header.Length + 0);
            switch (commandName)
            {
                case SMB2CommandName.Negotiate:
                {
                    if (structureSize == NegotiateResponse.DeclaredSize)
                        {
                            return ObjectsPool<NegotiateResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.SessionSetup:
                {
                    // SESSION_SETUP Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == SessionSetupResponse.DeclaredSize)
                        {
                            var status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS || status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED)
                            {
                                return ObjectsPool<SessionSetupResponse>.Get().Init(buffer, offset);
                            }

                            return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                        }

                        throw new InvalidDataException();
                }
                case SMB2CommandName.Logoff:
                {
                    if (structureSize == LogoffResponse.DeclaredSize)
                        {
                            return ObjectsPool<LogoffResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.TreeConnect:
                {
                    if (structureSize == TreeConnectResponse.DeclaredSize)
                        {
                            return ObjectsPool<TreeConnectResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.TreeDisconnect:
                {
                    if (structureSize == TreeDisconnectResponse.DeclaredSize)
                        {
                            return ObjectsPool<TreeDisconnectResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.Create:
                {
                    if (structureSize == CreateResponse.DeclaredSize)
                        {
                            return ObjectsPool<CreateResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.Close:
                {
                    if (structureSize == CloseResponse.DeclaredSize)
                        {
                            return ObjectsPool<CloseResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.Flush:
                {
                    if (structureSize == FlushResponse.DeclaredSize)
                        {
                            return ObjectsPool<FlushResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.Read:
                {
                    if (structureSize == SMB2.ReadResponse.DeclaredSize)
                        {
                            return ObjectsPool<ReadResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.Write:
                {
                    if (structureSize == WriteResponse.DeclaredSize)
                        {
                            return ObjectsPool<WriteResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.Lock:
                {
                    if (structureSize == LockResponse.DeclaredSize)
                        {
                            return ObjectsPool<LockResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.IOCtl:
                {
                    if (structureSize == IOCtlResponse.DeclaredSize)
                        {
                            return ObjectsPool<IOCtlResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.Cancel:
                {
                    if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                        }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.Echo:
                {
                    if (structureSize == EchoResponse.DeclaredSize)
                        {
                            return ObjectsPool<EchoResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                case SMB2CommandName.QueryDirectory:
                {
                    // QUERY_DIRECTORY Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == QueryDirectoryResponse.DeclaredSize)
                        {
                            var status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS)
                            {
                                return ObjectsPool<QueryDirectoryResponse>.Get().Init(buffer, offset);
                            }

                            return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                        }

                        throw new InvalidDataException();
                }
                case SMB2CommandName.ChangeNotify:
                {
                    // CHANGE_NOTIFY Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == ChangeNotifyResponse.DeclaredSize)
                        {
                            var status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS ||
                                status == NTStatus.STATUS_NOTIFY_CLEANUP || 
                                status == NTStatus.STATUS_NOTIFY_ENUM_DIR)
                            {
                                return ObjectsPool<ChangeNotifyResponse>.Get().Init(buffer, offset);
                            }

                            return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                        }

                        throw new InvalidDataException();
                }
                case SMB2CommandName.QueryInfo:
                {
                    // QUERY_INFO Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == QueryInfoResponse.DeclaredSize)
                        {
                            var status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS || status == NTStatus.STATUS_BUFFER_OVERFLOW)
                            {
                                return ObjectsPool<QueryInfoResponse>.Get().Init(buffer, offset);
                            }

                            return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                        }

                        throw new InvalidDataException();
                }
                case SMB2CommandName.SetInfo:
                {
                    if (structureSize == SetInfoResponse.DeclaredSize)
                        {
                            return ObjectsPool<SetInfoResponse>.Get().Init(buffer, offset);
                        }

                    if (structureSize == ErrorResponse.DeclaredSize)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(buffer, offset);
                    }

                    throw new InvalidDataException();
                }
                default:
                    throw new InvalidDataException("Invalid SMB2 command 0x" + ((ushort)commandName).ToString("X4"));
            }
        }

        public static List<SMB2Command> ReadResponseChain(Span<byte> buffer, int offset)
        {
            var result = new List<SMB2Command>();
            SMB2Command command;
            do
            {
                command = ReadResponse(buffer, offset);
                result.Add(command);
                offset += (int)command.Header.NextCommand;
            }
            while (command.Header.NextCommand != 0);
            return result;
        }
    }
}
