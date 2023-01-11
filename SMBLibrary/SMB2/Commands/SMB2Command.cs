/* Copyright (C) 2017-2021 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
using Utilities;

namespace SMBLibrary.SMB2
{
    public abstract class SMB2Request
    {
        public SMB2Header Header;

        public SMB2Request(SMB2CommandName commandName)
        {
            Header = new SMB2Header(commandName);
        }

        public SMB2Request(byte[] buffer, int offset)
        {
            Header = new SMB2Header(buffer, offset);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            Header.WriteBytes(buffer, offset);
            WriteCommandBytes(buffer, offset + SMB2Header.Length);
        }

        public abstract void WriteCommandBytes(byte[] buffer, int offset);

        public ArraySegment<byte>[] GetBytes()
        {
            byte[] buffer = new byte[this.Length];
            WriteBytes(buffer, 0);
            var result = new ArraySegment<byte>[] { buffer };

            return this is not IContentProvider contentProvider
                ? result
                : result.Concat(contentProvider.GetContentBytes()).ToArray();
        }

        public SMB2CommandName CommandName
        {
            get
            {
                return Header.Command;
            }
        }

        public ulong MessageID
        {
            get
            {
                return Header.MessageID;
            }
        }

        public int Length
        {
            get
            {
                return SMB2Header.Length + CommandLength;
            }
        }

        public abstract int CommandLength
        {
            get;
        }
    }

    public abstract class SMB2Response
    {
        public SMB2Header Header;

        public SMB2Response(SMB2CommandName commandName)
        {
            Header = new SMB2Header(commandName);
        }

        public SMB2Response(Span<byte> buffer, int offset)
        {
            Header = new SMB2Header(buffer, offset);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            Header.WriteBytes(buffer, offset);
            WriteCommandBytes(buffer, offset + SMB2Header.Length);
        }

        public abstract void WriteCommandBytes(byte[] buffer, int offset);

        public ArraySegment<byte>[] GetBytes()
        {
            byte[] buffer = new byte[this.Length];
            WriteBytes(buffer, 0);
            var result = new ArraySegment<byte>[] { buffer };

            return this is not IContentProvider contentProvider
                ? result
                : result.Concat(contentProvider.GetContentBytes()).ToArray();
        }

        public SMB2CommandName CommandName
        {
            get
            {
                return Header.Command;
            }
        }

        public ulong MessageID
        {
            get
            {
                return Header.MessageID;
            }
        }

        public int Length
        {
            get
            {
                return SMB2Header.Length + CommandLength;
            }
        }

        public abstract int CommandLength
        {
            get;
        }

        public static SMB2Response ReadResponse(byte[] buffer, int offset, byte[] dataBuffer, ArrayPool<byte> pool)
        {
            SMB2CommandName commandName = (SMB2CommandName)LittleEndianConverter.ToUInt16(buffer, offset + 12);
            ushort structureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            switch (commandName)
            {
                case SMB2CommandName.Negotiate:
                    {
                        if (structureSize == NegotiateResponse.DeclaredSize)
                        {
                            return new NegotiateResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.SessionSetup:
                    {
                        // SESSION_SETUP Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == SessionSetupResponse.DeclaredSize)
                        {
                            NTStatus status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS || status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED)
                            {
                                return new SessionSetupResponse(buffer, offset);
                            }
                            else
                            {
                                return new ErrorResponse(buffer, offset);
                            }
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.Logoff:
                    {
                        if (structureSize == LogoffResponse.DeclaredSize)
                        {
                            return new LogoffResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.TreeConnect:
                    {
                        if (structureSize == TreeConnectResponse.DeclaredSize)
                        {
                            return new TreeConnectResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.TreeDisconnect:
                    {
                        if (structureSize == TreeDisconnectResponse.DeclaredSize)
                        {
                            return new TreeDisconnectResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.Create:
                    {
                        if (structureSize == CreateResponse.DeclaredSize)
                        {
                            return new CreateResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.Close:
                    {
                        if (structureSize == CloseResponse.DeclaredSize)
                        {
                            return new CloseResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.Flush:
                    {
                        if (structureSize == FlushResponse.DeclaredSize)
                        {
                            return new FlushResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.Read:
                    {
                        if (structureSize == SMB2.ReadResponse.DeclaredSize)
                        {
                            return new ReadResponse(buffer, offset, dataBuffer, pool);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.Write:
                    {
                        if (structureSize == WriteResponse.DeclaredSize)
                        {
                            return new WriteResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.Lock:
                    {
                        if (structureSize == LockResponse.DeclaredSize)
                        {
                            return new LockResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.IOCtl:
                    {
                        if (structureSize == IOCtlResponse.DeclaredSize)
                        {
                            return new IOCtlResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.Cancel:
                    {
                        if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.Echo:
                    {
                        if (structureSize == EchoResponse.DeclaredSize)
                        {
                            return new EchoResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.QueryDirectory:
                    {
                        // QUERY_DIRECTORY Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == QueryDirectoryResponse.DeclaredSize)
                        {
                            NTStatus status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS)
                            {
                                return new QueryDirectoryResponse(buffer, offset);
                            }
                            else
                            {
                                return new ErrorResponse(buffer, offset);
                            }
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.ChangeNotify:
                    {
                        // CHANGE_NOTIFY Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == ChangeNotifyResponse.DeclaredSize)
                        {
                            NTStatus status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS ||
                                status == NTStatus.STATUS_NOTIFY_CLEANUP || 
                                status == NTStatus.STATUS_NOTIFY_ENUM_DIR)
                            {
                                return new ChangeNotifyResponse(buffer, offset);
                            }
                            else
                            {
                                return new ErrorResponse(buffer, offset);
                            }
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.QueryInfo:
                    {
                        // QUERY_INFO Response and ERROR Response have the same declared StructureSize of 9.
                        if (structureSize == QueryInfoResponse.DeclaredSize)
                        {
                            NTStatus status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, offset + 8);
                            if (status == NTStatus.STATUS_SUCCESS || status == NTStatus.STATUS_BUFFER_OVERFLOW)
                            {
                                return new QueryInfoResponse(buffer, offset);
                            }
                            else
                            {
                                return new ErrorResponse(buffer, offset);
                            }
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case SMB2CommandName.SetInfo:
                    {
                        if (structureSize == SetInfoResponse.DeclaredSize)
                        {
                            return new SetInfoResponse(buffer, offset);
                        }
                        else if (structureSize == ErrorResponse.DeclaredSize)
                        {
                            return new ErrorResponse(buffer, offset);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                default:
                    throw new InvalidDataException("Invalid SMB2 command 0x" + ((ushort)commandName).ToString("X4"));
            }
        }
    }
}
