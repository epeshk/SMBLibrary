/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary.SMB1
{
    public abstract class SMB1Command : IDisposable
    {
        protected IMemoryOwner<byte> SmbParameters;   // SMB_Parameters
        protected IMemoryOwner<byte> SmbData;         // SMB_Data

        public virtual SMB1Command Init()
        {
            SmbParameters = MemoryOwner<byte>.Empty;
            SmbData = MemoryOwner<byte>.Empty;

            return this;
        }

        public virtual SMB1Command Init(Span<byte> buffer, int offset, bool isUnicode)
        {
            var wordCount = ByteReader.ReadByte(buffer, ref offset);
            if (CommandName == CommandName.SMB_COM_NT_CREATE_ANDX && wordCount == NTCreateAndXResponseExtended.DeclaredParametersLength / 2)
            {
                // [MS-SMB] Section 2.2.4.9.2 and Note <49>:
                // Windows-based SMB servers send 50 (0x32) words in the extended response although they set the WordCount field to 0x2A.
                wordCount = NTCreateAndXResponseExtended.ParametersLength / 2;
            }

            SmbParameters = Arrays.Rent(wordCount * 2);
            ByteReader.ReadBytes(SmbParameters.Memory.Span, buffer, offset, wordCount * 2); offset += wordCount * 2;
            var byteCount = LittleEndianReader.ReadUInt16(buffer, ref offset);
            
            SmbData = Arrays.Rent(byteCount);
            ByteReader.ReadBytes(SmbData.Memory.Span, buffer, offset, byteCount); offset += byteCount;

            return this;
        }

        public abstract CommandName CommandName
        {
            get;
        }

        public virtual IMemoryOwner<byte> GetBytes(bool isUnicode)
        {
            if (SmbParameters.Length() % 2 > 0)
            {
                throw new Exception("SMB_Parameters Length must be a multiple of 2");
            }
            var length = 1 + SmbParameters.Length() + 2 + SmbData.Length();
            var buffer = Arrays.Rent<byte>(length);
            var wordCount = (byte)(SmbParameters.Length() / 2);
            if (this is NTCreateAndXResponseExtended)
            {
                // [MS-SMB] Section 2.2.4.9.2 and Note <49>:
                // Windows-based SMB servers send 50 (0x32) words in the extended response although they set the WordCount field to 0x2A.
                // WordCount SHOULD be set to 0x2A.
                wordCount = NTCreateAndXResponseExtended.DeclaredParametersLength / 2;
            }
            var byteCount = (ushort)SmbData.Length();

            var offset = 0;
            BufferWriter.WriteByte(buffer.Memory.Span, ref offset, wordCount);
            BufferWriter.WriteBytes(buffer.Memory.Span, ref offset, SmbParameters.Memory.Span);
            LittleEndianWriter.WriteUInt16(buffer.Memory.Span, ref offset, byteCount);
            BufferWriter.WriteBytes(buffer.Memory.Span, ref offset, SmbData.Memory.Span);

            return buffer;
        }

        public static SMB1Command ReadCommand(Span<byte> buffer, int offset, CommandName commandName, SMB1Header header)
        {
            if ((header.Flags & HeaderFlags.Reply) > 0)
            {
                return ReadCommandResponse(buffer, offset, commandName, header.UnicodeFlag);
            }

            return ReadCommandRequest(buffer, offset, commandName, header.UnicodeFlag);
        }

        public static SMB1Command ReadCommandRequest(Span<byte> buffer, int offset, CommandName commandName, bool isUnicode)
        {
            switch (commandName)
            {
                case CommandName.SMB_COM_CREATE_DIRECTORY:      return ObjectsPool<CreateDirectoryRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_DELETE_DIRECTORY:      return ObjectsPool<DeleteDirectoryRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_CLOSE:                 return ObjectsPool<CloseRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_FLUSH:                 return ObjectsPool<FlushRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_DELETE:                return ObjectsPool<DeleteRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_RENAME:                return ObjectsPool<RenameRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_QUERY_INFORMATION:     return ObjectsPool<QueryInformationRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_SET_INFORMATION:       return ObjectsPool<SetInformationRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_READ:                  return ObjectsPool<ReadRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_WRITE:                 return ObjectsPool<WriteRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_CHECK_DIRECTORY:       return ObjectsPool<CheckDirectoryRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_WRITE_RAW:             return ObjectsPool<WriteRawRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_SET_INFORMATION2:      return ObjectsPool<SetInformation2Request>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_LOCKING_ANDX:          return ObjectsPool<LockingAndXRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_TRANSACTION:           return ObjectsPool<TransactionRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_TRANSACTION_SECONDARY: return ObjectsPool<TransactionSecondaryRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_ECHO:                  return ObjectsPool<EchoRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_OPEN_ANDX:             return ObjectsPool<OpenAndXRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_READ_ANDX:             return ObjectsPool<ReadAndXRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_WRITE_ANDX:            return ObjectsPool<WriteAndXRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_TRANSACTION2:          return ObjectsPool<Transaction2Request>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_TRANSACTION2_SECONDARY: return ObjectsPool<Transaction2SecondaryRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_FIND_CLOSE2:           return ObjectsPool<FindClose2Request>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_TREE_DISCONNECT:       return ObjectsPool<TreeDisconnectRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_NEGOTIATE:             return ObjectsPool<NegotiateRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_SESSION_SETUP_ANDX:
                    {
                        var wordCount = ByteReader.ReadByte(buffer, offset);
                        if (wordCount * 2 == SessionSetupAndXRequest.ParametersLength)
                        {
                            return ObjectsPool<SessionSetupAndXRequest>.Get().Init(buffer, offset, isUnicode);
                        }

                        if (wordCount * 2 == SessionSetupAndXRequestExtended.ParametersLength)
                        {
                            return ObjectsPool<SessionSetupAndXRequestExtended>.Get().Init(buffer, offset, isUnicode);
                        }

                        throw new InvalidDataException();
                    }
                case CommandName.SMB_COM_LOGOFF_ANDX:
                    return ObjectsPool<LogoffAndXRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_TREE_CONNECT_ANDX:
                    return ObjectsPool<TreeConnectAndXRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_NT_TRANSACT:
                    return ObjectsPool<NTTransactRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_NT_TRANSACT_SECONDARY:
                    return ObjectsPool<NTTransactSecondaryRequest>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_NT_CREATE_ANDX:
                    return ObjectsPool<NTCreateAndXRequest>.Get().Init(buffer, offset, isUnicode);
                case CommandName.SMB_COM_NT_CANCEL:
                    return ObjectsPool<NTCancelRequest>.Get().Init(buffer, offset);
                default:
                    throw new InvalidDataException("Invalid SMB command 0x" + ((byte)commandName).ToString("X2"));
            }
        }

        public static SMB1Command ReadCommandResponse(Span<byte> buffer, int offset, CommandName commandName, bool isUnicode)
        {
            var wordCount = ByteReader.ReadByte(buffer, offset);
            switch (commandName)
            {
                case CommandName.SMB_COM_CREATE_DIRECTORY:
                    return ObjectsPool<CreateDirectoryResponse>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_DELETE_DIRECTORY:
                    return ObjectsPool<DeleteDirectoryResponse>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_CLOSE:
                    return ObjectsPool<CloseResponse>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_FLUSH:
                    return ObjectsPool<FlushResponse>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_DELETE:
                    return ObjectsPool<DeleteResponse>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_RENAME:
                    return ObjectsPool<RenameResponse>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_QUERY_INFORMATION:
                {
                    if (wordCount * 2 == QueryInformationResponse.ParameterLength)
                        {
                            return ObjectsPool<QueryInformationResponse>.Get().Init(buffer, offset);
                        }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_SET_INFORMATION:
                    return ObjectsPool<SetInformationResponse>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_READ:
                {
                    if (wordCount * 2 == ReadResponse.ParametersLength)
                        {
                            return ObjectsPool<ReadResponse>.Get().Init(buffer, offset);
                        }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_WRITE:
                {
                    if (wordCount * 2 == WriteResponse.ParametersLength)
                        {
                            return ObjectsPool<WriteResponse>.Get().Init(buffer, offset);
                        }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_CHECK_DIRECTORY:
                    return ObjectsPool<CheckDirectoryResponse>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_WRITE_RAW:
                {
                    if (wordCount * 2 == WriteRawInterimResponse.ParametersLength)
                        {
                            return ObjectsPool<WriteRawInterimResponse>.Get().Init(buffer, offset);
                        }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_WRITE_COMPLETE:
                {
                    if (wordCount * 2 == WriteRawFinalResponse.ParametersLength)
                        {
                            return ObjectsPool<WriteRawFinalResponse>.Get().Init(buffer, offset);
                        }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_SET_INFORMATION2:
                    return ObjectsPool<SetInformation2Response>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_LOCKING_ANDX:
                {
                    if (wordCount * 2 == LockingAndXResponse.ParametersLength)
                        {
                            return ObjectsPool<LockingAndXResponse>.Get().Init(buffer, offset);
                        }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_TRANSACTION:
                {
                    if (wordCount * 2 == TransactionInterimResponse.ParametersLength)
                        {
                            return ObjectsPool<TransactionInterimResponse>.Get().Init(buffer, offset);
                        }

                    return ObjectsPool<TransactionResponse>.Get().Init(buffer, offset);
                }
                case CommandName.SMB_COM_ECHO:
                {
                    if (wordCount * 2 == EchoResponse.ParametersLength)
                        {
                            return ObjectsPool<EchoResponse>.Get().Init(buffer, offset);
                        }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_OPEN_ANDX:
                {
                    if (wordCount * 2 == OpenAndXResponse.ParametersLength)
                        {
                            return ObjectsPool<OpenAndXResponse>.Get().Init(buffer, offset);
                        }

                    if (wordCount * 2 == OpenAndXResponseExtended.ParametersLength)
                    {
                        return ObjectsPool<OpenAndXResponseExtended>.Get().Init(buffer, offset);
                    }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_READ_ANDX:
                {
                    if (wordCount * 2 == ReadAndXResponse.ParametersLength)
                        {
                            return ObjectsPool<ReadAndXResponse>.Get().Init(buffer, offset, isUnicode);
                        }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_WRITE_ANDX:
                {
                    if (wordCount * 2 == WriteAndXResponse.ParametersLength)
                        {
                            return ObjectsPool<WriteAndXResponse>.Get().Init(buffer, offset);
                        }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_TRANSACTION2:
                {
                    if (wordCount * 2 == TransactionInterimResponse.ParametersLength)
                        {
                            return ObjectsPool<Transaction2InterimResponse>.Get().Init(buffer, offset);
                        }

                    return ObjectsPool<Transaction2Response>.Get().Init(buffer, offset);
                }
                case CommandName.SMB_COM_FIND_CLOSE2:
                    return ObjectsPool<FindClose2Response>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_TREE_DISCONNECT:
                    return ObjectsPool<TreeDisconnectResponse>.Get().Init(buffer, offset);
                case CommandName.SMB_COM_NEGOTIATE:
                    {
                        // Both NegotiateResponse and NegotiateResponseExtended have WordCount set to 17
                        if (wordCount * 2 == NegotiateResponse.ParametersLength)
                        {
                            var capabilities = (Capabilities)LittleEndianConverter.ToUInt32(buffer, offset + 20);
                            if ((capabilities & Capabilities.ExtendedSecurity) > 0)
                            {
                                return ObjectsPool<NegotiateResponseExtended>.Get().Init(buffer, offset);
                            }

                            return ObjectsPool<NegotiateResponse>.Get().Init(buffer, offset, isUnicode);
                        }
                        if (wordCount == 0)
                        {
                            return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                        }

                        throw new InvalidDataException();
                    }
                case CommandName.SMB_COM_SESSION_SETUP_ANDX:
                {
                    if (wordCount * 2 == SessionSetupAndXResponse.ParametersLength)
                        {
                            return ObjectsPool<SessionSetupAndXResponse>.Get().Init(buffer, offset, isUnicode);
                        }

                    if (wordCount * 2 == SessionSetupAndXResponseExtended.ParametersLength)
                    {
                        return ObjectsPool<SessionSetupAndXResponseExtended>.Get().Init(buffer, offset, isUnicode);
                    }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_LOGOFF_ANDX:
                {
                    if (wordCount * 2 == LogoffAndXResponse.ParametersLength)
                        {
                            return ObjectsPool<LogoffAndXResponse>.Get().Init(buffer, offset);
                        }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_TREE_CONNECT_ANDX:
                {
                    if (wordCount * 2 == TreeConnectAndXResponse.ParametersLength)
                        {
                            return ObjectsPool<TreeConnectAndXResponse>.Get().Init(buffer, offset, isUnicode);
                        }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                case CommandName.SMB_COM_NT_TRANSACT:
                {
                    if (wordCount * 2 == NTTransactInterimResponse.ParametersLength)
                        {
                            return ObjectsPool<NTTransactInterimResponse>.Get().Init(buffer, offset);
                        }

                    return ObjectsPool<NTTransactResponse>.Get().Init(buffer, offset);
                }
                case CommandName.SMB_COM_NT_CREATE_ANDX:
                {
                    if (wordCount * 2 == NTCreateAndXResponse.ParametersLength)
                        {
                            return ObjectsPool<NTCreateAndXResponse>.Get().Init(buffer, offset);
                        }

                    if (wordCount * 2 == NTCreateAndXResponseExtended.ParametersLength ||
                        wordCount * 2 == NTCreateAndXResponseExtended.DeclaredParametersLength)
                    {
                        return ObjectsPool<NTCreateAndXResponseExtended>.Get().Init(buffer, offset);
                    }

                    if (wordCount == 0)
                    {
                        return ObjectsPool<ErrorResponse>.Get().Init(commandName);
                    }

                    throw new InvalidDataException();
                }
                default:
                    throw new InvalidDataException("Invalid SMB command 0x" + ((byte)commandName).ToString("X2"));
            }
        }

        public static implicit operator List<SMB1Command>(SMB1Command command)
        {
            var result = new List<SMB1Command>();
            result.Add(command);
            return result;
        }

        public virtual void Dispose()
        {
            SmbParameters?.Dispose();
            SmbData?.Dispose();
            SmbParameters = SmbData = null;
        }
    }
}
