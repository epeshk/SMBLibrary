/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using MemoryPools.Memory;
using SMBLibrary.SMB1;

namespace SMBLibrary.Client
{
	public class SMB1FileStore : ISMBFileStore
	{
		private SMB1Client m_client;
		private ushort m_treeID;

		public SMB1FileStore(SMB1Client client, ushort treeID)
		{
			m_client = client;
			m_treeID = treeID;
		}

		public virtual NTStatus CreateFile(out object handle, out FileStatus fileStatus, IMemoryOwner<char> path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
		{
			handle = null;
			fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
			var request = (NTCreateAndXRequest) ObjectsPool<NTCreateAndXRequest>.Get().Init();
			request.FileName = path.Memory.ToString();
			request.DesiredAccess = desiredAccess;
			request.ExtFileAttributes = ToExtendedFileAttributes(fileAttributes);
			request.ShareAccess = shareAccess;
			request.CreateDisposition = createDisposition;
			request.CreateOptions = createOptions;
			request.ImpersonationLevel = ImpersonationLevel.Impersonation;

			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_NT_CREATE_ANDX);
			if (reply != null)
			{
				if (reply.Commands[0] is NTCreateAndXResponse)
				{
					var response = reply.Commands[0] as NTCreateAndXResponse;
					handle = response.FID;
					fileStatus = ToFileStatus(response.CreateDisposition);
					reply.Dispose();
					return reply.Header.Status;
				}

				if (reply.Commands[0] is ErrorResponse)
				{
					reply.Dispose();
					return reply.Header.Status;
				}
			}
			return NTStatus.STATUS_INVALID_SMB;
		}

		public virtual NTStatus CloseFile(object handle)
		{
			var request = (CloseRequest) ObjectsPool<CloseRequest>.Get().Init();
			request.FID = (ushort)handle;
			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_CLOSE);
			if (reply != null)
			{
				reply.Dispose();
				return reply.Header.Status;
			}
			return NTStatus.STATUS_INVALID_SMB;
		}

		public NTStatus ReadFile(out IMemoryOwner<byte> data, object handle, long offset, int maxCount)
		{
			if (maxCount <= ushort.MaxValue)
			{
				return ReadFileInternal(out data, handle, offset, maxCount);
			}

			data = Arrays.Rent<byte>(maxCount);
			long position = offset;
			int totalReadCount = 0;
			int readCount = -1;
			NTStatus status = NTStatus.STATUS_SUCCESS;

			while (totalReadCount < maxCount &&
			       readCount != 0 &&
			       status == NTStatus.STATUS_SUCCESS)
			{
				int remainingCount = maxCount - totalReadCount;
				int chunkMaxCount = remainingCount >= ushort.MaxValue ? ushort.MaxValue : remainingCount;
				status = ReadFileInternal(out var chunkData, handle, position, chunkMaxCount);
				chunkData.Memory.CopyTo(data.Memory[totalReadCount..]);
				readCount = chunkData.Length();
				totalReadCount += readCount;
				position += readCount;
				chunkData.Dispose();
			}

			data = data.Slice(0, totalReadCount);

			return status;
		}

		private NTStatus ReadFileInternal(out IMemoryOwner<byte> data, object handle, long offset, int maxCount)
		{
			data = null;
			var request = (ReadAndXRequest) ObjectsPool<ReadAndXRequest>.Get().Init();
			request.FID = (ushort)handle;
			request.Offset = (ulong)offset;
			request.MaxCountLarge = (uint) maxCount;
			request.MaxCount = maxCount > ushort.MaxValue ? ushort.MaxValue : (ushort)maxCount;
			
			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_READ_ANDX);
			if (reply != null)
			{
				if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is ReadAndXResponse)
				{
					data = ((ReadAndXResponse)reply.Commands[0]).Data.AddOwner();
				}
				reply.Dispose();
				return reply.Header.Status;
			}
			return NTStatus.STATUS_INVALID_SMB;
		}

		public NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, IMemoryOwner<byte> data)
		{
			numberOfBytesWritten = 0;
			var request = (WriteAndXRequest) ObjectsPool<WriteAndXRequest>.Get().Init();
			request.FID = (ushort)handle;
			request.Offset = (ulong)offset;
			request.Data = data;

			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_WRITE_ANDX);
			if (reply != null)
			{
				if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is WriteAndXResponse)
				{
					numberOfBytesWritten = (int)((WriteAndXResponse)reply.Commands[0]).Count;
				}
				reply.Dispose();
				return reply.Header.Status;
			}
			return NTStatus.STATUS_INVALID_SMB;
		}

		public NTStatus FlushFileBuffers(object handle)
		{
			throw new NotImplementedException();
		}

		public NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock)
		{
			throw new NotImplementedException();
		}

		public NTStatus UnlockFile(object handle, long byteOffset, long length)
		{
			throw new NotImplementedException();
		}

		public virtual NTStatus QueryDirectory(out List<FindFilesQueryResult> result, object handle, string fileName, FileInformationClass informationClass)
		{
			result = QueryDirectoryAsync(handle, fileName, informationClass, true, CancellationToken.None).ToEnumerable().ToList();
			return NTStatus.STATUS_SUCCESS;
		}

		public virtual async IAsyncEnumerable<FindFilesQueryResult> QueryDirectoryAsync(
			object handle, string fileName, FileInformationClass informationClass, bool closeOnFinish, CancellationToken outerToken)
		{
			var maxOutputLength = 4096;
			var subcommand = new Transaction2FindFirst2Request
			{
				SearchAttributes = SMBFileAttributes.Hidden | SMBFileAttributes.System | SMBFileAttributes.Directory,
				SearchCount = ushort.MaxValue,
				Flags = FindFlags.SMB_FIND_CLOSE_AT_EOS,
				InformationLevel = FindInformationLevel.SMB_FIND_FILE_DIRECTORY_INFO,
				FileName = fileName
			};
			
			var request = new Transaction2Request();
			request.Setup = Arrays.Rent(2);
			subcommand.GetSetupInto(request.Setup.Memory.Span);
			request.TransParameters = subcommand.GetParameters(m_client.Unicode);
			request.TransData = subcommand.GetData(m_client.Unicode);
			request.TotalDataCount = (ushort)request.TransData.Length();
			request.TotalParameterCount = (ushort)request.TransParameters.Length();
			request.MaxParameterCount = Transaction2FindFirst2Response.ParametersLength;
			request.MaxDataCount = (ushort)maxOutputLength;

			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_TRANSACTION2);
			if (reply != null)
			{
				if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
				{
					var response = (Transaction2Response)reply.Commands[0];
					var subcommandResponse = new Transaction2FindFirst2Response(response.TransParameters, response.TransData, reply.Header.UnicodeFlag);
					using (var findInformationList = subcommandResponse.GetFindInformationList(subcommand.InformationLevel, reply.Header.UnicodeFlag))
					{
						foreach (var findInformation in findInformationList)
						{
							yield return FindFilesQueryResult.From(findInformation as FindFileDirectoryInfo);
						}
					}
			
					var endOfSearch = subcommandResponse.EndOfSearch;
					while (!endOfSearch)
					{
						var nextSubcommand = new Transaction2FindNext2Request();
						nextSubcommand.SID = subcommandResponse.SID;
						nextSubcommand.SearchCount = UInt16.MaxValue;
						nextSubcommand.Flags = FindFlags.SMB_FIND_CLOSE_AT_EOS | FindFlags.SMB_FIND_CONTINUE_FROM_LAST;
						nextSubcommand.InformationLevel = FindInformationLevel.SMB_FIND_FILE_DIRECTORY_INFO;
						nextSubcommand.FileName = fileName;

						request = new Transaction2Request();
						request.Setup = Arrays.Rent(2);
						nextSubcommand.GetSetupInto(request.Setup.Memory.Span);
						request.TransParameters = nextSubcommand.GetParameters(m_client.Unicode);
						request.TransData = nextSubcommand.GetData(m_client.Unicode);
						request.TotalDataCount = (ushort)request.TransData.Length();
						request.TotalParameterCount = (ushort)request.TransParameters.Length();
						request.MaxParameterCount = Transaction2FindNext2Response.ParametersLength;
						request.MaxDataCount = (ushort)maxOutputLength;

						TrySendMessage(request);
						reply.Dispose();
						reply = m_client.WaitForCommand(CommandName.SMB_COM_TRANSACTION2);
						if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
						{
							response = (Transaction2Response)reply.Commands[0];
							var nextSubcommandResponse = new Transaction2FindNext2Response(
								response.TransParameters, 
								response.TransData,
								reply.Header.UnicodeFlag);

							using (var findInformationList = nextSubcommandResponse.GetFindInformationList(subcommand.InformationLevel, reply.Header.UnicodeFlag))
							{
								foreach (var fileInfo in findInformationList)
								{
									yield return FindFilesQueryResult.From(fileInfo as FindFileDirectoryInfo);
								}
							}

							endOfSearch = nextSubcommandResponse.EndOfSearch;
						}
						else
						{
							endOfSearch = true;
						}
					}
				}
				reply.Dispose();
			}
		}

		public NTStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass)
		{
			result = null;
			if (m_client.InfoLevelPassthrough)
			{
				var maxOutputLength = 4096;
				var subcommand = new Transaction2QueryFileInformationRequest();
				subcommand.FID = (ushort)handle;
				subcommand.FileInformationClass = informationClass;

				var request = (Transaction2Request) ObjectsPool<Transaction2Request>.Get().Init();
				request.Setup = Arrays.Rent(2);
				subcommand.GetSetupInto(request.Setup.Memory.Span);
				request.TransParameters = subcommand.GetParameters(m_client.Unicode);
				request.TransData = subcommand.GetData(m_client.Unicode);
				request.TotalDataCount = (ushort)request.TransData.Length();
				request.TotalParameterCount = (ushort)request.TransParameters.Length();
				request.MaxParameterCount = Transaction2QueryFileInformationResponse.ParametersLength;
				request.MaxDataCount = (ushort)maxOutputLength;

				TrySendMessage(request);
				var reply = m_client.WaitForCommand(CommandName.SMB_COM_TRANSACTION2);
				if (reply != null)
				{
					if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
					{
						var response = (Transaction2Response)reply.Commands[0];
						var subcommandResponse = new Transaction2QueryFileInformationResponse(
							response.TransParameters, 
							response.TransData,
							reply.Header.UnicodeFlag);
						if (informationClass == FileInformationClass.FileAllInformation)
						{
							// Windows implementations return SMB_QUERY_FILE_ALL_INFO when a client specifies native NT passthrough level "FileAllInformation".
							var queryFileAllInfo = subcommandResponse.GetQueryInformation(QueryInformationLevel.SMB_QUERY_FILE_ALL_INFO);
							result = QueryInformationHelper.ToFileInformation(queryFileAllInfo);
						}
						else
						{
							result = subcommandResponse.GetFileInformation(informationClass);
						}
					}
					reply.Dispose();
					return reply.Header.Status;
				}
				return NTStatus.STATUS_INVALID_SMB;
			}

			var informationLevel = QueryInformationHelper.ToFileInformationLevel(informationClass);
			QueryInformation queryInformation;
			var status = GetFileInformation(out queryInformation, handle, informationLevel);
			if (status == NTStatus.STATUS_SUCCESS)
			{
				result = QueryInformationHelper.ToFileInformation(queryInformation);
			}
			return status;
		}

		public NTStatus GetFileInformation(out QueryInformation result, object handle, QueryInformationLevel informationLevel)
		{
			result = null;
			var maxOutputLength = 4096;
			var subcommand = new Transaction2QueryFileInformationRequest();
			subcommand.FID = (ushort)handle;
			subcommand.QueryInformationLevel = informationLevel;

			var request = (Transaction2Request) ObjectsPool<Transaction2Request>.Get().Init();
			request.Setup = Arrays.Rent(2);
			subcommand.GetSetupInto(request.Setup.Memory.Span);
			request.TransParameters = subcommand.GetParameters(m_client.Unicode);
			request.TransData = subcommand.GetData(m_client.Unicode);
			request.TotalDataCount = (ushort)request.TransData.Length();
			request.TotalParameterCount = (ushort)request.TransParameters.Length();
			request.MaxParameterCount = Transaction2QueryFileInformationResponse.ParametersLength;
			request.MaxDataCount = (ushort)maxOutputLength;

			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_TRANSACTION2);
			if (reply != null)
			{
				if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
				{
					var response = (Transaction2Response)reply.Commands[0];
					var subcommandResponse = new Transaction2QueryFileInformationResponse(
						response.TransParameters,
						response.TransData,
						reply.Header.UnicodeFlag);
					result = subcommandResponse.GetQueryInformation(informationLevel);
				}
				reply.Dispose();
				return reply.Header.Status;
			}
			return NTStatus.STATUS_INVALID_SMB;
		}

		public NTStatus SetFileInformation(object handle, FileInformation information)
		{
			if (m_client.InfoLevelPassthrough)
			{
				if (information is FileRenameInformationType2)
				{
					var informationType1 = new FileRenameInformationType1();
					informationType1.FileName = ((FileRenameInformationType2)information).FileName.AddOwner();
					informationType1.ReplaceIfExists = ((FileRenameInformationType2)information).ReplaceIfExists;
					informationType1.RootDirectory = (uint)((FileRenameInformationType2)information).RootDirectory;
					information = informationType1;
				}
				
				var maxOutputLength = 4096;
				var subcommand = new Transaction2SetFileInformationRequest();
				subcommand.FID = (ushort)handle;
				subcommand.SetInformation(information);

				var request = (Transaction2Request) ObjectsPool<Transaction2Request>.Get().Init();
				request.Setup = Arrays.Rent(2);
				subcommand.GetSetupInto(request.Setup.Memory.Span);
				request.TransParameters = subcommand.GetParameters(m_client.Unicode);
				request.TransData = subcommand.GetData(m_client.Unicode);
				request.TotalDataCount = (ushort)request.TransData.Length();
				request.TotalParameterCount = (ushort)request.TransParameters.Length();
				request.MaxParameterCount = Transaction2SetFileInformationResponse.ParametersLength;
				request.MaxDataCount = (ushort)maxOutputLength;

				TrySendMessage(request);
				var reply = m_client.WaitForCommand(CommandName.SMB_COM_TRANSACTION2);
				if (reply != null)
				{
					var status = reply.Header.Status;
					reply.Dispose();
					return status;
				}
				return NTStatus.STATUS_INVALID_SMB;
			}

			throw new NotSupportedException("Server does not support InfoLevelPassthrough");
		}

		public NTStatus SetFileInformation(object handle, SetInformation information)
		{
			var maxOutputLength = 4096;
			var subcommand = new Transaction2SetFileInformationRequest();
			subcommand.FID = (ushort)handle;
			subcommand.SetInformation(information);

			var request = (Transaction2Request)ObjectsPool<Transaction2Request>.Get().Init();
			request.Setup = Arrays.Rent(2);
			subcommand.GetSetupInto(request.Setup.Memory.Span);
			request.TransParameters = subcommand.GetParameters(m_client.Unicode);
			request.TransData = subcommand.GetData(m_client.Unicode);
			request.TotalDataCount = (ushort)request.TransData.Length();
			request.TotalParameterCount = (ushort)request.TransParameters.Length();
			request.MaxParameterCount = Transaction2SetFileInformationResponse.ParametersLength;
			request.MaxDataCount = (ushort)maxOutputLength;

			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_TRANSACTION2);
			if (reply != null)
			{
				reply.Dispose();
				return reply.Header.Status;
			}
			return NTStatus.STATUS_INVALID_SMB;
		}

		public NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass)
		{
			if (m_client.InfoLevelPassthrough)
			{
				result = null;
				var maxOutputLength = 4096;
				var subcommand = new Transaction2QueryFSInformationRequest();
				subcommand.FileSystemInformationClass = informationClass;

				var request = (Transaction2Request)ObjectsPool<Transaction2Request>.Get().Init();
				request.Setup = Arrays.Rent(2);
				subcommand.GetSetupInto(request.Setup.Memory.Span);
				request.TransParameters = subcommand.GetParameters(m_client.Unicode);
				request.TransData = subcommand.GetData(m_client.Unicode);
				request.TotalDataCount = (ushort)request.TransData.Length();
				request.TotalParameterCount = (ushort)request.TransParameters.Length();
				request.MaxParameterCount = Transaction2QueryFSInformationResponse.ParametersLength;
				request.MaxDataCount = (ushort)maxOutputLength;

				TrySendMessage(request);
				var reply = m_client.WaitForCommand(CommandName.SMB_COM_TRANSACTION2);
				if (reply != null)
				{
					if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
					{
						var response = (Transaction2Response)reply.Commands[0];
						var subcommandResponse = new Transaction2QueryFSInformationResponse(
							response.TransParameters,
							response.TransData,
							reply.Header.UnicodeFlag);
						result = subcommandResponse.GetFileSystemInformation(informationClass);
					}
					reply.Dispose();
					return reply.Header.Status;
				}
				return NTStatus.STATUS_INVALID_SMB;
			}

			throw new NotSupportedException("Server does not support InfoLevelPassthrough");
		}

		public NTStatus GetFileSystemInformation(out QueryFSInformation result, QueryFSInformationLevel informationLevel)
		{
			result = null;
			var maxOutputLength = 4096;
			var subcommand = new Transaction2QueryFSInformationRequest();
			subcommand.QueryFSInformationLevel = informationLevel;

			var request = (Transaction2Request)ObjectsPool<Transaction2Request>.Get().Init();
			request.Setup = Arrays.Rent(2);
			subcommand.GetSetupInto(request.Setup.Memory.Span);
			request.TransParameters = subcommand.GetParameters(m_client.Unicode);
			request.TransData = subcommand.GetData(m_client.Unicode);
			request.TotalDataCount = (ushort)request.TransData.Length();
			request.TotalParameterCount = (ushort)request.TransParameters.Length();
			request.MaxParameterCount = Transaction2QueryFSInformationResponse.ParametersLength;
			request.MaxDataCount = (ushort)maxOutputLength;

			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_TRANSACTION2);
			if (reply != null)
			{
				if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is Transaction2Response)
				{
					var response = (Transaction2Response)reply.Commands[0];
					var subcommandResponse = new Transaction2QueryFSInformationResponse(
						response.TransParameters,
						response.TransData,
						reply.Header.UnicodeFlag);
					result = subcommandResponse.GetQueryFSInformation(informationLevel, reply.Header.UnicodeFlag);
				}
				reply.Dispose();
				return reply.Header.Status;
			}
			return NTStatus.STATUS_INVALID_SMB;
		}

		public NTStatus SetFileSystemInformation(FileSystemInformation information)
		{
			throw new NotImplementedException();
		}

		public NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle, SecurityInformation securityInformation)
		{
			result = null;
			var maxOutputLength = 4096;
			var subcommand = new NTTransactQuerySecurityDescriptorRequest();
			subcommand.FID = (ushort)handle;
			subcommand.SecurityInfoFields = securityInformation;

			var request = (NTTransactRequest)ObjectsPool<NTTransactRequest>.Get().Init();
			request.Function = subcommand.SubcommandName;
			request.Setup = subcommand.GetSetup();
			request.TransParameters = subcommand.GetParameters(m_client.Unicode);
			request.TransData = subcommand.GetData();
			request.TotalDataCount = (uint)request.TransData.Length();
			request.TotalParameterCount = (uint)request.TransParameters.Length();
			request.MaxParameterCount = NTTransactQuerySecurityDescriptorResponse.ParametersLength;
			request.MaxDataCount = (uint)maxOutputLength;

			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_NT_TRANSACT);
			if (reply != null)
			{
				if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is NTTransactResponse)
				{
					var response = (NTTransactResponse)reply.Commands[0];
					var subcommandResponse = new NTTransactQuerySecurityDescriptorResponse(response.TransParameters.Memory.Span, response.TransData.Memory.Span);
					result = subcommandResponse.SecurityDescriptor;
				}
				return reply.Header.Status;
			}
			return NTStatus.STATUS_INVALID_SMB;
		}

		public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
		{
			return NTStatus.STATUS_NOT_SUPPORTED;
		}

		public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
		{
			throw new NotImplementedException();
		}

		public NTStatus Cancel(object ioRequest)
		{
			throw new NotImplementedException();
		}

		public NTStatus DeviceIOControl(object handle, uint ctlCode, IMemoryOwner<byte> input, out IMemoryOwner<byte> output, int maxOutputLength)
		{
			if ((IoControlCode)ctlCode == IoControlCode.FSCTL_PIPE_TRANSCEIVE)
			{
				return FsCtlPipeTranscieve(handle, input, out output, maxOutputLength);
			}

			output = null;
			var subcommand = new NTTransactIOCTLRequest();
			subcommand.FID = (ushort)handle;
			subcommand.FunctionCode = ctlCode;
			subcommand.IsFsctl = true;
			subcommand.Data = input;

			var request = (NTTransactRequest) ObjectsPool<NTTransactRequest>.Get().Init();
			request.Function = subcommand.SubcommandName;
			request.Setup = subcommand.GetSetup();
			request.TransParameters = subcommand.GetParameters(m_client.Unicode);
			request.TransData = subcommand.GetData();
			request.TotalDataCount = (uint)request.TransData.Length();
			request.TotalParameterCount = (uint)request.TransParameters.Length();
			request.MaxParameterCount = NTTransactIOCTLResponse.ParametersLength;
			request.MaxDataCount = (uint)maxOutputLength;

			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_NT_TRANSACT);
			if (reply != null)
			{
				if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is NTTransactResponse)
				{
					var response = (NTTransactResponse)reply.Commands[0];
					var subcommandResponse = new NTTransactIOCTLResponse(response.Setup, response.TransData);
					output = Arrays.RentFrom<byte>(subcommandResponse.Data.Memory.Span);
				}
				return reply.Header.Status;
			}
			return NTStatus.STATUS_INVALID_SMB;
		}

		public NTStatus FsCtlPipeTranscieve(object handle, IMemoryOwner<byte> input, out IMemoryOwner<byte> output, int maxOutputLength)
		{
			output = null;
			var subcommand = new TransactionTransactNamedPipeRequest();
			subcommand.FID = (ushort)handle;
			subcommand.WriteData = input;

			var request = (TransactionRequest)ObjectsPool<TransactionRequest>.Get().Init();
			request.Setup = subcommand.GetSetup();
			request.TransParameters = subcommand.GetParameters();
			request.TransData = subcommand.GetData(m_client.Unicode);
			request.TotalDataCount = (ushort)request.TransData.Length();
			request.TotalParameterCount = (ushort)request.TransParameters.Length();
			request.MaxParameterCount = TransactionTransactNamedPipeResponse.ParametersLength;
			request.MaxDataCount = (ushort)maxOutputLength;
			request.Name = @"\PIPE\";

			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_TRANSACTION);
			if (reply != null)
			{
				if (reply.Header.Status == NTStatus.STATUS_SUCCESS && reply.Commands[0] is TransactionResponse)
				{
					var response = (TransactionResponse)reply.Commands[0];
					var subcommandResponse = new TransactionTransactNamedPipeResponse(response.TransData);
					output = Arrays.RentFrom<byte>(subcommandResponse.ReadData.Memory.Span);
				}
				return reply.Header.Status;
			}
			return NTStatus.STATUS_INVALID_SMB;
		}

		public NTStatus Disconnect()
		{
			var request = ObjectsPool<TreeDisconnectRequest>.Get().Init();
			TrySendMessage(request);
			var reply = m_client.WaitForCommand(CommandName.SMB_COM_TREE_DISCONNECT);
			if (reply != null)
			{
				return reply.Header.Status;
			}
			return NTStatus.STATUS_INVALID_SMB;
		}

		private void TrySendMessage(SMB1Command request)
		{
			m_client.TrySendMessage(request, m_treeID);
		}

		public uint MaxReadSize
		{
			get
			{
				return m_client.MaxReadSize;
			}
		}

		public uint MaxWriteSize
		{
			get
			{
				return m_client.MaxWriteSize;
			}
		}

		private static ExtendedFileAttributes ToExtendedFileAttributes(FileAttributes fileAttributes)
		{
			// We only return flags that can be used with NtCreateFile
			var extendedFileAttributes = ExtendedFileAttributes.ReadOnly |
										 ExtendedFileAttributes.Hidden |
										 ExtendedFileAttributes.System |
										 ExtendedFileAttributes.Archive |
										 ExtendedFileAttributes.Normal |
										 ExtendedFileAttributes.Temporary |
										 ExtendedFileAttributes.Offline |
										 ExtendedFileAttributes.Encrypted;
			return (extendedFileAttributes & (uint) fileAttributes);
		}

		private static FileStatus ToFileStatus(CreateDisposition createDisposition)
		{
			switch (createDisposition)
			{
				case CreateDisposition.FILE_SUPERSEDE:
					return FileStatus.FILE_SUPERSEDED;
				case CreateDisposition.FILE_OPEN:
					return FileStatus.FILE_OPENED;
				case CreateDisposition.FILE_CREATE:
					return FileStatus.FILE_CREATED;
				case CreateDisposition.FILE_OPEN_IF:
					return FileStatus.FILE_OVERWRITTEN;
				case CreateDisposition.FILE_OVERWRITE:
					return FileStatus.FILE_EXISTS;
				case CreateDisposition.FILE_OVERWRITE_IF:
					return FileStatus.FILE_DOES_NOT_EXIST;
				default:
					return FileStatus.FILE_OPENED;
			}
		}
	}
}
