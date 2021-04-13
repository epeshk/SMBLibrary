using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MemoryPools.Memory;
using SMBLibrary.SMB2;

namespace SMBLibrary.Client
{
	public partial class Smb2FileStore
	{
		internal class QueryDirectoryAsyncEnumerable : IAsyncEnumerable<FindFilesQueryResult>
		{
			private Smb2FileStore _store;
			private Smb2Client _client;
			private object _handle;
			private string _fileName;
			private FileInformationClass _informationClass;
			private bool _closeOnFinish;

			public QueryDirectoryAsyncEnumerable Init(
				Smb2FileStore store,
				Smb2Client client, 
				object handle, 
				string fileName, 
				FileInformationClass informationClass,
				bool closeOnFinish)
			{
				_store = store;
				_client = client;
				_handle = handle;
				_fileName = fileName;
				_informationClass = informationClass;
				_closeOnFinish = closeOnFinish;
				return this;
			}
			
			// only single call of GetAsyncEnumerator is supported
			public IAsyncEnumerator<FindFilesQueryResult> GetAsyncEnumerator(CancellationToken cancellationToken = new CancellationToken())
			{
				var (store, client, handle, fileName) = (_store, _client, _handle, _fileName);
				(_store, _client, _handle, _fileName) = (default, default, default, default);
				
				ObjectsPool<QueryDirectoryAsyncEnumerable>.Return(this);
				
				return ObjectsPool<QueryDirectoryAsyncEnumerator>.Get().Init(
					store, client, handle, fileName, _informationClass, cancellationToken, _closeOnFinish);
			}
			
			internal class QueryDirectoryAsyncEnumerator : IAsyncEnumerator<FindFilesQueryResult>
			{
				private int _step;
				private object _handle;
				private string _fileName;
				private Smb2Client _client;
				private Smb2FileStore _store;
				private FileInformationClass _informationClass;
				private CancellationToken _token;

				private QueryDirectoryRequest _request;
				private IMemoryOwner<QueryDirectoryFileInformation> _response;
				private int _indexInBatch;
				private bool _closeOnFinish;

				public QueryDirectoryAsyncEnumerator Init(
					Smb2FileStore store,
					Smb2Client client, 
					object handle, 
					string fileName, 
					FileInformationClass informationClass,
					CancellationToken token,
					bool closeOnFinish)
				{
					_step = 0;
					_indexInBatch = 0;
					_handle = handle;
					_fileName = fileName;
					_client = client;
					_store = store;
					_informationClass = informationClass;
					_token = token;
					_closeOnFinish = closeOnFinish;
					_request = default;
					_response = default;
					return this;
				}

				public ValueTask DisposeAsync()
				{
					CleanupAndFinish();
					ObjectsPool<QueryDirectoryAsyncEnumerator>.Return(this);
					return new ValueTask();
				}

				private void CleanupAndFinish()
				{
					if (_closeOnFinish && _handle != default)
					{
						_store.CloseFile(_handle);
					}

					CleanupResponse();

					_request?.Dispose();
					_request = default;
					_store = default;
					_client = default;
					_handle = default;
					_fileName = default;
					_informationClass = default;
					_token = default;
					Current = default;
				}

				private void CleanupResponse()
				{
					if (_response != null)
					{
						_response.Memory.Span.Clear();
						_response.Dispose();
						_response = null;
					}
				}

				public ValueTask<bool> MoveNextAsync()
				{
					// if finished, return false
					if (_step > 0 && _response == null)
					{
						return new ValueTask<bool>(false);
					}
					
					// if started or batch finished, request more data
					if (_step == 0 || _indexInBatch == _response.Length())
					{
						// dispose previous results if any
						CleanupResponse();
						
						// construct new request
						_request = ObjectsPool<QueryDirectoryRequest>.Get().Init();
						_request.Header.CreditCharge = (ushort) Math.Ceiling((double) _client.MaxTransactSize / BytesPerCredit);
						_request.FileInformationClass = _informationClass;
						_request.FileId = (FileID) _handle;
						_request.OutputBufferLength = _client.MaxTransactSize;
						_request.FileName = _fileName;
						_request.Reopen = (_step == 0);

						_indexInBatch = 0;

						_token.ThrowIfCancellationRequested();
                        _store.TrySendCommandAndDispose(_request);
                        
                        var response = _client.WaitForCommand(SMB2CommandName.QueryDirectory);
						if (response != null && response.Header.Status == NTStatus.STATUS_SUCCESS && response is QueryDirectoryResponse qdr)
						{ 
							_response = qdr.GetFileInformationList(_informationClass);
							response.Dispose();
						}
						else
						{
							// Nothing found. disposing.
							response?.Dispose();
							return new ValueTask<bool>(false);
						}
					}

					using (var info = (FileDirectoryInformation) _response.Memory.Span[_indexInBatch])
					{
						var res = FindFilesQueryResult.From(info);  // lnk +1
						Current = res;
					}
						
					_indexInBatch++;
					_step++;
					
					return new ValueTask<bool>(true);
				}

				public FindFilesQueryResult Current { get; private set; }
			}
		}
	}
}
