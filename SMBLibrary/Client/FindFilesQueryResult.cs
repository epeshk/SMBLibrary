using System;
using System.Buffers;
using MemoryPools.Memory;
using SMBLibrary.SMB1;

namespace SMBLibrary.Client
{
	public class FindFilesQueryResult : IDisposable
	{
		public uint? Index;
		public DateTime? CreationTime;
		public DateTime? LastAccessTime;
		public DateTime? LastWriteTime;
		public DateTime? ChangeTime;
		public long EndOfFile;
		public long AllocationSize;
		public ExtendedFileAttributes FileAttributes;
		public IMemoryOwner<char> FileName = MemoryOwner<char>.Empty;

		public static FindFilesQueryResult From(FileDirectoryInformation fdi)
		{
			var fi = ObjectsPool<FindFilesQueryResult>.Get();
			fi.Index = fdi.FileIndex;
			fi.CreationTime = fdi.CreationTime;
			fi.LastAccessTime = fdi.LastAccessTime;
			fi.LastWriteTime = fdi.LastWriteTime;
			fi.ChangeTime = fdi.ChangeTime;
			fi.EndOfFile = fdi.EndOfFile;
			fi.AllocationSize = fdi.AllocationSize;
			fi.FileAttributes = fdi.FileAttributes;
			fi.FileName = fdi.FileName.AddOwner();
			return fi;
		}
		
		public static FindFilesQueryResult From(FindFileDirectoryInfo fdi)
		{
			var fi = ObjectsPool<FindFilesQueryResult>.Get();
			fi.Index = fdi.FileIndex;
			fi.CreationTime = fdi.CreationTime;
			fi.LastAccessTime = fdi.LastAccessTime;
			fi.LastWriteTime = fdi.LastWriteTime;
			fi.ChangeTime = fdi.LastWriteTime;
			fi.EndOfFile = fdi.EndOfFile;
			fi.AllocationSize = fdi.AllocationSize;
			fi.FileAttributes = fdi.ExtFileAttributes;
			fi.FileName = fdi.FileName.AddOwner();
			return fi;
		}

		public void Dispose()
		{
			FileName.Dispose();
			ObjectsPool<FindFilesQueryResult>.Return(this);
		}
	}
}