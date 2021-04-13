/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.IO;

namespace SMBLibrary
{
    public class FileHandle : IDisposable
    {
        public IMemoryOwner<char> Path;
        public bool IsDirectory;
        public Stream Stream;
        public bool DeleteOnClose;

        public FileHandle(IMemoryOwner<char> path, bool isDirectory, Stream stream, bool deleteOnClose)
        {
            Path = path;
            IsDirectory = isDirectory;
            Stream = stream;
            DeleteOnClose = deleteOnClose;
        }

        public void Dispose()
        {
            // tocheck Path?.Dispose();
            // tocheck Path = null;
        }
    }
}
