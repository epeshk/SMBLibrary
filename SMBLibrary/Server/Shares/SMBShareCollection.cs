/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.Server
{
    public class SMBShareCollection : List<FileSystemShare>
    {
        public void Add(string shareName, IFileSystem fileSystem, CachingPolicy cachingPolicy)
        {
            var share = new FileSystemShare(shareName, fileSystem, cachingPolicy);
            Add(share);
        }

        public bool Contains(string shareName, StringComparison comparisonType)
        {
            return (IndexOf(shareName, comparisonType) != -1);
        }

        public int IndexOf(string shareName, StringComparison comparisonType)
        {
            for (var index = 0; index < Count; index++)
            {
                if (this[index].Name.Equals(shareName, comparisonType))
                {
                    return index;
                }
            }

            return -1;
        }

        public List<string> ListShares()
        {
            var result = new List<string>();
            for (var index = 0; index < Count; index++)
            {
                var share = this[index];
                result.Add(share.Name);
            }

            return result;
        }

        /// <param name="relativePath">e.g. \Shared</param>
        public FileSystemShare GetShareFromName(string shareName)
        {
            var index = IndexOf(shareName, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                return this[index];
            }

            return null;
        }
    }
}
