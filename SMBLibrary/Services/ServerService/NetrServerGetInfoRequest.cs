/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Buffers;
using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    /// <summary>
    /// NetrServerGetInfo Request (opnum 21)
    /// </summary>
    public class NetrServerGetInfoRequest
    {
        public string ServerName;
        public uint Level;

        public NetrServerGetInfoRequest()
        {
        }

        public NetrServerGetInfoRequest(IMemoryOwner<byte> buffer)
        {
            var parser = new NDRParser(buffer);
            ServerName = parser.ReadTopLevelUnicodeStringPointer();
            Level = parser.ReadUInt32();
        }

        public IMemoryOwner<byte> GetBytes()
        {
            var writer = new NDRWriter();
            writer.WriteTopLevelUnicodeStringPointer(ServerName);
            writer.WriteUInt32(Level);

            return writer.GetBytes();
        }
    }
}
