/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_SET_INFORMATION2 Response
    /// </summary>
    public class SetInformation2Response : SMB1Command
    {
        public override SMB1Command Init()
        {
            base.Init();
            return this;
        }

        public SetInformation2Response Init(Span<byte> buffer, int offset)
        {
            base.Init(buffer, offset, false);
            return this;
        }
        
        public override CommandName CommandName => CommandName.SMB_COM_SET_INFORMATION2;
    }
}
