/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace SMBLibrary.SMB1
{
	/// <summary>
	/// SMB_COM_TRANSACTION2 Request
	/// The SMB_COM_TRANSACTION2 request format is similar to that of the SMB_COM_TRANSACTION request except for the Name field.
	/// The differences are in the subcommands supported, and in the purposes and usages of some of the fields.
	/// </summary>
	public class Transaction2Request : TransactionRequest
	{
		public Transaction2Request() : base()
		{
			Init();
		}
		
		public override SMB1Command Init()
		{
			base.Init();
			return this;
		}

		public Transaction2Request Init(Span<byte> buffer, int offset)
		{
			base.Init(buffer, offset, false);
			return this;
		}

		public override CommandName CommandName => CommandName.SMB_COM_TRANSACTION2;
	}
}
