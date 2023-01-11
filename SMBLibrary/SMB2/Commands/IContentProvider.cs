using System;

namespace SMBLibrary.SMB2;

internal interface IContentProvider
{
  ArraySegment<byte>[] GetContentBytes();
}