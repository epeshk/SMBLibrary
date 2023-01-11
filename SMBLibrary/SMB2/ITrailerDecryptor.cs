using System;

namespace SMBLibrary.SMB2;

internal interface ITrailerDecryptor
{
  Span<byte> DecryptTrailer(Span<byte> trailer);
  void SetDecryptionKey(byte[] mDecryptionKey);
}