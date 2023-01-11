using System;

namespace SMBLibrary.SMB2;

internal class TrailerDecryptor : ITrailerDecryptor
{
  private byte[] decryptionKey;

  public Span<byte> DecryptTrailer(Span<byte> trailer)
  {
    if (decryptionKey == null || !SMB2TransformHeader.IsTransformHeader(trailer))
      return trailer;
    SMB2TransformHeader transformHeader = new SMB2TransformHeader(trailer);
    var message = trailer.Slice(SMB2TransformHeader.Length, (int)transformHeader.OriginalMessageSize);
    SMB2Cryptography.DecryptMessage(decryptionKey, transformHeader, message);
    return message;
  }

  public void SetDecryptionKey(byte[] mDecryptionKey)
  {
    decryptionKey = mDecryptionKey;
  }
}