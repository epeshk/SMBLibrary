using System;
using System.Security.Cryptography;

namespace SMBLibrary.SMB2;

internal class SMBEncryptor
{
  private readonly AesCcm aesCcm;
  private const int AesCcmNonceLength = 11;

  public SMBEncryptor(byte[] key)
  {
    aesCcm = new AesCcm(key);
  }
        
  public ArraySegment<byte>[] TransformMessage(ArraySegment<byte> message, ulong sessionID)
  {
    byte[] nonce = GenerateAesCcmNonce();
    byte[] signature;
    EncryptMessage(nonce, message, sessionID, out signature);
    SMB2TransformHeader transformHeader = SMB2Cryptography.CreateTransformHeader(nonce, message.Count, sessionID);
    transformHeader.Signature = signature;

    byte[] buffer = new byte[SMB2TransformHeader.Length];
    transformHeader.WriteBytes(buffer, 0);
    return new[]{buffer, message};
  }

  private static byte[] GenerateAesCcmNonce()
  {
    byte[] aesCcmNonce = new byte[AesCcmNonceLength];
    RandomNumberGenerator.Fill(aesCcmNonce);
    return aesCcmNonce;
  }

  public void EncryptMessage(byte[] nonce, Span<byte> message, ulong sessionID, out byte[] signature)
  {
    SMB2TransformHeader transformHeader = SMB2Cryptography.CreateTransformHeader(nonce, message.Length, sessionID);
    byte[] associatedata = transformHeader.GetAssociatedData();
    signature = new byte[SMB2TransformHeader.SignatureLength];
    aesCcm.Encrypt(nonce, message, message, signature, associatedata);
  }
}