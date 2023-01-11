using System.Security.Cryptography;
using Utilities;

namespace SMBLibrary.SMB2;

internal class SMBSigningKey
{
  public readonly IncrementalHash HMAC;
  public readonly AesCmac CMAC;

  public SMBSigningKey(byte[] key)
  {
    HMAC = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
    CMAC = new AesCmac(key);
  }
}