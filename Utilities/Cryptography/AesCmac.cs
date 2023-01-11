// MIT: https://github.com/dorssel/dotnet-aes-extra/blob/8714eb99bb134f6ebe5388af8e6fad9f90751b9f/AesExtra/AesCmac.cs

using System;
using System.Security.Cryptography;

namespace Utilities;

/// <summary>
/// Computes a Cipher-based Message Authentication Code (CMAC) by using the symmetric key AES block cipher.
/// </summary>
public sealed class AesCmac
    : KeyedHashAlgorithm
{
    const int BLOCKSIZE = 16; // bytes

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCmac" /> class with a randomly generated key.
    /// </summary>
    public AesCmac()
    {
        AesEcb = Aes.Create();
        AesEcb.Mode = CipherMode.ECB;
        AesEcb.Padding = PaddingMode.None;
        CryptoTransform = AesEcb.CreateEncryptor();
        HashSizeValue = BLOCKSIZE * 8;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AesCmac" /> class with the specified key data.
    /// </summary>
    /// <param name="key">The secret key for AES-CMAC algorithm.</param>
    public AesCmac(byte[] key)
        : this()
    {
        Key = key;
    }

    void ZeroizeState()
    {
        CryptographicOperations.ZeroMemory(C);
        CryptographicOperations.ZeroMemory(Partial);
    }

    #region IDisposable
    bool IsDisposed;

    /// <inheritdoc cref="KeyedHashAlgorithm.Dispose(bool)" />
    protected override void Dispose(bool disposing)
    {
        if (!IsDisposed)
        {
            if (disposing)
            {
                CryptoTransform.Dispose();
                AesEcb.Dispose();
                ZeroizeState();
            }
            IsDisposed = true;
        }
        base.Dispose(disposing);
    }
    #endregion

    /// <inheritdoc cref="KeyedHashAlgorithm.Key" />
    public override byte[] Key
    {
        get => AesEcb.Key;
        set
        {
            CryptoTransform.Dispose();
            AesEcb.Key = value;
            CryptoTransform = AesEcb.CreateEncryptor();
        }
    }

    readonly Aes AesEcb;
    ICryptoTransform CryptoTransform;

    // See: NIST SP 800-38B, Section 6.2, Step 5
    readonly byte[] C = new byte[BLOCKSIZE];

    // See: NIST SP 800-38B, Section 4.2.2
    //
    // In-place: X = CIPH_K(X)
    void CIPH_K_InPlace(byte[] X_Base, int X_Offset = 0)
    {
        CryptoTransform.TransformBlock(X_Base, X_Offset, BLOCKSIZE, X_Base, X_Offset);
    }

    // See: NIST SP 800-38B, Section 6.1
    //
    // Returns: first ? K1 : K2
    byte[] SUBK(bool first)
    {
        var X = new byte[BLOCKSIZE];
        // Step 1: X has the role of L
        CIPH_K_InPlace(X);
        // Step 2: X has the role of K1
        X.dbl_InPlace();
        if (first)
        {
            // Step 4: return K1
            return X;
        }
        // Step 3: X has the role of K1
        X.dbl_InPlace();
        // Step 4: return K2
        return X;
    }

    /// <inheritdoc cref="HashAlgorithm.Initialize" />
    public override void Initialize()
    {
        // See: NIST SP 800-38B, Section 6.2, Step 5
        ZeroizeState();

        PartialLength = 0;
    }

    readonly byte[] Partial = new byte[BLOCKSIZE];
    int PartialLength;

    // See: NIST SP 800-38B, Section 6.2, Step 6
    void AddBlock(byte[] blockBase, int blockOffset = 0)
    {
        C.xor_InPlace(0, blockBase, blockOffset, BLOCKSIZE);
        CIPH_K_InPlace(C);
    }

    /// <inheritdoc cref="HashAlgorithm.HashCore(byte[], int, int)" />
    public void HashCore2(byte[] array, int ibStart, int cbSize) => HashCore(array, ibStart, cbSize);
    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        if (cbSize == 0)
        {
            return;
        }

        // If we have a non-empty && non-full Partial block already -> append to that first.
        if ((0 < PartialLength) && (PartialLength < BLOCKSIZE))
        {
            var count = Math.Min(cbSize, BLOCKSIZE - PartialLength);
            Array.Copy(array, ibStart, Partial, PartialLength, count);
            PartialLength += count;
            if (count == cbSize)
            {
                // No more data supplied, we're done. Even if we filled up Partial completely,
                // because we don't know if it will be the final block.
                return;
            }
            ibStart += count;
            cbSize -= count;
        }

        // We get here only if Partial is either empty or full (i.e. we are block-aligned) && there is more to "hash".
        if (PartialLength == BLOCKSIZE)
        {
            // Since there is more to hash, this is not the final block.
            // See: NIST SP 800-38B, Section 6.2, Steps 3 and 6
            AddBlock(Partial);
            PartialLength = 0;
        }

        // We get here only if Partial is empty && there is more to "hash".
        // Add complete, non-final blocks. Never add the last block given in this call since we don't know if that will be the final block.
        for (int i = 0, nonFinalBlockCount = (cbSize - 1) / BLOCKSIZE; i < nonFinalBlockCount; i++)
        {
            // See: NIST SP 800-38B, Section 6.2, Steps 3 and 6
            AddBlock(array, ibStart);
            ibStart += BLOCKSIZE;
            cbSize -= BLOCKSIZE;
        }

        // Save what we have left (we always have some, by construction).
        Array.Copy(array, ibStart, Partial, 0, cbSize);
        PartialLength = cbSize;
    }

    public byte[] HashFinal2() => HashFinal();

    /// <inheritdoc cref="HashAlgorithm.HashFinal" />
    protected override byte[] HashFinal()
    {
        // Partial now has the role of Mn*
        if (PartialLength == BLOCKSIZE)
        {
            // See: NIST SP 800-38B, Section 6.2, Step 1: K1
            var K1 = SUBK(true);
            Partial.xor_InPlace(0, K1, 0, BLOCKSIZE);
            // Partial now has the role of Mn
        }
        else
        {
            // Add padding
            Partial[PartialLength] = 0x80;
            for (var i = PartialLength + 1; i < BLOCKSIZE; ++i)
            {
                Partial[i] = 0x00;
            }
            // See: NIST SP 800-38B, Section 6.2, Step 1: K2
            var K2 = SUBK(false);
            Partial.xor_InPlace(0, K2, 0, BLOCKSIZE);
            // Partial now has the role of Mn
        }
        // See: NIST SP 800-38B, Section 6.2, Steps 4 and 6
        AddBlock(Partial);
        PartialLength = 0;

        // NOTE: KeyedHashAlgorithm exposes the returned array reference as the
        // Hash property, so we must *not* return C itself as it may be reused.
        var cmac = new byte[BLOCKSIZE];
        C.CopyTo(cmac, 0);

        ZeroizeState();

        return cmac;
    }
}
static class ExtensionMethods
{
    const int BLOCKSIZE = 16;

    // See: NIST SP 800-38B, Section 4.2
    //
    // In place: X = (X << 1)
    // Returns final carry.
    static bool LeftShiftOne_InPlace(this byte[] X)
    {
        var carry = false;
        for (var i = X.Length - 1; i >= 0; --i)
        {
            var nextCarry = (X[i] & 0x80) != 0;
            _ = unchecked(X[i] <<= 1);
            if (carry)
            {
                X[i] |= 1;
            }
            carry = nextCarry;
        }
        return carry;
    }

    // See: NIST SP 800-38B, Section 6.1
    // See: RFC 5297, Section 2.1
    //
    // In place: S = dbl(S)
    public static void dbl_InPlace(this byte[] S)
    {
        // See: NIST SP 800-38B, Section 5.3
        // See: RFC 5297, Section 2.3
        const int Rb = 0b10000111;

        // See: NIST SP 800-38B, Section 6.1, Step 2/3
        if (S.LeftShiftOne_InPlace())
        {
            S[BLOCKSIZE - 1] ^= Rb;
        }
    }

    // See: NIST SP 800-38B, Section 4.2.2
    //
    // In place: X = (X xor Y)
    public static void xor_InPlace(this byte[] X_Base, int X_Offset, byte[] Y_Base, int Y_Offset, int count)
    {
        for (var i = 0; i < count; ++i)
        {
            X_Base[X_Offset + i] ^= Y_Base[Y_Offset + i];
        }
    }
}