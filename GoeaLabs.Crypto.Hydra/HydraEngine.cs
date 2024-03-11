/*
   Copyright 2023-2024, GoeaLabs

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

using System.Runtime.CompilerServices;
using GoeaLabs.Bedrock.Extensions;
using GoeaLabs.Crypto.Chaos;

namespace GoeaLabs.Crypto.Hydra;

/// <summary>
/// HYDRA encryption engine.
/// </summary>
[SkipLocalsInit]
public class HydraEngine
{
    #region Private constants

    /// <summary>
    /// Invalid xor key (X-KEY) length.
    /// </summary>
    private const string ErrKeyLen = "Invalid X-KEY buffer length.";
    
    /// <summary>
    /// Invalid number of rounds.
    /// </summary>
    private const string ErrRounds = "Invalid number of rounds.";
    
    /// <summary>
    /// Invalid encryption/decryption source buffer length.
    /// </summary>
    private const string ErrSrcLen = "Invalid encryption/decryption source buffer length.";
    
    /// <summary>
    /// Invalid encryption/decryption output buffer length.
    /// </summary>
    private const string ErrOutLen = "Invalid encryption/decryption output buffer length.";
    
    /// <summary>
    /// Invalid ciphertext signature.
    /// </summary>
    private const string ErrVerify = "Invalid ciphertext signature.";

    #endregion
    
    #region Public constants
    
    /// <summary>
    /// X-KEY, N-KEY and E-KEY length in bytes.
    /// </summary>
    public const int KeyLength = 32;

    /// <summary>
    /// Default number of rounds.
    /// </summary>
    public const int DefRounds = ChaosEngine.DefRounds;

    #endregion

    #region Private properties

    /// <summary>
    /// <see cref="IHydraSigner"/> for authenticated encryption.
    /// </summary>
    private IHydraSigner Signer { get; }
    
    /// <summary>
    /// Number of rounds to apply.
    /// </summary>
    private int Rounds { get; }
    
    /// <summary>
    /// Engine's X-KEY.
    /// </summary>
    private byte[] XorKey { get; }

    #endregion

    #region Public properties

    /// <summary>
    /// Hydra{Rounds}{Signer} 
    /// </summary>
    public string Scheme { get; }

    #endregion

    #region Public constructors

    /// <summary>
    /// Instantiates a new engine instance.
    /// </summary>
    /// <param name="xorKey">X-KEY.</param>
    /// <param name="signer">Signing engine.</param>
    /// <param name="rounds">Number of rounds.</param>
    /// <exception cref="HydraException">
    /// If <paramref name="xorKey"/> length is not equal to <see cref="KeyLength"/>.
    /// </exception>
    /// <exception cref="HydraException">
    /// If <paramref name="rounds"/> is not greater than or equal to <see cref="DefRounds"/>
    /// and even.
    /// </exception>
    public HydraEngine(byte[] xorKey, IHydraSigner signer, int rounds = DefRounds)
    {
        if (xorKey.Length != KeyLength)
            throw new HydraException(HydraErrorCode.ErrKeyLen, ErrKeyLen);

        if (rounds < DefRounds || rounds % 2 > 0)
            throw new HydraException(HydraErrorCode.ErrRounds, ErrRounds);
        
        XorKey = xorKey;
        Rounds = rounds;
        Signer = signer;

        Scheme = $"HYDRA{Rounds}{Signer.Scheme}";
    }

    /// <summary>
    /// Instantiates a new engine instance.
    /// </summary>
    /// <param name="xorKey">X-KEY.</param>
    /// <param name="rounds">Number of rounds.</param>
    /// <param name="signer">Signing engine.</param>
    /// <exception cref="HydraException">
    /// If <paramref name="rounds"/> is not greater than
    /// or equal to <see cref="DefRounds"/> and even.
    /// </exception>
    public HydraEngine(string xorKey, IHydraSigner signer, int rounds = DefRounds) 
        : this(Convert.FromHexString(xorKey), signer, rounds) { }

    #endregion
    
    #region Internal methods
    
    /// <summary>
    /// Encrypts a buffer using the given nKey.
    /// </summary>
    /// <remarks>
    /// This method only exists for testing purposes.
    /// </remarks>
    /// <param name="nKey">Nonce data.</param>
    /// <param name="source">Plaintext buffer.</param>
    /// <param name="output">Ciphertext buffer.</param>
    internal void Encrypt(Span<byte> nKey, ReadOnlySpan<byte> source, Span<byte> output)
    {
        var nKeySlice = output[..KeyLength];
        var hashSlice = output[KeyLength..(KeyLength + Signer.SigLen)];
        var dataSlice = output[(KeyLength + Signer.SigLen)..];
        
        // Copy nKey key to output
        nKey.CopyTo(nKeySlice);

        // Compute actual encryption key bytes
        nKey.Xor(XorKey);

        // Compute uint encryption key (Chaos kernel)
        Span<uint> eKey = stackalloc uint[ChaosEngine.KernelLen];
        nKey.Merge(eKey);
        
        // Encrypt plaintext
        XOr(eKey, source, dataSlice);
        
        // Produce all the bytes necessary for hashing key (optional) and signature encryption key 
        Span<byte> hashingKeys = stackalloc byte[Signer.KeyLen + Signer.SigLen];
        _ = ChaosEngine.Load(hashingKeys, eKey, Rounds, new ChaosLocale(0, 0));
        
        // Assign hashing key bytes
        var hKey = Signer.KeyLen > 0 ? hashingKeys[..Signer.KeyLen] : Span<byte>.Empty;
        // Assign signature encryption key bytes
        var sKey = Signer.KeyLen > 0 ? hashingKeys[Signer.KeyLen..] : hashingKeys;
        
        // Compute signature and write it to output
        Signer.GenSig(dataSlice, hKey, hashSlice);
        
        // Encrypt signature
        hashSlice.Xor(sKey);
    }
    
    #endregion
    
    #region Private methods

    /// <summary>
    /// XORs each byte from <paramref name="source"/> with random bytes generated by
    /// <see cref="ChaosEngine"/> and writes the result to <paramref name="output"/>.
    /// </summary>
    /// <param name="kernel"><see cref="ChaosEngine"/> kernel.</param>
    /// <param name="source">Source buffer.</param>
    /// <param name="output">Output buffer.</param>
    private void XOr(Span<uint> kernel, ReadOnlySpan<byte> source, Span<byte> output)
    {
        Span<byte> buffer = stackalloc byte[ChaosEngine.PebbleLen];
        
        var locale = new ChaosLocale(0, 1);
        
        var now = -1;
        var end = source.Length - 1;

        do
        {
            locale = ChaosEngine.Load(buffer, kernel, Rounds, locale);
            
            foreach (var member in buffer)
            {
                output[++now] = (byte)(source[now] ^ member);

                if (now == end)
                    break;
            }
            
        } while (now != end);
    }

    #endregion

    #region Public methods

    /// <summary>
    /// Generates a new cryptographically secure X-KEY.
    /// </summary>
    /// <param name="output">Buffer to write to.</param>
    /// <exception cref="HydraException">
    /// If <paramref name="output"/> length is not equal to <see cref="KeyLength"/>.
    /// </exception>
    public static void NewKey(Span<byte> output)
    {
        if (output.Length != KeyLength)
            throw new HydraException(HydraErrorCode.ErrKeyLen, ErrKeyLen);
        
        output.FillRandom();
    }

    /// <summary>
    /// Generates a new cryptographically secure encryption key.
    /// </summary>
    /// <returns>The key as HEX string.</returns>
    public static string NewKey()
    {
        Span<byte> buffer = stackalloc byte[KeyLength];
        NewKey(buffer);

        return Convert.ToHexString(buffer);
    }

    /// <summary>
    /// If given a plaintext buffer, calculates the length of the
    /// ciphertext buffer.
    /// <br/>
    /// If given a ciphertext buffer, calculates the length of the
    /// plaintext buffer.
    /// </summary>
    /// <param name="source">Buffer to compute for.</param>
    /// <param name="isPlain">Whether the buffer is plaintext.</param>
    /// <returns>The length.</returns>
    /// <exception cref="HydraException">
    /// If <paramref name="source"/> length is 0.
    /// </exception>
    /// <exception cref="HydraException">
    /// If the result is not greater than 0.
    /// </exception>
    public int GetLen(ReadOnlySpan<byte> source, bool isPlain)
    {
        if (source.Length == 0)
            throw new HydraException(HydraErrorCode.ErrSrcLen, ErrSrcLen);

        var len = isPlain 
            ? KeyLength + Signer.SigLen + source.Length
            : source.Length - KeyLength - Signer.SigLen;
        
        if (len < 1)
            throw new HydraException(HydraErrorCode.ErrSrcLen, ErrSrcLen);

        return len;
    }
    
    /// <summary>
    /// Encrypts a buffer.
    /// </summary>
    /// <param name="source">Plaintext buffer.</param>
    /// <param name="output">Encrypted buffer.</param>
    /// <exception cref="HydraException">
    /// If <paramref name="source"/> buffer length is 0.
    /// </exception>
    /// <exception cref="HydraException">
    /// If <paramref name="output"/> buffer length is
    /// not large enough to accomodate the encrypted data.
    /// </exception>
    public void Encrypt(ReadOnlySpan<byte> source, Span<byte> output)
    {
        if (output.Length != GetLen(source, true))
            throw new HydraException(HydraErrorCode.ErrOutLen, ErrOutLen);
        
        Span<byte> nKey = stackalloc byte[KeyLength];
        NewKey(nKey);
        
        Encrypt(nKey, source, output);
    }

    /// <summary>
    /// Decrypts a buffer.
    /// </summary>
    /// <param name="source">Encrypted buffer.</param>
    /// <param name="output">Plaintext buffer.</param>
    /// <exception cref="HydraException">
    /// If <paramref name="source"/> buffer length is
    /// invalid.
    /// </exception>
    /// <exception cref="HydraException">
    /// If <paramref name="output"/> buffer length is
    /// not large enough to accomodate the decrypted data.
    /// </exception>
    /// <exception cref="HydraException">
    /// If the signature of <paramref name="source"/> fails
    /// verification.
    /// </exception>
    public void Decrypt(ReadOnlySpan<byte> source, Span<byte> output)
    {
        if (output.Length != GetLen(source, false))
            throw new HydraException(HydraErrorCode.ErrOutLen, ErrOutLen);
        
        var nKeySlice = source[..KeyLength];
        var hashSlice = source[KeyLength..(KeyLength + Signer.SigLen)];
        var dataSlice = source[(KeyLength + Signer.SigLen)..];
        
        // Extract nKey bytes from encrypted
        Span<byte> nKey = stackalloc byte[KeyLength];
        nKeySlice.CopyTo(nKey);
        
        // Compute uint encryption key from nKey bytes and secret key
        nKey.Xor(XorKey);
        Span<uint> eKey = stackalloc uint[ChaosEngine.KernelLen];
        nKey.Merge(eKey);
        
        // Extract encrypted signature bytes
        Span<byte> signature = stackalloc byte[Signer.SigLen];
        hashSlice.CopyTo(signature);
        
        // Produce all the bytes necessary for optional hashing key and signature encryption key 
        Span<byte> hashingKeys = stackalloc byte[Signer.KeyLen + Signer.SigLen];
        _ = ChaosEngine.Load(hashingKeys, eKey, Rounds, new ChaosLocale(0, 0));

        // Decrypt signature
        signature.Xor(Signer.KeyLen > 0 ? hashingKeys[Signer.KeyLen..] : hashingKeys);
        
        // Assign optional hashing key
        var hashingKey = Signer.KeyLen > 0 ? hashingKeys[..Signer.KeyLen] : Span<byte>.Empty;
        
        // Compute encrypted signature
        Span<byte> computedSignature = stackalloc byte[Signer.SigLen];
        Signer.GenSig(dataSlice, hashingKey, computedSignature);

        // Abort if signature does not match
        if (!signature.SequenceEqual(computedSignature))
            throw new HydraException(HydraErrorCode.ErrVerify, ErrVerify);
        
        // Decrypt encrypted
        XOr(eKey, dataSlice, output);
    }

    #endregion
}