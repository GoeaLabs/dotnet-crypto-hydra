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

namespace GoeaLabs.Crypto.Hydra;

/// <summary>
/// AEAD interface.
/// </summary>
public interface IHydraSigner
{
    /// <summary>
    /// Error message for invalid hashing key (H-KEY) buffer length.
    /// </summary>
    public const string ErrSigKey = "Invalid hashing key (H-KEY) buffer length.";
    
    /// <summary>
    /// Error message for invalid signature output buffer length.
    /// </summary>
    public const string ErrSigOut = "Invalid signature output buffer length.";
    
    /// <summary>
    /// Hashing scheme.
    /// </summary>
    public string Scheme { get; }
    
    /// <summary>
    /// H-KEY length in <see cref="byte"/>(s).
    /// </summary>
    public int KeyLen { get; }
    
    /// <summary>
    /// Signature length in <see cref="byte"/>(s).
    /// </summary>
    public int SigLen { get; }

    /// <summary>
    /// Generates the signature of the source data.
    /// </summary>
    /// <param name="src">Buffer to sign.</param>
    /// <param name="key">Key to hash with.</param>
    /// <param name="sig">Generated signature.</param>
    public void GenSig(ReadOnlySpan<byte> src, ReadOnlySpan<byte> key, Span<byte> sig);
}