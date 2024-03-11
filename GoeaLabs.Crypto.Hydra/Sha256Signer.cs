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

using System.Security.Cryptography;

namespace GoeaLabs.Crypto.Hydra;

/// <summary>
/// SHA256 signer.
/// </summary>
public class Sha256Signer : IHydraSigner
{
    /// <inheritdoc/>
    public string Scheme => "SHA256";
    
    /// <inheritdoc/>
    public int KeyLen => 0;

    /// <inheritdoc/>
    public int SigLen => 32;

    /// <inheritdoc/>
    /// <exception cref="HydraException">
    /// If the <paramref name="sig"/> buffer is not large enough to accomodate the
    /// computed signature.
    /// </exception>
    public void GenSig(ReadOnlySpan<byte> src, ReadOnlySpan<byte> key, Span<byte> sig) => 
        SHA256.TryHashData(src, sig, out _);
}