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
/// Represents errors that occur during
/// <see cref="HydraEngine"/> operations.
/// </summary>
public class HydraException : Exception
{
    /// <summary>
    /// Error code.
    /// </summary>
    public HydraErrorCode ErrorCode { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="HydraException"/>
    /// with a <see cref="HydraErrorCode"/> and optional message.
    /// </summary>
    /// <param name="errCode">Error code.</param>
    /// <param name="message">Message.</param>
    public HydraException(HydraErrorCode errCode, string? message = null) 
        : base(message)
    {
        ErrorCode = errCode;
    }
}