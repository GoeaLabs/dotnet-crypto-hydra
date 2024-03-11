﻿namespace GoeaLabs.Crypto.Hydra.Tests;

public static class HydraTestVectors
{
    /// <summary>
    /// <see cref="HydraEngine"/> X-KEY as <see cref="byte"/>(s).
    /// </summary>
    public static byte[] XKey =>
    [
        0x51, 0xFF, 0x15, 0x86, 0x4A, 0xCD, 0xA5, 0x14,
        0x43, 0x9D, 0xE8, 0xEF, 0x62, 0x02, 0xE8, 0x1F,
        0x43, 0xE5, 0x9D, 0x9A, 0x8A, 0x04, 0x97, 0xD4,
        0x98, 0x39, 0xEF, 0x4B, 0xBB, 0x55, 0x81, 0x81
    ];

    /// <summary>
    /// <see cref="HydraEngine"/> N-KEY (nonce) as <see cref="byte"/>(s).
    /// </summary>
    public static byte[] NKey =>
    [
        0x07, 0x65, 0xDE, 0x1A, 0xC0, 0x09, 0x2D, 0x74,
        0x6B, 0x3E, 0xF6, 0x09, 0x08, 0x0E, 0x30, 0x7E,
        0x92, 0xD2, 0x3C, 0x36, 0x27, 0x50, 0xB2, 0xAD,
        0x4C, 0x70, 0x38, 0x62, 0xDC, 0x7A, 0x7F, 0x42
    ];

    /// <summary>
    /// ASCII bytes for the phrase: 'HydraEngine: A cipher serpent coils, scales glistening 
    /// with might, data entwined in cryptic embrace, secrets safeguarded unyieldingly.'
    /// </summary>
    public static byte[] Plaintext =>
    [
        0x48, 0x79, 0x64, 0x72, 0x61, 0x3A, 0x20, 0x41,
        0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20,
        0x73, 0x65, 0x72, 0x70, 0x65, 0x6E, 0x74, 0x20,
        0x63, 0x6F, 0x69, 0x6C, 0x73, 0x2C, 0x20, 0x73,
        0x63, 0x61, 0x6C, 0x65, 0x73, 0x20, 0x67, 0x6C,
        0x69, 0x73, 0x74, 0x65, 0x6E, 0x69, 0x6E, 0x67,
        0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x6D, 0x69,
        0x67, 0x68, 0x74, 0x2C, 0x20, 0x64, 0x61, 0x74,
        0x61, 0x20, 0x65, 0x6E, 0x74, 0x77, 0x69, 0x6E,
        0x65, 0x64, 0x20, 0x69, 0x6E, 0x20, 0x63, 0x72,
        0x79, 0x70, 0x74, 0x69, 0x63, 0x20, 0x65, 0x6D,
        0x62, 0x72, 0x61, 0x63, 0x65, 0x2C, 0x20, 0x73,
        0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x20, 0x73,
        0x61, 0x66, 0x65, 0x67, 0x75, 0x61, 0x72, 0x64,
        0x65, 0x64, 0x20, 0x75, 0x6E, 0x79, 0x69, 0x65,
        0x6C, 0x64, 0x69, 0x6E, 0x67, 0x6C, 0x79, 0x2E
    ];

    /// <summary>
    /// Expected ciphertext when signing with <see cref="Sha256Signer"/>
    /// </summary>
    public static byte[] CiphertextSha256 =>
    [
        // N-KEY (nonce)
        0x07, 0x65, 0xDE, 0x1A, 0xC0, 0x09, 0x2D, 0x74,
        0x6B, 0x3E, 0xF6, 0x09, 0x08, 0x0E, 0x30, 0x7E,
        0x92, 0xD2, 0x3C, 0x36, 0x27, 0x50, 0xB2, 0xAD,
        0x4C, 0x70, 0x38, 0x62, 0xDC, 0x7A, 0x7F, 0x42,
        // encrypted signature
        0x1F, 0x11, 0xC4, 0x18, 0x9D, 0x6E, 0x17, 0xF0,
        0x19, 0xB5, 0xE6, 0x14, 0x69, 0x7D, 0xC0, 0x75,
        0x17, 0x90, 0x6E, 0x45, 0x66, 0x4D, 0xF3, 0xF7,
        0xE0, 0xD6, 0x9C, 0x32, 0xB9, 0x82, 0xF8, 0x4F,
        // encrypted data (HydraBytes)
        0xDA, 0x0D, 0x6C, 0xBA, 0x47, 0x2E, 0xD4, 0x24,
        0xFE, 0x91, 0x36, 0x41, 0x9C, 0x17, 0xB4, 0x73,
        0x78, 0xC6, 0x65, 0x74, 0xA6, 0x87, 0x58, 0xCE,
        0x5A, 0xAF, 0x4B, 0xA3, 0xC4, 0xEA, 0x2F, 0xE1,
        0xB7, 0xD4, 0xE6, 0x28, 0x63, 0xD9, 0xC9, 0xCE,
        0xFD, 0x43, 0xA9, 0xC7, 0x39, 0x4F, 0x00, 0x8E,
        0x98, 0x15, 0xBD, 0x40, 0x04, 0x07, 0x6E, 0x6E,
        0x66, 0xAA, 0x0C, 0xD5, 0xA7, 0x0D, 0xA8, 0x30,
        0x12, 0xF1, 0x8A, 0x48, 0xDC, 0xAA, 0xCF, 0xC4,
        0x17, 0xD1, 0xBA, 0x14, 0x8E, 0x4E, 0x6E, 0x35,
        0xC8, 0x5B, 0xAA, 0xBF, 0x9B, 0x9F, 0xC6, 0x83,
        0xA1, 0xCC, 0x11, 0xFA, 0xDD, 0xC0, 0x13, 0x79,
        0xAF, 0x54, 0xF2, 0xA0, 0x27, 0x5C, 0x3A, 0x9B,
        0xCA, 0xB3, 0x3B, 0x54, 0xB7, 0x43, 0xCC, 0x8D,
        0x43, 0x2F, 0x9E, 0x13, 0xF2, 0x2E, 0x47, 0x90,
        0x25, 0x8A, 0x9F, 0x42, 0xB2, 0xEA, 0x87, 0x3A
    ];

    /// <summary>
    /// Expected ciphertext when signing with <see cref="Sha384Signer"/>
    /// </summary>
    // ReSharper disable once ReturnTypeCanBeEnumerable.Global
    public static byte[] CiphertextSha384 =>
    [
        // N-KEY (nonce)
        0x07, 0x65, 0xDE, 0x1A, 0xC0, 0x09, 0x2D, 0x74,
        0x6B, 0x3E, 0xF6, 0x09, 0x08, 0x0E, 0x30, 0x7E,
        0x92, 0xD2, 0x3C, 0x36, 0x27, 0x50, 0xB2, 0xAD,
        0x4C, 0x70, 0x38, 0x62, 0xDC, 0x7A, 0x7F, 0x42,
        // encrypted signature
        0x81, 0x2B, 0x93, 0x7D, 0xF5, 0xB7, 0x6E, 0xD6, 
        0x6B, 0xC1, 0x50, 0xF0, 0x8B, 0x9E, 0xDD, 0x16,
        0xB5, 0xF2, 0x39, 0x1B, 0x74, 0x6D, 0xCA, 0x3C,
        0x9F, 0x48, 0x93, 0x88, 0x60, 0x30, 0x55, 0x92,
        0xA6, 0x5A, 0x3E, 0xEC, 0x83, 0x1D, 0x73, 0x56,
        0xA9, 0xF7, 0xCD, 0x98, 0x64, 0xFA, 0x82, 0x1A,
        // encrypted data (HydraBytes)
        0xDA, 0x0D, 0x6C, 0xBA, 0x47, 0x2E, 0xD4, 0x24,
        0xFE, 0x91, 0x36, 0x41, 0x9C, 0x17, 0xB4, 0x73,
        0x78, 0xC6, 0x65, 0x74, 0xA6, 0x87, 0x58, 0xCE,
        0x5A, 0xAF, 0x4B, 0xA3, 0xC4, 0xEA, 0x2F, 0xE1,
        0xB7, 0xD4, 0xE6, 0x28, 0x63, 0xD9, 0xC9, 0xCE,
        0xFD, 0x43, 0xA9, 0xC7, 0x39, 0x4F, 0x00, 0x8E,
        0x98, 0x15, 0xBD, 0x40, 0x04, 0x07, 0x6E, 0x6E,
        0x66, 0xAA, 0x0C, 0xD5, 0xA7, 0x0D, 0xA8, 0x30,
        0x12, 0xF1, 0x8A, 0x48, 0xDC, 0xAA, 0xCF, 0xC4,
        0x17, 0xD1, 0xBA, 0x14, 0x8E, 0x4E, 0x6E, 0x35,
        0xC8, 0x5B, 0xAA, 0xBF, 0x9B, 0x9F, 0xC6, 0x83,
        0xA1, 0xCC, 0x11, 0xFA, 0xDD, 0xC0, 0x13, 0x79,
        0xAF, 0x54, 0xF2, 0xA0, 0x27, 0x5C, 0x3A, 0x9B,
        0xCA, 0xB3, 0x3B, 0x54, 0xB7, 0x43, 0xCC, 0x8D,
        0x43, 0x2F, 0x9E, 0x13, 0xF2, 0x2E, 0x47, 0x90,
        0x25, 0x8A, 0x9F, 0x42, 0xB2, 0xEA, 0x87, 0x3A
    ];
    
    /// <summary>
    /// Expected ciphertext when signing with <see cref="Sha512Signer"/>
    /// </summary>
    // ReSharper disable once ReturnTypeCanBeEnumerable.Global
    public static byte[] CiphertextSha512 =>
    [
        // N-KEY (nonce)
        0x07, 0x65, 0xDE, 0x1A, 0xC0, 0x09, 0x2D, 0x74,
        0x6B, 0x3E, 0xF6, 0x09, 0x08, 0x0E, 0x30, 0x7E,
        0x92, 0xD2, 0x3C, 0x36, 0x27, 0x50, 0xB2, 0xAD,
        0x4C, 0x70, 0x38, 0x62, 0xDC, 0x7A, 0x7F, 0x42,
        // encrypted signature
        0x2C, 0xED, 0x47, 0x07, 0x4B, 0x01, 0x54, 0x21,
        0xC4, 0xD4, 0x59, 0x20, 0xFC, 0xC9, 0x46, 0xF1,
        0xE4, 0xAA, 0xEA, 0xFE, 0x50, 0x14, 0x8C, 0x6A,
        0xA5, 0xA1, 0xC7, 0xEF, 0xF4, 0x82, 0x76, 0xF8,
        0x15, 0xA2, 0x0B, 0x95, 0xC7, 0xC9, 0x31, 0xFD,
        0x42, 0x0A, 0x2B, 0x04, 0xB2, 0x94, 0x9A, 0x1A,
        0x98, 0x0A, 0xB9, 0xF8, 0x4C, 0x1D, 0x5B, 0x58,
        0xB5, 0xAF, 0x8A, 0xAC, 0xCB, 0x2D, 0x2C, 0x38,
        // encrypted data (HydraBytes)
        0xDA, 0x0D, 0x6C, 0xBA, 0x47, 0x2E, 0xD4, 0x24,
        0xFE, 0x91, 0x36, 0x41, 0x9C, 0x17, 0xB4, 0x73,
        0x78, 0xC6, 0x65, 0x74, 0xA6, 0x87, 0x58, 0xCE,
        0x5A, 0xAF, 0x4B, 0xA3, 0xC4, 0xEA, 0x2F, 0xE1,
        0xB7, 0xD4, 0xE6, 0x28, 0x63, 0xD9, 0xC9, 0xCE,
        0xFD, 0x43, 0xA9, 0xC7, 0x39, 0x4F, 0x00, 0x8E,
        0x98, 0x15, 0xBD, 0x40, 0x04, 0x07, 0x6E, 0x6E,
        0x66, 0xAA, 0x0C, 0xD5, 0xA7, 0x0D, 0xA8, 0x30,
        0x12, 0xF1, 0x8A, 0x48, 0xDC, 0xAA, 0xCF, 0xC4,
        0x17, 0xD1, 0xBA, 0x14, 0x8E, 0x4E, 0x6E, 0x35,
        0xC8, 0x5B, 0xAA, 0xBF, 0x9B, 0x9F, 0xC6, 0x83,
        0xA1, 0xCC, 0x11, 0xFA, 0xDD, 0xC0, 0x13, 0x79,
        0xAF, 0x54, 0xF2, 0xA0, 0x27, 0x5C, 0x3A, 0x9B,
        0xCA, 0xB3, 0x3B, 0x54, 0xB7, 0x43, 0xCC, 0x8D,
        0x43, 0x2F, 0x9E, 0x13, 0xF2, 0x2E, 0x47, 0x90,
        0x25, 0x8A, 0x9F, 0x42, 0xB2, 0xEA, 0x87, 0x3A
    ];
    
    #region Reference stuff
    
    /// <summary>
    /// <see cref="HydraEngine"/> E-KEY as <see cref="byte"/>(s).
    /// </summary>
    private static readonly byte[] EKey =
    [
        0x56, 0x9A, 0xCB, 0x9C, 0x8A, 0xC4, 0x88, 0x60,
        0x28, 0xA3, 0x1E, 0xE6, 0x6A, 0x0C, 0xD8, 0x61,
        0xD1, 0x37, 0xA1, 0xAC, 0xAD, 0x54, 0x25, 0x79,
        0xD4, 0x49, 0xD7, 0x29, 0x67, 0x2F, 0xFE, 0xC3
    ];

    /// <summary>
    /// <see cref="HydraEngine"/> EKey as <see cref="uint"/>(s).
    /// </summary>
    private static readonly uint[] EKey32 =
    [
        0x569ACB9C, 0x8AC48860 ,0x28A31EE6, 0x6A0CD861,
        0xD137A1AC, 0xAD542579, 0xD449D729, 0x672FFEC3
    ];
    
    /// <summary>
    /// 128 Chaos bytes produced starting at pebble 0, stream 1.
    /// </summary>
    private static byte[] ChaosBytes =>
    [
        0x92, 0x74, 0x08, 0xC8, 0x26, 0x14, 0xF4, 0x65,
        0xDE, 0xF2, 0x5F, 0x31, 0xF4, 0x72, 0xC6, 0x53,
        0x0B, 0xA3, 0x17, 0x04, 0xC3, 0xE9, 0x2C, 0xEE,
        0x39, 0xC0, 0x22, 0xCF, 0xB7, 0xC6, 0x0F, 0x92,
        0xD4, 0xB5, 0x8A, 0x4D, 0x10, 0xF9, 0xAE, 0xA2,
        0x94, 0x30, 0xDD, 0xA2, 0x57, 0x26, 0x6E, 0xE9,
        0xB8, 0x62, 0xD4, 0x34, 0x6C, 0x27, 0x03, 0x07,
        0x01, 0xC2, 0x78, 0xF9, 0x87, 0x69, 0xC9, 0x44,
        0x73, 0xD1, 0xEF, 0x26, 0xA8, 0xDD, 0xA6, 0xAA,
        0x72, 0xB5, 0x9A, 0x7D, 0xE0, 0x6E, 0x0D, 0x47,
        0xB1, 0x2B, 0xDE, 0xD6, 0xF8, 0xBF, 0xA3, 0xEE,
        0xC3, 0xBE, 0x70, 0x99, 0xB8, 0xEC, 0x33, 0x0A,
        0xCA, 0x37, 0x80, 0xC5, 0x53, 0x2F, 0x1A, 0xE8,
        0xAB, 0xD5, 0x5E, 0x33, 0xC2, 0x22, 0xBE, 0xE9,
        0x26, 0x4B, 0xBE, 0x66, 0x9C, 0x57, 0x2E, 0xF5,
        0x49, 0xEE, 0xF6, 0x2C, 0xD5, 0x86, 0xFE, 0x14
    ];

    /// <summary>
    /// <see cref="HydraEngine"/> encrypted bytes.
    /// </summary>
    /// <remarks>
    /// These are produced by XOR-ing <see cref="Plaintext"/>
    /// with <see cref="ChaosBytes"/>.
    /// </remarks>
    public static byte[] Ciphertext =>
    [
        0xDA, 0x0D, 0x6C, 0xBA, 0x47, 0x2E, 0xD4, 0x24,
        0xFE, 0x91, 0x36, 0x41, 0x9C, 0x17, 0xB4, 0x73,
        0x78, 0xC6, 0x65, 0x74, 0xA6, 0x87, 0x58, 0xCE,
        0x5A, 0xAF, 0x4B, 0xA3, 0xC4, 0xEA, 0x2F, 0xE1,
        0xB7, 0xD4, 0xE6, 0x28, 0x63, 0xD9, 0xC9, 0xCE,
        0xFD, 0x43, 0xA9, 0xC7, 0x39, 0x4F, 0x00, 0x8E,
        0x98, 0x15, 0xBD, 0x40, 0x04, 0x07, 0x6E, 0x6E,
        0x66, 0xAA, 0x0C, 0xD5, 0xA7, 0x0D, 0xA8, 0x30,
        0x12, 0xF1, 0x8A, 0x48, 0xDC, 0xAA, 0xCF, 0xC4,
        0x17, 0xD1, 0xBA, 0x14, 0x8E, 0x4E, 0x6E, 0x35,
        0xC8, 0x5B, 0xAA, 0xBF, 0x9B, 0x9F, 0xC6, 0x83,
        0xA1, 0xCC, 0x11, 0xFA, 0xDD, 0xC0, 0x13, 0x79,
        0xAF, 0x54, 0xF2, 0xA0, 0x27, 0x5C, 0x3A, 0x9B,
        0xCA, 0xB3, 0x3B, 0x54, 0xB7, 0x43, 0xCC, 0x8D,
        0x43, 0x2F, 0x9E, 0x13, 0xF2, 0x2E, 0x47, 0x90,
        0x25, 0x8A, 0x9F, 0x42, 0xB2, 0xEA, 0x87, 0x3A
    ];

    /// <summary>
    /// 192 bytes (128 + 64) produced starting at pebble 0, stream 0.
    /// </summary>
    private static byte[] SignerBytes =>
    [
        0x18, 0x39, 0x70, 0x10, 0xD6, 0xED, 0x82, 0x31,
        0xFA, 0xE4, 0xC3, 0x63, 0xB0, 0xF9, 0x3F, 0x88,
        0xF1, 0x8C, 0x98, 0x82, 0x75, 0x22, 0x48, 0xEB,
        0x62, 0xC8, 0x11, 0x1C, 0xCC, 0x6C, 0x14, 0x23,
        0x1C, 0xA7, 0x55, 0x3F, 0x62, 0x9B, 0xE6, 0x8A,
        0xB5, 0xC1, 0xE4, 0xC4, 0xF6, 0xD0, 0xFB, 0xC3,
        0xAD, 0xE4, 0x53, 0x3B, 0xDC, 0x8B, 0x5A, 0x7B,
        0x27, 0xDA, 0x1A, 0xE1, 0xEF, 0x08, 0xD2, 0xFD,
        0x89, 0x55, 0xDF, 0x67, 0xAD, 0xA6, 0x5F, 0x82,
        0x96, 0xAE, 0x2F, 0xC3, 0x36, 0x9A, 0xB0, 0x4C,
        0x5C, 0x9A, 0x56, 0x22, 0x6D, 0x81, 0x58, 0x5E,
        0x32, 0x1F, 0xFA, 0x8A, 0x99, 0x54, 0xB9, 0x2E,
        0x68, 0x52, 0x23, 0xD8, 0x5F, 0xB4, 0xE9, 0x86,
        0x46, 0xFD, 0x11, 0x57, 0xA6, 0xAD, 0x7A, 0x65,
        0x6D, 0x83, 0x7F, 0x1F, 0xEC, 0x02, 0xE6, 0x73,
        0x17, 0xC2, 0x53, 0x11, 0xE5, 0x59, 0x29, 0xEF,
        0x50, 0x14, 0x52, 0x09, 0xB4, 0xA5, 0xA0, 0x8D,
        0xFD, 0xF8, 0xBE, 0x0E, 0x44, 0xE3, 0x4F, 0x41,
        0xD3, 0xD3, 0x03, 0x78, 0xBD, 0xBD, 0x51, 0x7D,
        0x10, 0xE1, 0xB2, 0xD5, 0x47, 0xF7, 0x1F, 0x9F,
        0x25, 0x46, 0x6B, 0x3B, 0x4F, 0x07, 0xEA, 0xB0,
        0x38, 0xDE, 0x78, 0xF9, 0x5E, 0x67, 0x84, 0xE1,
        0xE3, 0x5E, 0xF1, 0xD9, 0x22, 0xDB, 0x0D, 0x85,
        0xCD, 0x7E, 0x66, 0xC5, 0x06, 0x74, 0x88, 0x11
    ];

    /// <summary>
    /// Encryption key used to encrypt the signature produced by the <see cref="Sha256Signer"/>.
    /// </summary>
    private static readonly ArraySegment<byte> Sha256SignatureKey = new(SignerBytes, 0, 32);
    
    /// <summary>
    /// Encryption key used to encrypt the signature produced by the <see cref="Sha384Signer"/> signer.
    /// </summary>
    private static readonly ArraySegment<byte> Sha384SignatureKey = new(SignerBytes, 0, 48);
    
    /// <summary>
    /// Encryption key used to encrypt the signature produced by the <see cref="Sha512Signer"/> signer.
    /// </summary>
    private static readonly ArraySegment<byte> Sha512SignatureKey = new(SignerBytes, 0, 64);
    
    /// <summary>
    /// Expected signature when signing <see cref="Ciphertext"/> with SHA256.
    /// </summary>
    public static byte[] Sha256PlainSignature =>
    [
        0x07, 0x28, 0xB4, 0x08, 0x4B, 0x83, 0x95, 0xC1,
        0xE3, 0x51, 0x25, 0x77, 0xD9, 0x84, 0xFF, 0xFD,
        0xE6, 0x1C, 0xF6, 0xC7, 0x13, 0x6F, 0xBB, 0x1C,
        0x82, 0x1E, 0x8D, 0x2E, 0x75, 0xEE, 0xEC, 0x6C
    ];

    /// <summary>
    /// Expected signature after encrypting <see cref="Sha256PlainSignature"/>.
    /// </summary>
    private static byte[] Sha256EncryptedSignature =>
    [
        0x1F, 0x11, 0xC4, 0x18, 0x9D, 0x6E, 0x17, 0xF0,
        0x19, 0xB5, 0xE6, 0x14, 0x69, 0x7D, 0xC0, 0x75,
        0x17, 0x90, 0x6E, 0x45, 0x66, 0x4D, 0xF3, 0xF7,
        0xE0, 0xD6, 0x9C, 0x32, 0xB9, 0x82, 0xF8, 0x4F
    ];
    
    /// <summary>
    /// Expected signature when signing <see cref="Ciphertext"/> with SHA384.
    /// </summary>
    public static byte[] Sha384PlainSignature =>
    [
        0x99, 0x12, 0xE3, 0x6D, 0x23, 0x5A, 0xEC, 0xE7,
        0x91, 0x25, 0x93, 0x93, 0x3B, 0x67, 0xE2, 0x9E,
        0x44, 0x7E, 0xA1, 0x99, 0x01, 0x4F, 0x82, 0xD7,
        0xFD, 0x80, 0x82, 0x94, 0xAC, 0x5C, 0x41, 0xB1,
        0xBA, 0xFD, 0x6B, 0xD3, 0xE1, 0x86, 0x95, 0xDC,
        0x1C, 0x36, 0x29, 0x5C, 0x92, 0x2A, 0x79, 0xD9
    ];

    /// <summary>
    /// Expected signature after encrypting <see cref="Sha384PlainSignature"/>.
    /// </summary>
    private static byte[] Sha384EncryptedSignature =>
    [
        0x81, 0x2B, 0x93, 0x7D, 0xF5, 0xB7, 0x6E, 0xD6, 
        0x6B, 0xC1, 0x50, 0xF0, 0x8B, 0x9E, 0xDD, 0x16,
        0xB5, 0xF2, 0x39, 0x1B, 0x74, 0x6D, 0xCA, 0x3C,
        0x9F, 0x48, 0x93, 0x88, 0x60, 0x30, 0x55, 0x92,
        0xA6, 0x5A, 0x3E, 0xEC, 0x83, 0x1D, 0x73, 0x56,
        0xA9, 0xF7, 0xCD, 0x98, 0x64, 0xFA, 0x82, 0x1A
    ];
    
    /// <summary>
    /// Expected signature when signing <see cref="Ciphertext"/> with SHA512.
    /// </summary>
    public static byte[] Sha512PlainSignature =>
    [
        0x34, 0xD4, 0x37, 0x17, 0x9D, 0xEC, 0xD6, 0x10,
        0x3E, 0x30, 0x9A, 0x43, 0x4C, 0x30, 0x79, 0x79,
        0x15, 0x26, 0x72, 0x7C, 0x25, 0x36, 0xC4, 0x81,
        0xC7, 0x69, 0xD6, 0xF3, 0x38, 0xEE, 0x62, 0xDB,
        0x09, 0x05, 0x5E, 0xAA, 0xA5, 0x52, 0xD7, 0x77,
        0xF7, 0xCB, 0xCF, 0xC0, 0x44, 0x44, 0x61, 0xD9,
        0x35, 0xEE, 0xEA, 0xC3, 0x90, 0x96, 0x01, 0x23,
        0x92, 0x75, 0x90, 0x4D, 0x24, 0x25, 0xFE, 0xC5
    ];

    /// <summary>
    /// Expected signature after encrypting <see cref="Sha512PlainSignature"/>.
    /// </summary>
    private static byte[] Sha512EncryptedSignature =>
    [
        0x2C, 0xED, 0x47, 0x07, 0x4B, 0x01, 0x54, 0x21,
        0xC4, 0xD4, 0x59, 0x20, 0xFC, 0xC9, 0x46, 0xF1,
        0xE4, 0xAA, 0xEA, 0xFE, 0x50, 0x14, 0x8C, 0x6A,
        0xA5, 0xA1, 0xC7, 0xEF, 0xF4, 0x82, 0x76, 0xF8,
        0x15, 0xA2, 0x0B, 0x95, 0xC7, 0xC9, 0x31, 0xFD,
        0x42, 0x0A, 0x2B, 0x04, 0xB2, 0x94, 0x9A, 0x1A,
        0x98, 0x0A, 0xB9, 0xF8, 0x4C, 0x1D, 0x5B, 0x58,
        0xB5, 0xAF, 0x8A, 0xAC, 0xCB, 0x2D, 0x2C, 0x38
    ];
    
    #endregion
}