using GoeaLabs.Chaos;

namespace GoeaLabs.Crypto.Hydra.Tests;

[TestClass]
public class HydraEngineTests
{
    private const int CiphertextNKeyOffset = 0;
    
    private const int CiphertextNKeyCount = 32;
    
    private const int CiphertextSignatureOffset = 32;
    
    private const int CiphertextSignatureCount = 32;
    
    private static IHydraSigner Sha256Signer => new Sha256Signer();
    
    private static IHydraSigner Sha384Signer => new Sha384Signer();
    
    private static IHydraSigner Sha512Signer => new Sha512Signer();

    private static HydraEngine Hydra20Sha256 => new (HydraTestVectors.XKey, Sha256Signer);
    
    private static HydraEngine Hydra20Sha384 => new (HydraTestVectors.XKey, Sha384Signer);
    
    private static HydraEngine Hydra20Sha512 => new (HydraTestVectors.XKey, Sha512Signer);
    
    private static int Random(int minVal, int maxVal)
    {
        Span<uint> kernel = stackalloc uint[ChaosEngine.KernelLen];
        ChaosEngine.Make(kernel);

        const int rounds = HydraEngine.DefRounds;
        var locale = new ChaosLocale();
        
        Span<long> buffer = stackalloc long[1];
        ChaosEngine.Load(buffer, minVal, maxVal, kernel, rounds, locale);

        return (int)buffer[0];
    }

    [TestMethod]
    [DataRow(HydraEngine.KeyLength - 1, HydraEngine.DefRounds)]
    [DataRow(HydraEngine.KeyLength + 1, HydraEngine.DefRounds)]
    public void Constructor_throws_HydraException_if_incorrect_key_length(int length, int rounds)
    {
        var tested = new Exception();

        try
        {
            _ = new HydraEngine(new byte[length], Sha256Signer, rounds);        
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) 
            && ((HydraException)tested).ErrorCode == HydraErrorCode.ErrKeyLen);
    }
        

    [TestMethod]
    [DataRow(HydraEngine.DefRounds + 1)]
    [DataRow(HydraEngine.DefRounds - 1)]
    public void Constructor_throws_HydraException_if_incorrect_number_of_rounds(int rounds)
    {
        var tested = new Exception();

        try
        {
            _ = new HydraEngine(HydraTestVectors.XKey, Sha256Signer, rounds);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) 
            && ((HydraException)tested).ErrorCode == HydraErrorCode.ErrRounds);
    }

    [TestMethod]
    [DataRow(HydraEngine.KeyLength - 1)]
    [DataRow(HydraEngine.KeyLength + 1)]
    public void NewKey_throws_HydraException_if_incorrect_key_length(int length)
    {
        var tested = new Exception();

        try
        {
            Span<byte> xKey = stackalloc byte[length];
            
            HydraEngine.NewKey(xKey);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) 
            && ((HydraException)tested).ErrorCode == HydraErrorCode.ErrKeyLen);
    }
    
    [TestMethod]
    public void Encrypt_throws_HydraException_on_zero_source_length()
    {
        var tested = new Exception();

        try
        {
            Hydra20Sha256.Encrypt(Span<byte>.Empty, Span<byte>.Empty);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) && 
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrSrcLen);
    }
        
    
    // Correct length is 65 (32 + 32 + 1)
    [TestMethod]
    [DataRow(64)]
    [DataRow(66)]
    public void Encrypt_throws_HydraException_on_invalid_output_length(int length)
    {
        var tested = new Exception();

        try
        {
            Span<byte> plaintext = stackalloc byte[1];
            Span<byte> encrypted = stackalloc byte[length];
        
            Hydra20Sha256.Encrypt(plaintext, encrypted);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) && 
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrOutLen);
    }

    [TestMethod]
    [DataRow(false)]
    public void GetLen_throws_HydraException_if_buffer_length_is_zero(bool isPlain)
    {
        var tested = new Exception();

        try
        {
            Hydra20Sha256.GetLen(Span<byte>.Empty, false);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) && 
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrSrcLen);
    }
        


    [TestMethod]
    [DataRow(64, false)] // 0
    public void GetLen_throws_HydraException_if_result_not_greater_than_zero(int length, bool isPlain)
    {
        var tested = new Exception();

        try
        {
            Hydra20Sha256.GetLen(new byte[length], isPlain);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) && 
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrSrcLen);
    }
        
    
    [TestMethod]
    [DataRow(1, 65)]
    public void GetLen_behaves_correctly_for_encryption(int length, int correct)
    {
        Span<byte> plaintext = stackalloc byte[length];
        Assert.IsTrue(Hydra20Sha256.GetLen(plaintext, true) == correct);
    }
    
    [TestMethod]
    [DataRow(65, 1)]
    public void GetLen_behaves_correctly_for_decryption(int length, int correct)
    {
        Span<byte> ciphertext = stackalloc byte[length];
        Assert.IsTrue(Hydra20Sha256.GetLen(ciphertext, false) == correct);
    }

    [TestMethod]
    public void Hydra20Sha256_encrypts_correctly()
    {
        var encrypted = new byte[Hydra20Sha256.GetLen(HydraTestVectors.Plaintext, true)];
        Hydra20Sha256.Encrypt(HydraTestVectors.NKey, HydraTestVectors.Plaintext, encrypted);
        
        Assert.IsTrue(HydraTestVectors.CiphertextSha256.SequenceEqual(encrypted));
    }
    
    [TestMethod]
    public void Hydra20Sha384_encrypts_correctly()
    {
        var encrypted = new byte[Hydra20Sha384.GetLen(HydraTestVectors.Plaintext, true)];
        Hydra20Sha384.Encrypt(HydraTestVectors.NKey, HydraTestVectors.Plaintext, encrypted);
        
        Assert.IsTrue(HydraTestVectors.CiphertextSha384.SequenceEqual(encrypted));
    }
    
    [TestMethod]
    public void Hydra20Sha512_encrypts_correctly()
    {
        var encrypted = new byte[Hydra20Sha512.GetLen(HydraTestVectors.Plaintext, true)];
        Hydra20Sha512.Encrypt(HydraTestVectors.NKey, HydraTestVectors.Plaintext, encrypted);
        
        Assert.IsTrue(HydraTestVectors.CiphertextSha512.SequenceEqual(encrypted));
    }
    
    [TestMethod]
    public void Hydra20Sha256_decrypts_correctly()
    {
        var encrypted = new byte[Hydra20Sha256.GetLen(HydraTestVectors.Plaintext, true)];
        Hydra20Sha256.Encrypt(HydraTestVectors.NKey, HydraTestVectors.Plaintext, encrypted);

        var decrypted = new byte[Hydra20Sha256.GetLen(encrypted, false)];
        Hydra20Sha256.Decrypt(encrypted, decrypted);
        
        Assert.IsTrue(HydraTestVectors.Plaintext.SequenceEqual(decrypted));
    }
    
    [TestMethod]
    public void Hydra20Sha384_decrypts_correctly()
    {
        var encrypted = new byte[Hydra20Sha384.GetLen(HydraTestVectors.Plaintext, true)];
        Hydra20Sha384.Encrypt(HydraTestVectors.NKey, HydraTestVectors.Plaintext, encrypted);

        var decrypted = new byte[Hydra20Sha384.GetLen(encrypted, false)];
        Hydra20Sha384.Decrypt(encrypted, decrypted);
        
        Assert.IsTrue(HydraTestVectors.Plaintext.SequenceEqual(decrypted));
    }
    
    [TestMethod]
    public void Hydra20Sha512_decrypts_correctly()
    {
        var encrypted = new byte[Hydra20Sha512.GetLen(HydraTestVectors.Plaintext, true)];
        Hydra20Sha512.Encrypt(HydraTestVectors.NKey, HydraTestVectors.Plaintext, encrypted);

        var decrypted = new byte[Hydra20Sha512.GetLen(encrypted, false)];
        Hydra20Sha512.Decrypt(encrypted, decrypted);
        
        Assert.IsTrue(HydraTestVectors.Plaintext.SequenceEqual(decrypted));
    }

    [TestMethod]
    [DataRow(64)] // correct is 65 (32 + 32 + 1)
    public void Decrypt_throws_HydraException_on_invalid_source_length(int length)
    {
        Span<byte> source = stackalloc byte[length];
        Span<byte> output = stackalloc byte[1];
        
        var tested = new Exception();

        try
        {
            Hydra20Sha256.Decrypt(source, output);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) && 
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrSrcLen);
    }
    
    [TestMethod]
    [DataRow(66, 0)] // correct is 2, not 0
    public void Decrypt_throws_HydraException_on_invalid_output_length(int srcLen, int outLen)
    {
        Span<byte> source = stackalloc byte[srcLen];
        Span<byte> output = stackalloc byte[outLen];
        
        var tested = new Exception();

        try
        {
            Hydra20Sha256.Decrypt(source, output);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) && 
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrOutLen);
    }
    
    [TestMethod]
    public void Decrypt_throws_HydraException_if_nonce_is_modified()
    {
        Span<byte> tampered = new byte[HydraTestVectors.CiphertextSha256.Length];
        HydraTestVectors.CiphertextSha256.CopyTo(tampered);

        var location = Random(CiphertextNKeyOffset, CiphertextNKeyCount);
        
        tampered[location] = unchecked(++tampered[location]);
        
        var output = new byte[Hydra20Sha256.GetLen(tampered, false)];
        
        var tested = new Exception();

        try
        {
            Hydra20Sha256.Decrypt(tampered, output);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) &&
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrVerify);
    }
    
    [TestMethod]
    public void Decrypt_throws_HydraException_if_signature_is_modified()
    {
        Span<byte> tampered = new byte[HydraTestVectors.CiphertextSha256.Length];
        HydraTestVectors.CiphertextSha256.CopyTo(tampered);

        var location = Random(
            CiphertextSignatureOffset, CiphertextSignatureOffset + CiphertextSignatureCount);
        
        tampered[location] = unchecked(++tampered[location]);
        
        var output = new byte[Hydra20Sha256.GetLen(tampered, false)];
        
        var tested = new Exception();

        try
        {
            Hydra20Sha256.Decrypt(tampered, output);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        } 
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) &&
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrVerify);
    }
    
    [TestMethod]
    public void Decrypt_throws_HydraException_if_encrypted_data_is_modified()
    {
        Span<byte> tampered = stackalloc byte[HydraTestVectors.CiphertextSha256.Length];
        HydraTestVectors.CiphertextSha256.CopyTo(tampered);

        var location = Random(
            CiphertextSignatureOffset + CiphertextSignatureCount, 
            HydraTestVectors.CiphertextSha256.Length);
        
        tampered[location] = unchecked(++tampered[location]);

        var output = new byte[Hydra20Sha256.GetLen(tampered, false)];
        
        var tested = new Exception();

        try
        {
            Hydra20Sha256.Decrypt(tampered, output);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) &&
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrVerify);
    }
}