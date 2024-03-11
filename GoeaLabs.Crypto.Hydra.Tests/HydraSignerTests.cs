namespace GoeaLabs.Crypto.Hydra.Tests;

[TestClass]
public class HydraSignerTests
{
    private static Sha256Signer Sha256Signer => new();
    
    private static Sha384Signer Sha384Signer => new();
    
    private static Sha512Signer Sha512Signer => new();
    
    [TestMethod]
    [DataRow("add")]
    [DataRow("rem")]
    public void Sha256Signer_throws_HydraException_on_invalid_signature_buffer_length(string act)
    {
        var len = act == "add" 
            ? Sha256Signer.SigLen + 1 
            : Sha256Signer.SigLen - 1;
        
        var raw = HydraTestVectors.Ciphertext;
        var key = Span<byte>.Empty;
        
        Span<byte> sig = stackalloc byte[len];

        var tested  = new Exception();
        
        try
        {
            Sha256Signer.GenSig(raw, key, sig);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) &&
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrSigOut);
    }
    
    [TestMethod]
    [DataRow("add")]
    [DataRow("rem")]
    public void Sha384Signer_throws_HydraException_on_invalid_signature_buffer_length(string act)
    {
        var len = act == "add" 
            ? Sha384Signer.SigLen + 1 
            : Sha384Signer.SigLen - 1;
        
        var raw = HydraTestVectors.Ciphertext;
        var key = Span<byte>.Empty;
        
        Span<byte> sig = stackalloc byte[len];

        var tested  = new Exception();
        
        try
        {
            Sha384Signer.GenSig(raw, key, sig);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) &&
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrSigOut);
    }
    
    [TestMethod]
    [DataRow("add")]
    [DataRow("rem")]
    public void Sha512Signer_throws_HydraException_on_invalid_signature_buffer_length(string act)
    {
        var len = act == "add" 
            ? Sha512Signer.SigLen + 1 
            : Sha512Signer.SigLen - 1;
        
        var raw = HydraTestVectors.Ciphertext;
        var key = Span<byte>.Empty;
        
        Span<byte> sig = stackalloc byte[len];

        var tested  = new Exception();
        
        try
        {
            Sha512Signer.GenSig(raw, key, sig);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(HydraException) &&
            ((HydraException)tested).ErrorCode == HydraErrorCode.ErrSigOut);
    }
    
    [TestMethod]
    public void Sha256Signer_signs_correctly()
    {
        Span<byte> output = stackalloc byte[Sha256Signer.SigLen];
        Sha256Signer.GenSig(HydraTestVectors.Ciphertext, Span<byte>.Empty, output);
        
        Assert.IsTrue(output.SequenceEqual(HydraTestVectors.Sha256PlainSignature));
    }
    
    [TestMethod]
    public void Sha384Signer_signs_correctly()
    {
        Span<byte> output = stackalloc byte[Sha384Signer.SigLen];
        Sha384Signer.GenSig(HydraTestVectors.Ciphertext, Span<byte>.Empty, output);
        
        Assert.IsTrue(output.SequenceEqual(HydraTestVectors.Sha384PlainSignature));
    }
    
    [TestMethod]
    public void Sha512Signer_signs_correctly()
    {
        Span<byte> output = stackalloc byte[Sha512Signer.SigLen];
        Sha512Signer.GenSig(HydraTestVectors.Ciphertext, Span<byte>.Empty, output);
        
        Assert.IsTrue(output.SequenceEqual(HydraTestVectors.Sha512PlainSignature));
    }
}