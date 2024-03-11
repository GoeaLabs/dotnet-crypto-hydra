namespace GoeaLabs.Crypto.Hydra.Tests;

[TestClass]
public class HydraSignerTests
{
    private static Sha256Signer Sha256Signer => new();
    
    private static Sha384Signer Sha384Signer => new();
    
    private static Sha512Signer Sha512Signer => new();
    
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