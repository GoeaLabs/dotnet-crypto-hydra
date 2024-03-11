using BenchmarkDotNet.Attributes;
using GoeaLabs.Bedrock.Extensions;
// ReSharper disable once UnusedAutoPropertyAccessor.Global

namespace GoeaLabs.Crypto.Hydra.Benchmarks;

[Orderer(BenchmarkDotNet.Order.SummaryOrderPolicy.FastestToSlowest)]
public class Decryption : BaseBench
{
    private byte[] CiphertextSha256 { get; set; } = null!;
    
    private byte[] CiphertextSha384 { get; set; } = null!;
    
    private byte[] CiphertextSha512 { get; set; } = null!;
    
    
    [GlobalSetup]
    public void Setup()
    {
        Data = new byte[Bytes].FillRandom();
        XKey = Convert.FromHexString(HydraEngine.NewKey());
        
        Hydra20Sha256 = new HydraEngine(XKey, new Sha256Signer());
        Hydra20Sha384 = new HydraEngine(XKey, new Sha384Signer());
        Hydra20Sha512 = new HydraEngine(XKey, new Sha512Signer());

        CiphertextSha256 = new byte[Hydra20Sha256.GetLen(Data, true)];
        CiphertextSha384 = new byte[Hydra20Sha384.GetLen(Data, true)];
        CiphertextSha512 = new byte[Hydra20Sha512.GetLen(Data, true)];
        
        Hydra20Sha256.Encrypt(Data, CiphertextSha256);
        Hydra20Sha384.Encrypt(Data, CiphertextSha384);
        Hydra20Sha512.Encrypt(Data, CiphertextSha512);
    }
    
    [Benchmark]
    public void Hydra20Sha256Decrypt() => Hydra20Sha256.Decrypt(CiphertextSha256, Data);
    
    [Benchmark]
    public void Hydra20Sha384Decrypt() => Hydra20Sha384.Decrypt(CiphertextSha384, Data);
    
    [Benchmark]
    public void Hydra20Sha512Decrypt() => Hydra20Sha512.Decrypt(CiphertextSha512, Data);
}