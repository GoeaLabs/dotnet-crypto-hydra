using BenchmarkDotNet.Attributes;
using GoeaLabs.Bedrock.Extensions;
// ReSharper disable once UnusedAutoPropertyAccessor.Global

namespace GoeaLabs.Crypto.Hydra.Benchmarks;

[Orderer(BenchmarkDotNet.Order.SummaryOrderPolicy.FastestToSlowest)]
public class Encryption : BaseBench
{
    private byte[] OutputSha256 { get; set; } = null!;
    
    private byte[] OutputSha384 { get; set; } = null!;
    
    private byte[] OutputSha512 { get; set; } = null!;

    [GlobalSetup]
    public void Setup()
    {
        Data = new byte[Bytes].FillRandom();
        XKey = Convert.FromHexString(HydraEngine.NewKey());
        
        Hydra20Sha256 = new HydraEngine(XKey, new Sha256Signer());
        Hydra20Sha384 = new HydraEngine(XKey, new Sha384Signer());
        Hydra20Sha512 = new HydraEngine(XKey, new Sha512Signer());
        
        OutputSha256 = new byte[Hydra20Sha256.GetLen(Data, true)];
        OutputSha384 = new byte[Hydra20Sha384.GetLen(Data, true)];
        OutputSha512 = new byte[Hydra20Sha512.GetLen(Data, true)];
    }
    
    [Benchmark]
    public void Hydra20Sha256Encrypt() => Hydra20Sha256.Encrypt(Data, OutputSha256);
    
    [Benchmark]
    public void Hydra20Sha384Encrypt() => Hydra20Sha384.Encrypt(Data, OutputSha384);
    
    [Benchmark]
    public void Hydra20Sha512Encrypt() => Hydra20Sha512.Encrypt(Data, OutputSha512);
    
}