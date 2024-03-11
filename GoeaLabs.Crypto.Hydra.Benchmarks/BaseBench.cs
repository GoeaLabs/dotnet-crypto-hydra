using BenchmarkDotNet.Attributes;

namespace GoeaLabs.Crypto.Hydra.Benchmarks;

[MemoryDiagnoser, RankColumn, MarkdownExporter]
public abstract class BaseBench
{
    [Params(100, 1000, 1_000_000)]
    // ReSharper disable once UnusedAutoPropertyAccessor.Global
    public int Bytes { get; set; }

    protected byte[] Data { get; set; } = null!;
    
    protected byte[] XKey { get; set; } = null!;
    
    protected HydraEngine Hydra20Sha256 { get; set; } = null!;
    
    protected HydraEngine Hydra20Sha384 { get; set; } = null!;
    
    protected HydraEngine Hydra20Sha512 { get; set; } = null!;
}