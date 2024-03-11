// ReSharper disable once RedundantUsingDirective
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;

namespace GoeaLabs.Crypto.Hydra.Benchmarks;

public static class Program
{
    public static void Main(string[] args)
    {
        // _ = BenchmarkRunner.Run<DecryptionBenchmark>();
        // _ = BenchmarkRunner.Run<EncryptionBenchmark>();

        // BenchmarkRunner.Run(typeof(Program).Assembly,
        //     ManualConfig.Create(DefaultConfig.Instance)
        //         .WithOptions(ConfigOptions.JoinSummary));
        //         //.WithOptions(ConfigOptions.DisableLogFile));

        BenchmarkRunner.Run(typeof(Program).Assembly);
    }
}