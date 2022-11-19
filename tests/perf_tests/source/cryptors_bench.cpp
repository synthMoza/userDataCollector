#include <benchmark/benchmark.h>

#include <generate_helper.h>
#include <openssl_cryptors.h>

using namespace udc;

static void BM_AES128_Encrypt_RandomData(benchmark::State& state) {
    auto testData = helpers::GenerateRandomData(state.range(0));
    
    AES128_KeyGenerator KeyGen{};
    KeyGen.Generate();
    AES128_Cryptor AES_128_Cryptor{};
    
    for (auto _ : state)
    {        
        benchmark::DoNotOptimize(AES_128_Cryptor.Encrypt(testData, KeyGen.GetPublicKey()));
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BM_AES128_Encrypt_RandomData)->RangeMultiplier(2)->Range(2 << 8, 2 << 24)->Complexity(benchmark::oN);

static void BM_AES128_Decrypt_RandomData(benchmark::State& state) {
    auto testData = helpers::GenerateRandomData(state.range(0));
    
    AES128_KeyGenerator KeyGen{};
    KeyGen.Generate();
    AES128_Cryptor AES_128_Cryptor{};

    testData = AES_128_Cryptor.Encrypt(testData, KeyGen.GetPublicKey());
    for (auto _ : state)
    {        
        benchmark::DoNotOptimize(AES_128_Cryptor.Decrypt(testData, KeyGen.GetPrivateKey()));
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BM_AES128_Decrypt_RandomData)->RangeMultiplier(2)->Range(2 << 8, 2 << 24)->Complexity(benchmark::oN);
