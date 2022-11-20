#include <benchmark/benchmark.h>

#include <generate_helper.h>
#include <AES128_cryptor.h>
#include <RSA_cryptor.h>

using namespace udc;

// Generate keys only once
static AES128_KeyGenerator g_AES128_keyGen = MakeKeyGenerator<AES128_KeyGenerator>();

static void BM_AES128_Encrypt_RandomData(benchmark::State& state) 
{
    AES128_Cryptor cryptor{};

    auto testData = helpers::GenerateRandomData(state.range(0));
    for (auto _ : state)
    {        
        benchmark::DoNotOptimize(cryptor.Encrypt(testData, g_AES128_keyGen.GetPublicKey()));
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BM_AES128_Encrypt_RandomData)->RangeMultiplier(2)->Range(2 << 8, 2 << 24)->Complexity(benchmark::oN);

static void BM_AES128_Decrypt_RandomData(benchmark::State& state) 
{
    AES128_Cryptor cryptor{};

    auto testData = helpers::GenerateRandomData(state.range(0));
    testData = cryptor.Encrypt(testData, g_AES128_keyGen.GetPublicKey());
    for (auto _ : state)
    {        
        benchmark::DoNotOptimize(cryptor.Decrypt(testData, g_AES128_keyGen.GetPrivateKey()));
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BM_AES128_Decrypt_RandomData)->RangeMultiplier(2)->Range(2 << 8, 2 << 24)->Complexity(benchmark::oN);

static RSA_KeyGenerator g_RSA_keyGen = MakeKeyGenerator<RSA_KeyGenerator>();

static void BM_RSA_Encrypt_RandomData(benchmark::State& state) 
{
    RSA_Encryptor encryptor{};

    auto testData = helpers::GenerateRandomData(state.range(0));
    for (auto _ : state)
    {        
        benchmark::DoNotOptimize(encryptor.Encrypt(testData, g_RSA_keyGen.GetPublicKey()));
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BM_RSA_Encrypt_RandomData)->RangeMultiplier(2)->Range(2 << 2, 2 << 10)->Complexity(benchmark::oN);

static void BM_RSA_Decrypt_RandomData(benchmark::State& state) 
{
    RSA_Encryptor encryptor{};
    RSA_Decryptor decryptor{};

    auto testData = helpers::GenerateRandomData(state.range(0));
    testData = encryptor.Encrypt(testData, g_RSA_keyGen.GetPublicKey());
    for (auto _ : state)
    {        
        benchmark::DoNotOptimize(decryptor.Decrypt(testData, g_RSA_keyGen.GetPrivateKey()));
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BM_RSA_Decrypt_RandomData)->RangeMultiplier(2)->Range(2 << 2, 2 << 10)->Complexity(benchmark::oN);
