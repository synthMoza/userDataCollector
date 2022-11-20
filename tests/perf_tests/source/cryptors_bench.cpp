#include <benchmark/benchmark.h>

#include <generate_helper.h>
#include <AES128_cryptor.h>

using namespace udc;

static AES128_KeyGenerator g_keyGen;
static AES128_Cryptor g_cryptor;
static blob_t g_testData;

static void AES128_Encrypt_DoSetup(const benchmark::State& state) 
{
    g_keyGen.Generate();
    g_testData = helpers::GenerateRandomData(state.range(0));
}

static void BM_AES128_Encrypt_RandomData(benchmark::State& state) 
{
    for (auto _ : state)
    {        
        benchmark::DoNotOptimize(g_cryptor.Encrypt(g_testData, g_keyGen.GetPublicKey()));
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BM_AES128_Encrypt_RandomData)->RangeMultiplier(2)->Range(2 << 8, 2 << 24)->Setup(AES128_Encrypt_DoSetup)->Complexity(benchmark::oN);

static void AES128_Decrypt_DoSetup(const benchmark::State& state) 
{
    g_keyGen.Generate();
    g_testData = g_cryptor.Encrypt(helpers::GenerateRandomData(state.range(0)), g_keyGen.GetPublicKey());
}

static void BM_AES128_Decrypt_RandomData(benchmark::State& state) {
    for (auto _ : state)
    {        
        benchmark::DoNotOptimize(g_cryptor.Decrypt(g_testData, g_keyGen.GetPrivateKey()));
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BM_AES128_Decrypt_RandomData)->RangeMultiplier(2)->Range(2 << 8, 2 << 24)->Setup(AES128_Decrypt_DoSetup)->Complexity(benchmark::oN);
