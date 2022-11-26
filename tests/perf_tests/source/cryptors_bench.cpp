#include <benchmark/benchmark.h>

#include <generate_helper.h>
#include <AES128_cryptor.h>
#include <RSA_cryptor.h>
#include <double_cryptor.h>

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

BENCHMARK(BM_AES128_Encrypt_RandomData)->RangeMultiplier(2)->DenseRange(2 << 10, 2 << 26, 2 << 20)->Complexity(benchmark::oN);

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

BENCHMARK(BM_AES128_Decrypt_RandomData)->RangeMultiplier(2)->DenseRange(2 << 10, 2 << 26, 2 << 20)->Complexity(benchmark::oN);

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

BENCHMARK(BM_RSA_Encrypt_RandomData)->RangeMultiplier(2)->DenseRange(2 << 2, 2 << 12, 2 << 7)->Complexity(benchmark::oN);

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

BENCHMARK(BM_RSA_Decrypt_RandomData)->RangeMultiplier(2)->DenseRange(2 << 2, 2 << 12, 2 << 7)->Complexity(benchmark::oN);

static void BM_DoubleEncryptor_Encrypt_RandomData(benchmark::State& state) 
{
    DoubleEncryptor<AES128_Cryptor, RSA_Encryptor> doubleEncryptor;

    auto testData = helpers::GenerateRandomData(state.range(0));
    for (auto _ : state)
    {        
        benchmark::DoNotOptimize(doubleEncryptor.Encrypt(testData, {g_AES128_keyGen.GetPrivateKey(), g_RSA_keyGen.GetPublicKey()}));
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BM_DoubleEncryptor_Encrypt_RandomData)->RangeMultiplier(2)->DenseRange(2 << 10, 2 << 26, 2 << 20)->Complexity(benchmark::oN);

static void BM_DoubleEncryptor_Decrypt_RandomData(benchmark::State& state)
{
    DoubleEncryptor<AES128_Cryptor, RSA_Encryptor> doubleEncryptor;
    DoubleDecryptor<AES128_Cryptor, RSA_Decryptor> doubleDecryptor;

    auto testData = helpers::GenerateRandomData(state.range(0));
    testData = doubleEncryptor.Encrypt(testData, {g_AES128_keyGen.GetPrivateKey(), g_RSA_keyGen.GetPublicKey()});
    for (auto _ : state)
    {        
        benchmark::DoNotOptimize(doubleDecryptor.Decrypt(testData, g_RSA_keyGen.GetPrivateKey()));
    }

    state.SetComplexityN(state.range(0));
}

BENCHMARK(BM_DoubleEncryptor_Decrypt_RandomData)->RangeMultiplier(2)->DenseRange(2 << 10, 2 << 26, 2 << 20)->Complexity(benchmark::oN);
