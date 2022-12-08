#include <iostream>

#include <client_manager.h>
#include <RSA_cryptor.h>
#include <PGP_cryptor.h>
#include <AES128_cryptor.h>
#include <SHA256_hash.h>
#include <double_cryptor.h>
#include <hash_based_signature.h>

using namespace boost::asio; // delete me when io_service won't be created in main()
using namespace udc;
constexpr size_t KEYS_COUNT = 10;

using RSA_SHA256_SignatureCreator = HashBasedSignatureCreator<SHA256_Hash, RSA_Encryptor>;
using RSA_AES128_Encryptor = DoubleEncryptor<AES128_Cryptor, RSA_Encryptor>;
using RSA_AES128_PGP_Encryptor = PGP_Encryptor<RSA_SHA256_SignatureCreator, RSA_AES128_Encryptor>;

int main()
{
	udc::blob_t data;
	std::string info;
	int t1 = 8005;
	io_service server; // delete me!
	udc::ClientManager test1(server , t1);
	info = test1.GetCLInfo();
	std::cout << info << std::endl;
	for (auto&& it : info)
	{
		data.push_back(static_cast<int>(it));
	}

	std::vector<RSA_Key> myPublicKeys;
	std::vector<RSA_Key> myPrivateKeys;

	RSA_KeyGenerator keyGenerator;
	for (size_t i = 0; i < KEYS_COUNT; ++i)
	{
		keyGenerator.Generate();
		myPublicKeys.push_back(keyGenerator.GetPrivateKey());
		myPrivateKeys.push_back(keyGenerator.GetPublicKey());
	}

	AES128_KeyGenerator symKeyGenerator;
	symKeyGenerator.Generate();
	AES128_Key symKey = symKeyGenerator.GetPublicKey();

	test1.Connect();
	blob_t serverKeysBlob = test1.GetMessagge();
	std::vector<RSA_Key> serverPublicKeys = BlobToVector<RSA_Key>(serverKeysBlob);

	blob_t myKeysBlob = VectorToBlob(myPublicKeys);
	test1.SendMessage(myKeysBlob);

	PGPKeyData<RSA_Key, RSA_Key, AES128_Key> encryptionKey;
	encryptionKey.m_bunchOfPublicKeys = serverPublicKeys;
	encryptionKey.m_bunchOfPrivateKeys = myPrivateKeys;
	encryptionKey.m_sessionKey = symKey;

	RSA_AES128_PGP_Encryptor PGP_Encryptor;

	data = PGP_Encryptor.Encrypt(data, encryptionKey);
	test1.SendMessage(data);

	test1.CloseConnection();
	return 0;
}