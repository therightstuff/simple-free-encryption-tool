using System;
using System.Security.Cryptography;
using System.Text;

namespace MyProject.Data.Encryption
{
    /* Encryption, decryption, signing and signature verification that's compatible with
     * simple-free-encryption-tool
     */
    public class RSA
    {
        public const bool OAEP_PADDING = true;
        /// <summary>
        /// PKCS1 padding is required for most encryption using JavaScript packages
        /// </summary>
        public const bool PKCS1_PADDING = false;

        public static string Encrypt(
            RSACryptoServiceProvider csp,
            string plaintext
        ) {
            return Convert.ToBase64String(
                csp.Encrypt(
                    Encoding.UTF8.GetBytes(plaintext),
                    PKCS1_PADDING
                )
            );
        }

        public static string Decrypt(
            RSACryptoServiceProvider csp,
            string encrypted
        ) {
            return Encoding.UTF8.GetString(
                csp.Decrypt(
                    Convert.FromBase64String(encrypted),
                    PKCS1_PADDING
                )
            );
        }

        public static string Sign(
            RSACryptoServiceProvider csp,
            string plaintext
        ) {
            // compute sha256 hash of the data
            byte[] hash = new SHA256CryptoServiceProvider()
                .ComputeHash(Encoding.UTF8.GetBytes(plaintext));

            // base64 encode the signature
            return Convert.ToBase64String(
                csp.SignHash(hash, CryptoConfig.MapNameToOID("SHA256"))
            );
        }

        public static bool Verify(
            RSACryptoServiceProvider csp,
            string plaintext,
            string signature
        ) {
            // compute sha256 hash of the data
            byte[] hash = new SHA256CryptoServiceProvider()
                .ComputeHash(Encoding.UTF8.GetBytes(plaintext));

            return csp.VerifyHash(
                hash,
                CryptoConfig.MapNameToOID("SHA256"),
                Convert.FromBase64String(signature));
        }

        public static void runTests(){
            Console.WriteLine("Starting RSA tests");

            string plaintext = "this is my secret message";

            RSACryptoServiceProvider initialProvider = new RSACryptoServiceProvider(2048);
            string encrypted = Encrypt(initialProvider, plaintext);
            Console.WriteLine("plaintext encrypted to: " + encrypted);
            string decrypted = Decrypt(initialProvider, encrypted);
            Console.WriteLine("plaintext decrypted to: " + decrypted);
            string signature = Sign(initialProvider, plaintext);
            Console.WriteLine("signature: " + signature);
            Console.WriteLine("signature verified: " + Verify(initialProvider, plaintext, signature));

            // key and signature exported from simple-free-encryption-tool
            string publicKey = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA26+x8URoo0U5vk0Cs921
kVsqOnHYHs+YRiNuw64QIT/YnikCrEIqo3oEeH3Jt641LuplGiUPdQy3AaqvE2Dw
oiBHve0p1T/zGEMC9xTFdjIyD3eO0e9IROMZ3mAtbBqEYO6apG1yIoCh9lxPwZ0O
6FyKklpj1vZpw+GjnRMTPjoN/5TgEZ6RAZLYrRoKYS5b0GFMe5gLojTg+2PJ0pwk
OfSSIwJ+M4ngGPdIczKO3hxxJxWXOYvEsMuUzhUPPmi6nF+pv+6X10G9RpJpq2fd
nsodcxYx9YWA/2rLlvmLRmpH8plgRe83aHB1RIf5UNXgZWp7rsO7vf58rLFo2CQg
rQIDAQAB
-----END PUBLIC KEY-----";
            signature = "LKeGxl2O8eXzkiYDbB5hO5NEUzde5ggqJPyLTTO2CtOD8ESnEhzm864mCMbhl0yxDccfN1g6r9DeG39g6O8A8Bx8JvHvuPaq8PNFz0jOU0v3CoNw8LKQUfJYzGRNHTQDRKk1kqIn+8+tJfhAbGceHlneCzMuEz6FoIDkwr8IKSxqkJpvKGmv2LRWGyjtpYNZf71B9EjjeCeyRBRmCcD2CKs/A2+tj4mWTxzs/+U9ik2BSR9fnBq0fcPzOCCgxtI9sYxqR650AnZONVHmozUO0M3dzgSfltrFORsVT4QFm0bbdZqDTsQnulfJPSHY3CIV85qA5OD7M6GM6tdLAAVl8A==";

            RSACryptoServiceProvider importedProvider = RSAKeys.ImportPublicKey(publicKey);
            Console.WriteLine("imported signature verified: " + Verify(importedProvider, plaintext, signature));

            Console.WriteLine("RSA tests completed");
        }
   }
}