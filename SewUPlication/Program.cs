using System;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp
{
    class Program
    {
        private static readonly DateTime _date = DateTime.Now;
        static void Main(string[] args)
        {
            byte[] tag = new byte[16]; // Set the tag size to 16 bytes
                                       // Connect to the "Security" database and call the stored procedure to generate a nonce
            byte[] nonce = GenerateNonce();

            byte[] key = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(key);

            string plaintext = "Hello, world!";
            byte[] ciphertext;
            using (var cipher = new AesGcm(key))
            {

                ciphertext = new byte[plaintext.Length];
                cipher.Encrypt(nonce, Encoding.UTF8.GetBytes(plaintext), ciphertext, tag, nonce);
            }

            string decrypted;
            using (var cipher = new AesGcm(key))
            {
                byte[] decryptedBytes = new byte[ciphertext.Length];
                cipher.Decrypt(nonce, ciphertext, tag, decryptedBytes, nonce);
                decrypted = Encoding.UTF8.GetString(decryptedBytes);
            }
            //CreateGenerateNonceStoredProcedure();
            CreateLogTable();
            // Save the values in the ENC_DEC_LOG table
            SaveToLogTable(plaintext, ciphertext, decrypted, key, nonce, tag);

            Console.WriteLine("Plaintext: " + plaintext);
            Console.WriteLine("Key: " + Convert.ToBase64String(key));
            Console.WriteLine("Nonce: " + Convert.ToBase64String(nonce));
            Console.WriteLine("Tag: " + Convert.ToBase64String(tag));
            Console.WriteLine("Ciphertext: " + Convert.ToBase64String(ciphertext));
            Console.WriteLine("Decrypted: " + decrypted);
        }



        static byte[] GenerateNonce()
        {
            // Connect to the "Security" database
            using (var connection = new SqlConnection("Server=(localdb)\\mssqllocaldb;Database=Security;Trusted_Connection=True;MultipleActiveResultSets=true"))
            {
                connection.Open();

                // Create a SqlCommand object to call the stored procedure
                using (var command = new SqlCommand("GenerateNonce", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    // Add an output parameter to retrieve the generated nonce
                    SqlParameter outputParameter = new SqlParameter();
                    outputParameter.ParameterName = "@nonce";
                    outputParameter.DbType = System.Data.DbType.Binary;
                    outputParameter.Direction = System.Data.ParameterDirection.Output;
                    outputParameter.Size = 12; // nonce size
                    command.Parameters.Add(outputParameter);

                    command.ExecuteNonQuery();

                    // Retrieve the generated nonce from the output parameter
                    byte[] nonce = (byte[])outputParameter.Value;
                    return nonce;
                }
            }
        }
        static void SaveToLogTable(string plaintext, byte[] ciphertext, string decrypted, byte[] key, byte[] nonce, byte[] tag)
        {
            using (var connection = new SqlConnection("Server=(localdb)\\mssqllocaldb;Database=Security;Trusted_Connection=True;MultipleActiveResultSets=true"))
            {
                connection.Open();

                // Create a SqlCommand object to insert the values in the ENC_DEC_LOG table
                using (var command = new SqlCommand("INSERT INTO ENC_DEC_LOG (PROVIDED_VALUE, ENCRYPTED_VALUE, DECRYPTED_VALUE, CREATED_DATETIME, KEY_VALUE, NONCE_VALUE, TAG_VALUE) VALUES (@ProvidedValue, @EncryptedValue, @DecryptedValue, @CreateDate, @KeyValue, @NonceValue, @TagValue)", connection))
                {
                    command.Parameters.AddWithValue("@ProvidedValue", plaintext);
                    command.Parameters.AddWithValue("@EncryptedValue", Convert.ToBase64String(ciphertext));
                    command.Parameters.AddWithValue("@DecryptedValue", decrypted);
                    command.Parameters.AddWithValue("@CreateDate", _date);
                    command.Parameters.AddWithValue("@KeyValue", Convert.ToBase64String(key));
                    command.Parameters.AddWithValue("@NonceValue", Convert.ToBase64String(nonce));
                    command.Parameters.AddWithValue("@TagValue", Convert.ToBase64String(tag));
                    command.ExecuteNonQuery();
                }

                // Create a SqlCommand object to insert the key, nonce, and tag values in the KEY_NONCE_TAG table
                using (var command = new SqlCommand("INSERT INTO KEY_NONCE_TAG (KEY_VALUE, NONCE_VALUE, TAG_VALUE) VALUES (@KeyValue, @NonceValue, @TagValue)", connection))
                {
                    command.Parameters.AddWithValue("@KeyValue", Convert.ToBase64String(key));
                    command.Parameters.AddWithValue("@NonceValue", Convert.ToBase64String(nonce));
                    command.Parameters.AddWithValue("@TagValue", Convert.ToBase64String(tag));
                    command.ExecuteNonQuery();
                }
            }
        }

        static void CreateLogTable()
        {
            using (var connection = new SqlConnection("Server=(localdb)\\mssqllocaldb;Database=Security;Trusted_Connection=True;MultipleActiveResultSets=true"))
            {
                connection.Open();

                // Create a SqlCommand object to create the ENC_DEC_LOG table
                using (var command = new SqlCommand("CREATE TABLE ENC_DEC_LOG (ID INT IDENTITY(1,1) PRIMARY KEY, PROVIDED_VALUE NVARCHAR(MAX) NOT NULL, ENCRYPTED_VALUE NVARCHAR(MAX) NOT NULL, DECRYPTED_VALUE NVARCHAR(MAX) NOT NULL, CREATED_DATETIME DATETIME2(7) NOT NULL, KEY_VALUE NVARCHAR(MAX) NOT NULL, NONCE_VALUE NVARCHAR(MAX) NOT NULL, TAG_VALUE NVARCHAR(MAX) NOT NULL)", connection))
                {
                    command.ExecuteNonQuery();
                }

                // Create a SqlCommand object to create the KEY_NONCE_TAG table
                using (var command = new SqlCommand("CREATE TABLE KEY_NONCE_TAG (ID INT IDENTITY(1,1) PRIMARY KEY, KEY_VALUE NVARCHAR(MAX) NOT NULL, NONCE_VALUE NVARCHAR(MAX) NOT NULL, TAG_VALUE NVARCHAR(MAX) NOT NULL)", connection))
                {
                    command.ExecuteNonQuery();
                }
            }
        }


        static void CreateGenerateNonceStoredProcedure()
        {
            // Connect to the "Security" database
            using (var connection = new SqlConnection("Server=(localdb)\\mssqllocaldb;Database=Security;Trusted_Connection=True;MultipleActiveResultSets=true"))
            {
                connection.Open();

                // Create a SqlCommand object to create the stored procedure
                using (var command = new SqlCommand("CREATE PROCEDURE GenerateNonce (@nonce binary(12) OUTPUT) AS BEGIN SELECT @nonce = CAST(CRYPT_GEN_RANDOM(12) AS binary(12)) END;", connection))
                { 
                    command.ExecuteNonQuery();
                    
                }
            }
        }
    }
}
