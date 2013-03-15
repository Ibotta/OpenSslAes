using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace OpenSslAes
{
	public class OpenSslAes
	{
		public static void Encrypt(Stream inStream, Stream outStream, string passphrase)
		{
			byte[] key, iv;
			var salt = new byte[8];
			new RNGCryptoServiceProvider().GetNonZeroBytes(salt);
			
			EvpBytesToKey(passphrase, salt, out key, out iv);
			
			outStream.Write (Encoding.ASCII.GetBytes ("Salted__"), 0, 8);
			outStream.Write (salt, 0, 8);
			
			RijndaelManaged aesAlgorithm = new RijndaelManaged
			{
				Mode = CipherMode.CBC,
				KeySize = 256,
				BlockSize = 128,
				Key = key,
				IV = iv
			};
			
			var encryptor = aesAlgorithm.CreateEncryptor(aesAlgorithm.Key, aesAlgorithm.IV);
			
			var cryptoStream = new CryptoStream(outStream, encryptor, CryptoStreamMode.Write);
			inStream.CopyTo (cryptoStream);
			cryptoStream.FlushFinalBlock();
			
			inStream.Close ();
			cryptoStream.Close ();
			outStream.Close ();
		}
		
		public static void Decrypt(Stream inStream, Stream outStream, string passphrase)
		{
			byte[] salt = new byte[8];
			inStream.Seek (8, SeekOrigin.Begin);
			inStream.Read (salt, 0, 8); 
			//inStream.Seek (8 + salt.Length, SeekOrigin.Begin);
			
			byte[] key, iv;
			EvpBytesToKey(passphrase, salt, out key, out iv);
			
			RijndaelManaged aesAlgorithm = new RijndaelManaged
			{
				Mode = CipherMode.CBC,
				KeySize = 256,
				BlockSize = 128,
				Key = key,
				IV = iv
			};
			
			ICryptoTransform decryptor = aesAlgorithm.CreateDecryptor(aesAlgorithm.Key, aesAlgorithm.IV);
			
			CryptoStream cryptoStream = new CryptoStream(inStream, decryptor, CryptoStreamMode.Read);
			cryptoStream.CopyTo (outStream);
			outStream.Flush();
			
			inStream.Close ();
			cryptoStream.Close ();
			outStream.Close ();
		}
		
		// Key derivation algorithm used by OpenSSL
		//
		// Derives a key and IV from the passphrase and salt using a hash algorithm (in this case, MD5).
		//
		// Refer to http://www.openssl.org/docs/crypto/EVP_BytesToKey.html#KEY_DERIVATION_ALGORITHM
		private static void EvpBytesToKey(string passphrase, byte[] salt, out byte[] key, out byte[] iv)
		{
			var concatenatedHashes = new List<byte>(48);
			
			byte[] password = Encoding.UTF8.GetBytes(passphrase);
			byte[] currentHash = new byte[0];
			MD5 md5 = MD5.Create();
			bool enoughBytesForKey = false;
			
			while (!enoughBytesForKey)
			{
				int preHashLength = currentHash.Length + password.Length + salt.Length;
				byte[] preHash = new byte[preHashLength];
				
				Buffer.BlockCopy(currentHash, 0, preHash, 0, currentHash.Length);
				Buffer.BlockCopy(password, 0, preHash, currentHash.Length, password.Length);
				Buffer.BlockCopy(salt, 0, preHash, currentHash.Length + password.Length, salt.Length);
				
				currentHash = md5.ComputeHash(preHash);
				concatenatedHashes.AddRange(currentHash);
				
				if (concatenatedHashes.Count >= 48) enoughBytesForKey = true;
			}
			
			key = new byte[32];
			iv = new byte[16];
			concatenatedHashes.CopyTo(0, key, 0, 32);
			concatenatedHashes.CopyTo(32, iv, 0, 16);
			
			md5.Clear();
			md5 = null;
		}
	}
}
