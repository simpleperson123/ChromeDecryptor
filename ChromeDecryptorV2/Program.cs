using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Newtonsoft.Json;
using System.Data.SQLite;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Diagnostics;


namespace ChromeDecryptorV2
{
	class Credential
	{
		public string url { get; set; }
		public string username { get; set; }
		public string password { get; set; }
	}
    public class Program
	{
		static void Main(string[] args)
		{
			Process[] processlist = Process.GetProcessesByName("chrome");
			if(processlist.Length != 0)
			{
				Console.WriteLine("Chrome is running! You must close chrome to decrypt the data!");
				Console.ReadKey();
				return;
			}

			string localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
			string LoginDataPath = localappdata + "\\Google\\Chrome\\User Data\\Default\\Login Data";

			byte[] key = GetKey();

			string connectionString = String.Format("Data Source={0};Version=3;", LoginDataPath);

			SQLiteConnection conn = new SQLiteConnection(connectionString);
			conn.Open();

			List<Credential> creds = new List<Credential>();

			SQLiteCommand cmd = new SQLiteCommand("select * from logins", conn);
			SQLiteDataReader reader = cmd.ExecuteReader();

			while(reader.Read())
			{
				byte[] encryptedData = (byte[])reader["password_value"];
				if(IsV10(encryptedData))
				{
					byte[] nonce, ciphertextTag;
					Prepare(encryptedData, out nonce, out ciphertextTag);
					string password = Decrypt(ciphertextTag, key, nonce);
					creds.Add(new Credential {
						url = reader["origin_url"].ToString(),
						username = reader["username_value"].ToString(),
						password = password
					});
				}
				else
				{
					byte[] encryptedDataDPAPI = (byte[])reader["password_value"];
					string password;
					try
					{
					    password = Encoding.UTF8.GetString(ProtectedData.Unprotect(encryptedDataDPAPI, null, DataProtectionScope.CurrentUser));
					}
					catch
					{
						password = "Decryption failed :(";
					}
					creds.Add(new Credential
					{
						url = reader["origin_url"].ToString(),
						username = reader["username_value"].ToString(),
						password = password
					});
				}
			}

			foreach(Credential cred in creds)
			{
				Console.WriteLine("{0}-{1}-{2}", cred.url, cred.username, cred.password);
			}
			Console.ReadKey();

		}

		static bool IsV10(byte[] data)
		{
			if(Encoding.UTF8.GetString(data.Take(3).ToArray()) == "v10")
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		//Gets the key used for new AES encryption (from Chrome 80)
		static byte[] GetKey()
		{
			string localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
			string FilePath = localappdata + "\\Google\\Chrome\\User Data\\Local State";
			string content = File.ReadAllText(FilePath);
			dynamic json = JsonConvert.DeserializeObject(content);
			string key = json.os_crypt.encrypted_key;
			byte[] binkey = Convert.FromBase64String(key).Skip(5).ToArray();
			byte[] decryptedkey = ProtectedData.Unprotect(binkey, null, DataProtectionScope.CurrentUser);

			return decryptedkey;
		}

		//Gets cipher parameters for v10 decryption
		public static void Prepare(byte[] encryptedData, out byte[] nonce, out byte[] ciphertextTag)
		{
			nonce = new byte[12];
			ciphertextTag = new byte[encryptedData.Length - 3 - nonce.Length];

			System.Array.Copy(encryptedData, 3, nonce, 0, nonce.Length);
			System.Array.Copy(encryptedData, 3 + nonce.Length, ciphertextTag, 0, ciphertextTag.Length);
		}

		//Decrypts v10 credential
		public static string Decrypt(byte[] encryptedBytes, byte[] key, byte[] iv)
		{
			string sR = string.Empty;
			try
			{
				GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
				AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, iv, null);

				cipher.Init(false, parameters);
				byte[] plainBytes = new byte[cipher.GetOutputSize(encryptedBytes.Length)];
				Int32 retLen = cipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, plainBytes, 0);
				cipher.DoFinal(plainBytes, retLen);

				sR = Encoding.UTF8.GetString(plainBytes).TrimEnd("\r\n\0".ToCharArray());
			}
			catch (Exception ex)
			{
				return "Decryption failed :(";
			}

			return sR;
		}

	}
}
