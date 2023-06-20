using System.Security.Cryptography;
using System.Text;

namespace Cer
{
    public class Security
    {
        private readonly IConfiguration _configuration;
        private static string AppKey;

        public Security(IConfiguration configuration)
        {
            _configuration = configuration;
            AppKey = _configuration.GetSection("AWS:AppKey").Value;
        }

        public static async Task<string> EncryptAES(string password)
        {
            using Aes aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes(AppKey);
            aes.IV = Encoding.UTF8.GetBytes(AppKey);
            using MemoryStream outSteam = new();
            using CryptoStream cryptoStream = new CryptoStream(outSteam, aes.CreateEncryptor(), CryptoStreamMode.Write);
            await cryptoStream.WriteAsync(Encoding.UTF8.GetBytes(password));
            await cryptoStream.FlushAsync();
            return outSteam.ToArray().ToString();
        }

        public static async Task<string> DecryptAES(string cipher)
        {
            using Aes aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes(AppKey);
            aes.IV = Encoding.UTF8.GetBytes(AppKey);
            return "";
        }
    }
}
