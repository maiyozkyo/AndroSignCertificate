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
            AppKey = _configuration.GetSection("AppKey").Value;
        }

        public string Encrypt(string password)
        {
            var aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes("4512631236589784");
            aes.IV = Encoding.UTF8.GetBytes("4512631236589784");
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            aes.FeedbackSize = 16;
            var encryptor = aes.CreateEncryptor();
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(password);
                    }
                    var encrypted = msEncrypt.ToArray();
                    return Convert.ToBase64String(encrypted);
                }
            }
        }

        public string Decrypt(string cipher)
        {
            var aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes("4512631236589784");
            aes.IV = Encoding.UTF8.GetBytes("4512631236589784");
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            aes.FeedbackSize = 16;
            var decryptor = aes.CreateDecryptor();

            string password = "";
            try
            {
                var cipherBytes = Convert.FromBase64String(cipher);
                using var msDecrypt = new MemoryStream(cipherBytes);
                using CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using (var srDecrypt = new StreamReader(csDecrypt))
                {
                    password = srDecrypt.ReadToEnd();
                }
            }catch (Exception ex) {
                throw new Exception("Mật khẩu không chính xác!");
            }
            return password;
        }
    }
}
