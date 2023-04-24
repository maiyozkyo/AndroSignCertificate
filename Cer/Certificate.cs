using Amazon;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;
using Syncfusion.Pdf.Parsing;
using System.Configuration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Syncfusion.Pdf.Security;
using Syncfusion.Pdf.Graphics;
using Syncfusion.Drawing;

namespace Cer
{
    public class Certificate
    {
        private readonly IConfiguration _configuration;
        string AWS_ACCESS_ID;
        string AWS_SECRET_KEY;
        string AWS_S3_BUCKET;
        RegionEndpoint bucketRegion = RegionEndpoint.APSoutheast1;

        public Certificate(IConfiguration configuration){
            _configuration = configuration;
            AWS_ACCESS_ID = _configuration.GetSection("AWS:AWS_ACCESS_ID").Value;
            AWS_SECRET_KEY = _configuration.GetSection("AWS:AWS_SECRET_KEY").Value;
            AWS_S3_BUCKET = _configuration.GetSection("AWS:AWS_S3_BUCKET").Value;
        }

        public async Task<bool> UploadFile(byte[] fileBytes, string fileName)
        {
            var s3Client = new AmazonS3Client(AWS_ACCESS_ID, AWS_SECRET_KEY, bucketRegion);

            var fileTrans = new TransferUtility(s3Client);
            Stream fs = new MemoryStream(fileBytes);
            var fileTransReq = new TransferUtilityUploadRequest
            {
                BucketName = AWS_S3_BUCKET,
                InputStream = fs,
                StorageClass = S3StorageClass.StandardInfrequentAccess,
                PartSize = 6291456,
                Key = fileName,
                CannedACL = S3CannedACL.PublicRead,
            };

            await fileTrans.UploadAsync(fileTransReq);
            return true;
        }
        public async Task<byte[]> DownloadFile(string fileName)
        {
            
            var s3Client = new AmazonS3Client(AWS_ACCESS_ID, AWS_SECRET_KEY, bucketRegion);
            var objReq = new GetObjectRequest
            {
                BucketName = AWS_S3_BUCKET,
                Key = fileName,
            };
            using (var ms = new MemoryStream())
            {
                var responseObj = await s3Client.GetObjectAsync(objReq);
                await responseObj.ResponseStream.CopyToAsync(ms);
                return ms.ToArray();
            }
        }

        public byte[] createSelfCer(string issued, string password)
        {
            using (RSA rsa = RSACng.Create(2048))
            {
                var cngParams = new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextExport };
                var cngKey = CngKey.Create(CngAlgorithm.Rsa, null, cngParams);
                var key = new RSACng(cngKey);
                CertificateRequest req = new CertificateRequest(
                     $"CN={issued}",
                     rsa,
                     HashAlgorithmName.SHA512,
                     RSASignaturePadding.Pkcs1);

                req.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, false));

                req.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                        false));

                req.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection
                        {
                            new Oid("1.3.6.1.5.5.7.3.8")
                        },
                        true));

                req.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

                using (X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90)))
                {
                    var cerBytes = cert.Export(X509ContentType.Pfx, password);
                    return cerBytes;
                }
            }
        }

        public async Task<bool> signPdf(string pdfName, string userName, string passWord, int pageNumber)
        {
            var pdfBytes = await DownloadFile(pdfName);
            PdfLoadedDocument loadedDocument = new PdfLoadedDocument(pdfBytes);
            //Load digital ID with password.
            PdfCertificate certificate = null;
            var pfxName = userName + ".pfx";
            var cerBytes = await DownloadFile(pfxName);
            var cerStream = new MemoryStream(cerBytes);
            certificate = new PdfCertificate(cerStream, passWord);
            

            //Create a signature with loaded digital ID.
            PdfSignature signature = new Syncfusion.Pdf.Security.PdfSignature(loadedDocument, loadedDocument.Pages[pageNumber], certificate, "DigitalSignature");
            signature.Settings.CryptographicStandard = CryptographicStandard.CADES;
            var imgName = userName + ".png";
            var imgBytes = await DownloadFile(imgName);
            var imgStream = new MemoryStream(imgBytes);

            var signatureImage = PdfBitmap.FromStream(imgStream);
            signature.Bounds = new RectangleF(0, 0, 200, 100);
            signature.Appearance.Normal.Graphics.DrawImage(signatureImage, signature.Bounds);
            signature.Settings.DigestAlgorithm = DigestAlgorithm.SHA256;
            //This property enables the author or certifying signature.
            signature.Certificated = true;
            //Allow the form fill and and comments.
            signature.DocumentPermissions = PdfCertificationFlags.AllowFormFill | PdfCertificationFlags.AllowComments;

            //Save the document into stream.
            MemoryStream stream = new MemoryStream();
            loadedDocument.Save(stream);
            stream.Position = 0;
            //Close the document.
            var result = await UploadFile(stream.ToArray(), pdfName.Replace(".pdf", "") + "_signed.pdf");
            loadedDocument.Close(true);
            return result;
        }
    }
}
