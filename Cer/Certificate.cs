using Amazon;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;
using Syncfusion.Pdf.Parsing;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Syncfusion.Pdf.Security;
using Syncfusion.Pdf.Graphics;
using Syncfusion.Drawing;
using pdftron.PDF;
using System;
namespace Cer
{
    public class Certificate
    {
        private readonly IConfiguration _configuration;
        string AWS_ACCESS_ID;
        string AWS_SECRET_KEY;
        string AWS_S3_BUCKET;
        string SyncFusionLicense;
        RegionEndpoint bucketRegion = RegionEndpoint.APSoutheast1;

        public Certificate(IConfiguration configuration) {
            _configuration = configuration;
            AWS_ACCESS_ID = _configuration.GetSection("AWS:AWS_ACCESS_ID").Value;
            AWS_SECRET_KEY = _configuration.GetSection("AWS:AWS_SECRET_KEY").Value;
            AWS_S3_BUCKET = _configuration.GetSection("AWS:AWS_S3_BUCKET").Value;
            SyncFusionLicense = _configuration.GetSection("SyncLicense").Value;
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

        public byte[] createSelfCer(string issued, string password, int expireAfter = 90)
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

                using (X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(expireAfter)))
                {
                    var cerBytes = cert.Export(X509ContentType.Pfx, password);
                    return cerBytes;
                }
            }
        }

        public async Task<bool> signPdf(string pdfName, string userName, string passWord, int pageNumber)
        {
            Syncfusion.Licensing.SyncfusionLicenseProvider.RegisterLicense(SyncFusionLicense);
            //var pdfBytes = await DownloadFile(pdfName);
            //PdfLoadedDocument loadedDocument = new PdfLoadedDocument(pdfBytes);
            //Load digital ID with password.
            PdfCertificate certificate = null;
            var pfxName = userName + ".pfx";
            var cerBytes = await DownloadFile(pfxName);
            var cerStream = new MemoryStream(cerBytes);
            certificate = new PdfCertificate(cerStream, passWord);

            var pdfPath = "C:\\Users\\ekkob\\OneDrive\\Máy tính\\AndroSign\\sample.pdf";
            var xfdfPath = "C:\\Users\\ekkob\\OneDrive\\Máy tính\\AndroSign\\sample.xfdf";

            # region PdfTron
            pdftron.PDFNet.Initialize("demo:1685720134495:7db667fb0300000000e53ca7f74768e21067569be2eb860e4c7dec9119");
            PDFDoc doc = new PDFDoc(pdfPath);
            doc.MergeXFDF(xfdfPath);
            #endregion

            var mergeBytes = (byte[])doc.Save(pdftron.SDF.SDFDoc.SaveOptions.e_compatibility);

            #region Syncfusion
            PdfLoadedDocument pdfDoc = new PdfLoadedDocument(mergeBytes);

            if (pdfDoc.Form == null)
            {
                return false;
            }
            PdfLoadedSignatureField field = pdfDoc.Form.Fields[0] as PdfLoadedSignatureField;
            //Create a signature with loaded digital ID.

            field.Signature = new Syncfusion.Pdf.Security.PdfSignature(pdfDoc, pdfDoc.Pages[pageNumber], certificate, "DigitalSignature", field);
            field.Signature.Settings.CryptographicStandard = CryptographicStandard.CADES;

            #region Signature Image
            var imgName = userName + ".png";
            //var imgBytes = await DownloadFile(imgName);
            imgName = @"C:\Users\ekkob\OneDrive\Máy tính\Screenshot_20190720-174854_Facebook.jpg";
            var imgBytes = await  File.ReadAllBytesAsync(imgName);
            var imgStream = new MemoryStream(imgBytes);
            var signatureImage = PdfBitmap.FromStream(imgStream);
            #endregion
            #region Signature Properties
            field.Signature.ContactInfo = _configuration.GetSection("AppName").Value;
            field.Signature.Appearance.Normal.Graphics.DrawImage(signatureImage, new PointF(0, 0) /*field.Signature.Bounds.Location*/, field.Signature.Bounds.Size);
            field.Signature.Settings.DigestAlgorithm = DigestAlgorithm.SHA256;
            //This property enables the author or certifying signature.
            field.Signature.Certificated = true;
            field.Signature.DocumentPermissions = PdfCertificationFlags.ForbidChanges;
            field.Signature.IsLocked = true;
            field.Form.ReadOnly = true;
            #endregion

            MemoryStream stream = new MemoryStream();
            //var xfdfStream = new MemoryStream();
            var xfdfSignPath = "C:\\Users\\ekkob\\OneDrive\\Máy tính\\AndroSign\\signed.xfdf";
            
            //Save the document into stream.
            pdfDoc.Save(stream);
            stream.Position = 0;
            //Close the document.
            //xfdfStream.Position = 0;
            doc = new PDFDoc(stream);

            var xfdfDoc = doc.FDFExtract(PDFDoc.ExtractFlag.e_both);
            /*var xfdfString = */xfdfDoc.SaveAsXFDF(xfdfSignPath);
            //var xfdfBytes = System.Convert.FromBase64String(xfdfString);
            //File.WriteAllBytes(xfdfSignPath, xfdfBytes);

            var signedBytes = stream.ToArray();
            var signedPath = "C:\\Users\\ekkob\\OneDrive\\Máy tính\\AndroSign\\signed.pdf";
            File.WriteAllBytes(signedPath, signedBytes);
            //var result = await UploadFile(signedBytes, pdfName.Replace(".pdf", "") + "_signed.pdf");
            var result = true;
            pdfDoc.Close(true);
            return result;
        }

        public async Task<bool> mergeXFDF(string pdfPath, string xfdfPath)
        {
            

            #endregion
            return true;
        }
    }
}
