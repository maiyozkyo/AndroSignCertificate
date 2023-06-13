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
using System.Xml;
using Microsoft.OpenApi.Any;
using System.Text.Json;
using Cer.Model;

namespace Cer
{
    public class Certificate
    {
        private readonly IConfiguration _configuration;
        string AWS_ACCESS_ID;
        string AWS_SECRET_KEY;
        string AWS_S3_BUCKET;
        string SyncFusionLicense;
        string PdfTronLicense;
        RegionEndpoint bucketRegion = RegionEndpoint.APSoutheast1;

        public Certificate(IConfiguration configuration) {
            _configuration = configuration;
            AWS_ACCESS_ID = _configuration.GetSection("AWS:AWS_ACCESS_ID").Value;
            AWS_SECRET_KEY = _configuration.GetSection("AWS:AWS_SECRET_KEY").Value;
            AWS_S3_BUCKET = _configuration.GetSection("AWS:AWS_S3_BUCKET").Value;
            SyncFusionLicense = _configuration.GetSection("SyncLicense").Value;
            PdfTronLicense = _configuration.GetSection("TronLicense").Value;
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

        public async Task<string> signPdf(string pdfPath, string sXfdf, string pfxPath, string passWord, string imgPath, string stepNo)
        {
            var pdfBytes = await DownloadFile(pdfPath);
            if (pdfBytes == null || pdfBytes.Length == 0)
            {
                return "";
            }

            # region PdfTron
            pdftron.PDFNet.Initialize(PdfTronLicense);
            PDFDoc doc = new PDFDoc(pdfBytes, pdfBytes.Length);

            XmlDocument xml = new XmlDocument();
            xml.LoadXml(sXfdf);
            var lstWidgets = xml.GetElementsByTagName("widget").Cast<XmlElement>().ToList();
            var lstSignerFieldIDs = new List<string>();
            foreach (XmlElement widget in lstWidgets)
            {
                var sTrans = widget.GetElementsByTagName("trn-custom-data")?.Cast<XmlElement>().FirstOrDefault()?.Attributes?.Item(0)?.Value;
                if (string.IsNullOrEmpty(sTrans)) {
                    return "";
                }
                var oTrans = JsonSerializer.Deserialize<TransData>(sTrans);
                if (oTrans?.step == stepNo)
                {
                    var fieldID = widget?.Attributes?.GetNamedItem("field")?.Value;
                    if (string.IsNullOrEmpty(fieldID))
                    {
                        return "";
                    }
                    lstSignerFieldIDs.Add(fieldID);
                }
            }
            if (int.Parse(stepNo) == 0)
            {
                doc.MergeXFDF(sXfdf);
                pdfBytes = doc.Save(pdftron.SDF.SDFDoc.SaveOptions.e_compatibility);
            }
            doc.Close();
            #endregion

            #region Syncfusion
            Syncfusion.Licensing.SyncfusionLicenseProvider.RegisterLicense(SyncFusionLicense);
            PdfLoadedDocument pdfDoc = new PdfLoadedDocument(pdfBytes);
            if (pdfDoc.Form == null || pdfDoc.Form.Fields.Count == 0)
            {
                return "";
            }

            #region Certificate Authencation
            var cerBytes = await DownloadFile(pfxPath);
            var cerStream = new MemoryStream(cerBytes);
            PdfCertificate certificate = new PdfCertificate(cerStream, passWord);
            cerStream.Close();
            #endregion

            #region Signature Image
            var imgBytes = await DownloadFile(imgPath);
            var imgStream = new MemoryStream(imgBytes);
            var signatureImage = PdfBitmap.FromStream(imgStream);
            imgStream.Close();
            #endregion
            var tmpStream = new MemoryStream();

            foreach (var fieldID in lstSignerFieldIDs)
            {
                #region Signature Properties
                PdfLoadedSignatureField field = pdfDoc?.Form?.Fields?.Cast<PdfLoadedSignatureField>()?.FirstOrDefault(f => f.Name == fieldID && !f.IsSigned);
                //Create a signature with loaded digital ID.
                if (field == null)
                {
                    return "";
                }
                field.Signature = new Syncfusion.Pdf.Security.PdfSignature(pdfDoc, field.Page, certificate, "DigitalSignature", field);
                field.Signature.Settings.CryptographicStandard = CryptographicStandard.CADES;
                field.Signature.ContactInfo = _configuration.GetSection("AppName").Value;
                field.Signature.Appearance.Normal.Graphics.DrawImage(signatureImage, new PointF(0, 0), field.Signature.Bounds.Size);
                field.Signature.Settings.DigestAlgorithm = DigestAlgorithm.SHA256;
                //This property enables the author or certifying signature.
                //field.Signature.Certificated = true;
                field.Signature.DocumentPermissions = PdfCertificationFlags.ForbidChanges;
                #endregion

                pdfDoc.Save(tmpStream);
                pdfDoc.Close(true);
                tmpStream.Position = 0;
                pdfDoc = new PdfLoadedDocument(tmpStream);
            }
            #endregion

            #region Sign Result
            using MemoryStream signedStream = new MemoryStream();
            //Save the document into stream.
            pdfDoc.Save(signedStream);
            signedStream.Position = 0;
            //Close the document.
            //xfdfStream.Position = 0;
            doc = new PDFDoc(signedStream);

            var xfdfDoc = doc.FDFExtract(PDFDoc.ExtractFlag.e_both);
            var xfdfString = xfdfDoc.SaveAsXFDF();

            var signedBytes = signedStream.ToArray();
            pdfPath = pdfPath.Replace(".pdf", "_signed.pdf");
            var result = await UploadFile(signedBytes, pdfPath);
            //File.WriteAllBytes(@"C:\\Users\\admin\\Desktop\\CerFile\\" + pdfPath, signedBytes);
            pdfDoc.Close(true);
            signedStream.Close();
            if (result)
            {
                return xfdfString;
            }
            return "";
            #endregion
        }
    }
}
