﻿using Amazon;
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
using System.Text.Json;
using Cer.Model;
using Syncfusion.Pdf;
using Syncfusion.Pdf.Interactive;
using System.Text.RegularExpressions;
using pdftron.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto.IO;

namespace Cer.Business
{
    public class Certificate
    {
        private readonly IConfiguration _configuration;
        private string AWS_ACCESS_ID;
        private string AWS_SECRET_KEY;
        private string AWS_S3_BUCKET;
        private string SyncFusionLicense;
        private string PdfTronLicense;
        private Security Secur;
        RegionEndpoint bucketRegion = RegionEndpoint.APSoutheast1;

        public Certificate(IConfiguration configuration)
        {
            _configuration = configuration;
            AWS_ACCESS_ID = _configuration.GetSection("AWS:AWS_ACCESS_ID").Value;
            AWS_SECRET_KEY = _configuration.GetSection("AWS:AWS_SECRET_KEY").Value;
            AWS_S3_BUCKET = _configuration.GetSection("AWS:AWS_S3_BUCKET").Value;
            SyncFusionLicense = _configuration.GetSection("SyncLicense").Value;
            PdfTronLicense = _configuration.GetSection("TronLicense").Value;
            Secur = new Security(configuration);
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

        public Task<bool> createSelfCer(string issued, string password, string fileName, int expireAfter = 30)
        {
            password = Secur.Decrypt(password);
            using (RSA rsa = RSA.Create(2048))
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
                    var result = UploadFile(cerBytes, fileName);
                    return result;
                }
            }
        }

        public async Task<string> signPdf(string pdfPath, string sXfdf, string pfxPath, string passWord, string stepNo)
        {
            var pdfBytes = await DownloadFile(pdfPath);
            //var pdfBytes = File.ReadAllBytes(pdfPath);
            if (pdfBytes == null)
            {
                return "File is not exist";
            }
            using var pfdStream = new MemoryStream(pdfBytes);

            var cerBytes = await DownloadFile(pfxPath);
            if (cerBytes == null)
            {
                return "Certificate is not exist";
            }

            using var pfxStream = new MemoryStream(cerBytes);
            var store = new Pkcs12Store(pfxStream, passWord.ToArray());

            pfxStream.Close();

            var alias = "";

            // searching for private key
            foreach (string al in store.Aliases)
                if (store.IsKeyEntry(al) && store.GetKey(al).Key.IsPrivate)
                {
                    alias = al;
                    break;
                }

            var pk = store.GetKey(alias);

            ICollection<Org.BouncyCastle.X509.X509Certificate> chain = store.GetCertificateChain(alias).Select(c => c.Certificate).ToList();

            var parameters = pk.Key as RsaPrivateCrtKeyParameters;

            #region XML
            XmlDocument xml = new XmlDocument();
            xml.LoadXml(sXfdf);
            var lstWidgets = xml.GetElementsByTagName("widget").Cast<XmlElement>().ToList();
            var lstSignerField = new List<Widget>();
            foreach (XmlElement widgetEle in lstWidgets)
            {
                var sTrans = widgetEle.GetElementsByTagName("trn-custom-data")?.Cast<XmlElement>().FirstOrDefault()?.Attributes?.Item(0)?.Value;
                if (string.IsNullOrEmpty(sTrans))
                {
                    return "";
                }
                var oTrans = JsonSerializer.Deserialize<TransData>(sTrans);
                if (oTrans?.step == stepNo)
                {
                    var widget = new Widget();
                    widget.name = widgetEle.GetAttribute("name");
                    widget.page = int.Parse(widgetEle.GetAttribute("page"));
                    widget.field = widgetEle.GetAttribute("field");
                    var rect = widgetEle.GetElementsByTagName("rect").Cast<XmlElement>().FirstOrDefault();
                    widget.x1 = float.Parse(rect.GetAttribute("x1"));
                    widget.x2 = float.Parse(rect?.GetAttribute("x2"));
                    widget.y1 = float.Parse(rect?.GetAttribute("y1"));
                    widget.y2 = float.Parse(rect?.GetAttribute("y2"));

                    var imgTag = widgetEle.GetElementsByTagName("Normal").Cast<XmlElement>().FirstOrDefault();
                    if (imgTag != null)
                    {
                        var base64 = Regex.Replace(imgTag.InnerText, @"\t|\n|\r", "").Replace("data:image/png;base64,", "");
                        widget.imgBytes = System.Convert.FromBase64String(base64);
                    }
                    lstSignerField.Add(widget);
                }
            }
            #endregion
            var reader = new PdfReader(pdfBytes);
            var fieldIdx = 0;
            var xfdfString = "Error Unknow";
            while (fieldIdx < lstSignerField.Count)
            {
                using (var os = new MemoryStream())
                {
                    var field = lstSignerField[fieldIdx];
                    using (var stamper = PdfStamper.CreateSignature(reader, os, '\0', null, true))
                    {
                        var appearance = stamper.SignatureAppearance;
                        appearance.Reason = "";
                        var rectangle = new iTextSharp.text.Rectangle(field.x2, field.y2, field.x1, field.y1);
                        appearance.SetVisibleSignature(rectangle, field.page, field.field);
                        if (field.imgBytes != null)
                        {
                            appearance.SignatureGraphic = iTextSharp.text.Image.GetInstance(field.imgBytes);
                            appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC;
                        }
                        else
                        {
                            appearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
                        }
                        IExternalSignature pks = new PrivateKeySignature(parameters, DigestAlgorithms.SHA256);
                        MakeSignature.SignDetached(stamper.SignatureAppearance, pks, chain, null, null, null, 0, CryptoStandard.CMS);
                    }
                    var tmpPdfBytes = os.ToArray();
                    //continue
                    #region PdfTron
                    if (fieldIdx == lstSignerField.Count - 1)
                    {
                        UploadFile(tmpPdfBytes, pdfPath);
                        pdftron.PDFNet.Initialize(PdfTronLicense);
                        PDFDoc doc = new PDFDoc(tmpPdfBytes, tmpPdfBytes.Length);
                        var xfdfDoc = doc.FDFExtract(PDFDoc.ExtractFlag.e_both);
                        xfdfString = xfdfDoc.SaveAsXFDF();
                    }
                    #endregion
                    else
                    {
                        reader = new PdfReader(tmpPdfBytes);
                    }
                    //File.WriteAllBytes(@"C:\Users\admin\Desktop\CerFile\nbuubuu" + field.name + ".pdf", tmpPdfBytes);
                    //end
                }
                fieldIdx++;
            }
            reader.Dispose();
            return xfdfString;
        }

        //public async Task<string> signPdf(string pdfPath, string sXfdf, string pfxPath, string passWord, string stepNo)
        //{
        //    var pdfBytes = await DownloadFile(pdfPath);
        //    if (pdfBytes == null || pdfBytes.Length == 0)
        //    {
        //        return "File is not exist";
        //    }

        //    #region XML
        //    XmlDocument xml = new XmlDocument();
        //    xml.LoadXml(sXfdf);
        //    var lstWidgets = xml.GetElementsByTagName("widget").Cast<XmlElement>().ToList();
        //    var lstSignerField = new List<Widget>();
        //    foreach (XmlElement widgetEle in lstWidgets)
        //    {
        //        var sTrans = widgetEle.GetElementsByTagName("trn-custom-data")?.Cast<XmlElement>().FirstOrDefault()?.Attributes?.Item(0)?.Value;
        //        if (string.IsNullOrEmpty(sTrans))
        //        {
        //            return "";
        //        }
        //        var oTrans = JsonSerializer.Deserialize<TransData>(sTrans);
        //        if (oTrans?.step == stepNo)
        //        {
        //            var widget = new Widget();
        //            widget.name = widgetEle.GetAttribute("name");
        //            widget.page = int.Parse(widgetEle.GetAttribute("page"));
        //            widget.field = widgetEle.GetAttribute("field");
        //            var rect = widgetEle.GetElementsByTagName("rect").Cast<XmlElement>().FirstOrDefault();
        //            widget.x1 = float.Parse(rect.GetAttribute("x1"));
        //            widget.x2 = float.Parse(rect?.GetAttribute("x2"));
        //            widget.y1 = float.Parse(rect?.GetAttribute("y1"));
        //            widget.y2 = float.Parse(rect?.GetAttribute("y2"));

        //            var imgTag = widgetEle.GetElementsByTagName("Normal").Cast<XmlElement>().FirstOrDefault();
        //            if (imgTag != null)
        //            {
        //                var base64 = Regex.Replace(imgTag.InnerText, @"\t|\n|\r", "").Replace("data:image/png;base64,", "");
        //                widget.imgBytes = System.Convert.FromBase64String(base64);
        //            }
        //            lstSignerField.Add(widget);
        //        }
        //    }
        //    #endregion

        //    #region Syncfusion
        //    Syncfusion.Licensing.SyncfusionLicenseProvider.RegisterLicense(SyncFusionLicense);
        //    var pdfDoc = new PdfLoadedDocument(pdfBytes);
        //    if (pdfDoc.Form == null)
        //    {
        //        pdfDoc.CreateForm();
        //    }
        //    #region Certificate Authencation
        //    var cerBytes = await DownloadFile(pfxPath);
        //    if (cerBytes == null)
        //    {
        //        return "Certificate is invalid";
        //    }
        //    var cerStream = new MemoryStream(cerBytes);

        //    passWord = Secur.Decrypt(passWord);
        //    PdfCertificate certificate = new PdfCertificate(cerStream, passWord);
        //    cerStream.Close();
        //    if (certificate == null || certificate.ValidTo.Date < DateTime.UtcNow)
        //    {
        //        return "Certificate is invalid";
        //    }
        //    #endregion

        //    #region Add Field into Pdf
        //    foreach (var widget in lstSignerField)
        //    {
        //        PdfSignatureField field = new PdfSignatureField(pdfDoc.Pages[widget.page], widget.name);
        //        field.Bounds = new RectangleF(widget.x1, widget.y1, -widget.x1 + widget.x2, -widget.y1 + widget.y2);
        //        pdfDoc.Form.Fields.Add(field);
        //    }
        //    var tmpStream = new MemoryStream();
        //    pdfDoc.Save(tmpStream);
        //    pdfDoc.Close(true);
        //    pdfDoc = new PdfLoadedDocument(tmpStream);
        //    #endregion

        //    foreach (var widget in lstSignerField)
        //    {
        //        #region Signature Properties
        //        //Create a signature with loaded digital ID.
        //        var field = pdfDoc.Form.Fields[widget.name] as PdfLoadedSignatureField;
        //        PdfSignature signature = new PdfSignature(pdfDoc, pdfDoc.Pages[widget.page], certificate, pfxPath, field);
        //        signature.SignedName = pfxPath;
        //        signature.Settings.CryptographicStandard = CryptographicStandard.CADES;
        //        signature.ContactInfo = _configuration.GetSection("AppName").Value;
        //        signature.Bounds = field.Bounds;
        //        signature.Settings.DigestAlgorithm = DigestAlgorithm.SHA256;
        //        //This property enables the author or certifying signature.
        //        signature.DocumentPermissions = PdfCertificationFlags.ForbidChanges;
                
        //        if (widget.imgBytes != null)
        //        {
        //            #region Signature Image
        //            using var imgStream = new MemoryStream(widget.imgBytes);
        //            var signatureImage = PdfImage.FromStream(imgStream);
        //            signature.Appearance.Normal.Graphics.DrawImage(signatureImage, new PointF(0, 0), signature.Bounds.Size);
        //            imgStream.Close();
        //            #endregion

        //        }
        //        #endregion

        //        #region PDF version
        //        if (pdfDoc.FileStructure.Version == PdfVersion.Version1_0 || pdfDoc.FileStructure.Version == PdfVersion.Version1_1 || pdfDoc.FileStructure.Version == PdfVersion.Version1_2 || pdfDoc.FileStructure.Version == PdfVersion.Version1_3)
        //        {
        //            pdfDoc.FileStructure.Version = PdfVersion.Version1_4;
        //            pdfDoc.FileStructure.IncrementalUpdate = false;
        //        }
        //        #endregion
        //        tmpStream = new MemoryStream();
        //        if (lstSignerField.Count > 1)
        //        {
        //            pdfDoc.Save(tmpStream);
        //            pdfDoc.Close(true);
        //            tmpStream.Position = 0;
        //            pdfDoc = new PdfLoadedDocument(tmpStream);
        //        }
        //    }
        //    #endregion

        //    #region Sign Result
        //    using MemoryStream signedStream = new MemoryStream();
        //    //Save the document into stream.
        //    pdfDoc.Save(signedStream);
        //    pdfDoc.Close(true);

        //    signedStream.Position = 0;

        //    # region PdfTron
        //    pdftron.PDFNet.Initialize(PdfTronLicense);
        //    PDFDoc doc = new PDFDoc(signedStream);

        //    var xfdfDoc = doc.FDFExtract(PDFDoc.ExtractFlag.e_both);
        //    var xfdfString = xfdfDoc.SaveAsXFDF();
        //    #endregion

        //    var signedBytes = signedStream.ToArray();
        //    pdfPath = pdfPath.Replace(".pdf", "_fianlsigned.pdf");
        //    var result = await UploadFile(signedBytes, pdfPath);
        //    //File.WriteAllBytes(@"C:\Users\admin\Desktop\CerFile\" + pdfPath, signedBytes);
        //    signedStream.Close();
        //    if (result)
        //    {
        //        return xfdfString;
        //    }
        //    return "";
        //    #endregion
        //}
    }
}
