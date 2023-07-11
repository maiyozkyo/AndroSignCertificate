using Amazon;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using pdftron.PDF;
using System.Xml;
using System.Text.Json;
using Cer.Model;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using pdftron.PDF.Annots;
using Amazon.Runtime.Internal;
using static System.Net.Mime.MediaTypeNames;
using Syncfusion.DocIO.DLS;
using Syncfusion.DocIO;
using Syncfusion.DocIORenderer;
using Syncfusion.XlsIO;

namespace Cer.Business
{
    public class Certificate
    {
        private readonly IConfiguration _configuration;
        private string AWS_ACCESS_ID;
        private string AWS_SECRET_KEY;
        private string AWS_S3_BUCKET;
        private string PdfTronLicense;
        private string SyncLicense;
        private Security Secur;
        RegionEndpoint bucketRegion = RegionEndpoint.APSoutheast1;

        public Certificate(IConfiguration configuration)
        {
            _configuration = configuration;
            AWS_ACCESS_ID = _configuration.GetSection("AWS:AWS_ACCESS_ID").Value;
            AWS_SECRET_KEY = _configuration.GetSection("AWS:AWS_SECRET_KEY").Value;
            AWS_S3_BUCKET = _configuration.GetSection("AWS:AWS_S3_BUCKET").Value;
            PdfTronLicense = _configuration.GetSection("TronLicense").Value;
            SyncLicense = _configuration.GetSection("SyncLicense").Value;
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
            try
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
            catch (Exception ex)
            {
                return null;
            }
        }
        public async Task<bool> DeleteFile(string fileName)
        {
            try
            {
                DeleteObjectRequest delRequest = new DeleteObjectRequest
                {
                    BucketName = AWS_S3_BUCKET,
                    Key = fileName,
                };
                var s3Client = new AmazonS3Client(AWS_ACCESS_ID, AWS_SECRET_KEY, bucketRegion);
                await s3Client.DeleteObjectAsync(delRequest);
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
        public async Task<string> createSelfCer(string issued, string password, string fileName, int expireAfter = 30, bool isUpdate = false, string newPass = "")
        {
            fileName = "CAs/" + fileName;
            try
            {
                password = Secur.Decrypt(password);
            }
            catch(Exception ex)
            {
                throw;
            }

            var startDate = DateTimeOffset.UtcNow;
            var endDate = DateTimeOffset.UtcNow.AddDays(expireAfter);
            if (isUpdate)
            {
                var cerBytes = await DownloadFile(fileName);
                if (cerBytes == null)
                {
                    throw new Exception("Người dùng chưa có chữ ký số!");
                }
                try
                {
                    X509Certificate cert = new X509Certificate(cerBytes, password);
                    var sStartDate = cert.GetEffectiveDateString();
                    var sEndDate = cert.GetExpirationDateString();
                    startDate = DateTimeOffset.Parse(sStartDate);
                    endDate = DateTimeOffset.Parse(sEndDate);
                }
                catch (Exception ex)
                {
                    throw;//new Exception("Mật khẩu bảo vệ tài liệu không chính xác!");
                }

                try
                {
                    password = Secur.Decrypt(newPass);

                }
                catch (Exception ex)
                {
                    throw new Exception("Mật khẩu mới không đúng định dạng!");
                }
            }

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

                using (X509Certificate2 cert = req.CreateSelfSigned(startDate, endDate))
                {
                    var cerBytes = cert.Export(X509ContentType.Pfx, password);
                    var result = await UploadFile(cerBytes, fileName);
                    return "Tạo chữ ký số cá nhân thành công";
                }
            }
        }

        public async Task<string> signPdf(string pdfPath, string sXfdf, string pfxPath, string passWord, string stepNo)
        {
            var pdfBytes = await DownloadFile(pdfPath);
            if (pdfBytes == null)
            {
                throw new Exception("Tài liệu không tồn tại, vui lòng kiểm tra lại!");
            }
            using var pfdStream = new MemoryStream(pdfBytes);

            var cerBytes = await DownloadFile(pfxPath);
            if (cerBytes == null)
            {
                throw new Exception("Người dùng chưa đăng ký chữ ký số cá nhân!");
            }

            Pkcs12Store store = null;
            try
            {
                passWord = Secur.Decrypt(passWord);
                using var pfxStream = new MemoryStream(cerBytes);
                store = new Pkcs12Store(pfxStream, passWord.ToArray());
                X509Certificate cert = new X509Certificate(cerBytes, passWord);
                var sEndDate = cert.GetExpirationDateString();
                var endDate = DateTimeOffset.Parse(sEndDate);
                
                pfxStream.Close();
                if (endDate <= DateTime.Now)
                {
                    throw new Exception("Chữ ký số hết thời hạn!");

                }
            }
            catch(Exception ex)
            {
                throw new Exception("Mật khẩu không chính xác!");
            }

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
            var lstSignerField = new List<Model.Widget>();
            var lstNextField = new List<Model.Widget>();
            var lstUnsignField = new List<XmlElement>();
            var lstCustomData = new List<TransData>();
            var lstUnsignIDs = new List<string>();
            foreach (XmlElement widgetEle in lstWidgets)
            {
                var sTrans = widgetEle.GetElementsByTagName("trn-custom-data")?.Cast<XmlElement>().FirstOrDefault()?.Attributes?.Item(0)?.Value;
                if (!string.IsNullOrEmpty(sTrans))
                {
                    var oTrans = JsonSerializer.Deserialize<TransData>(sTrans);
                    var fieldID = widgetEle.GetAttribute("field");
                    oTrans.field = fieldID;
                    var widget = new Model.Widget();
                    widget.name = widgetEle.GetAttribute("name");
                    widget.page = int.Parse(widgetEle.GetAttribute("page"));
                    widget.field = fieldID;
                    var rect = widgetEle.GetElementsByTagName("rect").Cast<XmlElement>().FirstOrDefault();
                    widget.x1 = float.Parse(rect.GetAttribute("x1"));
                    widget.x2 = float.Parse(rect?.GetAttribute("x2"));
                    widget.y1 = float.Parse(rect?.GetAttribute("y1"));
                    widget.y2 = float.Parse(rect?.GetAttribute("y2"));
                    if (oTrans?.step == stepNo)
                    {
                        var imgTag = widgetEle.GetElementsByTagName("Normal").Cast<XmlElement>().FirstOrDefault();
                        if (imgTag != null)
                        {
                            var base64 = Regex.Replace(imgTag.InnerText, @"\t|\n|\r", "").Replace("data:image/png;base64,", "");
                            widget.imgBytes = System.Convert.FromBase64String(base64);
                        }
                        lstSignerField.Add(widget);
                    }
                    else if (int.Parse(oTrans?.step) > int.Parse(stepNo))
                    {
                        if (int.Parse(oTrans.step) == int.Parse(stepNo) + 1)
                        {
                            widgetEle.SetAttribute("flags", "");
                        }
                        lstUnsignField.Add(widgetEle);
                        lstUnsignIDs.Add(fieldID);
                        lstNextField.Add(widget);
                        lstCustomData.Add(oTrans);
                    }
                }
            }

            var lstFFields = xml.GetElementsByTagName("ffield").Cast<XmlElement>().Where(ele => lstUnsignIDs.Contains(ele.GetAttribute("name"))).ToList();
            var lstField = new List<XmlElement>();
            if (lstFFields != null && lstFFields.Count > 0)
            {
                foreach (var ff in lstFFields)
                {
                    var newField = xml.CreateElement("field");
                    newField.IsEmpty = false;
                    newField.SetAttribute("name", ff.GetAttribute("name"));
                    lstField.Add(newField);
                }
                lstUnsignField.AddRange(lstFFields);
            }
            #endregion
            var reader = new PdfReader(pdfBytes);
            var fieldIdx = 0;
            var xfdfString = "Error Unknow";

            try
            {
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
                            foreach (var nField in lstNextField)
                            {
                                var signF = doc.CreateDigitalSignatureField(nField.field);
                                var sWidget = SignatureWidget.Create(doc, new Rect(nField.x1, nField.y1, nField.x2, nField.y2), signF);
                                var curData = lstCustomData.Find(d => d.field == nField.field);
                                sWidget.SetCustomData("user", curData.user);
                                sWidget.SetCustomData("step", curData.step);
                                doc.GetPage(nField.page).AnnotPushBack(sWidget);
                            }

                            var xfdfDoc = doc.FDFExtract(PDFDoc.ExtractFlag.e_both);
                            xfdfString = xfdfDoc.SaveAsXFDF();
                        }
                        #endregion
                        else
                        {
                            reader = new PdfReader(tmpPdfBytes);
                        }
                    }
                    fieldIdx++;
                }
                reader.Dispose();
                return xfdfString;
            }
            catch (Exception ex)
            {
                throw new Exception("Tài liệu đã được ký, vui lòng kiểm tra lại!");
            }
           
        }

        private async Task<bool> ToPDFAsyncLogic(string pdfName, string ext)
        {
            var bytes = await DownloadFile(pdfName);
            if (bytes == null) return false;

            ext = ext.ToLower();
            if (ext.Equals(".pdf")) return true;

            var contents = new MemoryStream(bytes);

            //license
            Syncfusion.Licensing.SyncfusionLicenseProvider.RegisterLicense(SyncLicense);
            //

            List<string> wordExt = _configuration.GetSection("SyncLicense").Value.Split(" ").ToList();
            new List<string> { ".doc", ".docm", ".docx", ".txt" };
            List<string> excelExt = _configuration.GetSection("SyncLicense").Value.Split(" ").ToList();
            new List<string> { ".xlsx", ".xlsm", ".xlsb", ".xls" };
            List<string> imgExt = _configuration.GetSection("SyncLicense").Value.Split(" ").ToList(); 
            new List<string> { ".bmp", ".jpeg", ".gif", ".png", ".tiff", ".icon", ".ico" };
            byte[] converted = null;

            if (wordExt.Contains(ext))
            {
                //Loads file stream into Word document
                WordDocument wordDocument;
                try
                {
                    if (ext != ".txt")
                    {
                        wordDocument = new WordDocument(contents, Syncfusion.DocIO.FormatType.Automatic);
                    }
                    else
                    {
                        MemoryStream stream = new MemoryStream();
                        wordDocument = new WordDocument(contents, Syncfusion.DocIO.FormatType.Txt);
                        wordDocument.Save(stream, FormatType.Docx);
                        //wordDocument.Close();
                        //stream.Flush();
                        //stream.Position = 0;
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception(string.Format("Xảy ra lỗi, không thể chuyển tài liệu {0} thành pdf", ext));
                }

                DocIORenderer render = new DocIORenderer();
                render.Settings.ChartRenderingOptions.ImageFormat = Syncfusion.OfficeChart.ExportImageFormat.Jpeg;
                Syncfusion.Pdf.PdfDocument pdfDocument = render.ConvertToPDF(wordDocument);
                render.Dispose();
                wordDocument.Dispose();
                MemoryStream outputStream = new MemoryStream();
                pdfDocument.Save(outputStream);
                pdfDocument.Close();

                converted = outputStream.ToArray();
                outputStream.Dispose();
            }
            else if (excelExt.Contains(ext))
            {
                ExcelEngine excelEngine = new ExcelEngine();
                IApplication application = excelEngine.Excel;
                IWorkbook workbook = application.Workbooks.Open(contents);
                workbook.PrecisionAsDisplayed = true;
                //Initialize XlsIORendererSettings
                XlsIORendererSettings settings = new XlsIORendererSettings();

                //Enable AutoDetectComplexScript property
                settings.AutoDetectComplexScript = true;

                //Disable IsConvertBlankPage
                settings.IsConvertBlankPage = false;
                settings.IsConvertBlankSheet = false;
                settings.ExportBookmarks = false;
                settings.RenderBySheet = false;
                settings.LayoutOptions = LayoutOptions.Automatic;

                //Initialize XlsIO renderer.
                XlsIORenderer renderer = new XlsIORenderer();

                //Convert Excel document into PDF document
                PdfDocument pdfDocument = renderer.ConvertToPDF(workbook, settings);
                MemoryStream outputStream = new MemoryStream();
                pdfDocument.Save(outputStream);

                converted = outputStream.ToArray();
                outputStream.Dispose();
            }
            else if (imgExt.Contains(ext))
            {
                //Create a new PDF document

                PdfDocument pdfImg = new PdfDocument();

                //Add a page to the document

                PdfPage page = pdfImg.Pages.Add();

                //Create PDF graphics for the page

                PdfGraphics graphics = page.Graphics;

                //Load the image from the disk

                PdfBitmap image = new PdfBitmap(contents);
                float imgW = image.Width;
                float imgH = image.Height;

                if (image.Width > page.Size.Width)
                {
                    imgW = page.Size.Width;
                }
                if (image.Height > page.Size.Height)
                {
                    imgH = page.Size.Height;
                }
                graphics.DrawImage(image, 0, 0, imgW, imgH);

                //Save the document
                MemoryStream outputStream = new MemoryStream();

                pdfImg.Save(outputStream);
                converted = outputStream.ToArray();
                outputStream.Dispose();

                pdfImg.Close(true);

                //Close the document
            }
            if (converted != null)
            {
                DeleteFile(pdfName);
                var update = await UploadFile(converted, pdfName.Replace(ext, ""));
                return true;
            }

            throw new Exception(string.Format("Xảy ra lỗi, không thể chuyển tài liệu {0} thành pdf", ext));
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
