using Microsoft.AspNetCore.Mvc;
using Syncfusion.Pdf.Graphics;
using System.IO;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Cer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CerController : ControllerBase
    {
        private readonly Certificate _Cer;
        private readonly IConfiguration configuration;
        public CerController(IConfiguration _configuration)
        {
            configuration = _configuration;
            _Cer = new Certificate(configuration);
        }

        // GET api/<ValuesController>/5
        [HttpGet("CreateSelfCA")]
        public async Task<IActionResult> CreateSelfCA([FromQuery] string sParams)
        {
            var lstParams = sParams.Split("|");
            var issued = lstParams[0];
            var password = lstParams[1];
            var fileName = lstParams[2];
            byte[] cerBytes = _Cer.createSelfCer(issued, password);
            var result = await _Cer.UploadFile(cerBytes, fileName);
            return Ok(result);
        }

        [HttpGet("SignPDF")]
        public async Task<IActionResult> SignPDF(/*[FromQuery] string pdfName, [FromQuery] string userName, [FromQuery] string passWord, [FromQuery] int pageNumber*/)
        {
            var pdfPath = "nbuubuu";
            var sXfdf = "123456";
            var pfxPath = "123456";
            var passWord = "123456";
            var imgPath = "123456";
            var stepNo = 0;
            pdfPath = "C:\\Users\\admin\\Desktop\\CerFile\\sample.pdf";
            sXfdf = "C:\\Users\\admin\\Desktop\\CerFile\\sample.xfdf";
            pfxPath = "C:\\Users\\admin\\Desktop\\CerFile\\nbuubuu.pfx";
            imgPath = "C:\\Users\\admin\\Desktop\\CerFile\\nbuubuu.png";
            var result = await _Cer.signPdf(pdfPath, sXfdf, pfxPath, passWord, imgPath, stepNo);
            return Ok(result);
        }

        [HttpGet("UploadFile")]
        public async Task<IActionResult> UploadFile([FromQuery] string filePath, [FromQuery] string fileName)
        {
            var docStream = System.IO.File.ReadAllBytes(filePath);
            var result = await _Cer.UploadFile(docStream, fileName);
            return Ok(result);
        }
    }
}
