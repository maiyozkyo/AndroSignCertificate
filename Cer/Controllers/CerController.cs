using Microsoft.AspNetCore.Mvc;
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
            var userName = "nbuubuu";
            var passWord = "123456";
            var pdfName = "123456";
            var pageNumber = 0;
            var result = await _Cer.signPdf(pdfName, userName, passWord, pageNumber);
            return Ok(result);
        }

        [HttpGet("UploadFile")]
        public async Task<IActionResult> UploadFile([FromQuery] string filePath, [FromQuery] string fileName)
        {
            var docStream = System.IO.File.ReadAllBytes(filePath);

            var result = await _Cer.UploadFile(docStream, fileName);
            return Ok(result);
        }

        [HttpPost("MergePdf")]
        public async Task<IActionResult> MergePdf(/*[FromQuery] string pdfPath, [FromQuery] string xfdfPath*/)
        { 
            var pdfPath = "C:\\Users\\ekkob\\OneDrive\\Máy tính\\AndroSign\\sample.pdf";
            var xfdfPath = "C:\\Users\\ekkob\\OneDrive\\Máy tính\\AndroSign\\sample.xfdf";

            var result = await _Cer.mergeXFDF(pdfPath, xfdfPath);
            return Ok(result);
        }
    }
}
