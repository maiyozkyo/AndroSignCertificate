using Cer.Business;
using Cer.Model;
using Microsoft.AspNetCore.Mvc;
using System.Net;

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

        [HttpPost("")]
        public async Task<IActionResult> Index([FromQuery] string pt)
        {
            var se = new Security(configuration);
            var en = se.Encrypt(pt);
            var de = se.Decrypt(en);
            return Ok(string.Format("Cer Ok {0} {1}", en, de));
        }

        // GET api/<ValuesController>/5
        [HttpPost("CreateSelfCA")]
        public async Task<IActionResult> CreateSelfCA([FromQuery] string issued, [FromQuery] string password, [FromQuery] string fileName, [FromQuery] int expireAfter = 30, [FromQuery] bool isUpdate = false, [FromQuery] string newPass = "")
        {
            try
            {
                string msg = await _Cer.createSelfCer(issued, password, fileName, expireAfter, isUpdate, newPass);
                var response = new
                {
                    Data = msg,
                    Status = true,
                };
                return Ok(response);
            }
            catch (Exception ex)
            {
                var response = new
                {
                    Data = "",
                    Status = false,
                    Error = ex.Message,
                };
                return Ok(response);
            }
        }

        [HttpPost("SignPDF")]
        public async Task<IActionResult> SignPDF([FromBody] SignContract contract)
        {
            try
            {
               var result = await _Cer.signPdf(contract.PdfPath, contract.Xfdf, contract.PfxPath, contract.PassWord, contract.StepNo);
                var response = new {
                    Data = result,
                    Status = true,
                };
                return Ok(response);
            }
            catch (Exception ex)
            {
                var fail = new
                {
                    Data = "",
                    Status = false,
                    Error = ex.Message,
                };
                return Ok(fail);
            }
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
