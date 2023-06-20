namespace Cer.Model
{
    [Serializable]
    public class SignContract
    {
        public string PdfPath { get; set; }
        public string PfxPath { get; set; }
        public string PassWord { get; set; }
        public string ImgPath { get; set; }
        public string Xfdf {get; set; }
        public string StepNo { get; set; }
    }
}
