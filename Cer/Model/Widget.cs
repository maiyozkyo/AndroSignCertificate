namespace Cer.Model
{
    [Serializable]
    public class Widget
    {
       public string name { get; set; }
        public int page { get; set; }
        public string field { get; set; }
        public float x1 { get; set; }
        public float x2 { get; set; }
        public float y1 { get; set; }
        public float y2 { get; set; }
        public byte[] imgBytes { get; set; }
    }

    
}
