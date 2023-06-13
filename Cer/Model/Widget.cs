namespace Cer.Model
{
    [Serializable]
    public class Widget
    {
       public string name { get; set; }
        public int page { get; set; }
        public string field { get; set; }
        public Rect rect { get; set; }
    }

    public class Rect
    {
        public float x1 { get; set; }
        public float x2 { get; set; }
        public float y1 { get; set; }
        public float y2 { get; set; }
    }
}
