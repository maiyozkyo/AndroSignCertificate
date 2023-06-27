namespace Cer.Model
{
    [Serializable]
    public class TransData
    {
        //public TransData(string progress, int step, string user) 
        //{
        //    Progress = progress;
        //    Step = step;
        //    User = user;
        //}
        public string progress { get; set; }
        public string step { get; set; }
        public string user { get; set; }
        public string field { get; set; }
    }
}
