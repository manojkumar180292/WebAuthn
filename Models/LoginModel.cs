namespace WebAuthnDemo.Models
{
   
    public class Fingerprint
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public byte[] FingerprintData { get; set; }
    }

    public class FaceRecognition
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public byte[] FaceData { get; set; }
    }
    

}
