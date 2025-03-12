namespace WebAuthnDemo.Models
{
    public class LoginViewModel
    {
        public bool HasRegisteredFaceId { get; set; }
        public bool HasRegisteredFingerprint { get; set; }
        public string Username { get; set; }
    }
}
