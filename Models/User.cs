namespace WebAuthnDemo.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string PasswordHash { get; set; }
    public bool HasRegisteredFaceId { get; set; }
    public bool HasRegisteredFingerprint { get; set; }

    // Navigation property for related WebAuthn credentials
    public List<WebAuthnCredential> WebAuthnCredentials { get; set; }
}

public class WebAuthnCredential
{
    public int Id { get; set; }

    // Foreign key to the User table
    public int UserId { get; set; }

    // Navigation property to User
    public User User { get; set; }

    public byte[] CredentialId { get; set; }
    public string PublicKey { get; set; }
    public string SignCount { get; set; }
}