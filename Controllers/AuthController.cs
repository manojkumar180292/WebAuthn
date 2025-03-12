using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;
using WebAuthnDemo.Data;
using WebAuthnDemo.Models;

namespace WebAuthnDemo.Controllers
{
    public class AuthController : Controller
    {
        private readonly ApplicationDbContext _context;

        public AuthController(ApplicationDbContext context)
        {
            _context = context;
        }

        public IActionResult Register()
        {
            var users = _context.Users.ToList();
            return View(users);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Register(WebAuthnDemo.Models.User model)
        {
            if (ModelState.IsValid)
            {
                var passwordHash = HashPassword(model.PasswordHash, model.Username);
                model.PasswordHash = passwordHash;

                _context.Users.Add(model);
                _context.SaveChanges();

                return RedirectToAction("Login");
            }
            return View(model);
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login(string username, string password)
        {
            var user = _context.Users.SingleOrDefault(u => u.Username == username);

            if (user != null && VerifyPassword(password, user.PasswordHash, username))
            {
                return RedirectToAction("UserProfile");
            }

            ModelState.AddModelError("", "Invalid username or password");

            var model = new LoginViewModel
            {
                Username = user.Username,
                HasRegisteredFaceId = user.HasRegisteredFaceId,
                HasRegisteredFingerprint = user.HasRegisteredFingerprint
            };

            TempData["loggedUserName"] = username;

            return View(model);
        }

        [HttpPost]
        public IActionResult DeleteUser(int userId)
        {
            var user = _context.Users.FirstOrDefault(u => u.Id == userId);
            if (user != null)
            {
                _context.Users.Remove(user);
                _context.SaveChanges();
            }
            return RedirectToAction("Register");
        }

        public IActionResult UserProfile()
        {
            var loggedUserName = TempData["loggedUserName"];
            var user = _context.Users.FirstOrDefault(u => u.Username == loggedUserName);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            return View(user);
        }

        private string HashPassword(string password, string username)
        {
            var hashedPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: GenerateSalt(username),
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            return hashedPassword;
        }

        private bool VerifyPassword(string enteredPassword, string storedHash, string username)
        {
            return storedHash == HashPassword(enteredPassword, username);
        }

        public static byte[] GenerateSalt(string username)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] usernameBytes = Encoding.UTF8.GetBytes(username);
                return sha256.ComputeHash(usernameBytes); // This will be the salt
            }
        }

        // WebAuthn Registration Start (Generate Credentials)
        [HttpGet]
        public IActionResult StartWebAuthnRegistration()
        {
            var fido2 = new Fido2(new Fido2Configuration
            {
                ServerDomain = "https://localhost", // Update to match your domain
                ServerName = "WebAuthnDemo"
            });

            // Retrieve the logged-in user (from TempData or some other user tracking mechanism)
            var loggedUserName = "ajith";
            if (string.IsNullOrEmpty(loggedUserName))
            {
                return RedirectToAction("Login");
            }

            // Find the user in the database by their username
            var user = _context.Users.FirstOrDefault(u => u.Username == loggedUserName);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            // Create a Fido2User object using the logged-in user's details
            var fido2User = new Fido2User
            {
                DisplayName = user.Username,
                Id = Encoding.UTF8.GetBytes(user.Id.ToString()), // Convert the user ID to a byte array
                Name = user.Username
            };

            // Create authenticator selection object
            var authenticatorSelection = new AuthenticatorSelection
            {
                AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform, // or Platform if desired
                RequireResidentKey = false,
                UserVerification = UserVerificationRequirement.Preferred
            };

            // Request new credentials (registration options)
            var options = fido2.RequestNewCredential(
                fido2User,
                new List<PublicKeyCredentialDescriptor>(),
                authenticatorSelection,
                AttestationConveyancePreference.None
            );

            // Serialize the options into a byte array for session storage
            var serializedOptions = JsonConvert.SerializeObject(options);
            var byteArrayOptions = Encoding.UTF8.GetBytes(serializedOptions);

            // Store the options for later verification (for response verification)
            HttpContext.Session.Set("fido2_options", byteArrayOptions);

            // Return the options as JSON to send to the frontend for WebAuthn registration
            return Json(options);
        }

        [HttpPost]
        public async Task<IActionResult> CompleteWebAuthnRegistration([FromBody] AuthenticatorAttestationRawResponse attestationResponse)
        {
            var byteArrayOptions = HttpContext.Session.Get("fido2_options");
            if (byteArrayOptions == null)
            {
                return BadRequest("No registration options found.");
            }

            // Deserialize the stored options
            var serializedOptions = Encoding.UTF8.GetString(byteArrayOptions);
            var options = JsonConvert.DeserializeObject<CredentialCreateOptions>(serializedOptions);

            var fido2 = new Fido2(new Fido2Configuration
            {
                ServerDomain = "https://localhost", // Update to match your domain
                ServerName = "WebAuthnDemo"
            });

            // Define a delegate for checking if the credential is unique to the user
            IsCredentialIdUniqueToUserAsyncDelegate isCredentialIdUniqueToUser = async (credentialIdParams, cancellationToken) =>
            {
                var existingCredential = await _context.WebAuthnCredentials
                    .Where(c => c.CredentialId == credentialIdParams.CredentialId)
                    .FirstOrDefaultAsync(cancellationToken);

                return existingCredential == null; // Ensure credential is unique
            };

            // Verify the attestation response and create a new credential (async)
            var credentialResult = await fido2.MakeNewCredentialAsync(
                attestationResponse,
                options,
                isCredentialIdUniqueToUser
            );

            // Check if registration was successful
            if (credentialResult.Status != "ok")
            {
                return BadRequest($"Registration failed: {credentialResult.ErrorMessage}");
            }

            // Extract the created credential from the result
            var credential = credentialResult.Result;

            // Find the user who is registering (you may need to adjust this logic to track the logged-in user)
            var loggedUserName = TempData["loggedUserName"]?.ToString();
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == loggedUserName);
            if (user == null)
            {
                return RedirectToAction("Login");
            }

            // Save the new credential (public key) in the WebAuthnCredential table
            var userCredential = new WebAuthnCredential
            {
                UserId = user.Id, // You can use user.Username instead of UserId if desired
                CredentialId = credential.CredentialId,
                PublicKey = Convert.ToBase64String(credential.PublicKey),
                SignCount = credential.Counter.ToString()
            };
            _context.WebAuthnCredentials.Add(userCredential);
            await _context.SaveChangesAsync();

            // Return success response
            return Json("Registration Successful");
        }

        [HttpPost]
        public async Task<IActionResult> WebAuthnLogin([FromBody] AuthenticatorAssertionRawResponse assertionResponse)
        {
            var loggedUserName = TempData["loggedUserName"]?.ToString();
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == loggedUserName);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            // Retrieve stored credentials for this user
            var storedCredential = await _context.WebAuthnCredentials
                .Where(c => c.UserId == user.Id)
                .FirstOrDefaultAsync();

            if (storedCredential == null)
            {
                return NotFound("No credentials found for the user.");
            }

            var fido2 = new Fido2(new Fido2Configuration
            {
                ServerDomain = "https://localhost", // Update to match your domain
                ServerName = "WebAuthnDemo"
            });

            // Get the assertion options (challenge) for the user
            var options = fido2.GetAssertionOptions(new List<PublicKeyCredentialDescriptor>
    {
        new PublicKeyCredentialDescriptor { Id = storedCredential.CredentialId }
    }, UserVerificationRequirement.Preferred);

            // Store the options in session for later comparison
            var serializedOptions = JsonConvert.SerializeObject(options);
            var byteArrayOptions = Encoding.UTF8.GetBytes(serializedOptions);
            HttpContext.Session.Set("fido2_assertion_options", byteArrayOptions);

            // Verify the assertion response (FaceID/Fingerprint) asynchronously
            var result = await fido2.MakeAssertionAsync(
                assertionResponse,
                options,
                Convert.FromBase64String(storedCredential.PublicKey),
                uint.Parse(storedCredential.SignCount),
                async (credentialIdParams, cancellationToken) =>
                {
                    // Implement user handle ownership check if necessary
                    return credentialIdParams.UserHandle == storedCredential.CredentialId;
                }
            );

            if (result.Status == "ok")
            {
                // Successful authentication, log the user in
                TempData["loggedUserName"] = user.Username;
                return RedirectToAction("UserProfile");
            }

            return Unauthorized("Authentication failed.");
        }
    }
}