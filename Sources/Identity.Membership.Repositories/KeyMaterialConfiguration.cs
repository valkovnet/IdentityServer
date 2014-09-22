using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Identity.Membership.Repositories
{
    public class KeyMaterialConfiguration : IKeyMaterialConfiguration
    {
        public KeyMaterialConfiguration()
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            foreach (var certificate in store.Certificates.Cast<X509Certificate2>().Where(certificate => certificate.Subject.Contains("*.identity.com")))
            {
                SigningCertificate = certificate;                
            }

            store.Close();
        }

        [Display(Name = "SigningCertificate", Description = "SigningCertificateDescription")]
        [Required]
        public X509Certificate2 SigningCertificate { get; set; }

        [Display(Name = "DecryptionCertificate", Description = "DecryptionCertificateDescription")]
        public X509Certificate2 DecryptionCertificate { get; set; }

        //[Display(Name = "RSA Signing Key", Description = "The RSA key to sign outgoing JWT tokens")]
        //public RSA RSASigningKey { get; set; }

        [Display(Name = "SymmetricSigningKey", Description = "SymmetricSigningKeyDescription")]
        [Required]
        public string SymmetricSigningKey { get; set; }
    }
}
