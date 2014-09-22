using System.Security.Cryptography.X509Certificates;

namespace Identity.Membership.Interfaces
{
    public interface IKeyMaterialConfiguration
    {
        X509Certificate2 SigningCertificate { get; set; }
    }
}
