using System;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;

namespace Identity.Membership.Core
{
    public static class X509CertificateEndpointIdentityExtensions
    {
        /// <summary>
        /// Finds the leaf certificate on an X509EndpointIdentity
        /// </summary>
        /// <param name="epi">The epi.</param>
        /// <returns>The target site X509 certificate</returns>
        public static X509Certificate2 GetEndCertificate(this X509CertificateEndpointIdentity epi)
        {            
            string primaryHash64 = Convert.ToBase64String((byte[])epi.IdentityClaim.Resource);

            foreach (var certificate in epi.Certificates)
            {
                string certHash64 = Convert.ToBase64String(certificate.GetCertHash());
                if (string.Equals(primaryHash64, certHash64, StringComparison.OrdinalIgnoreCase))
                {
                    return certificate;
                }
            }

            throw new InvalidOperationException("No leaf certificate found");
        }
    }
}
