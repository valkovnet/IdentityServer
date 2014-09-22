using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Identity.Membership.Interfaces
{
    public interface IUserRepository
    {
        bool ValidateUser(string userName, string password);
        
        bool ValidateUser(X509Certificate2 clientCertificate, out string userName);
        
        IEnumerable<string> GetRoles(string userName);
    }
}
