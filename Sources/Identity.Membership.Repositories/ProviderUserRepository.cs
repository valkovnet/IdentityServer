using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Identity.Membership.Interfaces;

namespace Identity.Membership.Repositories
{
    public class ProviderUserRepository : IUserRepository
    {
        public bool ValidateUser(string userName, string password)
        {
            return true;
        }

        public bool ValidateUser(X509Certificate2 clientCertificate, out string userName)
        {
            userName = "Tester";
            return true;
        }

        public IEnumerable<string> GetRoles(string userName)
        {
            var returnedRoles = new List<string>
                {
                    "Admin"
                };

            return returnedRoles;
        }
    }
}
