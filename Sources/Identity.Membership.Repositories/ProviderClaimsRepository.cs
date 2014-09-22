using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Identity.Membership.Interfaces;
using Identity.Membership.Types;

namespace Identity.Membership.Repositories
{
    public class ProviderClaimsRepository : IClaimsRepository
    {
        public virtual IEnumerable<Claim> GetClaims(ClaimsPrincipal principal, RequestDetails requestDetails)
        {
            ////var userName = principal.Identity.Name;
            ////var claims = new List<Claim>(from c in principal.Claims select c);

            var claims = new List<Claim>();
            claims.Add(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "Tester"));
            claims.Add(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "Test User"));
            claims.Add(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", 
                "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password"));
            claims.Add(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant", "2013-12-24T12:01:09.299Z"));
            claims.Add(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "personal@tester.com"));
         
            return claims;
        }
    }
}
