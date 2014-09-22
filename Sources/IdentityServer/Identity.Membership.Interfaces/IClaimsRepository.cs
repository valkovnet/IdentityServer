using System.Collections.Generic;
using System.Security.Claims;
using Identity.Membership.Types;

namespace Identity.Membership.Interfaces
{
    public interface IClaimsRepository
    {
        IEnumerable<Claim> GetClaims(ClaimsPrincipal principal, RequestDetails requestDetails);        
    }
}
