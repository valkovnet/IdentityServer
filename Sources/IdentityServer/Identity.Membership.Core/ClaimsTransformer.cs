using System.Linq;
using System.Security.Claims;
using Identity.Membership.Interfaces;

namespace Identity.Membership.Core
{
    public class ClaimsTransformer : ClaimsAuthenticationManager
    {
        private readonly IUserRepository _userRepository;

        public ClaimsTransformer()
        {            
        }

        public ClaimsTransformer(IUserRepository userRepository)
        {
            this._userRepository = userRepository;
        }

        public override ClaimsPrincipal Authenticate(string resourceName, ClaimsPrincipal incomingPrincipal)
        {
            if (!incomingPrincipal.Identity.IsAuthenticated)
            {
                return base.Authenticate(resourceName, incomingPrincipal);
            }

            incomingPrincipal.Identities.First().AddClaim(new Claim(ClaimTypes.Role, "IdentityServerUsers", ClaimValueTypes.String, Constants.InternalIssuer));
            //this._userRepository.GetRoles(incomingPrincipal.Identity.Name).ToList().ForEach(role =>
            //    incomingPrincipal.Identities.First().AddClaim(new Claim(ClaimTypes.Role, role, ClaimValueTypes.String, Constants.InternalIssuer)));

            return incomingPrincipal;
        }
    }
}
