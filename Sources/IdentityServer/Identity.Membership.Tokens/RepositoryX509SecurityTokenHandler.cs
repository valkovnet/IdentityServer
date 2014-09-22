using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;

namespace Identity.Membership.Tokens
{
    public class RepositoryX509SecurityTokenHandler : X509SecurityTokenHandler
    {        
        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {            
            return new List<ClaimsIdentity>().AsReadOnly();
        }
    }    
}
