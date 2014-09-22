using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using Identity.Membership.Configurations;
using Identity.Membership.Interfaces;
using Identity.Membership.Repositories;
using Identity.Membership.Types;

namespace Identity.Membership.Core.WSTrust
{
    public class TokenService : SecurityTokenService
    {
        private readonly IIdentityConfiguration _identityConfiguration;

        private readonly IClaimsRepository _claimsRepository;
       
        public TokenService(SecurityTokenServiceConfiguration configuration)
            : base(configuration)
        {
            this._identityConfiguration = new IdentityIdentityConfiguration();
            this._claimsRepository = new ProviderClaimsRepository();
        }
        
        protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
        {
            var requestDetailsScope = scope as RequestDetailsScope;
            if (requestDetailsScope != null)
            {
                var requestDetails = requestDetailsScope.RequestDetails;            
                if (principal.HasClaim(c => c.Type == Constants.Claims.IdentityProvider && c.Issuer == Constants.InternalIssuer))
                {               
                    return GetExternalOutputClaims(principal, requestDetails);
                }

                var userClaims = GetOutputClaims(principal, requestDetails, this._claimsRepository);
                var outputIdentity = new ClaimsIdentity(userClaims, "IdSrv");
            
                if (requestDetails.IsActAsRequest)
                {                
                    return GetActAsClaimsIdentity(outputIdentity, requestDetails);
                }
                                     
                return outputIdentity;
            }

            return null;
        }

        protected virtual ClaimsIdentity GetExternalOutputClaims(ClaimsPrincipal principal, RequestDetails requestDetails)
        {
            var idpClaim = principal.FindFirst(c => c.Type == Constants.Claims.IdentityProvider && c.Issuer == Constants.InternalIssuer);
            if (idpClaim == null)
            {
                throw new InvalidOperationException("No identity provider claim found.");
            }

            throw new InvalidRequestException("Invalid identity provider.");
        }

        public static List<Claim> GetOutputClaims(ClaimsPrincipal principal, RequestDetails requestDetails, IClaimsRepository claimsRepository)
        {
            return claimsRepository.GetClaims(SanitizeInternalClaims(principal), requestDetails).ToList();
        }

        protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken req)
        {
            if (req.AppliesTo == null)
            {               
                throw new InvalidRequestException();
            }
           
            var authenticationMethod = principal.Identities.First().FindFirst(ClaimTypes.AuthenticationMethod);
            if (authenticationMethod != null)
            {
                
            }

            // analyze request
            var request = new Request(this._identityConfiguration);
            var details = request.Analyze(req, principal);

            ////// validate against policy
            request.Validate(details);            
            // create scope
            var scope = new RequestDetailsScope(
                details,
                SecurityTokenServiceConfiguration.SigningCredentials,
                this._identityConfiguration.Global.RequireEncryption);

            // set token type
            if (!string.IsNullOrWhiteSpace(details.TokenType))
            {
                req.TokenType = details.TokenType;
            }

            return scope;
        }

        protected override Lifetime GetTokenLifetime(Lifetime requestLifetime)
        {
            var scope = (RequestDetailsScope)Scope;
            var rp = scope.RequestDetails.RelyingPartyRegistration;

            if (!scope.RequestDetails.IsKnownRealm || rp.TokenLifeTime == 0)
            {
                return base.GetTokenLifetime(requestLifetime);
            }

            var lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(rp.TokenLifeTime));
            return lifetime;
        }

        protected virtual ClaimsIdentity GetActAsClaimsIdentity(ClaimsIdentity clientIdentity, RequestDetails requestDetails)
        {
            //var actAsSubject = requestDetails.Request.ActAs..GetSubject()[0];
            var actAsIdentity = requestDetails.Request.ActAs.GetIdentities().First();

            // find the last actor in the actAs identity
            ClaimsIdentity lastActor = actAsIdentity;
            while (lastActor.Actor != null)
            {
                lastActor = lastActor.Actor;
            }

            // set the caller's identity as the last actor in the delegation chain
            lastActor.Actor = clientIdentity;
            return actAsIdentity;
        }

        protected static ClaimsPrincipal SanitizeInternalClaims(ClaimsPrincipal incomingPrincipal)
        {
            var userClaims = from c in incomingPrincipal.Claims
                             where !c.Issuer.Equals(Constants.InternalIssuer, StringComparison.Ordinal)
                             select c;

            var id = new ClaimsIdentity(userClaims, Constants.AuthenticationType);
            return new ClaimsPrincipal(id);
        }

        protected override RequestSecurityTokenResponse GetResponse(RequestSecurityToken request, SecurityTokenDescriptor tokenDescriptor)
        {
            var response = base.GetResponse(request, tokenDescriptor);         
            return response;
        }
    }
}
