using System;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using Identity.Membership.Interfaces;
using Identity.Membership.Repositories;
using Identity.Membership.Types;

namespace Identity.Membership.Core
{
    public class Request
    {        
        private readonly IIdentityConfiguration _identityConfiguration;

        private readonly IRelyingPartyRepository _relyingPartyRepository;

        public Request(IIdentityConfiguration identityConfiguration)
        {
            this._identityConfiguration = identityConfiguration;
            this._relyingPartyRepository = new RelyingPartyRepository();
        }

        public Request(IIdentityConfiguration identityConfiguration, IRelyingPartyRepository relyingPartyRepository)
            : this(identityConfiguration)
        {
            this._relyingPartyRepository = relyingPartyRepository ?? new RelyingPartyRepository();
        }

        public RequestDetails Analyze(RequestSecurityToken rst, ClaimsPrincipal principal)
        {
            if (rst == null)
            {
                throw new ArgumentNullException("rst");
            }

            if (principal == null)
            {
                throw new ArgumentNullException("principal");
            }
          
            var clientIdentity = AnalyzeClientIdentity(principal);
            var details = new RequestDetails
            {
                ClientIdentity = clientIdentity,
                IsActive = false,
                Realm = null,
                IsKnownRealm = false,
                UsesSsl = false,
                UsesEncryption = false,
                ReplyToAddress = null,
                ReplyToAddressIsWithinRealm = false,
                IsReplyToFromConfiguration = false,
                EncryptingCertificate = null,
                ClaimsRequested = false,
                RequestClaims = null,
                Request = null,
                IsActAsRequest = false,
                RelyingPartyRegistration = null
            };

            AnalyzeRst(rst, details);
            AnalyzeKeyType(rst);
            AnalyzeRealm(rst, details);
            AnalyzeOperationContext(details);
            AnalyzeDelegation(rst, details);
            AnalyzeRelyingParty(details);
            AnalyzeTokenType(rst, details);
            AnalyzeEncryption(details);
            AnalyzeReplyTo(details);
            AnalyzeSsl(details);
            AnalyzeRequestClaims(details);
            
            return details;
        }

        public void Validate(RequestDetails details)
        {
            if (details == null)
            {
                throw new ArgumentNullException("details");
            }
         
            ValidateKnownRealm(details);
            ValidateRelyingParty(details);
            ValidateReplyTo(details);
            ValidateEncryption(details);            
        }

        protected virtual ClaimsIdentity AnalyzeClientIdentity(ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException("principal");
            }

            if (principal.Identity == null)
            {
                throw new ArgumentNullException("identity");
            }

            return principal.Identity as ClaimsIdentity;            
        }

        protected virtual void AnalyzeRst(RequestSecurityToken rst, RequestDetails options)
        {
            if (rst == null)
            {
                throw new ArgumentNullException("request");
            }

            options.Request = rst;
        }

        protected virtual void AnalyzeKeyType(RequestSecurityToken rst)
        {
            if (!string.IsNullOrEmpty(rst.KeyType))
            {
                ////Tracing.Information(String.Format("Requested KeyType: {0}", rst.KeyType));
            }
        }

        protected virtual void AnalyzeRealm(RequestSecurityToken rst, RequestDetails options)
        {            
            if (rst.AppliesTo == null || rst.AppliesTo.Uri == null)
            {
                throw new ArgumentNullException("AppliesTo is missing");
                //throw new MissingAppliesToException("AppliesTo is missing");
            }

            options.Realm = new EndpointAddress(rst.AppliesTo.Uri);
        }

        protected virtual void AnalyzeOperationContext(RequestDetails details)
        {            
            if (OperationContext.Current != null)
            {
                details.IsActive = true;         
            }            
        }

        protected virtual void ValidateKnownRealm(RequestDetails details)
        {
            // check if realm is allowed
            ////if (_identityConfiguration.Global.RequireRelyingPartyRegistration && (!details.IsKnownRealm))
            ////{
            ////    ////Tracing.Error("Configuration requires a known realm - but realm is not registered");

            ////    throw new InvalidRequestException("Invalid realm: " + details.Realm.Uri.AbsoluteUri);
            ////}
        }

        protected virtual void AnalyzeDelegation(RequestSecurityToken rst, RequestDetails details)
        {
            // check for identity delegation request
            if (rst.ActAs != null)
            {
                details.IsActAsRequest = true;
                ////Tracing.Information("Request is ActAs request");
            }
        }

        protected virtual RelyingParty AnalyzeRelyingParty(RequestDetails details)
        {
            // check if the relying party is registered
            RelyingParty rp = null;
            if (this._relyingPartyRepository.TryGet(details.Realm.Uri.AbsoluteUri, out rp))
            {
                details.RelyingPartyRegistration = rp;
                details.IsKnownRealm = true;
                
                if (rp.EncryptingCertificate != null)
                {
                    details.EncryptingCertificate = rp.EncryptingCertificate;
                }
            }

            return rp;
        }

        protected virtual void AnalyzeTokenType(RequestSecurityToken rst, RequestDetails details)
        {
            if (!string.IsNullOrWhiteSpace(rst.TokenType))
            {
                details.TokenType = rst.TokenType;
                return;
            }

            if (details.IsKnownRealm && details.RelyingPartyRegistration.TokenType != null)
            {
                switch (details.RelyingPartyRegistration.TokenType.Value)
                {
                    case TokenType.SAML11:
                        details.TokenType = Constants.TokenTypes.Saml11TokenProfile11;
                        break;
                    case TokenType.SAML20:
                        details.TokenType = Constants.TokenTypes.Saml2TokenProfile11;
                        break;
                    case TokenType.JWT:
                        details.TokenType = Constants.TokenTypes.JsonWebToken;
                        break;
                    default:
                        throw new InvalidRequestException(String.Format("Invalid token type: {0}", details.RelyingPartyRegistration.TokenType.Value.ToString()));
                }
            }
            else
            {
                details.TokenType = _identityConfiguration.Global.DefaultWSTokenType;                
            }
        }

        protected virtual void AnalyzeEncryption(RequestDetails details)
        {
            if (details.EncryptingCertificate == null)
            {
                X509Certificate2 requestCertificate;
                if (TryGetEncryptionCertificateFromRequest(details.Realm, out requestCertificate))
                {
                    details.EncryptingCertificate = requestCertificate;                    
                }
            }

            details.UsesEncryption = (details.EncryptingCertificate != null);            
        }

        protected virtual bool TryGetEncryptionCertificateFromRequest(EndpointAddress appliesTo, out X509Certificate2 certificate)
        {
            if (appliesTo == null)
            {
                throw new ArgumentNullException("appliesTo");
            }

            certificate = null;

            var epi = appliesTo.Identity as X509CertificateEndpointIdentity;
            if (epi != null && epi.Certificates.Count > 0)
            {
                certificate = epi.GetEndCertificate();
                return true;
            }

            // no cert found
            return false;
        }

        protected virtual void AnalyzeReplyTo(RequestDetails details)
        {
            var rp = details.RelyingPartyRegistration;

            // determine the reply to address (only relevant for passive requests)
            if (rp != null && rp.ReplyTo != null)
            {
                details.ReplyToAddress = rp.ReplyTo;
                details.IsReplyToFromConfiguration = true;

                // check if reply to is a sub-address of the realm address
                if (details.ReplyToAddress.AbsoluteUri.StartsWith(details.Realm.Uri.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
                {
                    details.ReplyToAddressIsWithinRealm = true;
                }

                ////Tracing.Information(String.Format("ReplyTo Address set from identityConfiguration: {0}", details.ReplyToAddress.AbsoluteUri));
            }
            else
            {
                if (!String.IsNullOrEmpty(details.Request.ReplyTo))
                {
                    if (_identityConfiguration.WSFederation.AllowReplyTo)
                    {
                        // explicit address
                        details.ReplyToAddress = new Uri(details.Request.ReplyTo);
                        ////Tracing.Information(String.Format("Explicit ReplyTo address set: {0}", details.ReplyToAddress.AbsoluteUri));

                        // check if reply to is a sub-address of the realm address
                        if (details.ReplyToAddress.AbsoluteUri.StartsWith(details.Realm.Uri.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
                        {
                            details.ReplyToAddressIsWithinRealm = true;
                        }

                        ////Tracing.Information(String.Format("ReplyTo Address is within Realm: {0}", details.ReplyToAddressIsWithinRealm));
                    }
                    else
                    {
                        // same as realm
                        details.ReplyToAddress = details.Realm.Uri;
                        details.ReplyToAddressIsWithinRealm = true;
                        ////Tracing.Warning(string.Format("ReplyTo address of ({0}) was supplied, but since identityConfiguration does not allow ReplyTo, the realm address is used", details.Request.ReplyTo));
                    }
                }
                else
                {
                    // same as realm
                    details.ReplyToAddress = details.Realm.Uri;
                    details.ReplyToAddressIsWithinRealm = true;
                    ////Tracing.Information("ReplyTo address set to realm address");
                }
            }
        }

        protected virtual void AnalyzeSsl(RequestDetails details)
        {
            // determine if reply to is via SSL
            details.UsesSsl = (details.ReplyToAddress.Scheme == Uri.UriSchemeHttps);
            ////Tracing.Information(String.Format("SSL used:{0}", details.UsesSsl));
        }

        protected virtual void AnalyzeRequestClaims(RequestDetails details)
        {
            // check if specific claims are requested
            if (details.Request.Claims != null && details.Request.Claims.Count > 0)
            {
                details.ClaimsRequested = true;
                details.RequestClaims = details.Request.Claims;

                var requestClaims = new StringBuilder(20);
                details.RequestClaims.ToList().ForEach(rq => requestClaims.AppendFormat("{0}\n", rq.ClaimType));
                ////Tracing.Information("Specific claims requested");
                ////Tracing.Information(String.Format("Request claims: {0}", requestClaims));
            }
            else
            {
                ////Tracing.Information("No request claims");
            }
        }

        protected virtual void ValidateRelyingParty(RequestDetails details)
        {
            if (details.RelyingPartyRegistration != null)
            {
                if (details.RelyingPartyRegistration.Enabled == false)
                {
                    ////Tracing.Error("Relying party is disabled");

                    ////TODO: throw new InvalidRequestException("Invalid realm: " + details.Realm.Uri.AbsoluteUri);
                }
            }
        }

        protected virtual void ValidateReplyTo(RequestDetails details)
        {
            // check if replyto is part of a registered realm (when not explicitly registered in config)
            if (!details.IsReplyToFromConfiguration)
            {
                if (_identityConfiguration.WSFederation.RequireReplyToWithinRealm && (!details.ReplyToAddressIsWithinRealm))
                {
                    ////Tracing.Error("Configuration requires that ReplyTo is a sub-address of the realm - this is not the case");
                    throw new InvalidRequestException("Invalid ReplyTo");
                }
            }
        }

        protected virtual void ValidateEncryption(RequestDetails details)
        {
            // check if token must be encrypted
            if (_identityConfiguration.Global.RequireEncryption && (!details.UsesEncryption))
            {
                ////Tracing.Error("Configuration requires encryption - but no key available");
                throw new InvalidRequestException("No encryption key available");
            }
        }      
    }    
}
