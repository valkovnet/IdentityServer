using System;
using System.IdentityModel.Configuration;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using Identity.Membership.Configurations;
using Identity.Membership.Interfaces;

namespace Identity.Membership.Core.WSTrust
{
    public class TokenServiceConfiguration : SecurityTokenServiceConfiguration
    {      
        private static readonly Lazy<TokenServiceConfiguration> Configuration = new Lazy<TokenServiceConfiguration>();

        private readonly IIdentityConfiguration _config;

        public TokenServiceConfiguration()
            : base()
        {            
            this._config = new IdentityIdentityConfiguration();

            SecurityTokenService = typeof(TokenService);
            DefaultTokenLifetime = TimeSpan.FromHours(1);
            MaximumTokenLifetime = TimeSpan.FromDays(1);
            DefaultTokenType = "urn:oasis:names:tc:SAML:2.0:assertion";

            TokenIssuerName = this._config.Global.IssuerUri;
            SigningCredentials = new X509SigningCredentials(this._config.Keys.SigningCertificate);

            if (this._config.WSTrust.EnableDelegation)
            {                
                var actAsRegistry = new ConfigurationBasedIssuerNameRegistry();
                actAsRegistry.AddTrustedIssuer(this._config.Keys.SigningCertificate.Thumbprint,
                                               this._config.Global.IssuerUri);

                var actAsHandlers = SecurityTokenHandlerCollectionManager["ActAs"];
                actAsHandlers.Configuration.IssuerNameRegistry = actAsRegistry;
                actAsHandlers.Configuration.AudienceRestriction.AudienceMode = AudienceUriMode.Never;
            }
        }

        public static TokenServiceConfiguration Instance
        {
            get
            {
                return Configuration.Value;
            }
        }
    }
}
