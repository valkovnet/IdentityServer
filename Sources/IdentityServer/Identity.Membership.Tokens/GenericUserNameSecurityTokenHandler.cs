using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Xml;

namespace Identity.Membership.Tokens
{
    public static class DateTimeFormats
    {
        public static string[] Accepted = new []
            {
                "yyyy-MM-ddTHH:mm:ss.fffffffZ", 
                "yyyy-MM-ddTHH:mm:ss.ffffffZ", 
                "yyyy-MM-ddTHH:mm:ss.fffffZ", 
                "yyyy-MM-ddTHH:mm:ss.ffffZ", 
                "yyyy-MM-ddTHH:mm:ss.fffZ", 
                "yyyy-MM-ddTHH:mm:ss.ffZ", 
                "yyyy-MM-ddTHH:mm:ss.fZ",
                "yyyy-MM-ddTHH:mm:ssZ", 
                "yyyy-MM-ddTHH:mm:ss.fffffffzzz", 
                "yyyy-MM-ddTHH:mm:ss.ffffffzzz", 
                "yyyy-MM-ddTHH:mm:ss.fffffzzz", 
                "yyyy-MM-ddTHH:mm:ss.ffffzzz", 
                "yyyy-MM-ddTHH:mm:ss.fffzzz", 
                "yyyy-MM-ddTHH:mm:ss.ffzzz", 
                "yyyy-MM-ddTHH:mm:ss.fzzz", 
                "yyyy-MM-ddTHH:mm:sszzz"
            };

        public static string Generated = "yyyy-MM-ddTHH:mm:ss.fffZ";
    }

    public static class AuthenticationInstantClaim
    {        
        public static Claim Now
        {
            get
            {
                return new Claim(ClaimTypes.AuthenticationInstant, XmlConvert.ToString(DateTime.UtcNow, DateTimeFormats.Generated), ClaimValueTypes.DateTime);
            }
        }
    }

    public class GenericUserNameSecurityTokenHandler : UserNameSecurityTokenHandler
    {
        public delegate bool ValidateUserNameCredentialDelegate(string username, string password);

        public ValidateUserNameCredentialDelegate ValidateUserNameCredential { get; set; }

        public GenericUserNameSecurityTokenHandler()
        {            
        }

        public GenericUserNameSecurityTokenHandler(ValidateUserNameCredentialDelegate validateUserNameCredential)
        {
            if (validateUserNameCredential == null)
            {
                throw new ArgumentNullException("ValidateUserNameCredential");
            }

            ValidateUserNameCredential = validateUserNameCredential;
        }

        protected virtual bool ValidateUserNameCredentialCore(string userName, string password)
        {
            if (ValidateUserNameCredential == null)
            {
                throw new InvalidOperationException("ValidateUserNameCredentialDelegate not set");
            }

            return ValidateUserNameCredential(userName, password);
        }

        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            if (token == null)
            {
                throw new ArgumentNullException("token");
            }

            if (Configuration == null)
            {
                throw new InvalidOperationException("No Configuration set");
            }

            UserNameSecurityToken unToken = token as UserNameSecurityToken;
            if (unToken == null)
            {
                throw new ArgumentException("SecurityToken is not a UserNameSecurityToken");
            }

            if (!ValidateUserNameCredentialCore(unToken.UserName, unToken.Password))
            {
                throw new SecurityTokenValidationException(unToken.UserName);
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, unToken.UserName),
                new Claim(ClaimTypes.AuthenticationMethod, AuthenticationMethods.Password),
                AuthenticationInstantClaim.Now
            };

            var identity = new ClaimsIdentity(claims);

            if (Configuration.SaveBootstrapContext)
            {
                if (RetainPassword)
                {
                    identity.BootstrapContext = new BootstrapContext(unToken, this);
                }
                else
                {
                    identity.BootstrapContext = new BootstrapContext(new UserNameSecurityToken(unToken.UserName, null), this);
                }
            }

            return new List<ClaimsIdentity> { new ClaimsIdentity(claims, "Password") }.AsReadOnly();
        }

        public override bool CanValidateToken
        {
            get
            {
                return true;
            }
        }
    }
}
