using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;
using System.Web.Mvc;

namespace Identity.Membership.Types
{
    public class WSFederationResult : ContentResult
    {
        public WSFederationResult(SignInResponseMessage message, bool requireSsl)
        {
            if (requireSsl)
            {
                if (message.BaseUri.Scheme != Uri.UriSchemeHttps)
                {
                    throw new InvalidRequestException("ReturnUrlMustBeSslException");
                }
            }

            Content = message.WriteFormPost();
        }
    }
}
