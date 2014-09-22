using System.IdentityModel;
using System.IdentityModel.Tokens;
using Identity.Membership.Types;

namespace Identity.Membership.Core
{
    public class RequestDetailsScope : Scope
    {
        public RequestDetails RequestDetails { get; protected set; }

        public RequestDetailsScope(RequestDetails details, SigningCredentials signingCredentials, bool requireEncryption)
            : base(details.Realm.Uri.AbsoluteUri, signingCredentials)
        {
            RequestDetails = details;

            if (RequestDetails.UsesEncryption)
            {
                EncryptingCredentials = new X509EncryptingCredentials(details.EncryptingCertificate);
            }

            if (RequestDetails.TokenType == Constants.TokenTypes.SimpleWebToken || RequestDetails.TokenType == Constants.TokenTypes.JsonWebToken)
            {
                if (details.RelyingPartyRegistration.SymmetricSigningKey != null && details.RelyingPartyRegistration.SymmetricSigningKey.Length > 0)
                {
                    SigningCredentials = new HmacSigningCredentials(details.RelyingPartyRegistration.SymmetricSigningKey);
                }
            }

            ReplyToAddress = RequestDetails.ReplyToAddress.AbsoluteUri;
            TokenEncryptionRequired = requireEncryption;
        }
    }
}
