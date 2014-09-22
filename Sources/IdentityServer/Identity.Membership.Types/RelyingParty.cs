using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;

namespace Identity.Membership.Types
{
    public enum TokenType
    {
        SAML11,
        SAML20,
        JWT
    }

    public class AbsoluteUriAttribute : ValidationAttribute
    {
        public AbsoluteUriAttribute()
        {
            this.ErrorMessageResourceName = "UriMustBeAbsolute";            
        }

        public override bool IsValid(object value)
        {
            if (value == null) return true;

            Uri uri = value as Uri;
            if (uri == null)
            {
                var s = value as string;
                if (s != null)
                {
                    if (!Uri.TryCreate(s, UriKind.Absolute, out uri))
                    {
                        return false;
                    }
                }
                else
                {
                    throw new Exception("AbsoluteUriAttribute applied to a value that is not a Uri or a string.");
                }
            }
            return uri.IsAbsoluteUri;
        }
    }

    public class RelyingParty
    {
        public RelyingParty()
        {
            TokenType = Types.TokenType.SAML20;
        }

        [Required]
        [UIHint("HiddenInput")]
        public string Id { get; set; }

        [Display(Name = "Enabled", Description = "EnabledDescription")]
        public bool Enabled { get; set; }

        [Required]
        [Display(Name = "Name", Description = "NameDescription")]
        public string Name { get; set; }

        [Required]
        [Display(Name = "Realm", Description = "RealmDescription")]
        [AbsoluteUri]
        public Uri Realm { get; set; }

        [UIHint("Enum")]
        [Display(Name = "TokenType", Description = "TokenTypeDescription")]
        public TokenType? TokenType { get; set; }

        [Required]
        [Display(Name = "TokenLifeTime", Description = "TokenLifeTimeDescription")]
        public int TokenLifeTime { get; set; }

        [Display(Name = "ReplyTo", Description = "ReplyToDescription")]
        [AbsoluteUri]
        public Uri ReplyTo { get; set; }

        [Display(Order = 10002, Name = "EncryptingCertificate", Description = "EncryptingCertificateDescription")]
        public X509Certificate2 EncryptingCertificate { get; set; }

        [Display(Order = 10003, Name = "EncryptingCertificateThumbprint", Description = "EncryptingCertificateThumbprintDescription")]
        public string EncryptingCertificateThumbprint
        {
            get
            {
                if (EncryptingCertificate == null) return null;
                return EncryptingCertificate.Thumbprint;
            }
        }

        [Display(Order = 10001, Name = "SymmetricSigningKey", Description = "SymmetricSigningKeyDescription")]
        public byte[] SymmetricSigningKey { get; set; }

        [Display(Name = "ExtraData1", Description = "ExtraData1Description")]
        public string ExtraData1 { get; set; }

        [Display(Name = "ExtraData2", Description = "ExtraData2Description")]
        public string ExtraData2 { get; set; }

        [Display(Name = "ExtraData3", Description = "ExtraData3Description")]
        public string ExtraData3 { get; set; }
    }
}
