using System;
using System.ComponentModel.DataAnnotations;
using Identity.Membership.Interfaces;

namespace Identity.Membership.Configurations
{
    public class GlobalConfiguration : IGlobalConfiguration
    {
        private bool _enableClientCertificateAuthentication = false;

        private int _httpsPort = 443;

        private int _ssoCookieLifetime = 10;

        private int _maximumTokenLifetime = 10;

        private string _siteName = "Identity Sample";

        private string _defaultWSTokenType = "urn:oasis:names:tc:SAML:2.0:assertion";

        private string _issuerUri = "https://client.identity.com/";

        [Display(Name = "IssuerUri", Description = "IssuerUriDescription")]
        [Required]
        public String IssuerUri { get { return this._issuerUri; } set { this._issuerUri = value; } }

        [Display(Name = "DefaultWSTokenType", Description = "DefaultWSTokenTypeDescription")]
        [Required]
        public string DefaultWSTokenType { get { return this._defaultWSTokenType; } set { this._defaultWSTokenType = value; } }

        [Display(Name = "SiteName", Description = "SiteNameDescription")]
        [Required]
        public String SiteName
        {
            get { return this._siteName; }
            set { this._siteName = value; }
        }

        [Display(Name = "RequireEncryption", Description = "RequireEncryptionDescription")]
        public Boolean RequireEncryption { get; set; }

        [Display(Description = "MaximumTokenLifetimeDescription")]
        [Range(0, Int32.MaxValue)]
        public int MaximumTokenLifetime { get { return this._maximumTokenLifetime; } set { this._maximumTokenLifetime = value; } }

        [Display(Name = "EnableClientCertificateAuthentication", Description = "EnableClientCertificateAuthenticationDescription")]
        public bool EnableClientCertificateAuthentication
        {
            get { return this._enableClientCertificateAuthentication; }
            set { this._enableClientCertificateAuthentication = value; }
        }

        [Display(Name = "SsoCookieLifetime", Description = "SsoCookieLifetimeDescription")]
        [Range(0, Int32.MaxValue)]
        public int SsoCookieLifetime
        {
            get { return this._ssoCookieLifetime; }
            set { this._ssoCookieLifetime = value; }
        }

        [Display(Name = "HttpsPort", Description = "HttpsPortDescription")]
        [Range(0, Int32.MaxValue)]
        public int HttpsPort
        {
            get { return this._httpsPort; } 
            set { this._httpsPort = value; }
        }
    }
}
