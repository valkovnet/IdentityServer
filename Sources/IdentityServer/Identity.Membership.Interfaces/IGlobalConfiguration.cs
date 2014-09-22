namespace Identity.Membership.Interfaces
{
    public interface IGlobalConfiguration
    {
        int HttpsPort { get; set; }

        int SsoCookieLifetime { get; set; }

        string IssuerUri { get; set; }

        string DefaultWSTokenType { get; set; }

        string SiteName { get; set; }

        bool RequireEncryption { get; set; }

        bool EnableClientCertificateAuthentication { get; set; }
    }
}
