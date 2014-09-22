namespace Identity.Membership.Interfaces
{
    public interface IWSTrustConfiguration
    {
        bool Enabled { get; set; }

        bool EnableMixedModeSecurity { get; set; }

        bool EnableClientCertificateAuthentication { get; set; }

        bool EnableMessageSecurity { get; set; }

        bool EnableDelegation { get; set; }
    }
}
