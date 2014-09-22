using System.ComponentModel.DataAnnotations;

namespace Identity.Membership.Configurations
{
    public class ProtocolConfiguration
    {
        [Display(Order = 1, Name = "Enabled", Description = "EnabledDescription")]
        public bool Enabled { get; set; }
    }
}
