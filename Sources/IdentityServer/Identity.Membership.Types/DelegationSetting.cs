using System;
using System.ComponentModel.DataAnnotations;

namespace Identity.Membership.Types
{
    public class DelegationSetting
    {
        [Required]
        [Display(Name = "Description", Description = "DescriptionDescription")]
        public string Description { get; set; }

        [Required]
        [Display(Name = "UserName", Description = "UserNameDescription")]
        public string UserName { get; set; }

        [Required]
        [Display(Name = "Realm", Description = "RealmDescription")]
        [AbsoluteUri]
        public Uri Realm { get; set; }
    }
}
