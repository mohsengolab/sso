using System.ComponentModel.DataAnnotations;

namespace SsoServer.ViewModels;

public class VerifyOtpViewModel
{
    [Required]
    public string PhoneNumber { get; set; } = string.Empty;

    [Required(ErrorMessage = "کد OTP الزامی است")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "کد باید ۶ رقم باشد")]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "کد باید فقط عدد باشد")]
    public string Code { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}
