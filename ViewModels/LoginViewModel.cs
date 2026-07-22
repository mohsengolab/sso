using System.ComponentModel.DataAnnotations;

namespace SsoServer.ViewModels;

public class LoginViewModel
{
    [Required(ErrorMessage = "شماره موبایل الزامی است")]
    [RegularExpression(@"^09\d{9}$", ErrorMessage = "فرمت شماره موبایل صحیح نیست (مثال: 09123456789)")]
    public string PhoneNumber { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}
