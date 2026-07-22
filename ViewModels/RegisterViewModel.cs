using System.ComponentModel.DataAnnotations;

namespace SsoServer.ViewModels;

public class RegisterViewModel
{
    [Required(ErrorMessage = "نام الزامی است")]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "نام خانوادگی الزامی است")]
    public string LastName { get; set; } = string.Empty;

    [Required(ErrorMessage = "ایمیل الزامی است")]
    [EmailAddress(ErrorMessage = "فرمت ایمیل صحیح نیست")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "شماره موبایل الزامی است")]
    [RegularExpression(@"^09\d{9}$", ErrorMessage = "فرمت شماره موبایل صحیح نیست (مثال: 09123456789)")]
    public string PhoneNumber { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}
