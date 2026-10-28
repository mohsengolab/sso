using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SsoServer.Data;
using SsoServer.Models;
using SsoServer.Services;
using SsoServer.ViewModels;

namespace SsoServer.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ISmsService _smsService;
    private readonly ApplicationDbContext _db;
    private readonly ILogger<AccountController> _logger;
    private readonly ITimeLimitedDataProtector _setPasswordProtector;

    private const int MaxOtpAttempts          = 5;
    private const int OtpResendSeconds        = 60;
    private const int SetPasswordTokenMinutes = 10;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ISmsService smsService,
        ApplicationDbContext db,
        ILogger<AccountController> logger,
        IDataProtectionProvider dataProtectionProvider)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _smsService = smsService;
        _db = db;
        _logger = logger;
        _setPasswordProtector = dataProtectionProvider
            .CreateProtector("SsoServer.Account.SetPassword")
            .ToTimeLimitedDataProtector();
    }

    // ─── مرحله ۱: ورود شماره موبایل (نام کاربری) ───────────────────────────

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
        => View(new LoginViewModel { ReturnUrl = returnUrl });

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var user = await FindByPhoneAsync(model.PhoneNumber);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "این شماره موبایل در سامانه ثبت نشده است.");
            return View(model);
        }

        // کاربری که رمز دارد مستقیم به صفحه رمز عبور می‌رود
        if (await _userManager.HasPasswordAsync(user))
            return RedirectToAction(nameof(EnterPassword),
                new { phone = model.PhoneNumber, returnUrl = model.ReturnUrl });

        // بار اول: پیامک کد، سپس تعریف رمز
        var error = await SendOtpAsync(model.PhoneNumber);
        if (error != null)
        {
            ModelState.AddModelError(string.Empty, error);
            return View(model);
        }

        return RedirectToAction(nameof(VerifyOtp),
            new { phone = model.PhoneNumber, returnUrl = model.ReturnUrl });
    }

    // ─── مرحله ۲ (کاربر دارای رمز): ورود رمز عبور ───────────────────────────

    [HttpGet]
    public IActionResult EnterPassword(string phone, string? returnUrl = null)
        => View(new EnterPasswordViewModel { PhoneNumber = phone, ReturnUrl = returnUrl });

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EnterPassword(EnterPasswordViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var user = await FindByPhoneAsync(model.PhoneNumber);
        if (user == null || !await _userManager.HasPasswordAsync(user))
            return RedirectToAction(nameof(Login), new { returnUrl = model.ReturnUrl });

        var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
        if (result.IsLockedOut)
        {
            ModelState.AddModelError(string.Empty,
                "به دلیل تلاش‌های ناموفق، حساب موقتاً قفل است. می‌توانید از «فراموشی رمز عبور» استفاده کنید.");
            return View(model);
        }
        if (!result.Succeeded)
        {
            ModelState.AddModelError(string.Empty, "رمز عبور اشتباه است.");
            return View(model);
        }

        _logger.LogInformation("کاربر {Phone} با رمز عبور وارد شد", model.PhoneNumber);
        return await SignInAndRedirectAsync(user, model.ReturnUrl);
    }

    // ─── فراموشی رمز عبور: ارسال دوباره پیامک ───────────────────────────────

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(string phone, string? returnUrl = null)
    {
        if (await FindByPhoneAsync(phone) == null)
            return RedirectToAction(nameof(Login), new { returnUrl });

        var error = await SendOtpAsync(phone);
        if (error != null)
            TempData["Error"] = error;

        return RedirectToAction(nameof(VerifyOtp), new { phone, returnUrl });
    }

    // ─── مرحله ۳: تأیید کد پیامک ────────────────────────────────────────────

    [HttpGet]
    public IActionResult VerifyOtp(string phone, string? returnUrl = null)
        => View(new VerifyOtpViewModel { PhoneNumber = phone, ReturnUrl = returnUrl });

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyOtp(VerifyOtpViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        if (await FindByPhoneAsync(model.PhoneNumber) == null)
            return RedirectToAction(nameof(Login), new { returnUrl = model.ReturnUrl });

        // فقط آخرین کد معتبر پذیرفته می‌شود
        var now = TehranNow();
        var record = await _db.VerifyMobiles
            .Where(v => v.PhoneNumber == model.PhoneNumber
                     && !v.IsUsed
                     && v.ExpiresAt  > now)
            .OrderByDescending(v => v.CreatedAt)
            .FirstOrDefaultAsync();

        if (record == null)
        {
            ModelState.AddModelError(string.Empty, "کد منقضی شده است. لطفاً کد جدید دریافت کنید.");
            return View(model);
        }

        if (record.Code != model.Code)
        {
            record.Attempts++;
            if (record.Attempts >= MaxOtpAttempts)
                record.IsUsed = true;
            await _db.SaveChangesAsync();

            ModelState.AddModelError(string.Empty, record.IsUsed
                ? "تعداد تلاش‌ها بیش از حد مجاز است. لطفاً کد جدید دریافت کنید."
                : "کد وارد شده اشتباه است.");
            return View(model);
        }

        record.IsUsed = true;
        await _db.SaveChangesAsync();

        return View(nameof(SetPassword), new SetPasswordViewModel
        {
            Token     = _setPasswordProtector.Protect(model.PhoneNumber, TimeSpan.FromMinutes(SetPasswordTokenMinutes)),
            ReturnUrl = model.ReturnUrl
        });
    }

    // ─── ارسال مجدد کد ───────────────────────────────────────────────────────

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResendOtp(string phone, string? returnUrl = null)
    {
        if (await FindByPhoneAsync(phone) == null)
            return RedirectToAction(nameof(Login), new { returnUrl });

        var error = await SendOtpAsync(phone);
        if (error != null)
            TempData["Error"] = error;
        else
            TempData["Message"] = "کد جدید ارسال شد.";

        return RedirectToAction(nameof(VerifyOtp), new { phone, returnUrl });
    }

    // ─── مرحله ۴: تعریف رمز عبور (بار اول یا فراموشی) ───────────────────────

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SetPassword(SetPasswordViewModel model)
    {
        string phone;
        try
        {
            phone = _setPasswordProtector.Unprotect(model.Token);
        }
        catch (CryptographicException)
        {
            TempData["Error"] = "زمان تعریف رمز به پایان رسید. لطفاً دوباره وارد شوید.";
            return RedirectToAction(nameof(Login), new { returnUrl = model.ReturnUrl });
        }

        if (!ModelState.IsValid) return View(model);

        var user = await FindByPhoneAsync(phone);
        if (user == null)
            return RedirectToAction(nameof(Login), new { returnUrl = model.ReturnUrl });

        // ResetPassword هم برای کاربر بدون رمز و هم برای فراموشی کار می‌کند
        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, resetToken, model.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);
            return View(model);
        }

        await _userManager.SetLockoutEndDateAsync(user, null);
        await _userManager.ResetAccessFailedCountAsync(user);
        _logger.LogInformation("کاربر {Phone} رمز عبور تعریف کرد", phone);

        return await SignInAndRedirectAsync(user, model.ReturnUrl);
    }

    [HttpGet]
    public IActionResult Register(string? returnUrl = null)
        => RedirectToAction(nameof(Login), new { returnUrl });

    // ─── ورود با نام کاربری/رمز عبور ──────────────────────────────────────────

    [HttpGet]
    public IActionResult PasswordLogin(string? returnUrl = null)
        => View(new PasswordLoginViewModel { ReturnUrl = returnUrl });

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> PasswordLogin(PasswordLoginViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var user = await _userManager.FindByNameAsync(model.Username);
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "نام کاربری یا رمز عبور اشتباه است.");
            return View(model);
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: false);
        if (!result.Succeeded)
        {
            ModelState.AddModelError(string.Empty, "نام کاربری یا رمز عبور اشتباه است.");
            return View(model);
        }

        await _signInManager.SignInAsync(user, isPersistent: false);
        _logger.LogInformation("کاربر {Username} با رمز عبور وارد شد", model.Username);

        if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            return Redirect(model.ReturnUrl);

        return RedirectToAction("Index", "Home");
    }

    // ─── ثبت‌نام با رمز عبور ──────────────────────────────────────────────────

    [HttpGet]
    public IActionResult PasswordRegister(string? returnUrl = null)
        => View(new PasswordRegisterViewModel { ReturnUrl = returnUrl });

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> PasswordRegister(PasswordRegisterViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var existingUser = await _userManager.FindByNameAsync(model.Username);
        if (existingUser != null)
        {
            ModelState.AddModelError(string.Empty, "این نام کاربری قبلاً استفاده شده است.");
            return View(model);
        }

        var user = new ApplicationUser
        {
            UserName             = model.Username,
            PhoneNumber          = model.PhoneNumber,
            PhoneNumberConfirmed = true,
            EmailConfirmed       = true,
            FirstName            = model.FirstName,
            LastName             = model.LastName,
            DisplayName          = $"{model.FirstName} {model.LastName}"
        };

        var result = await _userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);
            return View(model);
        }

        await _signInManager.SignInAsync(user, isPersistent: false);
        _logger.LogInformation("کاربر {Username} با رمز عبور ثبت‌نام کرد", model.Username);

        if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            return Redirect(model.ReturnUrl);

        return RedirectToAction("Index", "Home");
    }

    // ─── خروج ────────────────────────────────────────────────────────────────

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Login");
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private static DateTime TehranNow()
    {
        var zone = TimeZoneInfo.GetSystemTimeZones()
            .FirstOrDefault(z => z.Id == "Iran Standard Time" || z.Id == "Asia/Tehran")
            ?? TimeZoneInfo.Utc;
        return TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, zone);
    }

    private async Task<ApplicationUser?> FindByPhoneAsync(string phone)
        => await _userManager.Users.FirstOrDefaultAsync(u => u.PhoneNumber == phone);

    private async Task<IActionResult> SignInAndRedirectAsync(ApplicationUser user, string? returnUrl)
    {
        await _signInManager.SignInAsync(user, isPersistent: false);

        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            return Redirect(returnUrl);

        return RedirectToAction("Index", "Home");
    }

    // خطا را برمی‌گرداند؛ null یعنی پیامک ارسال شد
    private async Task<string?> SendOtpAsync(string phone)
    {
        var now = TehranNow();

        var last = await _db.VerifyMobiles
            .Where(v => v.PhoneNumber == phone)
            .OrderByDescending(v => v.CreatedAt)
            .FirstOrDefaultAsync();
        if (last != null && last.CreatedAt > now.AddSeconds(-OtpResendSeconds))
        {
            var wait = (int)Math.Ceiling((last.CreatedAt.AddSeconds(OtpResendSeconds) - now).TotalSeconds);
            return $"لطفاً {wait} ثانیه دیگر برای دریافت کد جدید تلاش کنید.";
        }

        var code = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();

        _db.VerifyMobiles.Add(new VerifyMobile
        {
            PhoneNumber = phone,
            Code        = code,
            CreatedAt   = now,
            ExpiresAt   = now.AddMinutes(3),
            IsUsed      = false
        });
        await _db.SaveChangesAsync();

        var message = $"کد تأیید شما: {code}\nاعتبار: ۳ دقیقه";
        try
        {
            await _smsService.SendAsync(phone, message);
        }
        catch (Exception)
        {
            return "ارسال پیامک ناموفق بود. لطفاً دوباره تلاش کنید.";
        }

        _logger.LogInformation("کد تأیید به {Phone} ارسال شد", phone);
        return null;
    }
}
