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

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ISmsService smsService,
        ApplicationDbContext db,
        ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _smsService = smsService;
        _db = db;
        _logger = logger;
    }

    // ─── مرحله ۱: ورود شماره موبایل ─────────────────────────────────────────

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
        => View(new LoginViewModel { ReturnUrl = returnUrl });

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var user = await _userManager.Users
            .FirstOrDefaultAsync(u => u.PhoneNumber == model.PhoneNumber);

        if (user == null)
        {
            user = new ApplicationUser
            {
                UserName             = model.PhoneNumber,
                PhoneNumber          = model.PhoneNumber,
                PhoneNumberConfirmed = true,
                EmailConfirmed       = true
            };

            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);
                return View(model);
            }
        }

        await SendOtpAsync(model.PhoneNumber);

        return RedirectToAction(nameof(VerifyOtp),
            new { phone = model.PhoneNumber, returnUrl = model.ReturnUrl });
    }

    // ─── مرحله ۲: تأیید کد OTP ───────────────────────────────────────────────

    [HttpGet]
    public IActionResult VerifyOtp(string phone, string? returnUrl = null)
        => View(new VerifyOtpViewModel { PhoneNumber = phone, ReturnUrl = returnUrl });

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyOtp(VerifyOtpViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var now = TehranNow();
        var record = await _db.VerifyMobiles
            .Where(v => v.PhoneNumber == model.PhoneNumber
                     && v.Code       == model.Code
                     && !v.IsUsed
                     && v.ExpiresAt  > now)
            .OrderByDescending(v => v.CreatedAt)
            .FirstOrDefaultAsync();

        if (record == null)
        {
            ModelState.AddModelError(string.Empty, "کد اشتباه یا منقضی شده است.");
            return View(model);
        }

        record.IsUsed = true;
        await _db.SaveChangesAsync();

        var user = await _userManager.Users
            .FirstOrDefaultAsync(u => u.PhoneNumber == model.PhoneNumber);

        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "کاربر یافت نشد.");
            return View(model);
        }

        await _signInManager.SignInAsync(user, isPersistent: false);
        _logger.LogInformation("کاربر {Phone} با OTP وارد شد", model.PhoneNumber);

        if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            return Redirect(model.ReturnUrl);

        return RedirectToAction("Index", "Home");
    }

    // ─── ارسال مجدد OTP ───────────────────────────────────────────────────────

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResendOtp(string phone, string? returnUrl = null)
    {
        await SendOtpAsync(phone);
        TempData["Message"] = "کد جدید ارسال شد.";
        return RedirectToAction(nameof(VerifyOtp), new { phone, returnUrl });
    }

    [HttpGet]
    public IActionResult Register(string? returnUrl = null)
        => RedirectToAction(nameof(Login), new { returnUrl });

    // ─── خروج ────────────────────────────────────────────────────────────────

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
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

    private async Task SendOtpAsync(string phone)
    {
        var code = new Random().Next(100000, 999999).ToString();
        var now  = TehranNow();

        _db.VerifyMobiles.Add(new VerifyMobile
        {
            PhoneNumber = phone,
            Code        = code,
            CreatedAt   = now,
            ExpiresAt   = now.AddMinutes(3),
            IsUsed      = false
        });
        await _db.SaveChangesAsync();

        var message = $"کد ورود شما: {code}\nاعتبار: ۳ دقیقه";
        await _smsService.SendAsync(phone, message);
        _logger.LogInformation("OTP {Code} به {Phone} ارسال شد", code, phone);
    }
}
