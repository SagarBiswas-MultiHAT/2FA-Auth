(() => {
  const titleEl = document.getElementById("title");
  const subtitleEl = document.getElementById("subtitle");
  const statusEl = document.getElementById("status");

  const authCard = document.getElementById("authCard");

  const authTabs = document.getElementById("authTabs");
  const tabSignIn = document.getElementById("tabSignIn");
  const tabSignUp = document.getElementById("tabSignUp");

  const signInForm = document.getElementById("signInForm");
  const signUpForm = document.getElementById("signUpForm");
  const forgotForm = document.getElementById("forgotForm");
  const dashboard = document.getElementById("dashboard");

  const signInEmail = document.getElementById("signInEmail");
  const signInPassword = document.getElementById("signInPassword");
  const signInSendRow = document.getElementById("signInSendRow");
  const signIn2faHint = document.getElementById("signIn2faHint");
  const signInSendBtn = document.getElementById("signInSendBtn");
  const signInOtpFieldset = document.getElementById("signInOtpFieldset");
  const signInTotpFieldset = document.getElementById("signInTotpFieldset");
  const signInBackupRow = document.getElementById("signInBackupRow");
  const signInBackupCode = document.getElementById("signInBackupCode");
  const signInBackupChoiceRow = document.getElementById(
    "signInBackupChoiceRow"
  );
  const signInPrimaryChoiceRow = document.getElementById(
    "signInPrimaryChoiceRow"
  );
  const signInUseBackupBtn = document.getElementById("signInUseBackupBtn");
  const signInUsePrimaryBtn = document.getElementById("signInUsePrimaryBtn");
  const signInResendRow = document.getElementById("signInResendRow");
  const signInResendBtn = document.getElementById("signInResendBtn");
  const signInResetBtn = document.getElementById("signInResetBtn");
  const signInBtn = document.getElementById("signInBtn");

  const forgotOpenBtn = document.getElementById("forgotOpenBtn");
  const forgotBackBtn = document.getElementById("forgotBackBtn");
  const forgotEmail = document.getElementById("forgotEmail");
  const forgotSendBtn = document.getElementById("forgotSendBtn");
  const forgotOtpFieldset = document.getElementById("forgotOtpFieldset");
  const forgotResendRow = document.getElementById("forgotResendRow");
  const forgotResendBtn = document.getElementById("forgotResendBtn");
  const forgotNewPassword = document.getElementById("forgotNewPassword");
  const forgotNewPassword2 = document.getElementById("forgotNewPassword2");
  const forgotResetBtn = document.getElementById("forgotResetBtn");

  const signUpName = document.getElementById("signUpName");
  const signUpUnique = document.getElementById("signUpUnique");
  const signUpPhone = document.getElementById("signUpPhone");
  const signUpEmail = document.getElementById("signUpEmail");
  const signUpSendBtn = document.getElementById("signUpSendBtn");
  const signUpOtpFieldset = document.getElementById("signUpOtpFieldset");
  const signUpResendRow = document.getElementById("signUpResendRow");
  const signUpResendBtn = document.getElementById("signUpResendBtn");
  const signUpPass = document.getElementById("signUpPass");
  const signUpPass2 = document.getElementById("signUpPass2");
  const signUpResetBtn = document.getElementById("signUpResetBtn");
  const signUpBtn = document.getElementById("signUpBtn");
  const uniqueHint = document.getElementById("uniqueHint");

  const welcomeEl = document.getElementById("welcome");
  const dashboardSecurity = document.getElementById("dashboardSecurity");
  const openAccountSettingsRow = document.getElementById(
    "openAccountSettingsRow"
  );
  const openAccountSettingsBtn = document.getElementById(
    "openAccountSettingsBtn"
  );
  const dashboardAccount = document.getElementById("dashboardAccount");
  const accountSettingsBackBtn = document.getElementById(
    "accountSettingsBackBtn"
  );
  const twoFaToggle = document.getElementById("twoFaToggle");
  const totpToggle = document.getElementById("totpToggle");
  const backupCodesToggle = document.getElementById("backupCodesToggle");
  const totpModal = document.getElementById("totpModal");
  const totpModalBackdrop = document.getElementById("totpModalBackdrop");
  const totpModalDesc = document.getElementById("totpModalDesc");
  const totpQrWrap = document.getElementById("totpQrWrap");
  const totpQrImg = document.getElementById("totpQrImg");
  const totpModalSecretEl = document.getElementById("totpModalSecret");
  const totpModalSecretHint = document.getElementById("totpModalSecretHint");
  const totpModalOtpFieldset = document.getElementById("totpModalOtpFieldset");
  const totpModalCancelBtn = document.getElementById("totpModalCancelBtn");
  const totpModalResetBtn = document.getElementById("totpModalResetBtn");
  const totpModalEnableBtn = document.getElementById("totpModalEnableBtn");
  const signOutBtn = document.getElementById("signOutBtn");

  const acctUsername = document.getElementById("acctUsername");
  const acctUnique = document.getElementById("acctUnique");
  const acctPhone = document.getElementById("acctPhone");
  const acctEmail = document.getElementById("acctEmail");
  const acctSaveBtn = document.getElementById("acctSaveBtn");
  const acctCurrentPassword = document.getElementById("acctCurrentPassword");
  const acctNewPassword = document.getElementById("acctNewPassword");
  const acctNewPassword2 = document.getElementById("acctNewPassword2");
  const acctPasswordBtn = document.getElementById("acctPasswordBtn");

  const backupCodesPanel = document.getElementById("backupCodesPanel");
  const backupCodesRemainingEl = document.getElementById(
    "backupCodesRemaining"
  );
  const backupCodesCreatedEl = document.getElementById("backupCodesCreated");
  const backupCodesDownloadBtn = document.getElementById(
    "backupCodesDownloadBtn"
  );

  let dashboardMode = "security";
  const setDashboardMode = (mode) => {
    const next = mode === "account" ? "account" : "security";
    const prev = dashboardMode;
    dashboardMode = next;

    if (prev !== next && next === "account") {
      resetAccountUniqueSuggestState();
    }

    if (authCard) {
      authCard.classList.toggle("card--accountWide", next === "account");
    }

    if (next === "account") {
      titleEl.textContent = "Account settings";
      subtitleEl.textContent = "Update your profile details and password.";
      if (authTabs) authTabs.classList.add("isHidden");
      if (dashboardSecurity) dashboardSecurity.classList.add("isHidden");
      if (dashboardAccount) dashboardAccount.classList.remove("isHidden");
    } else {
      titleEl.textContent = "Dashboard";
      subtitleEl.textContent = "Manage your security settings.";
      if (authTabs) authTabs.classList.remove("isHidden");
      if (dashboardAccount) dashboardAccount.classList.add("isHidden");
      if (dashboardSecurity) dashboardSecurity.classList.remove("isHidden");
    }
  };

  if (!titleEl || !subtitleEl || !statusEl) return;
  if (!signInForm || !signUpForm || !dashboard) return;
  if (!authTabs || !tabSignIn || !tabSignUp) return;

  const isValidEmail = (email) =>
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || "").trim());

  const isValidPhone = (phone) =>
    /^\+?[0-9]{8,15}$/.test(String(phone || "").replace(/\s+/g, ""));

  const showStatus = (type, message) => {
    const text = String(message || "").trim();
    if (!text) {
      statusEl.classList.add("isHidden");
      statusEl.classList.remove("status--success", "status--error");
      statusEl.textContent = "";
      return;
    }
    statusEl.classList.remove("isHidden");
    statusEl.classList.remove("status--success", "status--error");
    if (type === "success") statusEl.classList.add("status--success");
    if (type === "error") statusEl.classList.add("status--error");
    statusEl.textContent = text;
  };

  const postJson = async (url, body) => {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(body || {}),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || data.ok === false) {
      const msg =
        (data && (data.error || data.warning)) ||
        `Request failed (${res.status})`;
      const err = new Error(msg);
      if (data && typeof data.retryAfter === "number")
        err.retryAfter = data.retryAfter;
      throw err;
    }
    return data;
  };

  const getJson = async (url) => {
    const res = await fetch(url, { credentials: "include" });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || data.ok === false) {
      const msg =
        (data && (data.error || data.warning)) ||
        `Request failed (${res.status})`;
      throw new Error(msg);
    }
    return data;
  };

  const wireOtp = (fieldset) => {
    const inputs = Array.from(fieldset.querySelectorAll(".otp__input"));
    const sanitizeDigit = (value) => {
      const match = String(value || "").match(/\d/);
      return match ? match[0] : "";
    };
    const focusIndex = (idx) => {
      const next = inputs[idx];
      if (next) next.focus();
    };
    const fillFromString = (digits) => {
      const onlyDigits = String(digits || "")
        .replace(/\D/g, "")
        .slice(0, inputs.length);
      for (let i = 0; i < inputs.length; i++) {
        inputs[i].value = onlyDigits[i] ?? "";
      }
      const firstEmpty = inputs.findIndex((i) => !i.value);
      focusIndex(firstEmpty === -1 ? inputs.length - 1 : firstEmpty);
    };

    inputs.forEach((input, idx) => {
      input.addEventListener("focus", () => input.select());
      input.addEventListener("input", (e) => {
        const value = sanitizeDigit(e.target.value);
        e.target.value = value;
        if (value && idx < inputs.length - 1) focusIndex(idx + 1);
      });
      input.addEventListener("keydown", (e) => {
        if (e.key === "Backspace") {
          if (input.value) {
            input.value = "";
            e.preventDefault();
            return;
          }
          if (idx > 0) {
            inputs[idx - 1].value = "";
            focusIndex(idx - 1);
            e.preventDefault();
          }
        }
        if (e.key === "ArrowLeft" && idx > 0) {
          focusIndex(idx - 1);
          e.preventDefault();
        }
        if (e.key === "ArrowRight" && idx < inputs.length - 1) {
          focusIndex(idx + 1);
          e.preventDefault();
        }
      });
      input.addEventListener("paste", (e) => {
        const text = (e.clipboardData || window.clipboardData).getData("text");
        if (!text) return;
        e.preventDefault();
        fillFromString(text);
      });
    });

    return {
      clear() {
        inputs.forEach((i) => (i.value = ""));
      },
      enable(enabled) {
        inputs.forEach((i) => (i.disabled = !enabled));
      },
      code() {
        return inputs.map((i) => i.value).join("");
      },
      focusFirst() {
        inputs[0]?.focus();
      },
      length: inputs.length,
    };
  };

  const signUpOtp = wireOtp(signUpOtpFieldset);
  const signInOtp = wireOtp(signInOtpFieldset);
  const signInTotp = wireOtp(signInTotpFieldset);
  const forgotOtp = forgotOtpFieldset ? wireOtp(forgotOtpFieldset) : null;
  const totpModalOtp = totpModalOtpFieldset
    ? wireOtp(totpModalOtpFieldset)
    : null;
  signUpOtp.enable(false);
  signInOtp.enable(false);
  signInTotp.enable(false);
  if (forgotOtp) forgotOtp.enable(false);
  if (totpModalOtp) totpModalOtp.enable(true);

  const setView = (view) => {
    showStatus(null, "");
    if (authCard) authCard.classList.remove("card--accountWide");
    if (view === "signin") {
      if (authCard) authCard.classList.add("card--narrow");
      titleEl.textContent = "Sign in";
      subtitleEl.textContent = "Use your email and password.";
      tabSignIn.classList.add("isActive");
      tabSignUp.classList.remove("isActive");
      signInForm.classList.remove("isHidden");
      signUpForm.classList.add("isHidden");
      if (forgotForm) forgotForm.classList.add("isHidden");
      dashboard.classList.add("isHidden");
      return;
    }
    if (view === "forgot") {
      if (authCard) authCard.classList.remove("card--narrow");
      titleEl.textContent = "Reset password";
      subtitleEl.textContent = "Verify your email to set a new password.";
      tabSignIn.classList.add("isActive");
      tabSignUp.classList.remove("isActive");
      signInForm.classList.add("isHidden");
      signUpForm.classList.add("isHidden");
      if (forgotForm) forgotForm.classList.remove("isHidden");
      dashboard.classList.add("isHidden");
      return;
    }
    if (view === "signup") {
      if (authCard) authCard.classList.remove("card--narrow");
      titleEl.textContent = "Sign up";
      subtitleEl.textContent = "Create your account and verify email.";
      tabSignUp.classList.add("isActive");
      tabSignIn.classList.remove("isActive");
      signUpForm.classList.remove("isHidden");
      signInForm.classList.add("isHidden");
      if (forgotForm) forgotForm.classList.add("isHidden");
      dashboard.classList.add("isHidden");
      return;
    }
    if (view === "dashboard") {
      if (authCard) authCard.classList.remove("card--narrow");
      titleEl.textContent = "Dashboard";
      subtitleEl.textContent = "Manage your security settings.";
      signInForm.classList.add("isHidden");
      signUpForm.classList.add("isHidden");
      if (forgotForm) forgotForm.classList.add("isHidden");
      dashboard.classList.remove("isHidden");
    }
  };

  // Resend countdown (only for resend buttons)
  const startResendCountdown = (btn, originalText, seconds) => {
    let remaining = Number(seconds || 0);
    if (!(remaining > 0)) return;
    btn.disabled = true;
    const tick = () => {
      if (remaining <= 0) {
        btn.disabled = false;
        btn.textContent = originalText;
        return;
      }
      btn.textContent = `${originalText} (${remaining}s)`;
      remaining -= 1;
      window.setTimeout(tick, 1000);
    };
    tick();
  };

  // --- Sign up flow ---
  let signUpEmailSentTo = "";
  let uniqueDirty = false;
  let suggestTimer = null;

  // --- Forgot password flow ---
  let forgotEmailSentTo = "";
  const updateForgotSendState = () => {
    if (!forgotSendBtn) return;
    forgotSendBtn.disabled = !isValidEmail(forgotEmail?.value);
  };

  const resetForgot = () => {
    if (forgotEmail) forgotEmail.value = "";
    if (forgotNewPassword) forgotNewPassword.value = "";
    if (forgotNewPassword2) forgotNewPassword2.value = "";
    if (forgotOtp) {
      forgotOtp.clear();
      forgotOtp.enable(false);
    }
    if (forgotOtpFieldset) forgotOtpFieldset.classList.add("isHidden");
    if (forgotResendRow) forgotResendRow.classList.add("isHidden");
    forgotEmailSentTo = "";
    updateForgotSendState();
  };

  // --- Account settings: Unique UserName auto-suggest (like signup) ---
  let acctUniqueDirty = false;
  let acctSuggestTimer = null;
  let acctUniqueInitial = "";
  let acctLastSuggestedUnique = "";

  function resetAccountUniqueSuggestState() {
    acctUniqueDirty = false;
    acctUniqueInitial = String(acctUnique?.value || "").trim();
    acctLastSuggestedUnique = "";
  }

  const updateSignUpSendState = () => {
    signUpSendBtn.disabled = !isValidEmail(signUpEmail.value);
  };

  signUpEmail.addEventListener("input", updateSignUpSendState);

  if (forgotEmail) forgotEmail.addEventListener("input", updateForgotSendState);

  signUpUnique.addEventListener("input", () => {
    uniqueDirty = true;
    if (!String(signUpUnique.value || "").trim()) uniqueDirty = false;
  });

  signUpName.addEventListener("input", () => {
    if (suggestTimer) window.clearTimeout(suggestTimer);
    suggestTimer = window.setTimeout(async () => {
      const name = String(signUpName.value || "").trim();
      if (!name) return;
      try {
        const data = await getJson(
          `/api/username/suggest?name=${encodeURIComponent(name)}`
        );
        if (!uniqueDirty)
          signUpUnique.value = data.suggested || signUpUnique.value;
        if (
          uniqueHint &&
          Array.isArray(data.suggestions) &&
          data.suggestions.length
        ) {
          uniqueHint.textContent = `Suggestions: ${data.suggestions.join(
            ", "
          )}`;
        }
      } catch {
        // ignore
      }
    }, 250);
  });

  if (acctUnique) {
    acctUnique.addEventListener("input", () => {
      acctUniqueDirty = true;
      if (!String(acctUnique.value || "").trim()) acctUniqueDirty = false;
    });
  }

  if (acctUsername) {
    acctUsername.addEventListener("input", () => {
      if (acctSuggestTimer) window.clearTimeout(acctSuggestTimer);
      acctSuggestTimer = window.setTimeout(async () => {
        const name = String(acctUsername.value || "").trim();
        if (!name) return;
        if (!acctUnique || acctUniqueDirty) return;

        const currentUnique = String(acctUnique.value || "").trim();
        const canOverwrite =
          !currentUnique ||
          currentUnique === acctUniqueInitial ||
          currentUnique === acctLastSuggestedUnique;
        if (!canOverwrite) return;

        try {
          const data = await getJson(
            `/api/username/suggest?name=${encodeURIComponent(name)}`
          );
          const suggested = String(data.suggested || "").trim();
          if (!suggested) return;
          if (!acctUniqueDirty) {
            acctUnique.value = suggested;
            acctLastSuggestedUnique = suggested;
          }
        } catch {
          // ignore
        }
      }, 250);
    });
  }

  const resetSignUp = () => {
    signUpName.value = "";
    signUpUnique.value = "";
    signUpPhone.value = "";
    signUpEmail.value = "";
    signUpPass.value = "";
    signUpPass2.value = "";
    signUpOtp.clear();
    signUpOtp.enable(false);
    signUpOtpFieldset.classList.add("isHidden");
    signUpResendRow.classList.add("isHidden");
    signUpEmailSentTo = "";
    uniqueDirty = false;
    updateSignUpSendState();
    showStatus(null, "");
  };

  signUpResetBtn.addEventListener("click", resetSignUp);

  if (forgotOpenBtn) {
    forgotOpenBtn.addEventListener("click", () => {
      showStatus(null, "");
      resetForgot();
      if (forgotEmail) {
        const candidate = String(signInEmail?.value || "").trim();
        if (candidate) forgotEmail.value = candidate;
      }
      updateForgotSendState();
      setView("forgot");
    });
  }

  if (forgotBackBtn) {
    forgotBackBtn.addEventListener("click", () => {
      showStatus(null, "");
      resetForgot();
      setView("signin");
    });
  }

  if (forgotSendBtn) {
    forgotSendBtn.addEventListener("click", async () => {
      const email = String(forgotEmail?.value || "").trim();
      if (!isValidEmail(email)) return;
      showStatus(null, "");
      forgotSendBtn.disabled = true;
      const originalText = forgotSendBtn.textContent;
      forgotSendBtn.textContent = "Sending...";
      try {
        const result = await postJson("/api/password/forgot/send-code", {
          email,
        });
        forgotEmailSentTo = email;
        if (forgotOtpFieldset) forgotOtpFieldset.classList.remove("isHidden");
        if (forgotResendRow) forgotResendRow.classList.remove("isHidden");
        if (forgotOtp) {
          forgotOtp.enable(true);
          forgotOtp.clear();
          forgotOtp.focusFirst();
        }

        if (result.delivered === false && result.debug_code) {
          showStatus(
            "success",
            `Email delivery not configured. Use this code: ${result.debug_code}`
          );
        } else {
          showStatus("success", "Verification code sent.");
        }
        startResendCountdown(forgotResendBtn, "Click to resend.", 30);
      } catch (err) {
        const retryAfter =
          err && typeof err.retryAfter === "number" ? err.retryAfter : 0;
        if (retryAfter > 0) {
          showStatus("error", `Please wait ${retryAfter}s and try again.`);
          startResendCountdown(forgotResendBtn, "Click to resend.", retryAfter);
        } else {
          showStatus(
            "error",
            err instanceof Error ? err.message : "Failed to send code"
          );
        }
      } finally {
        forgotSendBtn.disabled = false;
        forgotSendBtn.textContent = originalText;
        updateForgotSendState();
      }
    });
  }

  if (forgotResendBtn) {
    forgotResendBtn.addEventListener("click", async () => {
      if (!forgotEmailSentTo) return;
      showStatus(null, "");
      forgotResendBtn.disabled = true;
      const originalText = forgotResendBtn.textContent;
      forgotResendBtn.textContent = "Resending...";
      try {
        const result = await postJson("/api/password/forgot/send-code", {
          email: forgotEmailSentTo,
        });
        if (result.delivered === false && result.debug_code) {
          showStatus(
            "success",
            `Email delivery not configured. Use this code: ${result.debug_code}`
          );
        } else {
          showStatus("success", "A new code has been sent.");
        }
        startResendCountdown(forgotResendBtn, originalText, 30);
      } catch (err) {
        const retryAfter =
          err && typeof err.retryAfter === "number" ? err.retryAfter : 0;
        if (retryAfter > 0) {
          showStatus("error", `Please wait ${retryAfter}s and try again.`);
          startResendCountdown(forgotResendBtn, originalText, retryAfter);
        } else {
          showStatus(
            "error",
            err instanceof Error ? err.message : "Failed to resend"
          );
          forgotResendBtn.disabled = false;
          forgotResendBtn.textContent = originalText;
        }
      }
    });
  }

  if (forgotForm) {
    forgotForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      showStatus(null, "");

      const email = String(forgotEmail?.value || "").trim();
      const code = forgotOtp ? forgotOtp.code() : "";
      const newPass = String(forgotNewPassword?.value || "");
      const confirm = String(forgotNewPassword2?.value || "");

      if (!isValidEmail(email)) return showStatus("error", "Invalid email.");
      if (!forgotOtp || code.length !== forgotOtp.length)
        return showStatus("error", "Enter the 4-digit code.");
      if (!newPass || newPass.length < 6)
        return showStatus(
          "error",
          "New password must be at least 6 characters."
        );
      if (newPass !== confirm)
        return showStatus("error", "Passwords do not match.");

      if (forgotResetBtn) {
        forgotResetBtn.disabled = true;
        const originalText = forgotResetBtn.textContent;
        forgotResetBtn.textContent = "Resetting...";
        try {
          await postJson("/api/password/forgot/reset", {
            email,
            code,
            newPassword: newPass,
          });
          showStatus("success", "Password reset. You can sign in now.");
          resetForgot();
          if (signInEmail) signInEmail.value = email;
          if (signInPassword) signInPassword.value = "";
          setView("signin");
        } catch (err) {
          showStatus(
            "error",
            err instanceof Error ? err.message : "Failed to reset password"
          );
        } finally {
          forgotResetBtn.disabled = false;
          forgotResetBtn.textContent = originalText;
        }
      }
    });
  }

  signUpSendBtn.addEventListener("click", async () => {
    const email = String(signUpEmail.value || "").trim();
    if (!isValidEmail(email)) return;
    showStatus(null, "");
    signUpSendBtn.disabled = true;
    signUpSendBtn.textContent = "Sending...";
    try {
      const result = await postJson("/api/signup/send-code", { email });
      signUpEmailSentTo = email;
      signUpOtpFieldset.classList.remove("isHidden");
      signUpResendRow.classList.remove("isHidden");
      signUpOtp.enable(true);
      signUpOtp.clear();
      signUpOtp.focusFirst();
      showStatus("success", `Code sent to ${email}.`);
      if (result.delivered === false && result.debug_code) {
        showStatus(
          "error",
          "Email delivery not configured; check server console for debug code."
        );
      }
      startResendCountdown(signUpResendBtn, "Click to resend.", 30);
    } catch (err) {
      const retryAfter =
        err && typeof err.retryAfter === "number" ? err.retryAfter : 0;
      if (retryAfter > 0) {
        showStatus("error", `Please wait ${retryAfter}s and try again.`);
      } else {
        showStatus(
          "error",
          err instanceof Error ? err.message : "Failed to send code"
        );
      }
    } finally {
      signUpSendBtn.textContent = "Send code";
      updateSignUpSendState();
    }
  });

  signUpResendBtn.addEventListener("click", async () => {
    if (!signUpEmailSentTo) return;
    showStatus(null, "");
    signUpResendBtn.disabled = true;
    signUpResendBtn.textContent = "Resending...";
    try {
      const result = await postJson("/api/signup/send-code", {
        email: signUpEmailSentTo,
      });
      showStatus("success", "A new code has been sent.");
      if (result.delivered === false && result.debug_code) {
        showStatus(
          "error",
          "Email delivery not configured; check server console for debug code."
        );
      }
      startResendCountdown(signUpResendBtn, "Click to resend.", 30);
    } catch (err) {
      const retryAfter =
        err && typeof err.retryAfter === "number" ? err.retryAfter : 0;
      if (retryAfter > 0) {
        showStatus("error", `Please wait ${retryAfter}s and try again.`);
        startResendCountdown(signUpResendBtn, "Click to resend.", retryAfter);
      } else {
        showStatus(
          "error",
          err instanceof Error ? err.message : "Failed to resend code"
        );
        signUpResendBtn.disabled = false;
        signUpResendBtn.textContent = "Click to resend.";
      }
    }
  });

  signUpForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    showStatus(null, "");

    const username = String(signUpName.value || "").trim();
    const uniqueUsername = String(signUpUnique.value || "").trim();
    const phone = String(signUpPhone.value || "").trim();
    const email = String(signUpEmail.value || "").trim();
    const pass1 = String(signUpPass.value || "");
    const pass2 = String(signUpPass2.value || "");
    const code = signUpOtp.code();

    if (!username) return showStatus("error", "UserName is required.");
    if (!uniqueUsername)
      return showStatus("error", "Unique UserName is required.");
    if (!isValidPhone(phone))
      return showStatus("error", "Invalid phone number.");
    if (!isValidEmail(email)) return showStatus("error", "Invalid email.");
    if (!signUpEmailSentTo || signUpEmailSentTo !== email) {
      return showStatus(
        "error",
        "Please send a verification code to this email first."
      );
    }
    if (code.length !== signUpOtp.length)
      return showStatus("error", "Enter the 4-digit code.");
    if (!pass1 || pass1.length < 6)
      return showStatus("error", "Password must be at least 6 characters.");
    if (pass1 !== pass2) return showStatus("error", "Passwords do not match.");

    signUpBtn.disabled = true;
    signUpBtn.textContent = "Creating...";
    try {
      await postJson("/api/signup", {
        username,
        uniqueUsername,
        phone,
        email,
        password: pass1,
        code,
      });
      showStatus("success", "Account created. Please sign in.");
      setView("signin");
      signInEmail.value = email;
      signInPassword.value = "";
      resetSignUp();
      signInEmail.focus();
    } catch (err) {
      showStatus("error", err instanceof Error ? err.message : "Signup failed");
    } finally {
      signUpBtn.disabled = false;
      signUpBtn.textContent = "Create account";
    }
  });

  // --- Sign in flow ---
  let signInAttemptId = "";
  let signInMethod = "";
  let signInBackupAvailable = false;
  let signInInputMode = "primary"; // 'primary' | 'backup'
  const signInResendText = signInResendBtn.textContent;

  const resetSignIn2faUi = () => {
    signInAttemptId = "";
    signInMethod = "";
    signInBackupAvailable = false;
    signInInputMode = "primary";
    signInSendRow.classList.add("isHidden");
    signInOtpFieldset.classList.add("isHidden");
    signInTotpFieldset.classList.add("isHidden");
    if (signInBackupRow) signInBackupRow.classList.add("isHidden");
    if (signInBackupChoiceRow) signInBackupChoiceRow.classList.add("isHidden");
    if (signInPrimaryChoiceRow)
      signInPrimaryChoiceRow.classList.add("isHidden");
    if (signInBackupCode) signInBackupCode.value = "";
    signInResendRow.classList.add("isHidden");
    signInOtp.clear();
    signInOtp.enable(false);
    signInTotp.clear();
    signInTotp.enable(false);
    signInSendBtn.disabled = false;
    signInSendBtn.textContent = "Send code";
    signInResendBtn.disabled = false;
    signInResendBtn.textContent = signInResendText;
    signInBtn.textContent = "Sign in";
    signInEmail.disabled = false;
    signInPassword.disabled = false;
    if (signIn2faHint)
      signIn2faHint.textContent = "Email code required (2FA enabled).";
  };

  const showPrimary2faUi = () => {
    signInInputMode = "primary";
    if (signInBackupRow) signInBackupRow.classList.add("isHidden");
    if (signInPrimaryChoiceRow)
      signInPrimaryChoiceRow.classList.add("isHidden");
    if (signInBackupChoiceRow) {
      if (signInBackupAvailable)
        signInBackupChoiceRow.classList.remove("isHidden");
      else signInBackupChoiceRow.classList.add("isHidden");
    }

    if (signInMethod === "backup") {
      // Backup codes are the primary sign-in verification step.
      signInInputMode = "backup";
      signInSendRow.classList.add("isHidden");
      signInResendRow.classList.add("isHidden");
      signInOtpFieldset.classList.add("isHidden");
      signInTotpFieldset.classList.add("isHidden");
      signInOtp.enable(false);
      signInTotp.enable(false);
      signInOtp.clear();
      signInTotp.clear();
      if (signInBackupChoiceRow)
        signInBackupChoiceRow.classList.add("isHidden");
      if (signInPrimaryChoiceRow)
        signInPrimaryChoiceRow.classList.add("isHidden");
      if (signInBackupRow) signInBackupRow.classList.remove("isHidden");
      if (signInBackupCode) {
        signInBackupCode.value = "";
        signInBackupCode.focus();
      }
      if (signIn2faHint) signIn2faHint.textContent = "Backup code required.";
      return;
    }

    if (signInMethod === "totp") {
      signInSendRow.classList.add("isHidden");
      signInResendRow.classList.add("isHidden");
      signInOtpFieldset.classList.add("isHidden");
      signInTotpFieldset.classList.remove("isHidden");
      signInTotp.enable(true);
      signInTotp.clear();
      signInTotp.focusFirst();
      if (signIn2faHint)
        signIn2faHint.textContent = "Authenticator code required (TOTP).";
      return;
    }

    // Email OTP
    signInSendRow.classList.remove("isHidden");
    signInOtpFieldset.classList.remove("isHidden");
    signInResendRow.classList.remove("isHidden");
    signInOtp.enable(true);
    signInOtp.clear();
    signInOtp.focusFirst();
    if (signIn2faHint)
      signIn2faHint.textContent = "Email code required (2FA enabled).";
  };

  const showBackup2faUi = () => {
    signInInputMode = "backup";

    // Hide primary 2FA UI.
    signInSendRow.classList.add("isHidden");
    signInResendRow.classList.add("isHidden");
    signInOtpFieldset.classList.add("isHidden");
    signInTotpFieldset.classList.add("isHidden");
    signInOtp.enable(false);
    signInTotp.enable(false);
    signInOtp.clear();
    signInTotp.clear();

    if (signInBackupChoiceRow) signInBackupChoiceRow.classList.add("isHidden");
    if (signInPrimaryChoiceRow)
      signInPrimaryChoiceRow.classList.remove("isHidden");
    if (signInBackupRow) signInBackupRow.classList.remove("isHidden");
    if (signInBackupCode) {
      signInBackupCode.value = "";
      signInBackupCode.focus();
    }
    if (signIn2faHint) signIn2faHint.textContent = "Backup code required.";
  };

  if (signInUseBackupBtn) {
    signInUseBackupBtn.addEventListener("click", () => {
      if (!signInAttemptId) return;
      if (!signInBackupAvailable) return;
      showStatus(null, "");
      showBackup2faUi();
    });
  }

  if (signInUsePrimaryBtn) {
    signInUsePrimaryBtn.addEventListener("click", () => {
      if (!signInAttemptId) return;
      showStatus(null, "");
      showPrimary2faUi();
    });
  }

  signInResetBtn.addEventListener("click", () => {
    showStatus(null, "");
    signInEmail.value = "";
    signInPassword.value = "";
    resetSignIn2faUi();
    signInEmail.focus();
  });

  signInSendBtn.addEventListener("click", async () => {
    if (!signInAttemptId) return;
    if (signInMethod !== "email") return;
    showStatus(null, "");
    signInSendBtn.disabled = true;
    signInSendBtn.textContent = "Sending...";
    try {
      const result = await postJson("/api/signin/send-code", {
        attemptId: signInAttemptId,
      });
      signInOtpFieldset.classList.remove("isHidden");
      signInResendRow.classList.remove("isHidden");
      signInOtp.enable(true);
      signInOtp.clear();
      signInOtp.focusFirst();
      if (result.delivered === false && result.debug_code) {
        showStatus(
          "success",
          `Email delivery not configured. Use this code: ${result.debug_code}`
        );
      } else {
        showStatus("success", "Code sent to your email.");
      }
      startResendCountdown(signInResendBtn, signInResendText, 30);
    } catch (err) {
      const retryAfter =
        err && typeof err.retryAfter === "number" ? err.retryAfter : 0;
      if (retryAfter > 0) {
        showStatus("error", `Please wait ${retryAfter}s and try again.`);
      } else {
        showStatus(
          "error",
          err instanceof Error ? err.message : "Failed to send code"
        );
      }
      signInSendBtn.disabled = false;
    } finally {
      signInSendBtn.textContent = "Send code";
    }
  });

  signInResendBtn.addEventListener("click", async () => {
    if (!signInAttemptId) return;
    if (signInMethod !== "email") return;
    showStatus(null, "");
    signInResendBtn.disabled = true;
    signInResendBtn.textContent = "Resending...";
    try {
      const result = await postJson("/api/signin/send-code", {
        attemptId: signInAttemptId,
      });
      if (result.delivered === false && result.debug_code) {
        showStatus(
          "success",
          `Email delivery not configured. Use this code: ${result.debug_code}`
        );
      } else {
        showStatus("success", "A new code has been sent.");
      }
      startResendCountdown(signInResendBtn, signInResendText, 30);
    } catch (err) {
      const retryAfter =
        err && typeof err.retryAfter === "number" ? err.retryAfter : 0;
      if (retryAfter > 0) {
        showStatus("error", `Please wait ${retryAfter}s and try again.`);
        startResendCountdown(signInResendBtn, signInResendText, retryAfter);
      } else {
        showStatus(
          "error",
          err instanceof Error ? err.message : "Failed to resend code"
        );
        signInResendBtn.disabled = false;
        signInResendBtn.textContent = signInResendText;
      }
    }
  });

  const showDashboard = (user) => {
    setView("dashboard");
    setDashboardMode(dashboardMode);
    if (welcomeEl) welcomeEl.textContent = `Welcome, ${user.username}!`;

    if (acctUsername) acctUsername.value = String(user.username || "");
    if (acctUnique) acctUnique.value = String(user.uniqueUsername || "");
    if (acctPhone) acctPhone.value = String(user.phone || "");
    if (acctEmail) acctEmail.value = String(user.email || "");
    const mode = String(
      user.twoFactorMode || (user.twoFactorEnabled ? "email" : "none")
    );
    if (twoFaToggle) twoFaToggle.checked = mode === "email";
    if (totpToggle) totpToggle.checked = mode === "totp";

    const remaining = Number(user.backupCodesRemaining || 0);
    const createdAt = user.backupCodesCreatedAt || "";
    if (backupCodesToggle) backupCodesToggle.checked = remaining > 0;
    if (backupCodesPanel) {
      if (remaining > 0) backupCodesPanel.classList.remove("isHidden");
      else backupCodesPanel.classList.add("isHidden");
    }
    if (backupCodesRemainingEl)
      backupCodesRemainingEl.textContent = `${remaining} backup codes remaining`;
    if (backupCodesCreatedEl)
      backupCodesCreatedEl.textContent = `Created ${daysSince(
        createdAt
      )} days ago`;
  };

  const daysSince = (isoOrMs) => {
    const t = typeof isoOrMs === "number" ? isoOrMs : Date.parse(isoOrMs);
    if (!Number.isFinite(t)) return 0;
    return Math.max(0, Math.floor((Date.now() - t) / (24 * 60 * 60 * 1000)));
  };

  let lastBackupCodesPlaintext = null;

  const showBackupCodesPanel = ({ remaining, createdAt }) => {
    const rem = Number(remaining || 0);
    if (backupCodesPanel) {
      if (rem > 0) backupCodesPanel.classList.remove("isHidden");
      else backupCodesPanel.classList.add("isHidden");
    }
    if (backupCodesRemainingEl)
      backupCodesRemainingEl.textContent = `${rem} backup codes remaining`;
    if (backupCodesCreatedEl)
      backupCodesCreatedEl.textContent = `Created ${daysSince(
        createdAt
      )} days ago`;
  };

  const downloadTextFile = (filename, text) => {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  signInForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    showStatus(null, "");

    const email = String(signInEmail.value || "").trim();
    const password = String(signInPassword.value || "");
    if (!isValidEmail(email)) return showStatus("error", "Invalid email.");
    if (!password) return showStatus("error", "Password is required.");

    signInBtn.disabled = true;
    signInBtn.textContent = "Signing in...";
    try {
      if (signInAttemptId) {
        let code = "";
        if (signInInputMode === "backup") {
          code = String(signInBackupCode?.value || "").trim();
          if (!code) {
            signInBtn.disabled = false;
            signInBtn.textContent = "Verify & sign in";
            return showStatus("error", "Enter a backup code.");
          }
        } else {
          code = signInMethod === "totp" ? signInTotp.code() : signInOtp.code();
          const expectedLength =
            signInMethod === "totp" ? signInTotp.length : signInOtp.length;
          if (code.length !== expectedLength) {
            signInBtn.disabled = false;
            signInBtn.textContent = "Verify & sign in";
            return showStatus(
              "error",
              signInMethod === "totp"
                ? "Enter the 6-digit code."
                : "Enter the 4-digit code."
            );
          }
        }
        const result = await postJson("/api/signin/complete", {
          attemptId: signInAttemptId,
          code,
        });
        showDashboard(result.user);
        resetSignIn2faUi();
        showStatus("success", "Signed in successfully.");
        return;
      }

      const result = await postJson("/api/signin/start", { email, password });
      if (result.requires2fa) {
        signInAttemptId = result.attemptId;
        signInMethod = String(result.method || "email");
        signInBackupAvailable = !!result.backupCodesAvailable;
        signInInputMode = "primary";

        signInEmail.disabled = true;
        signInPassword.disabled = true;
        signInBtn.textContent = "Verify & sign in";

        showPrimary2faUi();

        showStatus(
          "success",
          signInMethod === "backup"
            ? "Backup codes enabled. Enter a backup code to finish signing in."
            : signInMethod === "totp"
            ? "Enter the 6-digit code from your authenticator app to finish signing in."
            : "Email 2FA enabled. Click “Send code” and enter it to finish signing in."
        );
      } else {
        showDashboard(result.user);
        showStatus("success", "Signed in successfully.");
      }
    } catch (err) {
      showStatus(
        "error",
        err instanceof Error ? err.message : "Sign in failed"
      );
      resetSignIn2faUi();
    } finally {
      signInBtn.disabled = false;
      if (!signInAttemptId) signInBtn.textContent = "Sign in";
      else signInBtn.textContent = "Verify & sign in";
    }
  });

  // --- Dashboard actions ---
  const set2faMethod = async (method) => {
    const result = await postJson("/api/2fa/method", { method });
    return result;
  };

  const closeTotpModal = async ({ cancelSetup } = { cancelSetup: false }) => {
    if (!totpModal) return;
    totpModal.classList.add("isHidden");
    if (totpQrImg) totpQrImg.removeAttribute("src");
    if (totpModalSecretEl) totpModalSecretEl.value = "";
    if (totpModalSecretHint) totpModalSecretHint.textContent = "";
    if (totpModalDesc)
      totpModalDesc.textContent =
        "Scan the QR code with your authenticator app, then enter the 6-digit code.";
    if (totpQrWrap) totpQrWrap.classList.remove("isHidden");
    if (totpModalOtp) totpModalOtp.clear();
    if (cancelSetup) {
      try {
        await postJson("/api/totp/cancel", {});
      } catch {
        // ignore
      }
    }
  };

  const openTotpModal = async () => {
    if (!totpModal || !totpModalEnableBtn || !totpModalCancelBtn) {
      throw new Error("Authenticator setup UI is missing.");
    }
    totpModal.classList.remove("isHidden");

    if (totpModalSecretEl) totpModalSecretEl.value = "Loading...";
    if (totpModalSecretHint)
      totpModalSecretHint.textContent = "Generating setup data...";
    if (totpModalOtp) totpModalOtp.clear();

    totpModalEnableBtn.disabled = true;
    totpModalCancelBtn.disabled = true;

    try {
      const result = await postJson("/api/totp/begin", {});
      const qrSrc = result.qrUrl
        ? `${result.qrUrl}${
            String(result.qrUrl).includes("?") ? "&" : "?"
          }_=${Date.now()}`
        : result.qrDataUrl;
      if (result.alreadySetup) {
        if (totpQrWrap) {
          if (qrSrc) totpQrWrap.classList.remove("isHidden");
          else totpQrWrap.classList.add("isHidden");
        }
        if (totpQrImg && qrSrc) totpQrImg.src = qrSrc;
        if (totpModalSecretEl) totpModalSecretEl.value = result.secret || "";
        if (totpModalSecretHint)
          totpModalSecretHint.textContent = qrSrc
            ? "Authenticator is already set up. Scan again if needed, then enter the current 6-digit code to enable."
            : "Authenticator is already set up. Enter the current 6-digit code to enable.";
        if (totpModalDesc)
          totpModalDesc.textContent =
            "Enter the current 6-digit code from your authenticator app to enable.";
      } else {
        if (totpQrWrap) {
          if (qrSrc) totpQrWrap.classList.remove("isHidden");
          else totpQrWrap.classList.add("isHidden");
        }
        if (totpQrImg && qrSrc) totpQrImg.src = qrSrc;
        if (totpModalSecretEl) totpModalSecretEl.value = result.secret || "";
        if (totpModalSecretHint)
          totpModalSecretHint.textContent = qrSrc
            ? "Scan the QR code with your authenticator app."
            : "QR not available (missing server dependency). Use manual setup with the secret.";
      }

      if (totpModalOtp) {
        totpModalOtp.clear();
        totpModalOtp.focusFirst();
      }
    } finally {
      totpModalEnableBtn.disabled = false;
      totpModalCancelBtn.disabled = false;
    }
  };

  twoFaToggle.addEventListener("change", async () => {
    showStatus(null, "");
    try {
      const enabled = !!twoFaToggle.checked;
      if (enabled) {
        if (totpToggle) totpToggle.checked = false;
        await closeTotpModal({ cancelSetup: true });
        await set2faMethod("email");
      } else {
        if (!totpToggle || !totpToggle.checked) {
          await set2faMethod("none");
        }
      }
      showStatus(
        "success",
        enabled ? "Email 2FA enabled." : "Email 2FA disabled."
      );
    } catch (err) {
      twoFaToggle.checked = !twoFaToggle.checked;
      showStatus(
        "error",
        err instanceof Error ? err.message : "Failed to update 2FA setting"
      );
    }
  });

  totpToggle.addEventListener("change", async () => {
    showStatus(null, "");
    try {
      const wantsEnable = !!totpToggle.checked;

      // Disabling is immediate.
      if (!wantsEnable) {
        if (!twoFaToggle.checked) await set2faMethod("none");
        showStatus("success", "Authenticator 2FA disabled.");
        return;
      }

      // Enabling requires a verified 6-digit code.
      totpToggle.checked = false;
      await openTotpModal();
    } catch (err) {
      closeTotpModal({ cancelSetup: true });
      totpToggle.checked = !totpToggle.checked;
      showStatus(
        "error",
        err instanceof Error
          ? err.message
          : "Failed to update authenticator setting"
      );
    }
  });

  // --- Backup codes ---
  if (backupCodesDownloadBtn) {
    backupCodesDownloadBtn.addEventListener("click", async () => {
      showStatus(null, "");
      backupCodesDownloadBtn.disabled = true;
      backupCodesDownloadBtn.textContent = "Downloading...";
      try {
        // If user refreshed the page, we may not have plaintext codes anymore.
        // In that case, regenerate a fresh set and download those.
        if (
          !lastBackupCodesPlaintext ||
          !Array.isArray(lastBackupCodesPlaintext)
        ) {
          const regenerated = await postJson("/api/backup-codes/enable", {});
          lastBackupCodesPlaintext = Array.isArray(regenerated.codes)
            ? regenerated.codes.slice()
            : null;
          if (backupCodesToggle)
            backupCodesToggle.checked = Number(regenerated.remaining || 0) > 0;
          showBackupCodesPanel({
            remaining: regenerated.remaining,
            createdAt: regenerated.createdAt,
          });
        }

        const list = Array.isArray(lastBackupCodesPlaintext)
          ? lastBackupCodesPlaintext
          : [];
        const lines = list.map((c) => String(c)).join("\n");
        downloadTextFile("backup-codes.txt", lines + "\n");
        showStatus("success", "Backup codes downloaded.");
      } finally {
        backupCodesDownloadBtn.disabled = false;
        backupCodesDownloadBtn.textContent = "Download codes";
      }
    });
  }

  if (backupCodesToggle) {
    backupCodesToggle.addEventListener("change", async () => {
      showStatus(null, "");
      try {
        const wantsEnable = !!backupCodesToggle.checked;
        if (!wantsEnable) {
          await postJson("/api/backup-codes/disable", {});
          lastBackupCodesPlaintext = null;
          showBackupCodesPanel({ remaining: 0, createdAt: "" });
          if (backupCodesToggle) backupCodesToggle.checked = false;
          showStatus("success", "Backup codes disabled.");
          return;
        }

        // Enabling generates codes and reveals inline panel.
        const result = await postJson("/api/backup-codes/enable", {});
        lastBackupCodesPlaintext = Array.isArray(result.codes)
          ? result.codes.slice()
          : null;
        showBackupCodesPanel({
          remaining: result.remaining,
          createdAt: result.createdAt,
        });
        backupCodesToggle.checked = Number(result.remaining || 0) > 0;
      } catch (err) {
        backupCodesToggle.checked = !backupCodesToggle.checked;
        showStatus(
          "error",
          err instanceof Error ? err.message : "Failed to update backup codes"
        );
      }
    });
  }

  if (totpModalBackdrop) {
    totpModalBackdrop.addEventListener("click", () => {
      closeTotpModal({ cancelSetup: true });
    });
  }

  if (totpModalCancelBtn) {
    totpModalCancelBtn.addEventListener("click", () => {
      closeTotpModal({ cancelSetup: true });
    });
  }

  if (totpModalResetBtn) {
    totpModalResetBtn.addEventListener("click", async () => {
      showStatus(null, "");
      if (!totpModal) return;

      totpModalResetBtn.disabled = true;
      if (totpModalCancelBtn) totpModalCancelBtn.disabled = true;
      if (totpModalEnableBtn) totpModalEnableBtn.disabled = true;
      totpModalResetBtn.textContent = "Resetting...";
      try {
        const result = await postJson("/api/totp/reset-begin", {});
        const qrSrc = result.qrUrl
          ? `${result.qrUrl}${
              String(result.qrUrl).includes("?") ? "&" : "?"
            }_=${Date.now()}`
          : result.qrDataUrl;

        if (totpQrWrap) {
          if (qrSrc) totpQrWrap.classList.remove("isHidden");
          else totpQrWrap.classList.add("isHidden");
        }
        if (totpQrImg && qrSrc) totpQrImg.src = qrSrc;
        if (totpModalSecretEl) totpModalSecretEl.value = result.secret || "";
        if (totpModalSecretHint)
          totpModalSecretHint.textContent = qrSrc
            ? "New secret generated. Scan this QR, then enter the NEW 6-digit code to confirm."
            : "New secret generated. Use manual setup with the secret, then enter the NEW 6-digit code to confirm.";
        if (totpModalDesc)
          totpModalDesc.textContent =
            "Hard reset creates a new secret. Your old authenticator remains active until you confirm the new code.";

        if (totpModalOtp) {
          totpModalOtp.clear();
          totpModalOtp.focusFirst();
        }
        showStatus("success", "New secret created. Confirm to finish reset.");
      } catch (err) {
        showStatus(
          "error",
          err instanceof Error ? err.message : "Failed to reset authenticator"
        );
      } finally {
        totpModalResetBtn.disabled = false;
        if (totpModalCancelBtn) totpModalCancelBtn.disabled = false;
        if (totpModalEnableBtn) totpModalEnableBtn.disabled = false;
        totpModalResetBtn.textContent = "Hard reset";
      }
    });
  }

  if (totpModalEnableBtn) {
    totpModalEnableBtn.addEventListener("click", async () => {
      showStatus(null, "");
      if (!totpModalOtp) return showStatus("error", "Missing code inputs.");
      const code = totpModalOtp.code();
      if (code.length !== totpModalOtp.length) {
        return showStatus("error", "Enter the 6-digit code.");
      }

      totpModalEnableBtn.disabled = true;
      totpModalEnableBtn.textContent = "Enabling...";
      try {
        await postJson("/api/totp/confirm", { code });

        // Make it mutually exclusive.
        if (twoFaToggle) twoFaToggle.checked = false;
        if (totpToggle) totpToggle.checked = true;

        await closeTotpModal({ cancelSetup: false });
        showStatus("success", "Authenticator 2FA enabled.");
      } catch (err) {
        showStatus(
          "error",
          err instanceof Error ? err.message : "Failed to enable authenticator"
        );
        totpModalOtp.clear();
        totpModalOtp.focusFirst();
      } finally {
        totpModalEnableBtn.disabled = false;
        totpModalEnableBtn.textContent = "Enable";
      }
    });
  }

  window.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (!totpModal || totpModal.classList.contains("isHidden")) return;
    closeTotpModal({ cancelSetup: true });
  });

  signOutBtn.addEventListener("click", async () => {
    showStatus(null, "");
    try {
      await postJson("/api/signout", {});
    } catch {
      // ignore
    }
    resetSignIn2faUi();
    setDashboardMode("security");
    setView("signin");
    signInEmail.value = "";
    signInPassword.value = "";
  });

  if (openAccountSettingsRow) {
    openAccountSettingsRow.addEventListener("click", () => {
      showStatus(null, "");
      setDashboardMode("account");
    });
    openAccountSettingsRow.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      e.preventDefault();
      showStatus(null, "");
      setDashboardMode("account");
    });
    openAccountSettingsRow.setAttribute("role", "button");
    openAccountSettingsRow.setAttribute("tabindex", "0");
  }

  if (openAccountSettingsBtn) {
    openAccountSettingsBtn.addEventListener("click", (e) => {
      e.preventDefault();
      showStatus(null, "");
      setDashboardMode("account");
    });
  }

  if (accountSettingsBackBtn) {
    accountSettingsBackBtn.addEventListener("click", () => {
      showStatus(null, "");
      setDashboardMode("security");
    });
  }

  if (acctSaveBtn) {
    acctSaveBtn.addEventListener("click", async () => {
      showStatus(null, "");
      setDashboardMode("account");
      const username = String(acctUsername?.value || "").trim();
      const uniqueUsername = String(acctUnique?.value || "").trim();
      const phone = String(acctPhone?.value || "").trim();
      const email = String(acctEmail?.value || "").trim();

      if (!username) return showStatus("error", "UserName is required.");
      if (!uniqueUsername)
        return showStatus("error", "Unique UserName is required.");
      if (!isValidPhone(phone))
        return showStatus("error", "Invalid phone number.");
      if (!isValidEmail(email)) return showStatus("error", "Invalid email.");

      acctSaveBtn.disabled = true;
      const originalText = acctSaveBtn.textContent;
      acctSaveBtn.textContent = "Saving...";
      try {
        const result = await postJson("/api/account/update", {
          username,
          uniqueUsername,
          phone,
          email,
        });
        if (result && result.user) {
          showDashboard(result.user);
        }
        showStatus("success", "Profile updated.");
      } catch (err) {
        showStatus(
          "error",
          err instanceof Error ? err.message : "Failed to update profile"
        );
      } finally {
        acctSaveBtn.disabled = false;
        acctSaveBtn.textContent = originalText;
      }
    });
  }

  if (acctPasswordBtn) {
    acctPasswordBtn.addEventListener("click", async () => {
      showStatus(null, "");
      setDashboardMode("account");
      const currentPassword = String(acctCurrentPassword?.value || "");
      const newPassword = String(acctNewPassword?.value || "");
      const confirm = String(acctNewPassword2?.value || "");

      if (!currentPassword)
        return showStatus("error", "Current password is required.");
      if (!newPassword || newPassword.length < 6)
        return showStatus(
          "error",
          "New password must be at least 6 characters."
        );
      if (newPassword !== confirm)
        return showStatus("error", "Passwords do not match.");

      acctPasswordBtn.disabled = true;
      const originalText = acctPasswordBtn.textContent;
      acctPasswordBtn.textContent = "Updating...";
      try {
        await postJson("/api/account/password", {
          currentPassword,
          newPassword,
        });
        if (acctCurrentPassword) acctCurrentPassword.value = "";
        if (acctNewPassword) acctNewPassword.value = "";
        if (acctNewPassword2) acctNewPassword2.value = "";
        showStatus("success", "Password updated.");
      } catch (err) {
        showStatus(
          "error",
          err instanceof Error ? err.message : "Failed to update password"
        );
      } finally {
        acctPasswordBtn.disabled = false;
        acctPasswordBtn.textContent = originalText;
      }
    });
  }

  // Tabs
  tabSignIn.addEventListener("click", () => setView("signin"));
  tabSignUp.addEventListener("click", () => setView("signup"));

  // Initial state
  resetSignUp();
  resetSignIn2faUi();
  updateSignUpSendState();
  setView("signin");

  // Auto-resume session
  (async () => {
    try {
      const data = await getJson("/api/me");
      if (data && data.user) {
        showDashboard(data.user);
      }
    } catch {
      // not signed in
    }
  })();
})();
