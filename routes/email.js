const { Resend } = require('resend');

function getResend() {
  const key = process.env.RESEND_API_KEY;
  if (!key || key === 'your_resend_api_key_here') return null;
  return new Resend(key);
}

async function sendVerificationEmail(toEmail, username, token, baseUrl) {
  const resend = getResend();
  const verifyUrl = `${baseUrl}/api/auth/verify/${token}`;

  // If no Resend key, just log the link (useful for local dev)
  if (!resend) {
    console.log(`\n📧 [DEV MODE] Verification link for ${toEmail}:\n   ${verifyUrl}\n`);
    return { dev: true };
  }

  try {
    const result = await resend.emails.send({
      from: process.env.FROM_EMAIL || 'ShieldScan <onboarding@resend.dev>',
      to: toEmail,
      subject: '🛡️ Verify your ShieldScan account',
      html: `
        <!DOCTYPE html>
        <html>
        <body style="margin:0;padding:0;background:#060a10;font-family:'Segoe UI',sans-serif;">
          <div style="max-width:520px;margin:40px auto;background:#0d1321;border:1px solid rgba(99,179,255,0.15);border-radius:16px;overflow:hidden;">
            <div style="background:linear-gradient(135deg,#3b82f6,#06b6d4);padding:32px;text-align:center;">
              <div style="font-size:36px;margin-bottom:8px;">🛡️</div>
              <div style="color:white;font-size:24px;font-weight:800;letter-spacing:-0.5px;">ShieldScan</div>
              <div style="color:rgba(255,255,255,0.8);font-size:13px;margin-top:4px;">Link Safety Checker</div>
            </div>
            <div style="padding:36px 32px;">
              <h2 style="color:#e2e8f0;font-size:20px;margin:0 0 12px;font-weight:700;">Hi ${username}! 👋</h2>
              <p style="color:#94a3b8;font-size:15px;line-height:1.7;margin:0 0 28px;">
                Thanks for signing up for ShieldScan. Click the button below to verify your email address and activate your account.
              </p>
              <div style="text-align:center;margin-bottom:28px;">
                <a href="${verifyUrl}"
                   style="display:inline-block;background:linear-gradient(135deg,#3b82f6,#06b6d4);color:white;text-decoration:none;padding:14px 36px;border-radius:10px;font-size:15px;font-weight:700;letter-spacing:0.3px;">
                  ✅ Verify My Email
                </a>
              </div>
              <p style="color:#475569;font-size:13px;line-height:1.6;margin:0;border-top:1px solid rgba(99,179,255,0.1);padding-top:20px;">
                This link expires in <strong style="color:#94a3b8;">24 hours</strong>. If you didn't create an account, you can safely ignore this email.
              </p>
              <p style="color:#334155;font-size:12px;margin:12px 0 0;word-break:break-all;">
                Or copy this link: <span style="color:#3b82f6;">${verifyUrl}</span>
              </p>
            </div>
          </div>
        </body>
        </html>
      `
    });
    return result;
  } catch (err) {
    console.error('[Email Error]', err.message);
    throw err;
  }
}

module.exports = { sendVerificationEmail };
