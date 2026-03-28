const nodemailer = require('nodemailer');

function getTransporter() {
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;
  if (!user || !pass || user === 'your_gmail@gmail.com') return null;
  return nodemailer.createTransport({ service: 'gmail', auth: { user, pass } });
}

async function sendVerificationEmail(toEmail, username, token, baseUrl) {
  const transporter = getTransporter();
  const verifyUrl = `${baseUrl}/api/auth/verify/${token}`;

  if (!transporter) {
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('📧  DEV MODE — Gmail not configured');
    console.log(`👤  User: ${username} (${toEmail})`);
    console.log('🔗  Click this to verify:');
    console.log(`    ${verifyUrl}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    return { dev: true, verifyUrl };
  }

  await transporter.sendMail({
    from: `"ShieldScan" <${process.env.GMAIL_USER}>`,
    to: toEmail,
    subject: '🛡️ Verify your ShieldScan account',
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:520px;margin:40px auto;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
    <div style="background:linear-gradient(135deg,#3b82f6,#06b6d4);padding:36px;text-align:center;">
      <div style="font-size:40px;margin-bottom:10px;">🛡️</div>
      <div style="color:white;font-size:26px;font-weight:800;">ShieldScan</div>
      <div style="color:rgba(255,255,255,0.75);font-size:13px;margin-top:4px;">Link Safety Checker</div>
    </div>
    <div style="padding:40px 36px;">
      <h2 style="color:#1e293b;font-size:20px;margin:0 0 12px;">Hi ${username}! 👋</h2>
      <p style="color:#64748b;font-size:15px;line-height:1.7;margin:0 0 32px;">
        Thanks for signing up! Click the button below to verify your email and activate your ShieldScan account.
      </p>
      <div style="text-align:center;margin-bottom:32px;">
        <a href="${verifyUrl}"
           style="display:inline-block;background:linear-gradient(135deg,#3b82f6,#06b6d4);color:white;text-decoration:none;padding:15px 40px;border-radius:10px;font-size:15px;font-weight:700;">
          ✅ Verify My Email
        </a>
      </div>
      <div style="background:#f8fafc;border-radius:8px;padding:16px;margin-bottom:24px;">
        <p style="color:#94a3b8;font-size:12px;margin:0 0 6px;">Or copy this link into your browser:</p>
        <p style="color:#3b82f6;font-size:12px;word-break:break-all;margin:0;">${verifyUrl}</p>
      </div>
      <p style="color:#94a3b8;font-size:12px;margin:0;border-top:1px solid #f1f5f9;padding-top:20px;">
        This link expires in <strong>24 hours</strong>. If you didn't create a ShieldScan account, ignore this email.
      </p>
    </div>
  </div>
</body>
</html>`
  });

  return { dev: false };
}

module.exports = { sendVerificationEmail };
