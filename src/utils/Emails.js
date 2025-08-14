const nodemailer = require("nodemailer");
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

const sendMail = async (to, subject, html) => {
  try {
    const mailOptions = {
      from: `"Dev Tinder" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
    }; 
    await transporter.sendMail(mailOptions);
    console.log("EMail sent successfully to", to);
  } catch (err) {
    console.error("Email sending failed:", err.message);
    throw new Error("Failed to send email");
  }
};
module.exports = sendMail;
