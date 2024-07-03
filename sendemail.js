const nodemailer = require('nodemailer');

const sendemail = async (from, to, reply_to, subject, message) => {

    // create email transporter
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: 587,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
        tls: {
            rejectUnauthorized: false
        }
    });

    // options for sending email
    const options = {
        from: from,
        to: to,
        replyTo: reply_to,
        subject: subject,
        html: message,
    };

    // send email

    transporter.sendMail(options, function (err, info) {
        if (err) {
            console.log(err);
        } else {
            console.log(info);
        }
    });
};

module.exports = sendemail;
