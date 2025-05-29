const mailer = require('nodemailer');

const transporter = mailer.createTransport({
    service: 'gmail',
    auth: {
        user : process.env.MAIL_ID,
        pass : process.env.MAIL_PASSWD
    }
});

const mailCode = async (email , code) => {
    const mailOptions = {
        from : process.env.MAIL_ID,
        to : email,
        subject : 'Verification',
        text : `Your code is ${code}.`,
    };
    let done;
    transporter.sendMail(mailOptions , (error , info) => {
        if (error) {
            console.log(error);
            done = false;
        }
        else{
            done = true;
        }
    });
    return done;
}

module.exports = {mailCode};
