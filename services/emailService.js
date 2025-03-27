const nodemailer = require('nodemailer');
const ejs = require('ejs');


const redisService = require('./redisService');
const libs = require('../lib');

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    auth: {
        user: process.env.SMTP_AUTH_USER,
        pass: process.env.SMTP_AUTH_PASS,
    }
});

const sendEmail = async ({to, from, subject, message, isHTML = false}) => {
    return transporter.sendMail({
        to: to,
        html: isHTML? message :null,
        from: from,
        date: new Date(),
        text: isHTML? null : message,
        subject: subject,
    })
}

const pushIntoMailQueue = (data) => {
    return redisService.redis('rpush', libs.constants.redisKeys.emailQueue, JSON.stringify(data));
}

const popEmailFromEmailQueue = async () => {
    const data = await redisService.redis('lpop', libs.constants.redisKeys.emailQueue);
    if (!data) return;
    const parsedData = JSON.parse(data);
    sendEmail(parsedData);
}

/**
 * 
 * @param {{[string]: any}} data 
 * @param {{[string]: any}} user 
 * @param {{[string]: any}} session 
 * @returns { EmailClass }
 */
const CreateEmailFactory = (data, user, session) => {
    if (!data.Type) throw new Error(
        libs.messages.errorMessage.emailTypeNotProvided
    )

    data.to = data?.to ?? data?.email;
    if (!data.to) throw new Error(libs.messages.errorMessage.emailNotProvidedWhereToSendMail);
    switch (data.Type) {
        case libs.constants.emailType.NewUser: {
            if (!data.token) throw new Error(libs.messages.errorMessage.newUserTokenMissing);
            if (!user) throw new Error(libs.messages.errorMessage.userDataMissingEmailFactory);
            const emailData = libs.constants.emailContent[data.Type];
            return new EmailClass({data: data, emailData: emailData, user: user});
        }
        case libs.constants.emailType.WorkspaceInvite: {
            if (!data.workspaceId) throw new Error(libs.messages.errorMessage.workspaceInviteMissingWorkSpaceId)
            if (!user) throw new Error(libs.messages.errorMessage.userDataMissingEmailFactory);
            const emailData = libs.constants.emailContent[data.Type];
            return new EmailClass({data: data, emailData: emailData, user: user});
        }
        case libs.constants.emailType.ForgotPassword: {
            if (!data.token) throw new Error(libs.messages.errorMessage.varificationTokenNotPresent);
            if (!user) throw new Error(libs.messages.errorMessage.userDataMissingEmailFactory);
            const emailData = libs.constants.emailContent[data.Type];
            return new EmailClass({data: data, emailData: emailData, user: user});
        }
        case libs.constants.emailType.ChannelInvite: {
            if (!data.token) throw new Error(libs.messages.errorMessage.varificationTokenNotPresent);
            if (!user) throw new Error(libs.messages.errorMessage.userDataMissingEmailFactory);
            const emailData = libs.constants.emailContent[data.Type];
            return new EmailClass({data: data, emailData: emailData, user: user});
        }
        case libs.constants.emailType.UserAndChannelInvite: {
            if (!data.token) throw new Error(libs.messages.errorMessage.varificationTokenNotPresent);
            if (!user) throw new Error(libs.messages.errorMessage.userDataMissingEmailFactory);
            const emailData = libs.constants.emailContent[data.Type];
            return new EmailClass({data: data, emailData: emailData, user: user});
        }
        case libs.constants.emailType.fact:{
            if (!data.token) throw new Error(libs.messages.errorMessage.varificationTokenNotPresent);
            if (!user) throw new Error(libs.messages.errorMessage.userDataMissingEmailFactory);
            const emailData = libs.constants.emailContent[data.Type];
            return new EmailClass({data: data, emailData: emailData, user: user});
        }
        default: {
            throw new Error(libs.messages.errorMessage.invalidEmailType)
        }
    }
}

class EmailClass {
    #data
    #emailData
    #user
    #session
    constructor({data, emailData, user, session}) {
        this.#data = data;
        this.#emailData = emailData;
        if (this.#data === null) {
            this.#data = {};
        }
        this.#user = user;
        this.#session = session;
        this.#data = {...this.#data, ...libs.utils.getBaseConfig()}
    }

    render() {
        const data = {...this.#data, ...this.#session, ... this.#user};
        return ejs.render(this.#emailData.content, data)
    }

    sendEmail() {
        return pushIntoMailQueue({
            to: this.#data.to,
            from: this.#data.from,
            subject: this.#emailData.subject,
            message: this.render(),
            isHTML: true
        })
    }
}



module.exports = {
    sendEmail,
    CreateEmailFactory,
    popEmailFromEmailQueue
}
