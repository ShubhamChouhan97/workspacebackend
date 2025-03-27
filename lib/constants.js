const listenPort = global.argv[0] || 5555;
const fs = require('fs');
const path = require('path');


const longTermSessionExpireTime_Seconds = 60 * 60 * 24 * 7;
const sessionSecret = process.env.SESSION_SECRET;
const jwtSecret = process.env.JWT_SECRET;
const workspaceBackendKey = process.env.WORKSPACE_BACKEND_KEY;
const sessionPrefix = 'sess';
const sessionExpireTime_Seconds = 60 * 60;

const workSpaceTypes = {
    basicType: 1,
    courseType: 2,
    classType: 3,
}

const channelTypes = {
    basicType: 1,
    courseType: 2,
    classType: 3,
    privateType: 4,
}

const notificationTypes = {
    replyType: 1,
    mentionType: 2,
    addChannelType: 3,
    unreadMessageType: 4,
}

const messageType = {
    basic: 1,
    pinned: 2,
    poll: 3,
}

const messageStatus = {
    active: 1,
    edit:2,
    deleted: 3,
}

const messageEventType = {
    addType: 1,
    editType: 2,
    deleteType: 3,
}

const replyEventType = {
    addType: 1,
    editType: 2,
    deleteType: 3,
}

const channelWritePermissionType = {
    everyone: 1,
    adminsOnly: 2,  // all non students are included
}

const redisLockKeys = {
    'defaultKey': 'defaultKey',
    'streamKey': 'streamKey',
    'userActivityStreamKey': 'userActivityStreamKey',
    'notificationKey': 'notificationKey',
    'upcomingWorkspaceNotificationKey': 'upcomingWorkspaceNotificationKey',
}

const redisKeys = {
    'userData': 'userData',
    'id': 'id',
    'role': 'role',
    'email': 'email',
    'profilePic': 'profilePic',
    'displayname': 'displayname',
    'lastActive': 'lastActive',
    'messageCount': 'messageCount',
    'socketDataHash': 'socketDataHash',
    'workspaceId': 'workspaceId',
    'channelId': 'channelId',
    'userId': 'userId',
    'channelMsgStream': 'channelMsgStream',
    'userActivityStream': 'userActivityStream',
    'messageDataHash': 'messageDataHash',
    'messageId': 'messageId',
    'replyId': 'replyId',
    'activeChannelIdsSet': 'activeChannelIdsSet',
    'activeWorkspaceIdsSet': 'activeWorkspaceIdsSet',
    'content': 'content',
    'mentions': 'mentions',
    'attachments': 'attachments',
    'status': 'status',
    'createdAt': 'createdAt',
    'updatedAt': 'updatedAt',
    'deletedAt': 'deletedAt',
    'deletedBy': 'deletedBy',
    'replyCount': 'replyCount',
    'isResolved': 'isResolved',
    'isDiscussionRequired': 'isDiscussionRequired',
    'likedByUserIdsSet': 'likedByUserIdsSet',
    'unlikedByUserIdsSet': 'unlikedByUserIdsSet',
    'likedByCount': 'likedByCount',
    'unlikedByCount': 'unlikedByCount',
    'activeStreamChannelIdsHash': 'activeStreamChannelIdsHash',
    'activeUsersActivityStreamSet': 'activeUsersActivityStreamSet',
    'pauseMessageWriteToDb': 'pauseMessageWriteToDb',
    'pauseUserActivityWriteToDb': 'pauseUserActivityWriteToDb',
    'pauseDbWrite': 'pauseDbWrite',
    'workspacesTimestampHash': 'workspacesTimestampHash',  // Contains timestamps for the upcoming notification
    'userChannelDataHash': 'userChannelDataHash',
    'likedMessageIds': 'likedMessageIds',
    'unlikedMessageIds': 'unlikedMessageIds',
    'channelWritePermissionValue': 'channelWritePermissionValue',
    'notifyUserIds': 'notifyUserIds',
    'type': 'type',
    '_id': '_id',
    'emailQueue': 'emailQueue'
}

const defaultMessageCountLimit = 10;
const defaultUserActivityCountLimit = 10;
const defaultNotificationCountLimit = 10;

const rediskeyExpiryTimesInSec = {
    channelMsgCount: 60 * 60 * 24 * 2,  // 2 Days
    userDataHash: 60 * 60 * 24 * 2,  // 2 Days
}

const cqBackendRoutes = {
    addWorkspaceInCourse: '/api/course/addWorkspace',
    removeWorkspaceFromCourse: '/api/course/removeWorkspace',
    sendUserNotificationEmail: '/api/sendUserNotificationEmail',
}

const workspaceNotificationType = {
    cqNotificationType: 1,
    emailNotificationType: 2,
    SMSNotificationType: 3,
}

const userRoleType = {
    "admin" : "0",
    "user" : "1",
    "mentor" : "2",
    'subAdmin' : '3',
    "contentCreator" : "4",
    "support": "5",
    "recruiter" : "6",
    "custom": "7",
};

const superAdminUserId = "59f9c87bbace049edfca78cf";

const state = {
    active: 1,
    inActive: 2,
}

const userActivityType = {
    addToWorkspace: 1,
    removeFromWorkspace: 2,
    addToChannel: 3,
    removeFromChannel: 4,
    addMessage: 5,
    addReply: 6,
    mentioned: 7,
    mentionedInReply: 8,
    resolved: 9,
    toDiscuss: 10,
}

const statusToNumber = {
    'error': 0,
    'success': 1,
}

const renderTemplateFile = ( templateName ) => {
    const filePath = path.join(__dirname, '../views/mailTemplate', `${templateName}.ejs`);
    const fileData = fs.readFileSync(filePath).toString();
    return fileData.toString();
}

const emailType = {
    NewUser: 1,
    ChannelInvite: 2,
    ForgotPassword: 3,
    UserAndChannelInvite: 4,
    fact:5,
}


const emailContent = {
    [emailType.NewUser]: {
        'subject': 'Welcome To CodeQuotient Discussion Portal',
        'content': renderTemplateFile('newUser'),
    },
    [emailType.ChannelInvite]: {
        'subject': 'Channel Invite',
        'content': renderTemplateFile('channelInvite'),
    },
    [emailType.ForgotPassword]: {
        'subject': 'Reset Password CodeQuotient Discussion Portal',
        'content': renderTemplateFile('forgotPassword'),
    },
    [emailType.UserAndChannelInvite]: {
        'subject': 'Channel Invite',
        'content': renderTemplateFile('userAndChannelInvite'),
    },
    [emailType.fact]: {
        'subject': 'OTP For Login',
        'content': renderTemplateFile('fa'), 
        }
}

const queryParamsMessageType = {
    success: 1,
    error: 2,
}

const sessionUpdateCheckFieldName = 'isSessionUpdated';

module.exports = {
    listenPort,
    sessionSecret,
    jwtSecret,
    workspaceBackendKey,
    workSpaceTypes,
    channelTypes,
    notificationTypes,
    messageType,
    messageStatus,
    messageEventType,
    replyEventType,
    redisLockKeys,
    redisKeys,
    defaultMessageCountLimit,
    defaultUserActivityCountLimit,
    defaultNotificationCountLimit,
    rediskeyExpiryTimesInSec,
    cqBackendRoutes,
    workspaceNotificationType,
    userRoleType,
    superAdminUserId,
    state,
    channelWritePermissionType,
    userActivityType,
    statusToNumber,
    emailContent,
    emailType,
    sessionUpdateCheckFieldName,
    sessionPrefix,
    sessionExpireTime_Seconds,
    longTermSessionExpireTime_Seconds,
    queryParamsMessageType,
}