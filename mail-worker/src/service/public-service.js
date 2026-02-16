const BizError = require('../error/biz-error');
const orm = require('../entity/orm');
const { v4: uuidv4 } = require('uuid');
const { and, asc, desc, eq, sql } = require('drizzle-orm');
const saltHashUtils = require('../utils/crypto-utils');
const cryptoUtils = require('../utils/crypto-utils');
const emailUtils = require('../utils/email-utils');
const roleService = require('./role-service');
const verifyUtils = require('../utils/verify-utils');
const { t } = require('../i18n/i18n');
const reqUtils = require('../utils/req-utils');
const dayjs = require('dayjs');
const { isDel, roleConst } = require('../const/entity-const');
const email = require('../entity/email');
const userService = require('./user-service');
const KvConst = require('../const/kv-const');

const publicService = {
  async emailList(c, params) {
    // 密码校验核心逻辑
    const { email: userEmail, password } = params;
    if (!userEmail || !password) {
      throw new BizError(t('IncompleteInfo'));
    }
    await this.verifyUser(c, { email: userEmail, password });

    // 原有查询逻辑
    let { toEmail, content, subject, sendName, sendEmail, timeSort, num, size, type, isDel: emailIsDel } = params;
    const query = orm(c).select({
      emailId: email.emailId,
      sendName: email.name,
      sendEmail: email.sendEmail,
      subject: email.subject,
      toEmail: email.toEmail,
      toName: email.toName,
      type: email.type,
      createTime: email.createTime,
      content: email.content,
      text: email.text,
      isDel: email.isDel
    }).from(email);

    if (!size) size = 20;
    if (!num) num = 1;
    size = Number(size);
    num = Number(num);
    num = (num - 1) * size;

    let conditions = [];
    if (toEmail) conditions.push(sql`${email.toEmail} COLLATE NOCASE LIKE ${toEmail}`);
    if (sendEmail) conditions.push(sql`${email.sendEmail} COLLATE NOCASE LIKE ${sendEmail}`);
    if (sendName) conditions.push(sql`${email.name} COLLATE NOCASE LIKE ${sendName}`);
    if (subject) conditions.push(sql`${email.subject} COLLATE NOCASE LIKE ${subject}`);
    if (content) conditions.push(sql`${email.content} COLLATE NOCASE LIKE ${content}`);
    if (type || type === 0) conditions.push(eq(email.type, type));
    if (emailIsDel || emailIsDel === 0) conditions.push(eq(email.isDel, emailIsDel));

    if (conditions.length === 1) {
      query.where(...conditions);
    } else if (conditions.length > 1) {
      query.where(and(...conditions));
    }

    if (timeSort === 'asc') {
      query.orderBy(asc(email.emailId));
    } else {
      query.orderBy(desc(email.emailId));
    }

    return query.limit(size).offset(num);
  },

  async addUser(c, params) {
    const { list } = params;
    if (list.length === 0) return;

    for (const emailRow of list) {
      if (!verifyUtils.isEmail(emailRow.email)) {
        throw new BizError(t('notEmail'));
      }
      if (!c.env.domain.includes(emailUtils.getDomain(emailRow.email))) {
        throw new BizError(t('notEmailDomain'));
      }
      const { salt, hash } = await saltHashUtils.hashPassword(
        emailRow.password || cryptoUtils.genRandomPwd()
      );
      emailRow.salt = salt;
      emailRow.hash = hash;
    }

    const activeIp = reqUtils.getIp(c);
    const { os, browser, device } = reqUtils.getUserAgent(c);
    const activeTime = dayjs().format('YYYY-MM-DD HH:mm:ss');
    const roleList = await roleService.roleSelectUse(c);
    const defRole = roleList.find(roleRow => roleRow.isDefault === roleConst.isDefault.OPEN);
    const userList = [];

    for (const emailRow of list) {
      let { email, hash, salt, roleName } = emailRow;
      let type = defRole.roleId;
      if (roleName) {
        const roleRow = roleList.find(role => role.name === roleName);
        type = roleRow ? roleRow.roleId : type;
      }

      const userSql = `INSERT INTO user (email, password, salt, type, os, browser, active_ip, create_ip, device, active_time, create_time)
VALUES ('${email}', '${hash}', '${salt}', '${type}', '${os}', '${browser}', '${activeIp}', '${activeIp}', '${device}', '${activeTime}', '${activeTime}')`;
      const accountSql = `INSERT INTO account (email, name, user_id)
VALUES ('${email}', '${emailUtils.getName(email)}', 0);`;

      userList.push(c.env.db.prepare(userSql));
      userList.push(c.env.db.prepare(accountSql));
    }

    userList.push(c.env.db.prepare(`UPDATE account SET user_id = (SELECT user_id FROM user WHERE user.email = account.email) WHERE user_id = 0;`));

    try {
      await c.env.db.batch(userList);
    } catch (e) {
      if (e.message.includes('SQLITE_CONSTRAINT')) {
        throw new BizError(t('emailExistDatabase'));
      } else {
        throw e;
      }
    }
  },

  async genToken(c, params) {
    await this.verifyUser(c, params);
    const uuid = uuidv4();
    await c.env.kv.put(KvConst.PUBLIC_KEY, uuid);
    return { token: uuid };
  },

  async verifyUser(c, params) {
    const { email, password } = params;
    const userRow = await userService.selectByEmailIncludeDel(c, email);

    if (email !== c.env.admin) {
      throw new BizError(t('notAdmin'));
    }
    if (!userRow || userRow.isDel === isDel.DELETE) {
      throw new BizError(t('notExistUser'));
    }
    if (!await cryptoUtils.verifyPassword(password, userRow.salt, userRow.password)) {
      throw new BizError(t('IncorrectPwd'));
    }
  }
};

module.exports = publicService;
