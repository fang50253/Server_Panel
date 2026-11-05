'use strict';

/**
 * Alert message construction.
 *
 * Both alert types are rendered through the mail panel's `security-alert`
 * template (title, detail, action, url), so the wording lives here and the
 * visual design stays in one place.
 */

const { formatBytes, formatMbps } = require('./metrics');

const METRIC_LABEL = {
  cpu: 'CPU',
  mem: '内存',
  net: '网络',
};

function pad(n) {
  return String(n).padStart(2, '0');
}

/** "2026-11-05 09:41:07 (UTC)" — explicit zone, because the server is UTC. */
function formatTime(ms) {
  const d = new Date(ms);
  return (
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} (UTC)`
  );
}

function formatDuration(minutes) {
  if (minutes < 60) return `${minutes} 分钟`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return m ? `${h} 小时 ${m} 分钟` : `${h} 小时`;
}

function formatValue(metric, value) {
  if (metric === 'net') return formatMbps(value);
  return `${value.toFixed(1)}%`;
}

function formatThreshold(metric, threshold) {
  if (metric === 'net') return formatMbps(threshold);
  return `${threshold}%`;
}

/** Why this alert fired, in words the recipient can act on. */
function reasonText(action, rules) {
  const parts = [];
  if (action.consecutive >= rules.consecutive) {
    parts.push(`连续 ${action.consecutive} 次超过阈值`);
  }
  if (action.windowCount >= rules.windowCount) {
    parts.push(`${formatDuration(rules.windowMinutes)}内累计 ${action.windowCount} 次超过阈值`);
  }
  return parts.join('，') || '达到告警阈值';
}

/**
 * Resource alert.
 *
 * `detail` is multi-line: readable as plain text, and collapses to a flowing
 * paragraph in the HTML template.
 */
function buildResourceAlert({ action, sample, rules, host, url, now = Date.now() }) {
  const metric = action.metric;
  const label = METRIC_LABEL[metric] || metric;
  const value = formatValue(metric, action.value);
  const threshold = formatThreshold(metric, action.threshold);

  const lines = [
    `服务器 ${host} 的${label}占用持续过高。`,
    '',
    `${label}占用：${value}（告警阈值 ${threshold}）`,
    `触发条件：${reasonText(action, rules)}`,
  ];

  if (action.peak !== null && action.peak !== undefined) {
    lines.push(`本轮峰值：${formatValue(metric, action.peak)}`);
  }

  if (metric === 'mem' && sample && sample.mem) {
    lines.push(
      `内存明细：已用 ${formatBytes(sample.mem.usedBytes)} / 共 ${formatBytes(sample.mem.totalBytes)}，` +
        `可用 ${formatBytes(sample.mem.availableBytes)}`,
    );
  }

  if (metric === 'net' && sample && sample.net) {
    lines.push(
      `网络明细：入站 ${formatMbps(sample.net.rxMbps)}，出站 ${formatMbps(sample.net.txMbps)}`,
    );
  }

  if (metric === 'cpu' && sample && sample.cpuPercent !== null) {
    lines.push(`当前 CPU：${sample.cpuPercent.toFixed(1)}%，核心数 ${sample.cpuCores}`);
  }

  lines.push('', `检测时间：${formatTime(now)}`, `告警冷却：${formatDuration(rules.cooldownMinutes)}`);

  return {
    template: 'security-alert',
    vars: {
      title: `服务器${label}占用持续过高`,
      detail: lines.join('\n'),
      action: `请登录服务器检查 ${label} 占用情况，确认是否有异常进程、内存泄漏或流量突增。`,
      url,
    },
  };
}

/**
 * SSH new-IP alert.
 *
 * The requirement is explicit: the email must state country/region and the
 * login time, because that is what tells you whether the login was you.
 */
function buildSshAlert({ ip, user, method, ts, geo, host, url, isFirstEver = true }) {
  const when = formatTime(ts);
  const where = geo && geo.ok
    ? [geo.country, geo.city || geo.region].filter(Boolean).join(' · ')
    : '未知（GeoIP 查询失败）';

  const lines = [
    `服务器 ${host} 收到一个${isFirstEver ? '从未出现过' : ''}的全新 IP 的 SSH 登录。`,
    '',
    `来源 IP：${ip}`,
    `国家/地区：${where}`,
  ];

  if (geo && geo.ok && geo.org) lines.push(`网络归属：${geo.org}`);
  if (geo && geo.ok && geo.timezone) lines.push(`IP 时区：${geo.timezone}`);

  lines.push(
    `登录用户：${user}`,
    `认证方式：${method}`,
    `登录时间：${when}`,
    `服务器：${host}`,
  );

  return {
    template: 'security-alert',
    vars: {
      title: `全新 IP 登录：${ip}`,
      detail: lines.join('\n'),
      action:
        '如果这是你本人登录，可忽略本邮件；如果不是，请立即修改 SSH 密码与密钥，并在 panel.example.com 检查登录记录。',
      url,
    },
  };
}

/**
 * SSH brute-force alert.
 *
 * States the count, the window, the targeted usernames and the country, plus
 * the first/last attempt times. Those are the facts needed to judge severity
 * without logging into the box.
 */
function buildSshFailAlert({ ip, count, windowMinutes, users, first, last, geo, host, url, cooldownMinutes }) {
  const where = geo && geo.ok
    ? [geo.country, geo.city || geo.region].filter(Boolean).join(' · ')
    : '未知（GeoIP 查询失败）';

  const lines = [
    `服务器 ${host} 检测到同一 IP 在短时间内多次 SSH 登录失败，疑似暴力破解。`,
    '',
    `来源 IP：${ip}`,
    `国家/地区：${where}`,
  ];

  if (geo && geo.ok && geo.org) lines.push(`网络归属：${geo.org}`);

  lines.push(
    `失败次数：${count} 次`,
    `统计窗口：${formatDuration(windowMinutes)}内`,
    `尝试用户名：${(users || []).join(', ') || '未知'}`,
    `首次尝试：${formatTime(first)}`,
    `最近尝试：${formatTime(last)}`,
    `服务器：${host}`,
  );

  return {
    template: 'security-alert',
    vars: {
      title: `SSH 暴力破解告警：${ip}`,
      detail: lines.join('\n'),
      action:
        '如果这不是你在测试密码，请立即封禁该 IP（例如 ufw deny from <IP>），并确认 root 密码强度与密码登录是否必要。' +
        `同一 IP 在 ${formatDuration(cooldownMinutes)}内不会重复提醒。`,
      url,
    },
  };
}

module.exports = {
  buildResourceAlert,
  buildSshAlert,
  buildSshFailAlert,
  formatTime,
  formatDuration,
  formatValue,
  formatThreshold,
  METRIC_LABEL,
};
