#include "webdav_server.h"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QHash>
#include <QRandomGenerator>
#include <QSaveFile>
#include <QUrl>

#include "httplib.h"

#include <atomic>
#include <mutex>
#include <memory>
#include <string>
#include <thread>

namespace {

struct ServerConfig {
	std::string address;
	std::string port;
	std::string root;
	std::string user;
	std::string password;
};

struct ServerState {
	ServerConfig cfg;
	std::unique_ptr<httplib::Server> server;
	std::thread loop;
	std::atomic<bool> running;
};

ServerState *state = nullptr;
QHash<QString, QString> pathToToken;
QHash<QString, QString> tokenToPath;
std::mutex locksMutex;

bool allowedExtension(const QString &path) {
	return path.endsWith(".xbel", Qt::CaseInsensitive) ||
		path.endsWith(".xbel.lock", Qt::CaseInsensitive) ||
		path.endsWith(".html", Qt::CaseInsensitive) ||
		path.endsWith(".htm", Qt::CaseInsensitive);
}

bool normalizePath(const std::string &path, const QString &root,
	QString &relOut, QString &fullOut) {
	QString decoded = QUrl::fromPercentEncoding(
		QByteArray::fromStdString(path));
	if (decoded.startsWith('/')) {
		decoded.remove(0, 1);
	}
	if (decoded.contains("..")) {
		return false;
	}
	relOut = QDir::cleanPath(decoded);
	fullOut = QDir(root).filePath(relOut);
	return true;
}

void replyAuth(httplib::Response &res) {
	res.status = 401;
	res.set_header("WWW-Authenticate",
		"Basic realm=\"Restricted\"");
}

bool checkAuth(const httplib::Request &req, httplib::Response &res,
	const ServerConfig &cfg) {
	auto header = req.get_header_value("Authorization");
	if (header.rfind("Basic ", 0) != 0) {
		replyAuth(res);
		return false;
	}
	QByteArray decoded = QByteArray::fromBase64(
		QByteArray::fromStdString(header.substr(6)));
	int sep = decoded.indexOf(':');
	if (sep < 0) {
		replyAuth(res);
		return false;
	}
	QString user = QString::fromUtf8(decoded.left(sep));
	QString pass = QString::fromUtf8(decoded.mid(sep + 1));
	if (user.toStdString() != cfg.user ||
		pass.toStdString() != cfg.password) {
		replyAuth(res);
		return false;
	}
	return true;
}

QString httpDate(const QDateTime &t) {
	return t.toUTC().toString("ddd, dd MMM yyyy HH:mm:ss 'GMT'");
}

QString escapeXml(const QString &value) {
	QString escaped = value;
	escaped.replace("&", "&amp;");
	escaped.replace("<", "&lt;");
	escaped.replace(">", "&gt;");
	escaped.replace("\"", "&quot;");
	escaped.replace("'", "&apos;");
	return escaped;
}

QString hrefFor(const QString &rel, bool isDir) {
	QString path = rel;
	if (!path.startsWith('/')) {
		path.prepend('/');
	}
	if (isDir && !path.endsWith('/')) {
		path.append('/');
	}
	return path;
}

QString buildPropXml(const QFileInfo &info, const QString &href) {
	QString xml;
	xml.append("<D:response>");
	xml.append("<D:href>");
	xml.append(escapeXml(href));
	xml.append("</D:href>");
	xml.append("<D:propstat><D:prop>");
	xml.append("<D:displayname>");
	xml.append(escapeXml(info.fileName()));
	xml.append("</D:displayname>");
	if (info.isFile()) {
		xml.append("<D:getcontentlength>");
		xml.append(QString::number(info.size()));
		xml.append("</D:getcontentlength>");
		xml.append("<D:resourcetype/>");
	} else {
		xml.append("<D:resourcetype><D:collection/></D:resourcetype>");
	}
	xml.append("<D:creationdate>");
	xml.append(info.birthTime().toUTC().toString(Qt::ISODate));
	xml.append("</D:creationdate>");
	xml.append("<D:getlastmodified>");
	xml.append(httpDate(info.lastModified()));
	xml.append("</D:getlastmodified>");
	xml.append("</D:prop><D:status>");
	xml.append("HTTP/1.1 200 OK");
	xml.append("</D:status></D:propstat>");
	xml.append("</D:response>");
	return xml;
}

bool ensureDirFor(const QString &path) {
	QFileInfo info(path);
	QDir dir = info.dir();
	if (dir.exists()) {
		return true;
	}
	return dir.mkpath(".");
}

QString lockTokenFromHeader(const std::string &value) {
	if (value.empty()) {
		return "";
	}
	QString header = QString::fromStdString(value);
	int idx = header.indexOf("opaquelocktoken:");
	if (idx < 0) {
		return "";
	}
	int end = header.indexOf('>', idx);
	return header.mid(idx, end > idx ? end - idx :
		header.length() - idx);
}

QString ensureLockToken(const QString &path) {
	QString token = "opaquelocktoken:" +
		QString::number(QRandomGenerator::global()->generate64(),
			16);
	std::lock_guard<std::mutex> guard(locksMutex);
	pathToToken.insert(path, token);
	tokenToPath.insert(token, path);
	return token;
}

bool isLocked(const QString &path, const QString &token) {
	std::lock_guard<std::mutex> guard(locksMutex);
	if (!pathToToken.contains(path)) {
		return false;
	}
	if (token.isEmpty()) {
		return true;
	}
	return pathToToken.value(path) != token;
}

bool unlockPath(const QString &path, const QString &token) {
	std::lock_guard<std::mutex> guard(locksMutex);
	if (!pathToToken.contains(path)) {
		return false;
	}
	if (pathToToken.value(path) != token) {
		return false;
	}
	pathToToken.remove(path);
	tokenToPath.remove(token);
	return true;
}

void handlePut(httplib::Response &res, const QString &fullPath,
	const httplib::Request &req) {
	QString token = lockTokenFromHeader(req.get_header_value("If"));
	if (isLocked(fullPath, token)) {
		res.status = 423;
		return;
	}
	if (!ensureDirFor(fullPath)) {
		res.status = 507;
		return;
	}
	QSaveFile file(fullPath);
	if (!file.open(QIODevice::WriteOnly)) {
		res.status = 507;
		return;
	}
	file.write(req.body.data(), static_cast<qint64>(req.body.size()));
	if (!file.commit()) {
		res.status = 507;
		return;
	}
	res.status = 201;
}

void handleDelete(httplib::Response &res, const QString &fullPath,
	const httplib::Request &req) {
	QString token = lockTokenFromHeader(req.get_header_value("If"));
	if (isLocked(fullPath, token)) {
		res.status = 423;
		return;
	}
	if (!QFile::exists(fullPath)) {
		res.status = 404;
		return;
	}
	if (!QFile::remove(fullPath)) {
		res.status = 507;
		return;
	}
	res.status = 204;
}

void handleGetHead(httplib::Response &res, const QString &fullPath,
	bool headOnly) {
	QFile file(fullPath);
	if (!file.exists()) {
		res.status = 404;
		return;
	}
	if (!file.open(QIODevice::ReadOnly)) {
		res.status = 507;
		return;
	}
	QByteArray data = file.readAll();
	res.status = 200;
	res.set_header("Cache-Control", "no-cache");
	if (!headOnly) {
		res.set_content(data.toStdString(), "application/octet-stream");
	} else {
		res.set_header("Content-Length",
			QString::number(data.size()).toStdString());
	}
}

void handleMkcol(httplib::Response &res, const QString &fullPath) {
	QDir dir(fullPath);
	if (dir.exists()) {
		res.status = 200;
		return;
	}
	if (dir.mkpath(".")) {
		res.status = 201;
	} else {
		res.status = 507;
	}
}

void handlePropfind(httplib::Response &res, const QString &relPath,
	const QString &fullPath, const std::string &depthHeader) {
	QFileInfo target(fullPath);
	if (!target.exists()) {
		res.status = 404;
		return;
	}
	int depth = 0;
	if (depthHeader == "1") {
		depth = 1;
	}
	QString xml = "<D:multistatus xmlns:D=\"DAV:\">";
	xml.append(buildPropXml(target, hrefFor(relPath, target.isDir())));
	if (target.isDir() && depth == 1) {
		QDir dir(fullPath);
		QFileInfoList entries = dir.entryInfoList(
			QDir::Dirs | QDir::Files | QDir::NoDotAndDotDot,
			QDir::Name | QDir::DirsFirst);
		for (const QFileInfo &entry : entries) {
			if (entry.isFile() &&
				!allowedExtension(entry.fileName())) {
				continue;
			}
			QString childRel = relPath;
			if (!childRel.isEmpty() && !childRel.endsWith('/')) {
				childRel.append('/');
			}
			childRel.append(entry.fileName());
			xml.append(buildPropXml(entry,
				hrefFor(childRel, entry.isDir())));
		}
	}
	xml.append("</D:multistatus>");
	std::string body = xml.toUtf8().toStdString();
	res.status = 207;
	res.set_header("Content-Type", "application/xml");
	res.set_content(body, "application/xml");
}

void handleLock(httplib::Response &res, const QString &relPath,
	const QString &fullPath) {
	if (!relPath.isEmpty() && !allowedExtension(relPath)) {
		res.status = 403;
		return;
	}
	if (!QFile::exists(fullPath)) {
		if (!ensureDirFor(fullPath)) {
			res.status = 507;
			return;
		}
		QSaveFile f(fullPath);
		f.open(QIODevice::WriteOnly);
		f.commit();
	}
	QString token = ensureLockToken(fullPath);
	QString body = "<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery>"
		"<D:activelock><D:locktype><D:write/></D:locktype>"
		"<D:lockscope><D:exclusive/></D:lockscope>"
		"<D:depth>infinity</D:depth><D:locktoken><D:href>";
	body.append(token);
	body.append("</D:href></D:locktoken></D:activelock>"
		"</D:lockdiscovery></D:prop>");
	res.status = 200;
	res.set_header("Content-Type", "application/xml");
	res.set_header("Lock-Token",
		QString("<%1>").arg(token).toStdString());
	res.set_content(body.toStdString(), "application/xml");
}

void handleUnlock(httplib::Response &res, const QString &fullPath,
	const httplib::Request &req) {
	QString token = lockTokenFromHeader(
		req.get_header_value("Lock-Token"));
	if (token.isEmpty()) {
		res.status = 400;
		return;
	}
	if (!unlockPath(fullPath, token)) {
		res.status = 409;
		return;
	}
	res.status = 204;
}

httplib::Server::HandlerResponse routeRequest(
	const httplib::Request &req, httplib::Response &res,
	const ServerConfig &cfg) {
	if (!checkAuth(req, res, cfg)) {
		return httplib::Server::HandlerResponse::Handled;
	}
	QString rel;
	QString full;
	if (!normalizePath(req.path, QString::fromStdString(cfg.root),
		rel, full)) {
		res.status = 403;
		return httplib::Server::HandlerResponse::Handled;
	}
	bool isFileOp = req.method == "GET" || req.method == "HEAD" ||
		req.method == "PUT" || req.method == "DELETE";
	if (isFileOp && !rel.isEmpty() && !allowedExtension(rel)) {
		res.status = 403;
		return httplib::Server::HandlerResponse::Handled;
	}
	if (req.method == "PROPFIND") {
		if (!rel.isEmpty()) {
			QFileInfo info(full);
			if (info.isFile() && !allowedExtension(rel)) {
				res.status = 403;
				return httplib::Server::HandlerResponse::Handled;
			}
		}
		auto depth = req.get_header_value("Depth");
		handlePropfind(res, rel, full, depth);
		return httplib::Server::HandlerResponse::Handled;
	}
	if (req.method == "MKCOL") {
		handleMkcol(res, full);
		return httplib::Server::HandlerResponse::Handled;
	}
	if (req.method == "LOCK") {
		handleLock(res, rel, full);
		return httplib::Server::HandlerResponse::Handled;
	}
	if (req.method == "UNLOCK") {
		handleUnlock(res, full, req);
		return httplib::Server::HandlerResponse::Handled;
	}
	if (req.method == "PUT") {
		handlePut(res, full, req);
		return httplib::Server::HandlerResponse::Handled;
	}
	if (req.method == "DELETE") {
		handleDelete(res, full, req);
		return httplib::Server::HandlerResponse::Handled;
	}
	if (req.method == "GET" || req.method == "HEAD") {
		handleGetHead(res, full, req.method == "HEAD");
		return httplib::Server::HandlerResponse::Handled;
	}
	res.status = 405;
	return httplib::Server::HandlerResponse::Handled;
}

} // namespace

bool serverStart(const std::string &address, const std::string &port,
	const std::string &root, const std::string &user,
	const std::string &password) {
	serverStop();
	state = new ServerState();
	state->cfg.address = address;
	state->cfg.port = port;
	state->cfg.root = root;
	state->cfg.user = user;
	state->cfg.password = password;
	state->server.reset(new httplib::Server());
	state->running = true;
	state->server->set_pre_routing_handler(
		[=](const httplib::Request &req, httplib::Response &res) {
			return routeRequest(req, res, state->cfg);
		});
	int portNum = std::stoi(port);
	state->loop = std::thread([=]() {
		state->server->listen(address.c_str(), portNum);
		state->running = false;
	});
	return true;
}

void serverStop() {
	if (state == nullptr) {
		return;
	}
	if (state->server) {
		state->server->stop();
	}
	if (state->loop.joinable()) {
		state->loop.join();
	}
	delete state;
	state = nullptr;
}
