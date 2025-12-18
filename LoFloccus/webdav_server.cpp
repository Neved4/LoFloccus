#include "webdav_server.h"

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
pid_t serverPid = -1;
std::string prefixDir;
std::string configPath;
std::string authPath;

bool ensureDir(const std::string &path)
{
	if (mkdir(path.c_str(), 0755) == 0) {
		return true;
	}
	return errno == EEXIST;
}

std::string tempBase()
{
	const char *env = std::getenv("TMPDIR");
	if (env && env[0] != '\0') {
		return std::string(env) + "/lofloccus-httpd";
	}
	return "/tmp/lofloccus-httpd";
}

std::string hashPassword(const std::string &password)
{
	const char *salt = "lf";
	char *hashed = crypt(password.c_str(), salt);
	if (hashed == nullptr) {
		return "";
	}
	return std::string(hashed);
}

bool writeAuthFile(const std::string &user, const std::string &password)
{
	if (user.empty() || password.empty()) {
		return false;
	}

	authPath = prefixDir + "/htpasswd";
	std::ofstream auth(authPath.c_str(), std::ios::trunc);
	if (!auth.is_open()) {
		return false;
	}

	std::string hashed = hashPassword(password);
	if (hashed.empty()) {
		return false;
	}

	auth << user << ":" << hashed << "\n";
	return true;
}

bool writeConfig(const std::string &address, const std::string &port,
	const std::string &root, const std::string &user,
	const std::string &password)
{
	prefixDir = tempBase();
	if (!ensureDir(prefixDir) || !ensureDir(prefixDir + "/logs")) {
		return false;
	}

	if (!writeAuthFile(user, password)) {
		return false;
	}

	configPath = prefixDir + "/httpd.conf";
	std::ofstream cfg(configPath.c_str(), std::ios::trunc);
	if (!cfg.is_open()) {
		return false;
	}

	cfg << "ServerRoot \"/etc/apache2\"\n";
	cfg << "PidFile " << prefixDir << "/httpd.pid\n";
	cfg << "Listen " << address << ":" << port << "\n";
	cfg << "ServerName lofloccus.local\n";
	cfg << "LoadModule mpm_event_module "
		"/usr/libexec/apache2/mod_mpm_event.so\n";
	cfg << "LoadModule authn_file_module "
		"/usr/libexec/apache2/mod_authn_file.so\n";
	cfg << "LoadModule authz_core_module "
		"/usr/libexec/apache2/mod_authz_core.so\n";
	cfg << "LoadModule auth_basic_module "
		"/usr/libexec/apache2/mod_auth_basic.so\n";
	cfg << "LoadModule dav_module "
		"/usr/libexec/apache2/mod_dav.so\n";
	cfg << "LoadModule dav_fs_module "
		"/usr/libexec/apache2/mod_dav_fs.so\n";
	cfg << "LoadModule unixd_module "
		"/usr/libexec/apache2/mod_unixd.so\n";
	cfg << "LoadModule dir_module "
		"/usr/libexec/apache2/mod_dir.so\n";
	cfg << "LoadModule mime_module "
		"/usr/libexec/apache2/mod_mime.so\n";
	cfg << "LoadModule alias_module "
		"/usr/libexec/apache2/mod_alias.so\n";
	cfg << "User _www\n";
	cfg << "Group _www\n";
	cfg << "Timeout 30\n";
	cfg << "ErrorLog " << prefixDir << "/logs/error.log\n";
	cfg << "CustomLog " << prefixDir << "/logs/access.log combined\n";
	cfg << "DocumentRoot \"" << root << "\"\n";
	cfg << "<Directory \"" << root << "\">\n";
	cfg << "  Options Indexes FollowSymLinks\n";
	cfg << "  AllowOverride None\n";
	cfg << "  Require all granted\n";
	cfg << "</Directory>\n";
	cfg << "DAVLockDB " << prefixDir << "/DavLock\n";
	cfg << "<Location />\n";
	cfg << "  DAV On\n";
	cfg << "  AuthType Basic\n";
	cfg << "  AuthName \"Restricted\"\n";
	cfg << "  AuthUserFile " << authPath << "\n";
	cfg << "  Require valid-user\n";
	cfg << "</Location>\n";

	return true;
}
}

bool serverStart(const std::string &address, const std::string &port,
	const std::string &root, const std::string &user,
	const std::string &password)
{
	if (serverPid > 0) {
		serverStop();
	}
	if (!writeConfig(address, port, root, user, password)) {
		return false;
	}

	pid_t pid = fork();
	if (pid < 0) {
		return false;
	}
	if (pid == 0) {
		execlp("httpd",
			"httpd",
			"-f",
			configPath.c_str(),
			"-DFOREGROUND",
			static_cast<char *>(0));
		_exit(1);
	}

	serverPid = pid;
	return true;
}

void serverStop()
{
	if (serverPid <= 0) {
		return;
	}
	kill(serverPid, SIGTERM);
	waitpid(serverPid, 0, 0);
	serverPid = -1;
}
