#pragma once

#include <string>
#include <vector>

namespace KeyAuth {

struct Subscription {
    std::string name;
    std::string expiry;
};

struct UserData {
    std::string username;
    std::string ip;
    std::string hwid;
    std::string createdate;
    std::string lastlogin;
    std::vector<Subscription> subscriptions;
};

struct AuthResponse {
    bool success = false;
    std::string message;
    bool isPaid = false;
};

class Client {
public:
    Client(std::string name, std::string ownerId, std::string version, std::string apiUrl, std::string apiPath);

    AuthResponse Init();
    AuthResponse Login(const std::string& username, const std::string& password, const std::string& tfaCode = "");
    AuthResponse Register(const std::string& username, const std::string& password, const std::string& licenseKey);
    AuthResponse CheckSession();
    AuthResponse CheckKeyStatus(const std::string& licenseKey);

    const UserData& user() const { return user_; }
    const AuthResponse& response() const { return lastResponse_; }
    bool authenticated() const { return authenticated_; }

private:
    AuthResponse Post(const std::string& body);
    std::string BuildHwid() const;

    std::string name_;
    std::string ownerId_;
    std::string version_;
    std::string apiUrl_;
    std::string apiPath_;
    std::string sessionId_;
    std::string hwid_;
    UserData user_;
    AuthResponse lastResponse_;
    bool authenticated_ = false;
};

} // namespace KeyAuth
