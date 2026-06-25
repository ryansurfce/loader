#include "auth_screen.h"

#include "../auth/credentials.h"
#include "../auth/keyauth.h"
#include "theme.h"
#include "widgets.h"

#include "imgui.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <future>
#include <thread>

namespace AuthScreen {
namespace {

struct PendingAuth {
    std::future<KeyAuth::AuthResponse> future;
    Mode mode{};
    bool rememberMe = false;
    char username[128]{};
    char password[128]{};
    char licenseKey[128]{};
};

PendingAuth g_pending{};
bool g_hasPending = false;

void SetStatus(State& state, const char* message) {
    std::strncpy(state.statusMessage, message, sizeof(state.statusMessage) - 1);
}

void StartAuth(State& state, KeyAuth::Client& client) {
    if (g_hasPending) {
        return;
    }

    state.loading = true;
    SetStatus(state, "Connecting to KeyAuth...");

    g_pending.mode = state.mode;
    g_pending.rememberMe = state.rememberMe;
    std::strncpy(g_pending.username, state.username, sizeof(g_pending.username) - 1);
    std::strncpy(g_pending.password, state.password, sizeof(g_pending.password) - 1);
    std::strncpy(g_pending.licenseKey, state.licenseKey, sizeof(g_pending.licenseKey) - 1);

    if (state.mode == Mode::Login) {
        const std::string user = state.username;
        const std::string pass = state.password;
        const std::string tfa = state.needsTfa ? state.tfaCode : "";
        g_pending.future = std::async(std::launch::async, [&client, user, pass, tfa]() {
            return client.Login(user, pass, tfa);
        });
    } else { // Register mode
        const std::string user = state.username;
        const std::string pass = state.password;
        const std::string key = state.licenseKey;
        g_pending.future = std::async(std::launch::async, [&client, user, pass, key]() {
            return client.Register(user, pass, key);
        });
    }

    g_hasPending = true;
}

void PollAuth(State& state, KeyAuth::Client& client) {
    if (!g_hasPending) {
        return;
    }

    if (g_pending.future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        return;
    }

    const KeyAuth::AuthResponse response = g_pending.future.get();
    state.loading = false;
    g_hasPending = false;

    if (!response.success) {
        if (response.message == "2FA code required.") {
            state.needsTfa = true;
            SetStatus(state, "Enter your 2FA code.");
            return;
        }
        SetStatus(state, response.message.empty() ? "Authentication failed." : response.message.c_str());
        return;
    }

    state.needsTfa = false;
    state.authenticated = true;
    SetStatus(state, "Welcome back!");

    Credentials::SavedCreds creds;
    creds.rememberMe = g_pending.rememberMe;
    creds.username = g_pending.username;
    creds.password = g_pending.password;
    creds.licenseKey = g_pending.licenseKey;
    if (creds.rememberMe) {
        Credentials::Save(creds);
    } else {
        Credentials::Clear();
    }
}

void DrawTabButton(const char* label, Mode mode, State& state, float* hoverAnim) {
    const bool active = state.mode == mode;
    if (active) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.35f, 0.55f, 1.0f, 0.55f));
    }
    if (UiWidgets::GradientButton(label, ImVec2(110.0f, 34.0f), hoverAnim)) {
        state.mode = mode;
    }
    if (active) {
        ImGui::PopStyleColor();
    }
    ImGui::SameLine();
}

} // namespace

void Init(State& state, KeyAuth::Client& client) {
    if (const auto saved = Credentials::Load()) {
        std::strncpy(state.username, saved->username.c_str(), sizeof(state.username) - 1);
        std::strncpy(state.password, saved->password.c_str(), sizeof(state.password) - 1);
        std::strncpy(state.licenseKey, saved->licenseKey.c_str(), sizeof(state.licenseKey) - 1);
        state.rememberMe = saved->rememberMe;

        state.loading = true;
        SetStatus(state, "Restoring saved session...");

        if (!saved->licenseKey.empty()) {
            // Check if license key is still valid
            const std::string key = saved->licenseKey;
            g_pending.future = std::async(std::launch::async, [&client, key]() {
                return client.CheckKeyStatus(key);
            });
        } else if (!saved->username.empty()) {
            state.mode = Mode::Login;
            const std::string user = saved->username;
            const std::string pass = saved->password;
            g_pending.future = std::async(std::launch::async, [&client, user, pass]() {
                return client.Login(user, pass);
            });
        }
        g_hasPending = true;
    }
}

void Render(State& state, KeyAuth::Client& client) {
    const float dt = UiTheme::DeltaTime();
    state.fadeIn = std::min(1.0f, state.fadeIn + dt * 2.5f);
    state.tabAnim = (state.mode == Mode::Login) ? 0.0f : 1.0f;

    PollAuth(state, client);

    const ImVec2 windowSize(420.0f, 520.0f);
    ImGui::SetNextWindowSize(windowSize, ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));

    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, state.fadeIn);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
    ImGui::Begin("Auth", nullptr,
                 ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar |
                     ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBackground);

    ImDrawList* drawList = ImGui::GetWindowDrawList();
    const ImVec2 winPos = ImGui::GetWindowPos();
    const ImVec2 winSize = ImGui::GetWindowSize();
    UiWidgets::DrawRoundedPanel(drawList, winPos, ImVec2(winPos.x + winSize.x, winPos.y + winSize.y), 18.0f,
                                ImGui::ColorConvertFloat4ToU32(ImVec4(0.08f, 0.09f, 0.12f, 0.82f)),
                                ImGui::ColorConvertFloat4ToU32(ImVec4(0.35f, 0.55f, 1.0f, 0.35f)));

    const ImVec2 logoCenter(winPos.x + winSize.x * 0.5f, winPos.y + 70.0f);
    UiWidgets::DrawLogo(drawList, logoCenter, 34.0f, static_cast<float>(ImGui::GetTime()));

    ImGui::SetCursorPosY(120.0f);
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]);
    {
        const char* title = "Pulse Optimizer";
        const ImVec2 titleSize = ImGui::CalcTextSize(title);
        ImGui::SetCursorPosX((winSize.x - titleSize.x) * 0.5f);
        ImGui::TextUnformatted(title);
    }
    ImGui::PopFont();

    ImGui::SetCursorPosY(155.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.65f, 0.70f, 0.82f, 1.0f));
    {
        const char* subtitle = "Secure loader powered by KeyAuth";
        const ImVec2 subSize = ImGui::CalcTextSize(subtitle);
        ImGui::SetCursorPosX((winSize.x - subSize.x) * 0.5f);
        ImGui::TextUnformatted(subtitle);
    }
    ImGui::PopStyleColor();

    ImGui::SetCursorPos(ImVec2(24.0f, 190.0f));
    DrawTabButton("Login", Mode::Login, state, &state.loginHover);
    DrawTabButton("Register", Mode::Register, state, &state.registerHover);

    ImGui::SetCursorPos(ImVec2(24.0f, 240.0f));
    ImGui::BeginChild("AuthForm", ImVec2(winSize.x - 48.0f, 200.0f), false, ImGuiWindowFlags_NoScrollbar);

    if (state.mode == Mode::Login) {
        ImGui::TextUnformatted("Username");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##username", state.username, sizeof(state.username));

        ImGui::TextUnformatted("Password");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##password", state.password, sizeof(state.password), ImGuiInputTextFlags_Password);
    } else { // Register mode
        ImGui::TextUnformatted("Username");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##username", state.username, sizeof(state.username));

        ImGui::TextUnformatted("Password");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##password", state.password, sizeof(state.password), ImGuiInputTextFlags_Password);

        ImGui::TextUnformatted("License Key");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##license", state.licenseKey, sizeof(state.licenseKey));
    }

    if (state.needsTfa) {
        ImGui::TextUnformatted("2FA Code");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##tfa", state.tfaCode, sizeof(state.tfaCode));
    }

    UiWidgets::AnimatedCheckbox("Remember me", &state.rememberMe, &state.rememberAnim);
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(24.0f, 455.0f));
    const char* actionLabel = state.mode == Mode::Login ? "Sign In" : "Create Account & Activate";
    if (UiWidgets::GradientButton(actionLabel, ImVec2(winSize.x - 48.0f, 42.0f), &state.loginHover) && !state.loading) {
        StartAuth(state, client);
    }

    if (state.loading) {
        UiWidgets::DrawSpinner(drawList, ImVec2(winPos.x + winSize.x * 0.5f, winPos.y + 430.0f), 16.0f,
                               static_cast<float>(ImGui::GetTime()));
    }

    if (state.statusMessage[0] != '\0') {
        ImGui::SetCursorPos(ImVec2(24.0f, 410.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, state.authenticated ? ImVec4(0.4f, 0.9f, 0.5f, 1.0f) : ImVec4(1.0f, 0.45f, 0.45f, 1.0f));
        ImGui::TextWrapped("%s", state.statusMessage);
        ImGui::PopStyleColor();
    }

    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();
}

} // namespace AuthScreen
