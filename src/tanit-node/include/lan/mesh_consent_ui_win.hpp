#pragma once

// Optional Win32 UI on top of lan/mesh_consent.hpp.
//
// `ensure_win32_mesh_consent_prompt()` installs a process-wide prompt that
// shows ConsentDlg when a peer hits level=ask. Headless sessions (no input
// desktop) keep Deny. Language and dark/light follow appearance settings
// (en, de, es, fr, it, ar, zh — same tags as ConsentDlg).
//
// Not the LLM `/v1/chat/consent` pipe.

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "lan/mesh_consent.hpp"

#include "security/types.hpp"
#include "security/ui/win/ConsentDlg.hpp"
#include "security/ui/win/ConsentDlg_i18n.hpp"

#include "settings/win/settings_store.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

namespace pm::lan {
namespace mesh_consent_ui_detail {

inline bool desktop_interactive() noexcept
{
    HDESK d = ::OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
    if (!d)
        return false;
    ::CloseDesktop(d);
    return true;
}

inline bool theme_is_dark(media::settings::Theme t) noexcept
{
    switch (t) {
    case media::settings::Theme::Light:
        return false;
    case media::settings::Theme::Dark:
        return true;
    case media::settings::Theme::System:
    default:
        break;
    }
    HKEY key = nullptr;
    bool dark = false;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER,
                        L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                        0, KEY_READ, &key) == ERROR_SUCCESS) {
        DWORD value = 1;
        DWORD size = sizeof(value);
        DWORD type = 0;
        if (::RegQueryValueExW(key, L"AppsUseLightTheme", nullptr, &type,
                               reinterpret_cast<LPBYTE>(&value), &size) == ERROR_SUCCESS
            && type == REG_DWORD)
            dark = value == 0;
        ::RegCloseKey(key);
    }
    return dark;
}

inline const char* capability_label(const pm::security::ui::i18n::MeshStrings& s,
                                    std::string_view capability) noexcept
{
    if (capability == k_cap_vfs)
        return s.cap_vfs;
    if (capability == k_cap_audio_capture)
        return s.cap_audio_capture;
    if (capability == k_cap_video_capture)
        return s.cap_video_capture;
    if (capability == k_cap_chat_turn)
        return s.cap_chat_turn;
    if (capability == k_cap_tools_call)
        return s.cap_tools_call;
    return s.cap_other;
}

inline std::string operation_label(const pm::security::ui::i18n::MeshStrings& s,
                                   const std::string& operation)
{
    if (operation == "read" || operation == "stat" || operation == "resolve")
        return s.op_read;
    if (operation == "write" || operation == "mkdir" || operation == "move" || operation == "delete")
        return s.op_write;
    if (operation == "list")
        return s.op_list;
    if (operation.empty())
        return s.op_other;
    return operation;
}

inline std::string format_why(const pm::security::ui::i18n::MeshStrings& s,
                              const MeshConsentRequest& ask)
{
    const char* cap = capability_label(s, ask.capability);
    char buf[512];
    if (!ask.operation.empty()) {
        const std::string op = operation_label(s, ask.operation);
        std::snprintf(buf, sizeof(buf), s.why_op_fmt, ask.peer_name.c_str(), cap, op.c_str());
    } else {
        std::snprintf(buf, sizeof(buf), s.why_fmt, ask.peer_name.c_str(), cap);
    }
    return std::string(buf);
}

inline pm::security::ui::ConsentUiOptions load_ui_options()
{
    pm::security::ui::ConsentUiOptions opts;
    media::settings::AppearanceSettings app;
    std::string err;
    if (media::settings::load_appearance(app, err)) {
        opts.language = app.display_language.empty() ? "en" : app.display_language;
        opts.dark = theme_is_dark(app.theme);
    } else {
        opts.language = "en";
        opts.dark = true;
    }
    opts.aiAutoAvailable = false;
    opts.makeGrant = [](const pm::security::ToolRequest& r, pm::security::GrantLifetime lt,
                        std::vector<std::string> scopes) {
        pm::security::CapabilityGrant g;
        g.tool = r.tool;
        g.action = r.action;
        g.lifetime = lt;
        g.resourceScopes = std::move(scopes);
        g.sessionId = r.sessionId;
        g.approvedBy = "human";
        return g;
    };
    try {
        opts.settingsPath = media::settings::get_config_dir().generic_string();
    } catch (...) {
    }
    return opts;
}

} // namespace mesh_consent_ui_detail

inline pm::security::ConsentRequest to_security_consent_request(const MeshConsentRequest& ask,
                                                                std::string_view language)
{
    using pm::security::Action;
    using pm::security::Actor;
    using pm::security::ConsentRequest;
    using pm::security::Risk;
    using pm::security::ToolRequest;

    const auto& copy = pm::security::ui::i18n::mesh_strings_for(language);

    ConsentRequest out;
    out.title = copy.title;
    out.risk = (ask.capability == k_cap_vfs
                && (ask.operation == "write" || ask.operation == "mkdir" || ask.operation == "move"
                    || ask.operation == "delete"))
                   ? Risk::High
                   : Risk::Medium;
    out.whyNeeded = mesh_consent_ui_detail::format_why(copy, ask);
    out.possibleRisk = copy.possible_risk;
    if (!ask.resource.empty())
        out.resourcePreview.push_back(ask.resource);

    ToolRequest tool;
    tool.actor = Actor::User;
    tool.tool.toolId = "mesh." + ask.capability;
    tool.tool.provider = "builtin";
    tool.action = (ask.operation == "write" || ask.operation == "mkdir" || ask.operation == "move"
                   || ask.operation == "delete")
                      ? Action::Write
                      : Action::Read;
    tool.userVisibleIntent = out.whyNeeded;
    tool.sessionId = ask.peer_id;
    if (!ask.resource.empty()) {
        pm::security::ResourceTarget target;
        target.uri = ask.resource;
        tool.target = std::move(target);
    }
    out.request = std::move(tool);
    return out;
}

inline MeshConsentResult from_security_consent_result(const MeshConsentRequest& ask,
                                                      const pm::security::ConsentResult& picked)
{
    MeshConsentResult out;
    if (picked.kind != pm::security::DecisionKind::Allow) {
        out.answer = MeshConsentAnswer::Deny;
        return out;
    }
    const pm::security::GrantLifetime life =
        picked.grant ? picked.grant->lifetime : pm::security::GrantLifetime::Once;
    if (life == pm::security::GrantLifetime::Once || life == pm::security::GrantLifetime::Task) {
        out.answer = MeshConsentAnswer::AllowOnce;
        return out;
    }
    if (ask.capability == k_cap_vfs) {
        out.answer = (ask.operation == "write" || ask.operation == "mkdir" || ask.operation == "move"
                      || ask.operation == "delete")
                         ? MeshConsentAnswer::PersistWrite
                         : MeshConsentAnswer::PersistRead;
        return out;
    }
    out.answer = MeshConsentAnswer::PersistOn;
    return out;
}

inline MeshConsentResult win32_mesh_consent_prompt(const MeshConsentRequest& ask)
{
    if (!mesh_consent_ui_detail::desktop_interactive()) {
        MeshConsentResult denied;
        denied.answer = MeshConsentAnswer::Deny;
        return denied;
    }
    const auto opts = mesh_consent_ui_detail::load_ui_options();
    return from_security_consent_result(
        ask, pm::security::ui::show_consent_dialog(to_security_consent_request(ask, opts.language),
                                                   opts));
}

/// Installs the Win32 dialog as the process-wide mesh consent prompt once.
inline void ensure_win32_mesh_consent_prompt()
{
    static std::atomic_flag installed = ATOMIC_FLAG_INIT;
    if (installed.test_and_set(std::memory_order_relaxed))
        return;
    set_mesh_consent_prompt([](const MeshConsentRequest& ask) {
        return win32_mesh_consent_prompt(ask);
    });
}

} // namespace pm::lan

#endif // _WIN32
