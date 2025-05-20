#pragma once

#include "helpers.h"

#include <windows.h>
#include <wincred.h>
#include <string>

class TOTPCredentials
{
public:
    static bool AddCredential(
        const std::wstring& target,
        const std::wstring& username,
        const std::wstring& password,
        DWORD persistence = CRED_PERSIST_LOCAL_MACHINE,
        const std::wstring& comment = L""
    ) {
        CREDENTIALW cred = { 0 };
        cred.Flags = 0;
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = const_cast<LPWSTR>(target.c_str());
        cred.Comment = const_cast<LPWSTR>(comment.c_str());
        cred.CredentialBlobSize = static_cast<DWORD>(password.size() * sizeof(wchar_t));
        cred.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<wchar_t*>(password.c_str()));
        cred.Persist = persistence;
        cred.UserName = const_cast<LPWSTR>(username.c_str());

        return CredWriteW(&cred, 0);
    }

    static bool RemoveCredential(const std::wstring& target) {
        return CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0);
    }

    static void LogCredentials() {
        PCREDENTIALW* pcred = NULL;
        DWORD count = 0;

        BOOL result = CredEnumerateW(NULL, 0, &count, &pcred);

        if (result) {
            for (DWORD i = 0; i < count; i++) {
                std::wstring targetName = (*pcred)[i].TargetName;
                std::wstring userName = (*pcred)[i].UserName;
                int type = (*pcred)[i].Type;

                std::wstring log = L"Credential";
                log += L"[" + std::to_wstring(i) + L"]";
                log += L" = " + targetName;
                log += L" :: " + userName;
                log += L" :: " + std::to_wstring(type);
                LogToEventViewer(log);
                log = L"";
            }
            CredFree(pcred);
        }
        else {
            DWORD error = GetLastError();
            LogToEventViewer(L"Error enumerating credentials: " + std::to_wstring(error));
        }
    }

    static bool GetCredentials(const std::wstring& target, std::wstring& username, std::wstring& password) {
#ifndef NDEBUG
            TOTPCredentials::LogCredentials();
#endif

        PCREDENTIALW pCredential = nullptr;

        if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &pCredential)) {
            std::wstring error_msg = target;
            error_msg += L" credentials weren't found";
            LogToEventViewer(error_msg);
            return false; // Credential не найдено
        }

        // Извлекаем данные
        username = pCredential->UserName;
        LogToEventViewer(username);

        if (pCredential->CredentialBlob && pCredential->CredentialBlobSize > 0) {
            password.assign(
                reinterpret_cast<wchar_t*>(pCredential->CredentialBlob),
                pCredential->CredentialBlobSize / sizeof(wchar_t)
            );
        }
        else {
            password.clear();
        }
        LogToEventViewer(password);

        CredFree(pCredential);
        return true;
    }
};

