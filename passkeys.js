(() => {
    // Passkeys are bound to one RP domain. Keep Vercel preview visits on that domain.
    const registrationOrigin = "https://alepht08passkeyportfolio.vercel.app";
    if (window.location.hostname.endsWith(".vercel.app") && window.location.origin !== registrationOrigin) {
        window.location.replace(registrationOrigin + "/#private-info");
        return;
    }
    const form = document.getElementById("passkey-form");
    if (!form) return;
    const button = document.getElementById("passkey-register");
    const status = document.getElementById("passkey-status");
    const panel = document.getElementById("passkey-list-panel");
    const list = document.getElementById("passkey-list");
    const accountForm = document.getElementById("account-name-form");
    const accountInput = document.getElementById("account-name");
    const accountSave = document.getElementById("account-name-save");
    const accountStatus = document.getElementById("account-name-status");
    let accountVersion = 0;
    function clearAccount() {
        accountVersion++;
        accountInput.value = "";
        accountSave.hidden = true;
        accountSave.disabled = false;
        accountStatus.textContent = "";
    }
    async function signalAccount(account) {
        if (typeof window.PublicKeyCredential?.signalCurrentUserDetails !== "function") return false;
        try {
            await window.PublicKeyCredential.signalCurrentUserDetails({
                rpId: account.rpId, userId: account.userId, name: account.name, displayName: account.name
            });
            return true;
        } catch { return false; }
    }
    accountForm.addEventListener("submit", async event => {
        event.preventDefault();
        if (!authenticated) {
            accountStatus.textContent = "계정 이름을 입력한 뒤 아래 패스키 등록 버튼을 눌러 주세요.";
            return;
        }
        if (accountSave.disabled || !accountInput.reportValidity()) return;
        const version = ++accountVersion;
        accountSave.disabled = true;
        try {
            const data = await api("rename", { accountName: accountInput.value });
            if (!authenticated || version !== accountVersion) return;
            accountInput.value = data.account.name;
            const signalled = await signalAccount(data.account);
            if (!authenticated || version !== accountVersion) return;
            accountStatus.textContent = signalled
                ? "계정 이름을 저장하고 인증 기기에 이름 갱신을 요청했습니다. 인증 창 반영은 기기에 따라 다를 수 있습니다."
                : "계정 이름을 저장했습니다. 현재 브라우저나 인증 기기에서는 기존 패스키의 이름이 그대로 표시될 수 있습니다.";
        } catch (error) {
            if (version !== accountVersion) return;
            accountStatus.textContent = error.message;
            if (error.status === 401) window.dispatchEvent(new CustomEvent("t08-session-expired"));
        } finally { if (version === accountVersion) accountSave.disabled = false; }
    });
    let busy = false;
    let authenticated = false;
    let listVersion = 0;
    let knownCredentialIds = new Set();
    const help = document.getElementById("passkey-manage-help");

    function decode(value) {
        const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
        return Uint8Array.from(atob(base64 + "=".repeat((4 - base64.length % 4) % 4)), char => char.charCodeAt(0));
    }
    function encode(value) {
        return btoa(String.fromCharCode(...new Uint8Array(value))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    }
    async function api(action, body) {
        const response = await fetch(`/api/passkeys?action=${action}`, {
            method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store",
            headers: body === undefined ? {} : { "Content-Type": "application/json" },
            body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000)
        });
        let data;
        try { data = await response.json(); } catch { throw new Error("서버 응답을 확인하지 못했습니다."); }
        if (!response.ok) {
            const error = new Error(data.message || "등록 정보를 확인하지 못했습니다.");
            error.status = response.status;
            throw error;
        }
        return data;
    }
    async function refreshList() {
        const version = ++listVersion;
        try {
            const data = await api("list");
            if (version !== listVersion) return false;
            authenticated = data.authenticated === true;
            if (authenticated && data.account) {
                accountVersion++;
                accountSave.disabled = false;
                accountSave.hidden = false;
                accountInput.value = data.account.name;
                accountStatus.textContent = `현재 계정: ${data.account.name} · 이름을 변경한 뒤 저장해 주세요.`;
                void signalAccount(data.account);
            } else accountSave.hidden = true;
            knownCredentialIds = new Set((data.passkeys || []).map(item => item.credential_id));
            list.replaceChildren();
            for (const item of data.passkeys || []) {
                const row = document.createElement("li");
                const name = document.createElement("strong");
                const meta = document.createElement("small");
                name.textContent = item.name;
                const date = new Date(item.created_at).toLocaleString("ko-KR", { timeZone: "Asia/Seoul" });
                meta.textContent = `${item.storage_label} · 등록: ${date} (한국 시간)`;
                row.append(name, meta);
                if (authenticated) {
                    const remove = document.createElement("button");
                    remove.type = "button"; remove.className = "passkey-delete";
                    remove.textContent = "삭제";
                    remove.setAttribute("aria-label", `${item.name} 패스키 삭제`);
                    remove.disabled = data.passkeys.length <= 1;
                    if (remove.disabled) remove.title = "마지막 패스키는 삭제할 수 없습니다.";
                    remove.addEventListener("click", async () => {
                        if (busy || !window.confirm(`${item.name} 패스키를 삭제할까요? 삭제 후 남은 패스키로 다시 로그인해야 합니다.`)) return;
                        busy = true; remove.disabled = true;
                        try {
                            await api("delete", { credentialId: item.credential_id });
                            window.dispatchEvent(new CustomEvent("t08-passkey-deleted"));
                            status.textContent = "패스키를 삭제했습니다. 남은 패스키로 다시 로그인해 주세요.";
                        } catch (error) {
                            status.textContent = error.message;
                            if (error.status === 401) window.dispatchEvent(new CustomEvent("t08-session-expired"));
                            else await refreshList();
                        } finally { busy = false; }
                    });
                    row.append(remove);
                }
                list.append(row);
            }
            panel.hidden = !list.children.length;
            button.disabled = busy || (!authenticated && !!list.children.length);
            button.textContent = authenticated ? "패스키 추가 등록" : "패스키 등록";
            help.textContent = authenticated
                ? "같은 계정에 추가할 다른 기기나 관리자를 선택해 주세요. 같은 패스키는 중복 등록되지 않습니다."
                : "추가 등록과 삭제는 패스키로 로그인한 뒤 이용할 수 있습니다.";
            return !!list.children.length;
        } catch (error) {
            if (version !== listVersion) return false;
            authenticated = false;
            clearAccount();
            panel.hidden = true;
            if (error.status !== 401) status.textContent = "패스키 목록을 불러오지 못했습니다.";
            return false;
        }
    }

    form.addEventListener("submit", async event => {
        event.preventDefault();
        if (busy) return;
        if (!authenticated && !accountInput.reportValidity()) return;
        if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials?.create) {
            status.textContent = "HTTPS 주소에서 패스키를 지원하는 브라우저와 기기로 이용해 주세요.";
            return;
        }
        busy = true; button.disabled = true;
        let challengeId; let createdCredentialId; let phase = "options"; let registered = false;
        try {
            status.textContent = "패스키 등록을 준비하고 있습니다.";
            const data = await api("options", {
                accountName: accountInput.value,
                name: document.getElementById("passkey-name").value,
                storage: document.getElementById("passkey-storage").value
            });
            challengeId = data.challengeId;
            const publicKey = typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function"
                ? PublicKeyCredential.parseCreationOptionsFromJSON(data.options)
                : { ...data.options, challenge: decode(data.options.challenge),
                    user: { ...data.options.user, id: decode(data.options.user.id) },
                    excludeCredentials: (data.options.excludeCredentials || []).map(item => ({ ...item, id: decode(item.id) })) };
            phase = "device";
            status.textContent = "기기에 표시된 창에서 패스키 등록을 진행해 주세요.";
            const credential = await navigator.credentials.create({ publicKey });
            if (!credential) throw new DOMException("Cancelled", "NotAllowedError");
            createdCredentialId = credential.id;
            const result = typeof credential.toJSON === "function" ? credential.toJSON() : {
                id: credential.id, rawId: encode(credential.rawId), type: credential.type,
                authenticatorAttachment: credential.authenticatorAttachment,
                response: { clientDataJSON: encode(credential.response.clientDataJSON),
                    attestationObject: encode(credential.response.attestationObject),
                    transports: credential.response.getTransports?.() || [] },
                clientExtensionResults: credential.getClientExtensionResults()
            };
            phase = "verify";
            status.textContent = "기기의 응답을 확인하고 있습니다.";
            await api("verify", { challengeId, credential: result });
            registered = true;
            status.textContent = authenticated ? "같은 계정에 패스키를 추가했습니다." : "패스키가 등록되었습니다.";
            if (!await refreshList()) status.textContent = "패스키는 등록됐지만 목록을 불러오지 못했습니다. 페이지를 새로고침해 주세요.";
        } catch (error) {
            if (phase === "device" && challengeId) {
                try {
                    await api("cancel", { challengeId });
                    status.textContent = error.name === "NotAllowedError" || error.name === "AbortError"
                        ? "등록이 취소되었거나 시간이 지났습니다. 패스키는 저장되지 않았습니다."
                        : error.name === "InvalidStateError"
                            ? "이미 등록된 패스키입니다. 다른 기기나 관리자를 선택해 주세요."
                            : "기기에서 등록을 완료하지 못했습니다. 패스키는 저장되지 않았습니다.";
                } catch {
                    status.textContent = "등록을 완료하지 못했습니다. 취소 요청의 서버 반영 여부는 연결 후 확인이 필요합니다.";
                }
            } else if (phase === "verify" && await refreshList() && knownCredentialIds.has(createdCredentialId)) {
                registered = true;
                status.textContent = "서버에 등록된 패스키를 확인했습니다.";
            } else {
                status.textContent = error.message || "등록을 완료하지 못했습니다. 다시 시도해 주세요.";
            }
        } finally {
            busy = false; button.disabled = registered && !authenticated;
        }
    });
    window.addEventListener("t08-auth-state", event => {
        authenticated = event.detail.authenticated;
        if (authenticated) refreshList();
        else { clearAccount(); listVersion++; knownCredentialIds.clear(); list.replaceChildren(); panel.hidden = true; button.disabled = false; button.textContent = "패스키 등록"; help.textContent = "추가 등록과 삭제는 패스키로 로그인한 뒤 이용할 수 있습니다."; }
    });
    refreshList();
})();
