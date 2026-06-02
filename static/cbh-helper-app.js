(function () {
  const targetProfiles = JSON.parse(document.getElementById("target-profiles").textContent);
  const translations = {
    zh: {
      title: "CBH 辅助连接",
      bastion: "堡垒机",
      target: "目标",
      language: "语言",
      bastionUsername: "堡垒机用户名",
      bastionPassword: "堡垒机密码",
      mfaCode: "MFA 验证码",
      targetProfile: "目标资源",
      targetSelector: "目标选择命令",
      resourceAccountProfile: "资源账号选项",
      customResourceAccount: "自定义账号",
      resourceAccount: "资源账号",
      resourcePassword: "资源密码",
      shareLogin: "共享本次登录给本地 SSH",
      connect: "连接",
      reconnect: "重连",
      idle: "空闲。",
      ready: "就绪。",
      connecting: "正在连接。",
      disconnected: "已断开。",
      connectionError: "连接错误。",
      localSshConnection: "本地 SSH 连接",
      localSshEmpty: "连接一个终端并勾选共享后可用于本地 SSH。",
      localSshUnavailable: "未选择可复用终端。",
      localSshSelected: "本地 SSH 将使用已选择的终端。",
      newTerminal: "新建终端",
      closeTerminal: "关闭终端",
      closeTerminalConfirm: "该终端仍在连接中，关闭会断开远端会话。确定关闭吗？",
      manualResourceAccount: "手动输入资源账号",
      terminal: "终端",
      error: "错误"
    },
    en: {
      title: "CBH Helper",
      bastion: "Bastion",
      target: "Target",
      language: "Language",
      bastionUsername: "Bastion username",
      bastionPassword: "Bastion password",
      mfaCode: "MFA code",
      targetProfile: "Target profile",
      targetSelector: "Target selector",
      resourceAccountProfile: "Resource account option",
      customResourceAccount: "Custom account",
      resourceAccount: "Resource account",
      resourcePassword: "Resource password",
      shareLogin: "Share this login with local SSH",
      connect: "Connect",
      reconnect: "Reconnect",
      idle: "Idle.",
      ready: "Ready.",
      connecting: "Connecting.",
      disconnected: "Disconnected.",
      connectionError: "Connection error.",
      localSshConnection: "Local SSH connection",
      localSshEmpty: "Connect a terminal with sharing enabled to use local SSH.",
      localSshUnavailable: "No reusable terminal is selected.",
      localSshSelected: "Local SSH will use the selected terminal.",
      newTerminal: "New terminal",
      closeTerminal: "Close terminal",
      closeTerminalConfirm: "This terminal is still connected. Closing it will disconnect the remote session. Close it?",
      manualResourceAccount: "Manual resource account",
      terminal: "Terminal",
      error: "Error"
    }
  };

  let currentLanguage = "zh";
  const form = document.getElementById("login");
  const button = document.getElementById("connect");
  const reconnectButton = document.getElementById("reconnect");
  const statusEl = document.getElementById("status");
  const language = document.getElementById("language");
  const targetSummary = document.getElementById("target-summary");
  const targetProfile = document.getElementById("target-profile");
  const targetCommand = document.getElementById("target-command");
  const resourceAccountProfile = document.getElementById("resource-account-profile");
  const resourceAccount = document.getElementById("resource-account");
  const resourcePassword = document.getElementById("resource-password");
  const cacheForCmd = document.getElementById("cache-for-cmd");
  const terminalTabsEl = document.getElementById("terminal-tabs");
  const terminalPanesEl = document.getElementById("terminal-panes");
  const addTerminalTabButton = document.getElementById("add-terminal-tab");
  const localSshList = document.getElementById("local-ssh-list");
  const localSshStatus = document.getElementById("local-ssh-status");
  const defaultResourceAccount = resourceAccount.value || "root";
  const resourcePasswordMemory = new Map();
  const RESOURCE_ACCOUNT_CUSTOM = "__custom__";
  const terminalTheme = {
    background: "#0b0d0f",
    foreground: "#edf0f2",
    cursor: "#32c48d"
  };

  let currentResourcePasswordKey = "";
  let activeTabId = "";
  let nextTabNumber = 1;
  let selectedLocalSshKey = "";
  let loadingTabForm = false;
  const terminalTabs = [];

  function t(key) {
    return (translations[currentLanguage] && translations[currentLanguage][key]) || translations.zh[key] || key;
  }

  function setLanguage(value) {
    currentLanguage = translations[value] ? value : "zh";
    localStorage.setItem("cbh-helper-language", currentLanguage);
    document.documentElement.lang = currentLanguage === "zh" ? "zh-CN" : "en";
    document.querySelectorAll("[data-i18n]").forEach((node) => {
      const key = node.getAttribute("data-i18n");
      if (key && translations[currentLanguage][key]) {
        node.textContent = translations[currentLanguage][key];
      }
    });
    const customOption = resourceAccountProfile.querySelector("option[value='__custom__']");
    if (customOption) {
      customOption.textContent = t("customResourceAccount");
    }
    addTerminalTabButton.title = t("newTerminal");
    renderTabs();
    renderLocalSshCandidates();
  }

  function selectedProfile() {
    return targetProfiles[Number(targetProfile.value || 0)] || targetProfiles[0] || {};
  }

  function normalizeAccounts(profile) {
    const accounts = Array.isArray(profile.accounts) ? profile.accounts.slice() : [];
    const legacyAccount = String(profile.resource_account || "").trim();
    if (legacyAccount && !accounts.some((entry) => String(entry.account || "").trim() === legacyAccount)) {
      accounts.unshift({
        account: legacyAccount,
        target_command: profile.target_command || "",
        resource_password: ""
      });
    }
    return accounts.filter((entry) => String(entry.account || "").trim());
  }

  function passwordKey(profile, account, command) {
    return `${profile.name || ""}|${command || ""}|${account || ""}`;
  }

  function rememberCurrentResourcePassword() {
    if (currentResourcePasswordKey) {
      resourcePasswordMemory.set(currentResourcePasswordKey, resourcePassword.value);
    }
  }

  function setResourcePassword(profile, account, command, fallbackPassword = "") {
    currentResourcePasswordKey = passwordKey(profile, account, command);
    resourcePassword.value = resourcePasswordMemory.has(currentResourcePasswordKey)
      ? resourcePasswordMemory.get(currentResourcePasswordKey)
      : fallbackPassword;
  }

  function applyResourceAccount(profile, value) {
    const accounts = normalizeAccounts(profile);
    const index = Number(value);
    if (value !== RESOURCE_ACCOUNT_CUSTOM && Number.isInteger(index) && accounts[index]) {
      const accountProfile = accounts[index];
      const account = String(accountProfile.account || "").trim();
      const command = accountProfile.target_command || profile.target_command || "";
      targetCommand.value = command;
      resourceAccount.value = account;
      resourceAccount.readOnly = true;
      setResourcePassword(profile, account, command, accountProfile.resource_password || "");
      return;
    }

    const command = profile.target_command || "";
    targetCommand.value = command;
    resourceAccount.readOnly = false;
    resourceAccount.value = profile.resource_account || resourceAccount.value || defaultResourceAccount;
    setResourcePassword(profile, resourceAccount.value, command);
  }

  function installResourceAccounts(profile) {
    resourceAccountProfile.innerHTML = "";
    const customOption = document.createElement("option");
    customOption.value = RESOURCE_ACCOUNT_CUSTOM;
    customOption.textContent = t("customResourceAccount");
    resourceAccountProfile.appendChild(customOption);

    normalizeAccounts(profile).forEach((accountProfile, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = accountProfile.account || `Account ${index + 1}`;
      resourceAccountProfile.appendChild(option);
    });

    resourceAccountProfile.value = RESOURCE_ACCOUNT_CUSTOM;
    applyResourceAccount(profile, RESOURCE_ACCOUNT_CUSTOM);
  }

  function applyProfile(index, remember = true) {
    if (remember) {
      rememberCurrentResourcePassword();
    }
    const profile = targetProfiles[index] || targetProfiles[0] || {};
    targetSummary.textContent = profile.name || profile.target_command || "";
    targetCommand.value = profile.target_command || "";
    installResourceAccounts(profile);
  }

  function installProfiles() {
    targetProfile.innerHTML = "";
    targetProfiles.forEach((profile, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = profile.name || profile.target_command || `Target ${index + 1}`;
      targetProfile.appendChild(option);
    });
    applyProfile(0, false);
  }

  function parseHostPortFromCommand(command) {
    const value = String(command || "").trim();
    if (!value.startsWith("?")) {
      return { host: "", port: "" };
    }
    const parts = value.slice(1).split("_");
    if (parts.length < 2) {
      return { host: "", port: "" };
    }
    return { host: parts[0] || "", port: parts[1] || "" };
  }

  function hostPortFromProfile(profile, command) {
    const resourceHost = String(profile.resource_host || "");
    if (resourceHost) {
      const separator = resourceHost.lastIndexOf(":");
      if (separator > 0) {
        return {
          host: resourceHost.slice(0, separator),
          port: resourceHost.slice(separator + 1)
        };
      }
      return { host: resourceHost, port: "" };
    }
    return parseHostPortFromCommand(command);
  }

  function hostPortLabel(snapshot) {
    if (snapshot.resourceHost && snapshot.resourcePort) {
      return `${snapshot.resourceHost}:${snapshot.resourcePort}`;
    }
    return snapshot.resourceHost || "";
  }

  function candidateKeyFromSnapshot(snapshot) {
    const hostPort = hostPortLabel(snapshot) || snapshot.targetCommand || "";
    return `${hostPort}|${String(snapshot.resourceAccount || "").trim()}`;
  }

  function findProfileIndexByCommand(command) {
    const value = String(command || "");
    const index = targetProfiles.findIndex((profile) => String(profile.target_command || "") === value);
    return index >= 0 ? index : 0;
  }

  function captureBastionSnapshot() {
    return {
      username: document.getElementById("username").value,
      password: document.getElementById("password").value,
      mfa: document.getElementById("mfa").value,
      cacheForCmd: cacheForCmd.checked
    };
  }

  function captureConnectionSnapshot(tab) {
    const profile = selectedProfile();
    const command = targetCommand.value;
    const hostPort = hostPortFromProfile(profile, command);
    const resourceName = String(profile.resource_name || "");
    const fallbackLabel = hostPort.host && hostPort.port ? `${hostPort.host}:${hostPort.port}` : command;
    const targetLabel = profile.name || resourceName || fallbackLabel;
    const snapshot = {
      tabId: tab.id,
      tabTitle: tab.title,
      username: document.getElementById("username").value,
      password: document.getElementById("password").value,
      mfa: document.getElementById("mfa").value,
      targetCommand: command,
      targetLabel,
      resourceName,
      resourceHost: hostPort.host,
      resourcePort: hostPort.port,
      resourceAccount: resourceAccount.value,
      resourcePassword: resourcePassword.value,
      cacheForCmd: cacheForCmd.checked,
      profileIndex: Number(targetProfile.value || 0),
      resourceAccountProfileValue: resourceAccountProfile.value,
      resourceAccountReadOnly: resourceAccount.readOnly,
      connectedAt: Date.now() / 1000
    };
    snapshot.candidateKey = candidateKeyFromSnapshot(snapshot);
    return snapshot;
  }

  function captureDraftSnapshot(tab) {
    const snapshot = captureConnectionSnapshot(tab);
    snapshot.connectedAt = tab.connectionSnapshot ? tab.connectionSnapshot.connectedAt : 0;
    return snapshot;
  }

  function saveActiveTabDraft() {
    const tab = activeTab();
    if (!tab) {
      return;
    }
    rememberCurrentResourcePassword();
    tab.bastionSnapshot = captureBastionSnapshot();
    tab.draftSnapshot = captureDraftSnapshot(tab);
  }

  function updateActiveTabDraft() {
    if (loadingTabForm) {
      return;
    }
    const tab = activeTab();
    if (!tab) {
      return;
    }
    tab.bastionSnapshot = captureBastionSnapshot();
    tab.draftSnapshot = captureDraftSnapshot(tab);
  }

  function loadTabForm(tab) {
    loadingTabForm = true;
    try {
      const snapshot = tab.draftSnapshot || tab.connectionSnapshot || null;
      const bastionSnapshot = snapshot || tab.bastionSnapshot || captureBastionSnapshot();
      document.getElementById("username").value = bastionSnapshot.username || "";
      document.getElementById("password").value = bastionSnapshot.password || "";
      document.getElementById("mfa").value = bastionSnapshot.mfa || "";
      cacheForCmd.checked = bastionSnapshot.cacheForCmd !== false;

      if (snapshot) {
        const profileIndex = Number.isInteger(snapshot.profileIndex)
          ? snapshot.profileIndex
          : findProfileIndexByCommand(snapshot.targetCommand);
        targetProfile.value = String(profileIndex);
        applyProfile(profileIndex, false);
        targetCommand.value = snapshot.targetCommand || "";
        targetSummary.textContent = snapshot.targetLabel || targetCommand.value;
        resourceAccount.value = snapshot.resourceAccount || "";
        resourceAccount.readOnly = Boolean(snapshot.resourceAccountReadOnly);
        const accountProfileValue = snapshot.resourceAccountProfileValue || RESOURCE_ACCOUNT_CUSTOM;
        if (Array.from(resourceAccountProfile.options).some((option) => option.value === accountProfileValue)) {
          resourceAccountProfile.value = accountProfileValue;
        } else {
          resourceAccountProfile.value = RESOURCE_ACCOUNT_CUSTOM;
          resourceAccount.readOnly = false;
        }
        currentResourcePasswordKey = passwordKey(selectedProfile(), resourceAccount.value, targetCommand.value);
        resourcePassword.value = snapshot.resourcePassword || "";
        if (currentResourcePasswordKey) {
          resourcePasswordMemory.set(currentResourcePasswordKey, resourcePassword.value);
        }
      } else {
        resourceAccount.value = defaultResourceAccount;
        resourcePassword.value = "";
        resourceAccount.readOnly = false;
        currentResourcePasswordKey = "";
        targetProfile.value = "0";
        applyProfile(0, false);
        resourcePassword.value = "";
      }
    } finally {
      loadingTabForm = false;
    }
  }

  function setStatus(text, error = false) {
    statusEl.textContent = text;
    statusEl.classList.toggle("error", error);
  }

  function wsUrl() {
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    return `${scheme}://${location.host}/ws`;
  }

  function activeTab() {
    return terminalTabs.find((tab) => tab.id === activeTabId) || terminalTabs[0] || null;
  }

  function stopTabKeepalive(tab) {
    if (tab.wsKeepaliveTimer) {
      clearInterval(tab.wsKeepaliveTimer);
      tab.wsKeepaliveTimer = null;
    }
  }

  function updateActionButtons() {
    const tab = activeTab();
    const busy = Boolean(tab && tab.connecting);
    button.disabled = busy;
    reconnectButton.disabled = !tab || busy || !tab.connectionSnapshot;
  }

  function renderTabs() {
    terminalTabsEl.innerHTML = "";
    terminalTabs.forEach((tab) => {
      const tabButton = document.createElement("button");
      tabButton.type = "button";
      tabButton.className = `terminal-tab${tab.id === activeTabId ? " active" : ""}`;
      tabButton.title = tab.title;

      const label = document.createElement("span");
      label.className = "terminal-tab-label";
      label.textContent = tab.title;

      tabButton.addEventListener("click", () => activateTab(tab.id));
      tabButton.appendChild(label);
      if (terminalTabs.length > 1) {
        const close = document.createElement("button");
        close.type = "button";
        close.className = "terminal-tab-close";
        close.textContent = "×";
        close.title = t("closeTerminal");
        close.addEventListener("click", (event) => {
          event.stopPropagation();
          closeTerminalTab(tab.id);
        });
        tabButton.appendChild(close);
      }
      terminalTabsEl.appendChild(tabButton);
      tab.pane.classList.toggle("active", tab.id === activeTabId);
    });
    updateActionButtons();
  }

  function activateTab(tabId) {
    const tab = terminalTabs.find((item) => item.id === tabId);
    if (!tab) {
      return;
    }
    if (activeTabId && activeTabId !== tab.id) {
      saveActiveTabDraft();
    }
    activeTabId = tab.id;
    loadTabForm(tab);
    setStatus(tab.statusText || t("ready"), tab.statusIsError);
    renderTabs();
    window.setTimeout(() => {
      tab.fitAddon.fit();
      if (tab.socket && tab.socket.readyState === WebSocket.OPEN) {
        tab.socket.send(JSON.stringify({
          type: "resize",
          cols: tab.terminal.cols,
          rows: tab.terminal.rows
        }));
      }
    }, 0);
  }

  function createTerminalTab() {
    saveActiveTabDraft();
    const tabNumber = nextTabNumber++;
    const pane = document.createElement("div");
    pane.className = "terminal-pane";
    terminalPanesEl.appendChild(pane);

    const terminal = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontFamily: "Consolas, 'Cascadia Mono', monospace",
      fontSize: 14,
      theme: terminalTheme
    });
    const fitAddon = new FitAddon.FitAddon();
    terminal.loadAddon(fitAddon);

    const tab = {
      id: `tab-${Date.now()}-${tabNumber}`,
      title: `${t("terminal")} ${tabNumber}`,
      pane,
      terminal,
      fitAddon,
      socket: null,
      wsKeepaliveTimer: null,
      statusText: t("ready"),
      statusIsError: false,
      connecting: false,
      connected: false,
      bastionSnapshot: captureBastionSnapshot(),
      draftSnapshot: null,
      connectionSnapshot: null,
      localSshRegistered: false
    };

    terminalTabs.push(tab);
    activeTabId = tab.id;
    loadTabForm(tab);
    renderTabs();
    terminal.open(pane);
    terminal.onData((data) => {
      if (tab.socket && tab.socket.readyState === WebSocket.OPEN) {
        tab.socket.send(JSON.stringify({ type: "input", data }));
      } else if (tab.id === activeTabId) {
        setStatus(t("disconnected"), true);
      }
    });
    terminal.writeln(t("ready"));
    setStatus(tab.statusText, tab.statusIsError);
    window.setTimeout(() => fitAddon.fit(), 0);
    return tab;
  }

  function updateTabStatus(tab, text, error = false) {
    tab.statusText = text;
    tab.statusIsError = error;
    if (tab.id === activeTabId) {
      setStatus(text, error);
    }
  }

  function connectTab(tab) {
    if (!tab) {
      return;
    }
    if (tab.socket) {
      const previousSocket = tab.socket;
      stopTabKeepalive(tab);
      previousSocket.close();
      tab.socket = null;
    }

    tab.terminal.clear();
    tab.fitAddon.fit();
    tab.bastionSnapshot = captureBastionSnapshot();
    tab.connectionSnapshot = captureConnectionSnapshot(tab);
    tab.draftSnapshot = tab.connectionSnapshot;
    tab.title = tab.connectionSnapshot.targetLabel || tab.title;
    tab.connecting = true;
    tab.connected = false;
    tab.localSshRegistered = false;
    renderTabs();

    const nextSocket = new WebSocket(wsUrl());
    tab.socket = nextSocket;
    updateTabStatus(tab, t("connecting"));
    updateActionButtons();

    nextSocket.addEventListener("open", () => {
      rememberCurrentResourcePassword();
      const snapshot = tab.connectionSnapshot;
      const payload = {
        type: "start",
        tabId: tab.id,
        tabTitle: tab.title,
        targetLabel: snapshot.targetLabel,
        resourceHost: snapshot.resourceHost,
        resourcePort: snapshot.resourcePort,
        resourceName: snapshot.resourceName,
        username: snapshot.username,
        password: snapshot.password,
        mfa: snapshot.mfa,
        targetCommand: snapshot.targetCommand,
        resourceAccount: snapshot.resourceAccount,
        resourcePassword: snapshot.resourcePassword,
        cacheForCmd: snapshot.cacheForCmd,
        cols: tab.terminal.cols,
        rows: tab.terminal.rows,
        term: "xterm"
      };
      nextSocket.send(JSON.stringify(payload));
      stopTabKeepalive(tab);
      tab.wsKeepaliveTimer = setInterval(() => {
        if (nextSocket.readyState === WebSocket.OPEN) {
          nextSocket.send(JSON.stringify({ type: "noop" }));
        }
      }, 30000);
      updateActionButtons();
    });

    nextSocket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.type === "data") {
        tab.connected = true;
        tab.connecting = false;
        tab.terminal.write(message.data);
        updateActionButtons();
      } else if (message.type === "status") {
        updateTabStatus(tab, message.text);
        tab.terminal.writeln(`\r\n[${message.text}]`);
      } else if (message.type === "error") {
        updateTabStatus(tab, message.text, true);
        tab.terminal.writeln(`\r\n[${t("error")}] ${message.text}`);
      } else if (message.type === "localSshCandidates") {
        tab.connected = true;
        tab.connecting = false;
        tab.localSshRegistered = Boolean(tab.connectionSnapshot && tab.connectionSnapshot.cacheForCmd);
        if (tab.connectionSnapshot) {
          tab.connectionSnapshot.connectedAt = Date.now() / 1000;
        }
        renderLocalSshCandidates();
        updateActionButtons();
      }
    });

    nextSocket.addEventListener("close", () => {
      if (tab.socket !== nextSocket) {
        return;
      }
      stopTabKeepalive(tab);
      tab.socket = null;
      tab.connecting = false;
      tab.connected = false;
      tab.localSshRegistered = false;
      updateTabStatus(tab, t("disconnected"));
      renderLocalSshCandidates();
      updateActionButtons();
    });

    nextSocket.addEventListener("error", () => {
      if (tab.socket !== nextSocket) {
        return;
      }
      stopTabKeepalive(tab);
      tab.socket = null;
      tab.connecting = false;
      tab.connected = false;
      tab.localSshRegistered = false;
      updateTabStatus(tab, t("connectionError"), true);
      renderLocalSshCandidates();
      updateActionButtons();
    });
  }

  function closeTerminalTab(tabId) {
    if (terminalTabs.length <= 1) {
      return;
    }
    const index = terminalTabs.findIndex((tab) => tab.id === tabId);
    if (index < 0) {
      return;
    }
    const tab = terminalTabs[index];
    if (tab.socket && tab.socket.readyState === WebSocket.OPEN && !window.confirm(t("closeTerminalConfirm"))) {
      return;
    }
    stopTabKeepalive(tab);
    if (tab.socket) {
      tab.socket.close();
      tab.socket = null;
    }
    tab.terminal.dispose();
    tab.pane.remove();
    terminalTabs.splice(index, 1);
    renderLocalSshCandidates();
    if (activeTabId === tabId) {
      const next = terminalTabs[Math.min(index, terminalTabs.length - 1)];
      activateTab(next.id);
    } else {
      renderTabs();
    }
  }

  function candidateGroups() {
    const groups = new Map();
    terminalTabs.forEach((tab) => {
      const snapshot = tab.connectionSnapshot;
      if (!tab.connected || !tab.localSshRegistered || !snapshot || !snapshot.cacheForCmd) {
        return;
      }
      const key = snapshot.candidateKey || candidateKeyFromSnapshot(snapshot);
      const current = groups.get(key);
      if (!current || Number(snapshot.connectedAt || 0) >= Number(current.snapshot.connectedAt || 0)) {
        groups.set(key, { key, tab, snapshot });
      }
    });
    return Array.from(groups.values());
  }

  function renderLocalSshCandidates() {
    const groups = candidateGroups();
    if (selectedLocalSshKey && !groups.some((group) => group.key === selectedLocalSshKey)) {
      selectedLocalSshKey = "";
      selectLocalSshCandidate("");
    }
    if (!selectedLocalSshKey && groups.length === 1) {
      selectedLocalSshKey = groups[0].key;
      selectLocalSshCandidate(selectedLocalSshKey);
    }
    groups.sort((left, right) => {
      if (left.key === selectedLocalSshKey) {
        return -1;
      }
      if (right.key === selectedLocalSshKey) {
        return 1;
      }
      return Number(right.snapshot.connectedAt || 0) - Number(left.snapshot.connectedAt || 0);
    });

    localSshList.innerHTML = "";
    if (!groups.length) {
      const empty = document.createElement("div");
      empty.className = "local-ssh-empty";
      empty.textContent = t("localSshEmpty");
      localSshList.appendChild(empty);
      localSshStatus.textContent = t("localSshUnavailable");
      localSshStatus.classList.add("error");
      return;
    }

    groups.forEach((group) => {
      const snapshot = group.snapshot;
      const option = document.createElement("button");
      option.type = "button";
      option.className = `local-ssh-option${group.key === selectedLocalSshKey ? " active" : ""}`;

      const title = document.createElement("span");
      title.className = "local-ssh-option-title";
      title.textContent = snapshot.resourceName || snapshot.targetLabel || hostPortLabel(snapshot) || snapshot.targetCommand || group.tab.title;

      const detail = document.createElement("span");
      detail.className = "local-ssh-option-detail";
      const account = String(snapshot.resourceAccount || "").trim() || t("manualResourceAccount");
      const host = hostPortLabel(snapshot);
      detail.textContent = host ? `${account} · ${host}` : account;

      option.appendChild(title);
      option.appendChild(detail);
      option.addEventListener("click", () => {
        selectedLocalSshKey = group.key;
        selectLocalSshCandidate(group.key);
        renderLocalSshCandidates();
      });
      localSshList.appendChild(option);
    });

    localSshStatus.textContent = selectedLocalSshKey ? t("localSshSelected") : t("localSshUnavailable");
    localSshStatus.classList.toggle("error", !selectedLocalSshKey);
  }

  function selectLocalSshCandidate(key) {
    fetch("/api/local-ssh/select", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key })
    }).catch(() => {});
  }

  targetProfile.addEventListener("change", () => {
    applyProfile(Number(targetProfile.value || 0));
    updateActiveTabDraft();
  });

  resourceAccountProfile.addEventListener("change", () => {
    rememberCurrentResourcePassword();
    applyResourceAccount(selectedProfile(), resourceAccountProfile.value);
    updateActiveTabDraft();
  });

  resourceAccount.addEventListener("input", () => {
    if (resourceAccountProfile.value === RESOURCE_ACCOUNT_CUSTOM) {
      const profile = selectedProfile();
      currentResourcePasswordKey = passwordKey(profile, resourceAccount.value, targetCommand.value);
    }
    updateActiveTabDraft();
  });

  resourcePassword.addEventListener("input", () => {
    rememberCurrentResourcePassword();
    updateActiveTabDraft();
  });

  [
    document.getElementById("username"),
    document.getElementById("password"),
    document.getElementById("mfa"),
    targetCommand,
    cacheForCmd
  ].forEach((node) => {
    node.addEventListener("input", updateActiveTabDraft);
    node.addEventListener("change", updateActiveTabDraft);
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    rememberCurrentResourcePassword();
    connectTab(activeTab());
  });

  reconnectButton.addEventListener("click", () => {
    rememberCurrentResourcePassword();
    connectTab(activeTab());
  });

  addTerminalTabButton.addEventListener("click", () => {
    createTerminalTab();
  });

  window.addEventListener("resize", () => {
    const tab = activeTab();
    if (!tab) {
      return;
    }
    tab.fitAddon.fit();
    if (tab.socket && tab.socket.readyState === WebSocket.OPEN) {
      tab.socket.send(JSON.stringify({
        type: "resize",
        cols: tab.terminal.cols,
        rows: tab.terminal.rows
      }));
    }
  });

  installProfiles();
  language.value = localStorage.getItem("cbh-helper-language") || "zh";
  setLanguage(language.value);
  language.addEventListener("change", () => {
    setLanguage(language.value);
  });
  createTerminalTab();
  renderLocalSshCandidates();
})();
