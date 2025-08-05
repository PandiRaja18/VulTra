// Background script for password breach checker
class BackgroundService {
  constructor() {
    this.init();
  }

  init() {
    // Handle extension installation
    chrome.runtime.onInstalled.addListener(() => {
      this.setupDefaultSettings();
    });

    // Handle messages from content script
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      this.handleMessage(request, sender, sendResponse);
      return true; // Keep message channel open for async response
    });
  }

  async setupDefaultSettings() {
    try {
      const result = await chrome.storage.local.get(['breachedPasswords']);
      if (!result.breachedPasswords) {
        // Set default breached passwords list
        const defaultBreachedPasswords = [
          'password', '123456', '123456789', 'qwerty', 'abc123',
          'password123', 'admin', 'letmein', 'welcome', 'monkey',
          'dragon', 'pass', 'master', 'hello', 'login',
          '12345678', 'sunshine', 'iloveyou', 'princess', 'admin123',
          'welcome123', 'password1', 'qwerty123', 'Password',
          'Password123', '1234567890', 'football', 'baseball',
          'shadow', 'michael', 'jennifer', 'jordan', 'hunter',
          'fuckyou', 'access', 'buster', 'soccer', 'harley',
          'batman', 'andrew', 'tigger', 'charlie', 'robert',
          'freedom', 'daniel', 'thomas', 'nicole', 'jessica',
          'michelle', 'maggie', 'melissa', 'anthony', 'love',
          'secret', 'summer', 'ashley', 'andrea', 'joshua'
        ];
        
        await chrome.storage.local.set({
          breachedPasswords: defaultBreachedPasswords
        });
      }
    } catch (error) {
      console.error('Failed to setup default settings:', error);
    }
  }

  handleMessage(request, sender, sendResponse) {
    switch (request.action) {
      case 'getBreachedPasswords':
        this.getBreachedPasswords(sendResponse);
        break;
      case 'addBreachedPassword':
        this.addBreachedPassword(request.password, sendResponse);
        break;
      case 'removeBreachedPassword':
        this.removeBreachedPassword(request.password, sendResponse);
        break;
      default:
        sendResponse({ error: 'Unknown action' });
    }
  }

  async getBreachedPasswords(sendResponse) {
    try {
      const result = await chrome.storage.local.get(['breachedPasswords']);
      sendResponse({ passwords: result.breachedPasswords || [] });
    } catch (error) {
      sendResponse({ error: error.message });
    }
  }

  async addBreachedPassword(password, sendResponse) {
    try {
      const result = await chrome.storage.local.get(['breachedPasswords']);
      const passwords = result.breachedPasswords || [];
      
      if (!passwords.includes(password)) {
        passwords.push(password);
        await chrome.storage.local.set({ breachedPasswords: passwords });
      }
      
      sendResponse({ success: true });
    } catch (error) {
      sendResponse({ error: error.message });
    }
  }

  async removeBreachedPassword(password, sendResponse) {
    try {
      const result = await chrome.storage.local.get(['breachedPasswords']);
      const passwords = result.breachedPasswords || [];
      
      const updatedPasswords = passwords.filter(p => p !== password);
      await chrome.storage.local.set({ breachedPasswords: updatedPasswords });
      
      sendResponse({ success: true });
    } catch (error) {
      sendResponse({ error: error.message });
    }
  }
}

// Initialize background service
new BackgroundService();