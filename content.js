// Password breach checker content script
class PasswordBreachChecker {
  constructor() {
    this.breachedPasswords = new Set();
    this.monitoredFields = new WeakMap();
    this.warningPopup = null;
    this.debounceTimer = null;
    
    this.init();
  }

  async init() {
    await this.loadBreachedPasswords();
    this.setupPasswordFieldMonitoring();
    this.createWarningPopupTemplate();
  }

  async loadBreachedPasswords() {
    try {
      // Load from extension storage
      const result = await chrome.storage.local.get(['breachedPasswords']);
      if (result.breachedPasswords) {
        this.breachedPasswords = new Set(result.breachedPasswords);
      } else {
        // Default list of commonly breached passwords
        this.breachedPasswords = new Set([
          'password', '123456', '123456789', 'qwerty', 'abc123',
          'password123', 'admin', 'letmein', 'welcome', 'monkey',
          'dragon', 'pass', 'master', 'hello', 'login',
          '12345678', 'sunshine', 'iloveyou', 'princess', 'admin123',
          'welcome123', 'password1', 'qwerty123', 'Password',
          'Password123', '1234567890', 'football', 'baseball'
        ]);
      }
    } catch (error) {
      console.error('Failed to load breached passwords:', error);
    }
  }

  setupPasswordFieldMonitoring() {
    // Monitor existing password fields
    this.scanForPasswordFields();
    
    // Monitor for dynamically added password fields
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              this.scanForPasswordFields(node);
            }
          });
        }
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  scanForPasswordFields(container = document) {
    const passwordFields = container.querySelectorAll('input[type="password"]');
    
    passwordFields.forEach(field => {
      if (!this.monitoredFields.has(field)) {
        this.monitorPasswordField(field);
      }
    });
  }

  monitorPasswordField(field) {
    this.monitoredFields.set(field, true);
    
    // Add event listeners for password input
    field.addEventListener('input', (e) => {
      this.handlePasswordInput(e.target);
    });
    
    field.addEventListener('blur', (e) => {
      this.handlePasswordInput(e.target);
    });
    
    field.addEventListener('focus', () => {
      this.hideWarningPopup();
    });
  }

  handlePasswordInput(field) {
    clearTimeout(this.debounceTimer);
    
    this.debounceTimer = setTimeout(() => {
      const password = field.value;
      
      if (password.length > 0) {
        this.checkPassword(password, field);
      } else {
        this.hideWarningPopup();
      }
    }, 500); // Debounce for 500ms
  }

  checkPassword(password, field) {
    if (this.breachedPasswords.has(password)) {
      this.showWarningPopup(field);
    } else {
      this.hideWarningPopup();
    }
  }

  createWarningPopupTemplate() {
    const popup = document.createElement('div');
    popup.id = 'password-breach-warning';
    popup.className = 'password-breach-popup';
    popup.innerHTML = `
      <div class="warning-content">
        <div class="warning-icon">⚠️</div>
        <div class="warning-text">
          <strong>Password Breach Warning!</strong><br>
          Your password has been found in data breaches. Please change it immediately.
        </div>
        <button class="close-btn" onclick="this.parentElement.parentElement.style.display='none'">×</button>
      </div>
    `;
    
    document.body.appendChild(popup);
    this.warningPopup = popup;
  }

  showWarningPopup(field) {
    if (!this.warningPopup) {
      this.createWarningPopupTemplate();
    }
    
    const rect = field.getBoundingClientRect();
    const popup = this.warningPopup;
    
    popup.style.display = 'block';
    popup.style.position = 'fixed';
    popup.style.top = `${rect.bottom + window.scrollY + 5}px`;
    popup.style.left = `${rect.left + window.scrollX}px`;
    popup.style.zIndex = '10000';
    
    // Auto-hide after 10 seconds
    setTimeout(() => {
      this.hideWarningPopup();
    }, 10000);
  }

  hideWarningPopup() {
    if (this.warningPopup) {
      this.warningPopup.style.display = 'none';
    }
  }
}

// Initialize the password breach checker
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new PasswordBreachChecker();
  });
} else {
  new PasswordBreachChecker();
}