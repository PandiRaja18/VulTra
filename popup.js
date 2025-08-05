// Popup script for password breach checker
class PopupManager {
  constructor() {
    this.statusElement = document.getElementById('status');
    this.passwordListElement = document.getElementById('passwordList');
    this.totalCountElement = document.getElementById('totalCount');
    this.newPasswordInput = document.getElementById('newPassword');
    this.addButton = document.getElementById('addBtn');
    
    this.init();
  }

  init() {
    this.setupEventListeners();
    this.loadPasswordList();
  }

  setupEventListeners() {
    this.addButton.addEventListener('click', () => {
      this.addPassword();
    });

    this.newPasswordInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        this.addPassword();
      }
    });

    this.newPasswordInput.addEventListener('input', () => {
      this.hideStatus();
    });
  }

  async loadPasswordList() {
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'getBreachedPasswords'
      });

      if (response.error) {
        this.showStatus('Failed to load password list', 'error');
        return;
      }

      const passwords = response.passwords || [];
      this.renderPasswordList(passwords);
      this.updateStats(passwords.length);
    } catch (error) {
      this.showStatus('Failed to load password list', 'error');
      console.error('Error loading passwords:', error);
    }
  }

  renderPasswordList(passwords) {
    if (passwords.length === 0) {
      this.passwordListElement.innerHTML = `
        <div class="empty-state">
          No breached passwords in the list.<br>
          Add some passwords to monitor.
        </div>
      `;
      return;
    }

    const passwordItems = passwords.map(password => `
      <div class="password-item">
        <span title="${this.escapeHtml(password)}">${this.truncatePassword(password)}</span>
        <button class="remove-btn" data-password="${this.escapeHtml(password)}">Remove</button>
      </div>
    `).join('');

    this.passwordListElement.innerHTML = passwordItems;

    // Add event listeners to remove buttons
    this.passwordListElement.querySelectorAll('.remove-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const password = e.target.dataset.password;
        this.removePassword(password);
      });
    });
  }

  async addPassword() {
    const password = this.newPasswordInput.value.trim();
    
    if (!password) {
      this.showStatus('Please enter a password', 'error');
      return;
    }

    try {
      const response = await chrome.runtime.sendMessage({
        action: 'addBreachedPassword',
        password: password
      });

      if (response.error) {
        this.showStatus('Failed to add password', 'error');
        return;
      }

      this.newPasswordInput.value = '';
      this.showStatus('Password added successfully', 'success');
      this.loadPasswordList();
    } catch (error) {
      this.showStatus('Failed to add password', 'error');
      console.error('Error adding password:', error);
    }
  }

  async removePassword(password) {
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'removeBreachedPassword',
        password: password
      });

      if (response.error) {
        this.showStatus('Failed to remove password', 'error');
        return;
      }

      this.showStatus('Password removed successfully', 'success');
      this.loadPasswordList();
    } catch (error) {
      this.showStatus('Failed to remove password', 'error');
      console.error('Error removing password:', error);
    }
  }

  showStatus(message, type) {
    this.statusElement.textContent = message;
    this.statusElement.className = `status ${type}`;
    this.statusElement.style.display = 'block';

    setTimeout(() => {
      this.hideStatus();
    }, 3000);
  }

  hideStatus() {
    this.statusElement.style.display = 'none';
  }

  updateStats(count) {
    this.totalCountElement.textContent = count;
  }

  truncatePassword(password) {
    if (password.length > 20) {
      return password.substring(0, 17) + '...';
    }
    return password;
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize popup manager when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new PopupManager();
});