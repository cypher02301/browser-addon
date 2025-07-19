/**
 * Phishing Detector Browser Extension - Popup Interface
 * 
 * User interface controller for displaying security analysis results,
 * statistics, and providing user controls for managing the extension.
 * 
 * @author Anthony Frederick
 * @version 1.0
 * @created 2025
 * @description Popup controller for extension user interface that shows
 *              risk scores, domain analysis, and user action buttons
 */

// Popup script for displaying phishing analysis results
// This controls the interface that appears when users click the extension icon
class PopupController {
  constructor() {
    // Store the current tab's security analysis data
    this.currentAnalysis = null;
    this.init();
  }

  /**
   * Initialize the popup interface
   * Sets up all data loading and event handling
   */
  async init() {
    await this.loadAnalysis();      // Get security analysis for current tab
    this.setupEventListeners();     // Set up button click handlers
    this.loadStats();               // Load extension usage statistics
  }

  async loadAnalysis() {
    try {
      // Get current tab analysis
      const response = await chrome.runtime.sendMessage({ action: 'getAnalysis' });
      this.currentAnalysis = response;
      
      if (this.currentAnalysis) {
        this.displayAnalysis();
      } else {
        this.displayNoAnalysis();
      }
      
      // Hide loading, show content
      document.getElementById('loading').style.display = 'none';
      document.getElementById('content').style.display = 'block';
      
    } catch (error) {
      console.error('Error loading analysis:', error);
      this.displayError();
    }
  }

  displayAnalysis() {
    const { domain, riskScore, url } = this.currentAnalysis;
    
    // Update domain info
    document.getElementById('current-domain').textContent = domain;
    
    // Update status based on risk score
    this.updateStatus(riskScore);
    
    // Update risk score display
    document.getElementById('risk-score').textContent = `${riskScore}/100`;
    
    // Load and display any security flags
    this.loadSecurityFlags();
  }

  updateStatus(riskScore) {
    const statusCard = document.getElementById('status');
    const statusIcon = document.getElementById('status-icon');
    const statusMessage = document.getElementById('status-message');
    
    // Remove existing status classes
    statusCard.classList.remove('status-safe', 'status-warning', 'status-danger');
    
    if (riskScore <= 20) {
      statusCard.classList.add('status-safe');
      statusIcon.textContent = '✅';
      statusMessage.textContent = 'Safe Site';
    } else if (riskScore <= 40) {
      statusCard.classList.add('status-safe');
      statusIcon.textContent = '🔒';
      statusMessage.textContent = 'Low Risk';
    } else if (riskScore <= 70) {
      statusCard.classList.add('status-warning');
      statusIcon.textContent = '⚠️';
      statusMessage.textContent = 'Medium Risk - Be Cautious';
    } else {
      statusCard.classList.add('status-danger');
      statusIcon.textContent = '🚫';
      statusMessage.textContent = 'High Risk - Potential Phishing';
    }
  }

  displayNoAnalysis() {
    document.getElementById('current-domain').textContent = 'No analysis available';
    document.getElementById('status-icon').textContent = '❓';
    document.getElementById('status-message').textContent = 'Unable to analyze';
    document.getElementById('risk-score').textContent = '--';
  }

  displayError() {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('content').innerHTML = `
      <div class="status-card status-warning">
        <div class="status-text">
          <span class="status-icon">❌</span>
          Error loading analysis
        </div>
      </div>
    `;
  }

  async loadSecurityFlags() {
    try {
      // Try to get flags from content script
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      if (tab) {
        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => window.phishingFlags || []
        });
        
        if (results && results[0] && results[0].result && results[0].result.length > 0) {
          this.displayFlags(results[0].result);
        }
      }
    } catch (error) {
      console.error('Error loading security flags:', error);
    }
  }

  displayFlags(flags) {
    const flagsContainer = document.getElementById('flags');
    const flagsList = document.getElementById('flags-list');
    
    if (flags.length > 0) {
      flagsList.innerHTML = '';
      flags.forEach(flag => {
        const flagElement = document.createElement('div');
        flagElement.className = 'flag';
        flagElement.textContent = flag;
        flagsList.appendChild(flagElement);
      });
      
      flagsContainer.style.display = 'block';
    }
  }

  setupEventListeners() {
    // Report phishing button
    document.getElementById('report-btn').addEventListener('click', async () => {
      if (this.currentAnalysis) {
        try {
          await chrome.runtime.sendMessage({
            action: 'reportPhishing',
            url: this.currentAnalysis.url
          });
          
          this.showNotification('Site reported as phishing', 'success');
          this.updateStats();
        } catch (error) {
          this.showNotification('Error reporting site', 'error');
        }
      }
    });

    // Whitelist button
    document.getElementById('whitelist-btn').addEventListener('click', async () => {
      if (this.currentAnalysis) {
        try {
          // Add to whitelist in storage
          const domain = this.currentAnalysis.domain;
          const result = await chrome.storage.local.get(['whitelistedDomains']);
          const whitelist = result.whitelistedDomains || [];
          
          if (!whitelist.includes(domain)) {
            whitelist.push(domain);
            await chrome.storage.local.set({ whitelistedDomains: whitelist });
            this.showNotification('Site added to trusted list', 'success');
            
            // Update display
            setTimeout(() => {
              this.loadAnalysis();
            }, 1000);
          } else {
            this.showNotification('Site already trusted', 'info');
          }
        } catch (error) {
          this.showNotification('Error adding to whitelist', 'error');
        }
      }
    });
  }

  async loadStats() {
    try {
      const result = await chrome.storage.local.get(['stats']);
      const stats = result.stats || { sitesBlocked: 0, threatsDetected: 0, alertsShown: 0 };
      
      document.getElementById('sites-blocked').textContent = stats.sitesBlocked || 0;
      document.getElementById('threats-detected').textContent = stats.threatsDetected || 0;
      document.getElementById('alerts-shown').textContent = stats.alertsShown || 0;
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  }

  async updateStats() {
    try {
      const result = await chrome.storage.local.get(['stats']);
      const stats = result.stats || { sitesBlocked: 0, threatsDetected: 0 };
      
      stats.threatsDetected = (stats.threatsDetected || 0) + 1;
      
      await chrome.storage.local.set({ stats });
      this.loadStats();
    } catch (error) {
      console.error('Error updating stats:', error);
    }
  }

  showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      left: 50%;
      transform: translateX(-50%);
      background: ${type === 'success' ? '#4CAF50' : type === 'error' ? '#f44336' : '#2196F3'};
      color: white;
      padding: 10px 20px;
      border-radius: 5px;
      z-index: 1000;
      font-size: 12px;
      opacity: 0;
      transition: opacity 0.3s ease;
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Fade in
    setTimeout(() => {
      notification.style.opacity = '1';
    }, 100);
    
    // Remove after 3 seconds
    setTimeout(() => {
      notification.style.opacity = '0';
      setTimeout(() => {
        if (notification.parentNode) {
          notification.parentNode.removeChild(notification);
        }
      }, 300);
    }, 3000);
  }
}

// Initialize popup when DOM is ready
// Interface designed and developed by Anthony Frederick, 2025
document.addEventListener('DOMContentLoaded', () => {
  new PopupController();
});