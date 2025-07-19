/**
 * Phishing Detector Browser Extension - Background Service Worker
 * 
 * Advanced phishing detection and protection system
 * 
 * @author Anthony Frederick
 * @version 1.0
 * @created 2024
 * @description Real-time URL analysis and phishing detection engine
 */

// Background service worker for phishing detection
class PhishingDetector {
  constructor() {
    this.suspiciousDomains = new Set();
    this.whitelistedDomains = new Set([
      'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 
      'amazon.com', 'github.com', 'stackoverflow.com', 'wikipedia.org'
    ]);
    this.phishingPatterns = [
      /secure.*verify/i,
      /account.*suspended/i,
      /click.*here.*immediately/i,
      /urgent.*action.*required/i,
      /verify.*identity/i,
      /update.*payment/i,
      /suspicious.*activity/i,
      /limited.*time/i
    ];
    this.init();
  }

  init() {
    // Listen for tab updates
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === 'complete' && tab.url) {
        this.analyzeUrl(tab.url, tabId);
      }
    });

    // Listen for web navigation
    chrome.webNavigation.onBeforeNavigate.addListener((details) => {
      if (details.frameId === 0) {
        this.analyzeUrl(details.url, details.tabId);
      }
    });

    // Load suspicious domains from storage
    this.loadSuspiciousDomains();
  }

  async loadSuspiciousDomains() {
    try {
      const result = await chrome.storage.local.get(['suspiciousDomains']);
      if (result.suspiciousDomains) {
        this.suspiciousDomains = new Set(result.suspiciousDomains);
      }
    } catch (error) {
      console.error('Error loading suspicious domains:', error);
    }
  }

  async saveSuspiciousDomains() {
    try {
      await chrome.storage.local.set({
        suspiciousDomains: Array.from(this.suspiciousDomains)
      });
    } catch (error) {
      console.error('Error saving suspicious domains:', error);
    }
  }

  analyzeUrl(url, tabId) {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();
      const riskScore = this.calculateRiskScore(urlObj);
      
      console.log(`Phishing Detector: Analyzing ${domain} - Risk Score: ${riskScore}`);
      
      if (riskScore > 60) { // Lowered threshold for blocking
        console.log(`Phishing Detector: BLOCKING ${domain} (Score: ${riskScore})`);
        this.showPhishingAlert(tabId, url, riskScore, 'BLOCKED');
        this.blockPhishingSite(tabId, url, riskScore);
      } else if (riskScore > 30) { // Lowered threshold for warnings
        console.log(`Phishing Detector: WARNING for ${domain} (Score: ${riskScore})`);
        this.showPhishingAlert(tabId, url, riskScore, 'WARNING');
        this.warnUser(tabId, url, riskScore);
      }

      // Update badge based on risk
      this.updateBadge(tabId, riskScore);
      
      // Update statistics
      this.updateDetectionStats(riskScore);
      
      // Store analysis result
      chrome.storage.local.set({
        [`analysis_${tabId}`]: {
          url,
          domain,
          riskScore,
          timestamp: Date.now()
        }
      });

    } catch (error) {
      console.error('Error analyzing URL:', error);
    }
  }

  calculateRiskScore(urlObj) {
    // Advanced risk calculation algorithm - Anthony Frederick, 2024
    let score = 0;
    const domain = urlObj.hostname.toLowerCase();
    const fullUrl = urlObj.href.toLowerCase();

    console.log(`Phishing Detector: Starting analysis for ${domain}`);

    // Check if domain is whitelisted
    if (this.whitelistedDomains.has(domain)) {
      console.log(`Phishing Detector: ${domain} is whitelisted`);
      return 0;
    }

    // Check suspicious domains
    if (this.suspiciousDomains.has(domain)) {
      console.log(`Phishing Detector: ${domain} is in suspicious domains list`);
      score += 80;
    }

    // Domain analysis
    const domainScore = this.analyzeDomain(domain);
    console.log(`Phishing Detector: Domain analysis score: ${domainScore}`);
    score += domainScore;
    
    // URL structure analysis
    const urlScore = this.analyzeUrlStructure(urlObj);
    console.log(`Phishing Detector: URL structure score: ${urlScore}`);
    score += urlScore;
    
    // Content pattern analysis (for full URL)
    const patternScore = this.analyzePatterns(fullUrl);
    console.log(`Phishing Detector: Pattern analysis score: ${patternScore}`);
    score += patternScore;

    const finalScore = Math.min(score, 100);
    console.log(`Phishing Detector: Final risk score for ${domain}: ${finalScore}`);
    return finalScore;
  }

  analyzeDomain(domain) {
    let score = 0;
    console.log(`Phishing Detector: Analyzing domain structure: ${domain}`);
    
    // Suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq'];
    if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
      console.log(`Phishing Detector: Suspicious TLD detected`);
      score += 30;
    }

    // Domain length (very long domains are suspicious)
    if (domain.length > 30) {
      console.log(`Phishing Detector: Long domain detected (${domain.length} chars)`);
      score += 15;
    }

    // Excessive subdomains
    const subdomains = domain.split('.').length - 2;
    if (subdomains > 3) {
      console.log(`Phishing Detector: Excessive subdomains detected (${subdomains})`);
      score += 20;
    }

    // Contains digits mixed with letters
    if (/\d/.test(domain) && /[a-z]/.test(domain)) {
      console.log(`Phishing Detector: Mixed digits and letters detected`);
      score += 10;
    }

    // Homograph attack detection (basic)
    if (this.detectHomograph(domain)) {
      console.log(`Phishing Detector: Homograph attack detected`);
      score += 40;
    }

    // Check for brand impersonation
    const brandScore = this.checkBrandImpersonation(domain);
    console.log(`Phishing Detector: Brand impersonation score: ${brandScore}`);
    score += brandScore;

    return score;
  }

  analyzeUrlStructure(urlObj) {
    let score = 0;
    console.log(`Phishing Detector: Analyzing URL structure: ${urlObj.href}`);
    
    // Check for non-HTTPS for login/security related domains
    if (urlObj.protocol === 'http:' && (
      urlObj.hostname.includes('login') || 
      urlObj.hostname.includes('secure') || 
      urlObj.hostname.includes('account') ||
      urlObj.hostname.includes('bank') ||
      urlObj.hostname.includes('paypal') ||
      urlObj.hostname.includes('paypa')
    )) {
      console.log(`Phishing Detector: HTTP protocol with security-related domain detected`);
      score += 40;
    }
    
    // Check for URL shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
    if (shorteners.includes(urlObj.hostname)) {
      console.log(`Phishing Detector: URL shortener detected`);
      score += 25;
    }

    // Suspicious path patterns
    if (urlObj.pathname.includes('..')) {
      console.log(`Phishing Detector: Suspicious path pattern detected`);
      score += 30;
    }

    // Very long URLs
    if (urlObj.href.length > 100) {
      console.log(`Phishing Detector: Very long URL detected (${urlObj.href.length} chars)`);
      score += 10;
    }

    // Multiple redirections indicators
    if (urlObj.search.includes('redirect') || urlObj.search.includes('url=')) {
      console.log(`Phishing Detector: Redirection indicators detected`);
      score += 15;
    }

    return score;
  }

  analyzePatterns(url) {
    let score = 0;
    
    for (const pattern of this.phishingPatterns) {
      if (pattern.test(url)) {
        score += 20;
      }
    }

    return score;
  }

  detectHomograph(domain) {
    // Basic homograph detection
    const suspiciousChars = /[а-я]|[α-ω]|[а-я]/;
    return suspiciousChars.test(domain);
  }

  checkBrandImpersonation(domain) {
    const popularBrands = [
      'paypal', 'amazon', 'google', 'facebook', 'microsoft', 
      'apple', 'netflix', 'instagram', 'twitter', 'linkedin',
      'ebay', 'walmart', 'target', 'chase', 'wellsfargo'
    ];
    
    // Check for exact brand matches in suspicious contexts
    for (const brand of popularBrands) {
      // Check if domain contains brand but isn't the official domain
      if (domain.includes(brand) && !domain.endsWith(`${brand}.com`) && !domain.endsWith(`${brand}.org`)) {
        return 50; // Higher score for brand impersonation
      }
    }
    
    // Enhanced character substitution detection for PayPal specifically
    if (this.detectPayPalImpersonation(domain)) {
      return 80; // Very high score for PayPal impersonation
    }
    
    // General character substitution detection
    if (this.detectCharacterSubstitution(domain)) {
      return 60;
    }
    
    return 0;
  }

  detectPayPalImpersonation(domain) {
    // Common PayPal impersonation patterns
    const paypalVariants = [
      'paypa1',     // 1 instead of l
      'paypaI',     // capital I instead of l
      'payp4l',     // 4 instead of a
      'p4ypal',     // 4 instead of a
      'payp@l',     // @ instead of a
      'paypai',     // i instead of l
      'papyal',     // transposed letters
      'payapl',     // transposed letters
      'paipal',     // i instead of y
      'paypal1',    // with number
      'paypal-'     // with dash
    ];
    
    console.log(`Phishing Detector: Checking PayPal variants for domain: ${domain}`);
    
    for (const variant of paypalVariants) {
      if (domain.includes(variant)) {
        console.log(`Phishing Detector: PayPal impersonation detected! Variant: ${variant}`);
        return true;
      }
    }
    
    console.log(`Phishing Detector: No PayPal impersonation detected`);
    return false;
  }

  detectCharacterSubstitution(domain) {
    // Common character substitutions used in phishing
    const substitutions = [
      { original: 'o', fake: '0' },
      { original: 'l', fake: '1' },
      { original: 'l', fake: 'I' },
      { original: 'a', fake: '@' },
      { original: 'a', fake: '4' },
      { original: 'e', fake: '3' },
      { original: 's', fake: '5' },
      { original: 'g', fake: '9' }
    ];
    
    const brands = ['paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple'];
    
    for (const brand of brands) {
      for (const sub of substitutions) {
        const fakeBrand = brand.replace(new RegExp(sub.original, 'g'), sub.fake);
        if (domain.includes(fakeBrand) && fakeBrand !== brand) {
          return true;
        }
      }
    }
    
    return false;
  }

  async showPhishingAlert(tabId, url, riskScore, alertType) {
    try {
      const domain = new URL(url).hostname;
      
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: (domain, riskScore, alertType, url) => {
          // Create custom alert dialog - Anthony Frederick, 2024
          const alertDialog = document.createElement('div');
          alertDialog.id = 'phishing-alert-dialog';
          alertDialog.innerHTML = `
            <div style="
              position: fixed;
              top: 0;
              left: 0;
              right: 0;
              bottom: 0;
              background: rgba(0, 0, 0, 0.8);
              z-index: 2147483647;
              display: flex;
              align-items: center;
              justify-content: center;
              font-family: Arial, sans-serif;
            ">
              <div style="
                background: white;
                border-radius: 15px;
                padding: 30px;
                max-width: 500px;
                text-align: center;
                box-shadow: 0 10px 30px rgba(0,0,0,0.5);
                border: ${alertType === 'BLOCKED' ? '3px solid #f44336' : '3px solid #ff9800'};
              ">
                <div style="
                  font-size: 60px;
                  margin-bottom: 20px;
                  color: ${alertType === 'BLOCKED' ? '#f44336' : '#ff9800'};
                ">
                  ${alertType === 'BLOCKED' ? '🚫' : '⚠️'}
                </div>
                
                <h2 style="
                  color: ${alertType === 'BLOCKED' ? '#f44336' : '#ff9800'};
                  margin: 0 0 15px 0;
                  font-size: 24px;
                ">
                  ${alertType === 'BLOCKED' ? 'PHISHING SITE BLOCKED!' : 'SUSPICIOUS SITE DETECTED!'}
                </h2>
                
                <div style="
                  background: ${alertType === 'BLOCKED' ? '#ffebee' : '#fff3e0'};
                  border-radius: 8px;
                  padding: 15px;
                  margin: 20px 0;
                  border-left: 4px solid ${alertType === 'BLOCKED' ? '#f44336' : '#ff9800'};
                ">
                  <p style="margin: 5px 0; color: #333;"><strong>Domain:</strong> ${domain}</p>
                  <p style="margin: 5px 0; color: #333;"><strong>Risk Score:</strong> ${riskScore}/100</p>
                  <p style="margin: 5px 0; color: #333;"><strong>Protocol:</strong> ${url.split(':')[0].toUpperCase()}</p>
                </div>
                
                <p style="color: #666; line-height: 1.4; margin: 15px 0;">
                  ${alertType === 'BLOCKED' 
                    ? 'This website appears to be a phishing site designed to steal your personal information. Access has been blocked for your protection.'
                    : 'This website shows suspicious characteristics that may indicate a phishing attempt. Please proceed with caution.'
                  }
                </p>
                
                <div style="margin-top: 25px;">
                  ${alertType === 'BLOCKED' 
                    ? `
                      <button onclick="window.history.back()" style="
                        background: #4CAF50;
                        color: white;
                        border: none;
                        padding: 12px 25px;
                        border-radius: 25px;
                        cursor: pointer;
                        font-size: 16px;
                        margin: 5px;
                        font-weight: bold;
                      ">← Go Back</button>
                      <button onclick="window.close()" style="
                        background: #757575;
                        color: white;
                        border: none;
                        padding: 12px 25px;
                        border-radius: 25px;
                        cursor: pointer;
                        font-size: 16px;
                        margin: 5px;
                      ">Close Tab</button>
                    `
                    : `
                      <button onclick="document.getElementById('phishing-alert-dialog').remove()" style="
                        background: #ff9800;
                        color: white;
                        border: none;
                        padding: 12px 25px;
                        border-radius: 25px;
                        cursor: pointer;
                        font-size: 16px;
                        margin: 5px;
                        font-weight: bold;
                      ">I Understand</button>
                      <button onclick="window.history.back()" style="
                        background: #4CAF50;
                        color: white;
                        border: none;
                        padding: 12px 25px;
                        border-radius: 25px;
                        cursor: pointer;
                        font-size: 16px;
                        margin: 5px;
                      ">Go Back</button>
                    `
                  }
                </div>
                
                <p style="
                  font-size: 12px;
                  color: #999;
                  margin-top: 20px;
                  border-top: 1px solid #eee;
                  padding-top: 15px;
                ">
                  Protected by Phishing Detector<br>
                  Created by Anthony Frederick
                </p>
              </div>
            </div>
          `;
          
          // Remove any existing alert
          const existingAlert = document.getElementById('phishing-alert-dialog');
          if (existingAlert) {
            existingAlert.remove();
          }
          
          // Add new alert
          document.body.appendChild(alertDialog);
          
          // Auto-dismiss warning alerts after 15 seconds
          if (alertType === 'WARNING') {
            setTimeout(() => {
              const alertEl = document.getElementById('phishing-alert-dialog');
              if (alertEl) {
                alertEl.remove();
              }
            }, 15000);
          }
          
          // Play alert sound if available
          try {
            const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmMZBDGOzvHZeSEEJ37e9N2ZTAoRZ7vs7qpVFAlEn+L2wmIXBDKNzPDYeCADJ3zd8tyYTQcQarf02qtWFQdCnt9vMH...');
            audio.volume = 0.3;
            audio.play().catch(() => {}); // Ignore errors
          } catch (e) {}
        },
        args: [domain, riskScore, alertType, url]
      });
      
      // Show browser notification for additional alerting
      this.showNotification(domain, riskScore, alertType);
      
    } catch (error) {
      console.error('Error showing phishing alert:', error);
    }
  }

  showNotification(domain, riskScore, alertType) {
    try {
      const notificationOptions = {
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: alertType === 'BLOCKED' ? '🚫 Phishing Site Blocked!' : '⚠️ Suspicious Site Detected!',
        message: `Domain: ${domain}\nRisk Score: ${riskScore}/100\n\n${
          alertType === 'BLOCKED' 
            ? 'This phishing site has been blocked for your protection.'
            : 'This site shows suspicious characteristics. Please proceed with caution.'
        }`,
        contextMessage: 'Phishing Detector by Anthony Frederick',
        priority: alertType === 'BLOCKED' ? 2 : 1,
        requireInteraction: alertType === 'BLOCKED',
        buttons: alertType === 'BLOCKED' 
          ? [{ title: 'View Details' }, { title: 'Report False Positive' }]
          : [{ title: 'View Details' }, { title: 'Continue Anyway' }]
      };

      chrome.notifications.create(`phishing-alert-${Date.now()}`, notificationOptions);
      
    } catch (error) {
      console.error('Error showing notification:', error);
    }
  }

  async blockPhishingSite(tabId, url, riskScore) {
    try {
      // Add to suspicious domains
      const domain = new URL(url).hostname;
      this.suspiciousDomains.add(domain);
      await this.saveSuspiciousDomains();

      // Inject blocking page using modern scripting API
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: (riskScore) => {
          document.documentElement.innerHTML = `
            <style>
              body { 
                font-family: Arial, sans-serif; 
                background: #f44336; 
                color: white; 
                text-align: center; 
                padding: 50px; 
                margin: 0;
              }
              .warning { 
                background: white; 
                color: #333; 
                padding: 30px; 
                border-radius: 10px; 
                max-width: 600px; 
                margin: 0 auto; 
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
              }
              .risk-score { 
                font-size: 24px; 
                font-weight: bold; 
                color: #f44336; 
              }
              .blocked-icon {
                font-size: 60px;
                margin-bottom: 20px;
              }
              button {
                background: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
                margin: 10px;
              }
              button:hover {
                background: #45a049;
              }
            </style>
            <div class="warning">
              <div class="blocked-icon">🛡️</div>
              <h1>⚠️ PHISHING SITE BLOCKED</h1>
              <p><strong>This website has been identified as a potential phishing site.</strong></p>
              <p>Domain: <code>${window.location.hostname}</code></p>
              <p class="risk-score">Risk Score: ${riskScore}/100</p>
              <p>This site appears to be impersonating a legitimate service to steal your personal information.</p>
              <p><strong>For your safety, access has been blocked by Phishing Detector.</strong></p>
              <button onclick="history.back()">← Go Back</button>
              <button onclick="window.close()">Close Tab</button>
            </div>
          `;
        },
        args: [riskScore]
      });
    } catch (error) {
      console.error('Error blocking phishing site:', error);
    }
  }

  async warnUser(tabId, url, riskScore) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: (riskScore, hostname) => {
          if (!document.querySelector('#phishing-warning')) {
            const warning = document.createElement('div');
            warning.id = 'phishing-warning';
            warning.innerHTML = `
              <div style="
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: linear-gradient(135deg, #ff9800, #f57c00);
                color: white;
                padding: 15px;
                text-align: center;
                z-index: 2147483647;
                font-family: Arial, sans-serif;
                box-shadow: 0 2px 10px rgba(0,0,0,0.3);
                animation: slideDown 0.3s ease-out;
              ">
                <style>
                  @keyframes slideDown {
                    from { transform: translateY(-100%); }
                    to { transform: translateY(0); }
                  }
                </style>
                <span style="font-size: 20px; margin-right: 10px;">⚠️</span>
                <strong>SUSPICIOUS SITE DETECTED</strong><br>
                <small>Domain: ${hostname} | Risk Score: ${riskScore}/100</small>
                <button onclick="this.parentElement.parentElement.remove()" style="
                  margin-left: 15px;
                  background: rgba(255,255,255,0.2);
                  color: white;
                  border: 1px solid rgba(255,255,255,0.3);
                  padding: 5px 15px;
                  border-radius: 15px;
                  cursor: pointer;
                  font-size: 12px;
                ">Dismiss</button>
              </div>
            `;
            document.body.appendChild(warning);
            
            // Auto-dismiss after 10 seconds
            setTimeout(() => {
              const warningEl = document.querySelector('#phishing-warning');
              if (warningEl) {
                warningEl.remove();
              }
            }, 10000);
          }
        },
        args: [riskScore, new URL(url).hostname]
      });
    } catch (error) {
      console.error('Error showing warning:', error);
    }
  }

  updateBadge(tabId, riskScore) {
    let badgeText = '';
    let badgeColor = '#4CAF50'; // Green for safe

    if (riskScore > 60) { // Updated to match new threshold
      badgeText = '🚫';
      badgeColor = '#f44336'; // Red for high risk
    } else if (riskScore > 30) { // Updated to match new threshold
      badgeText = '⚠';
      badgeColor = '#ff9800'; // Orange for medium risk
    } else if (riskScore > 0) {
      badgeText = '✓';
      badgeColor = '#4CAF50'; // Green for analyzed
    }

    chrome.action.setBadgeText({ text: badgeText, tabId });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
  }

  async updateDetectionStats(riskScore) {
    try {
      const result = await chrome.storage.local.get(['stats']);
      const stats = result.stats || { sitesBlocked: 0, threatsDetected: 0, alertsShown: 0 };
      
      if (riskScore > 60) {
        stats.sitesBlocked = (stats.sitesBlocked || 0) + 1;
      }
      
      if (riskScore > 30) {
        stats.threatsDetected = (stats.threatsDetected || 0) + 1;
        stats.alertsShown = (stats.alertsShown || 0) + 1;
      }
      
      await chrome.storage.local.set({ stats });
    } catch (error) {
      console.error('Error updating detection stats:', error);
    }
  }
}

// Initialize the phishing detector
// Created and developed by Anthony Frederick, 2024
const phishingDetector = new PhishingDetector();

// Handle notification clicks
chrome.notifications.onClicked.addListener((notificationId) => {
  console.log('Notification clicked:', notificationId);
  // Open extension popup or focus tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.tabs.update(tabs[0].id, { active: true });
    }
  });
  chrome.notifications.clear(notificationId);
});

chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  console.log('Notification button clicked:', notificationId, buttonIndex);
  
  if (buttonIndex === 0) { // View Details
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.action.openPopup();
      }
    });
  } else if (buttonIndex === 1) { // Report False Positive or Continue Anyway
    // Handle based on alert type - could open a form or override warning
    console.log('User action:', buttonIndex === 1 ? 'Report/Continue' : 'Unknown');
  }
  
  chrome.notifications.clear(notificationId);
});

// Handle messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getAnalysis') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.storage.local.get([`analysis_${tabs[0].id}`], (result) => {
          sendResponse(result[`analysis_${tabs[0].id}`] || null);
        });
      }
    });
    return true;
  }
  
  if (request.action === 'reportPhishing') {
    const domain = new URL(request.url).hostname;
    phishingDetector.suspiciousDomains.add(domain);
    phishingDetector.saveSuspiciousDomains();
    sendResponse({ success: true });
  }
});