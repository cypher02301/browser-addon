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
      
      if (riskScore > 70) {
        this.blockPhishingSite(tabId, url, riskScore);
      } else if (riskScore > 40) {
        this.warnUser(tabId, url, riskScore);
      }

      // Update badge based on risk
      this.updateBadge(tabId, riskScore);
      
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
    let score = 0;
    const domain = urlObj.hostname.toLowerCase();
    const fullUrl = urlObj.href.toLowerCase();

    // Check if domain is whitelisted
    if (this.whitelistedDomains.has(domain)) {
      return 0;
    }

    // Check suspicious domains
    if (this.suspiciousDomains.has(domain)) {
      score += 80;
    }

    // Domain analysis
    score += this.analyzeDomain(domain);
    
    // URL structure analysis
    score += this.analyzeUrlStructure(urlObj);
    
    // Content pattern analysis (for full URL)
    score += this.analyzePatterns(fullUrl);

    return Math.min(score, 100);
  }

  analyzeDomain(domain) {
    let score = 0;
    
    // Suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq'];
    if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
      score += 30;
    }

    // Domain length (very long domains are suspicious)
    if (domain.length > 30) {
      score += 15;
    }

    // Excessive subdomains
    const subdomains = domain.split('.').length - 2;
    if (subdomains > 3) {
      score += 20;
    }

    // Contains digits mixed with letters
    if (/\d/.test(domain) && /[a-z]/.test(domain)) {
      score += 10;
    }

    // Homograph attack detection (basic)
    if (this.detectHomograph(domain)) {
      score += 40;
    }

    // Check for brand impersonation
    score += this.checkBrandImpersonation(domain);

    return score;
  }

  analyzeUrlStructure(urlObj) {
    let score = 0;
    
    // Check for URL shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
    if (shorteners.includes(urlObj.hostname)) {
      score += 25;
    }

    // Suspicious path patterns
    if (urlObj.pathname.includes('..')) {
      score += 30;
    }

    // Very long URLs
    if (urlObj.href.length > 100) {
      score += 10;
    }

    // Multiple redirections indicators
    if (urlObj.search.includes('redirect') || urlObj.search.includes('url=')) {
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
      'apple', 'netflix', 'instagram', 'twitter', 'linkedin'
    ];
    
    for (const brand of popularBrands) {
      if (domain.includes(brand) && !domain.endsWith(`${brand}.com`)) {
        return 35;
      }
    }
    return 0;
  }

  async blockPhishingSite(tabId, url, riskScore) {
    try {
      // Add to suspicious domains
      const domain = new URL(url).hostname;
      this.suspiciousDomains.add(domain);
      await this.saveSuspiciousDomains();

      // Inject blocking page
      await chrome.tabs.executeScript(tabId, {
        code: `
          document.documentElement.innerHTML = \`
            <style>
              body { 
                font-family: Arial, sans-serif; 
                background: #f44336; 
                color: white; 
                text-align: center; 
                padding: 50px; 
              }
              .warning { 
                background: white; 
                color: #333; 
                padding: 30px; 
                border-radius: 10px; 
                max-width: 600px; 
                margin: 0 auto; 
              }
              .risk-score { 
                font-size: 24px; 
                font-weight: bold; 
                color: #f44336; 
              }
            </style>
            <div class="warning">
              <h1>⚠️ PHISHING SITE BLOCKED</h1>
              <p>This website has been identified as a potential phishing site.</p>
              <p class="risk-score">Risk Score: ${riskScore}/100</p>
              <p>For your safety, access has been blocked.</p>
              <button onclick="history.back()">Go Back</button>
            </div>
          \`;
        `
      });
    } catch (error) {
      console.error('Error blocking phishing site:', error);
    }
  }

  async warnUser(tabId, url, riskScore) {
    try {
      await chrome.tabs.executeScript(tabId, {
        code: `
          if (!document.querySelector('#phishing-warning')) {
            const warning = document.createElement('div');
            warning.id = 'phishing-warning';
            warning.innerHTML = \`
              <div style="
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: #ff9800;
                color: white;
                padding: 10px;
                text-align: center;
                z-index: 10000;
                font-family: Arial, sans-serif;
              ">
                ⚠️ Warning: This site may be suspicious (Risk: ${riskScore}/100)
                <button onclick="this.parentElement.parentElement.remove()" style="
                  margin-left: 10px;
                  background: white;
                  color: #ff9800;
                  border: none;
                  padding: 5px 10px;
                  border-radius: 3px;
                  cursor: pointer;
                ">Dismiss</button>
              </div>
            \`;
            document.body.appendChild(warning);
          }
        `
      });
    } catch (error) {
      console.error('Error showing warning:', error);
    }
  }

  updateBadge(tabId, riskScore) {
    let badgeText = '';
    let badgeColor = '#4CAF50'; // Green for safe

    if (riskScore > 70) {
      badgeText = '⚠';
      badgeColor = '#f44336'; // Red for high risk
    } else if (riskScore > 40) {
      badgeText = '⚡';
      badgeColor = '#ff9800'; // Orange for medium risk
    }

    chrome.action.setBadgeText({ text: badgeText, tabId });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
  }
}

// Initialize the phishing detector
const phishingDetector = new PhishingDetector();

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