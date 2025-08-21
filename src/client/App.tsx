import React, { useState, useEffect } from 'react';
import './App.css';

// 定义平台类型
type Platform = 'linux' | 'macos' | 'windows';

// 定义下载项接口
interface DownloadItem {
  platform: Platform;
  name: string;
  description: string;
  isAvailable: boolean;
  icon: string;
}

const App: React.FC = () => {
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [isLoading, setIsLoading] = useState<Platform | null>(null);

  // 切换暗黑模式
  const toggleDarkMode = () => {
    setIsDarkMode(!isDarkMode);
  };

  // 在组件挂载时检查系统主题偏好
  useEffect(() => {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    setIsDarkMode(prefersDark);
  }, []);

  // 应用主题到body
  useEffect(() => {
    if (isDarkMode) {
      document.body.classList.add('dark-mode');
    } else {
      document.body.classList.remove('dark-mode');
    }
  }, [isDarkMode]);

  // 获取下载链接并触发下载
  const fetchAndDownload = async (platform: Platform) => {
    try {
      setIsLoading(platform);
      
      // 调用后端 API 获取下载链接
      const response = await fetch(`/v1/lightnode/ezdeploy/${platform}`);
      
      if (!response.ok) {
        throw new Error(`获取下载链接失败: ${response.status} ${response.statusText}`);
      }
      
      // 获取后端返回的完整URL
      let downloadUrl: string = await response.text();
      
      // 去除可能存在的首尾引号
      downloadUrl = downloadUrl.replace(/^"(.*)"$/, '$1');
      
      // 验证URL是否有效
      try {
        new URL(downloadUrl);
      } catch (e) {
        throw new Error(`无效的下载链接: ${downloadUrl}`);
      }
      
      // 触发下载
      triggerDownload(downloadUrl, platform);
    } catch (error) {
      console.error('下载失败:', error);
      alert(`下载失败: ${(error as Error).message}`);
    } finally {
      setIsLoading(null);
    }
  };

  // 触发文件下载
  const triggerDownload = (url: string, platform: Platform) => {
    const link = document.createElement('a');
    link.href = url;
    link.download = `fisco_ezdeploy_${platform}`; // 可执行文件名
    link.target = '_blank'; // 在新标签页中打开链接
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // 定义下载项列表
  const downloadItems: DownloadItem[] = [
    {
      platform: 'linux',
      name: 'Linux',
      description: '适用于大多数 Linux 发行版 (x86_64)',
      isAvailable: true,
      icon: 'L',
    },
    {
      platform: 'macos',
      name: 'macOS',
      description: '适用于 macOS 10.15 及以上版本 (Intel/Apple Silicon)',
      isAvailable: true,
      icon: 'M',
    },
    {
      platform: 'windows',
      name: 'Windows',
      description: '敬请期待',
      isAvailable: false,
      icon: 'W',
    },
  ];

  // 处理下载
  const handleDownload = async (platform: Platform) => {
    if (platform === 'windows') {
      alert('Windows 版本敬请期待！');
      return;
    }
    
    await fetchAndDownload(platform);
  };

  return (
    <div className="app-container">
      {/* 主导航栏 */}
      <nav className="navbar glass-effect">
        <div className="nav-brand">
          <h2>FISCO EZDeploy</h2>
        </div>
        <div className="nav-actions">
          <button 
            className="theme-toggle glass-button"
            onClick={toggleDarkMode}
            aria-label="切换主题"
          >
            {isDarkMode ? '☀️' : '🌙'}
          </button>
        </div>
      </nav>

      {/* 主要内容区域 */}
      <main className="main-content">
        <section className="hero-section">
          <div className="hero-content glass-card">
            <h1 className="hero-title">FISCO 区块链一键部署工具</h1>
            <p className="hero-description">
              EZDeploy 让您能够快速、轻松地部署和管理 FISCO BCOS 区块链网络。
              无论您是开发者、企业用户还是区块链爱好者，都能通过我们的工具快速上手。
            </p>
            <div className="hero-stats">
              <div className="stat-item">
                <span className="stat-number">10分钟</span>
                <span className="stat-label">快速部署</span>
              </div>
              <div className="stat-item">
                <span className="stat-number">3步</span>
                <span className="stat-label">简单操作</span>
              </div>
              <div className="stat-item">
                <span className="stat-number">100%</span>
                <span className="stat-label">开源免费</span>
              </div>
            </div>
          </div>
        </section>

        <section className="download-section">
          <div className="section-header">
            <h2>选择您的平台</h2>
            <p>获取适用于您操作系统的 EZDeploy 工具</p>
          </div>
          
          <div className="download-grid">
            {downloadItems.map((item) => (
              <div 
                key={item.platform} 
                className={`download-card glass-card ${item.isAvailable ? 'available' : 'unavailable'}`}
              >
                <div className="platform-icon">
                  {item.icon}
                </div>
                <div className="card-content">
                  <h3>{item.name}</h3>
                  <p className="platform-description">{item.description}</p>
                  <button 
                    onClick={() => handleDownload(item.platform)}
                    disabled={!item.isAvailable || isLoading === item.platform}
                    className={`download-button ${item.isAvailable ? 'primary' : 'secondary'} ${isLoading === item.platform ? 'loading' : ''}`}
                  >
                    {isLoading === item.platform ? (
                      <span className="button-content">
                        <span className="spinner"></span>
                        获取中...
                      </span>
                    ) : item.isAvailable ? (
                      '立即下载'
                    ) : (
                      '敬请期待'
                    )}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="features-section">
          <div className="section-header">
            <h2>为什么选择 EZDeploy</h2>
            <p>我们致力于为您提供最简单、最高效的区块链部署体验</p>
          </div>
          
          <div className="features-grid">
            <div className="feature-card glass-card">
              <div className="feature-icon">⚡</div>
              <h3>极速部署</h3>
              <p>无需复杂的配置，一键完成区块链网络的部署</p>
            </div>
            
            <div className="feature-card glass-card">
              <div className="feature-icon">🔒</div>
              <h3>安全可靠</h3>
              <p>采用企业级安全标准，保障您的区块链网络稳定运行</p>
            </div>
            
            <div className="feature-card glass-card">
              <div className="feature-icon">🔄</div>
              <h3>灵活扩展</h3>
              <p>支持动态添加节点，轻松实现网络扩容</p>
            </div>
            
            <div className="feature-card glass-card">
              <div className="feature-icon">🌐</div>
              <h3>多平台支持</h3>
              <p>支持主流操作系统，满足不同环境下的部署需求</p>
            </div>
          </div>
        </section>

        <section className="instructions-section">
          <div className="section-header">
            <h2>使用说明</h2>
            <p>简单三步，快速部署您的区块链网络</p>
          </div>
          
          <div className="instructions-steps">
            <div className="instruction-step glass-card">
              <div className="step-number">1</div>
              <h3>下载工具</h3>
              <p>选择您的操作系统并下载对应的 EZDeploy 工具</p>
            </div>
            
            <div className="instruction-step glass-card">
              <div className="step-number">2</div>
              <h3>运行工具</h3>
              <p>在终端中运行下载的可执行文件，按照提示完成配置</p>
            </div>
            
            <div className="instruction-step glass-card">
              <div className="step-number">3</div>
              <h3>启动网络</h3>
              <p>工具将自动完成区块链网络的部署和启动</p>
            </div>
          </div>
        </section>
      </main>

      {/* 页脚 */}
      <footer className="app-footer glass-effect">
        <div className="footer-content">
          <div className="footer-info">
            <h3>FISCO BCOS</h3>
            <p>企业级区块链底层平台</p>
          </div>
          <div className="footer-links">
            <a href="https://fisco-bcos.org" className="footer-link" target="_blank" rel="noopener noreferrer">官网</a>
            <a href="https://github.com/FISCO-BCOS" className="footer-link" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a href="https://fisco-bcos.org/docs/" className="footer-link" target="_blank" rel="noopener noreferrer">文档</a>
          </div>
        </div>
        <div className="footer-bottom">
          <p>&copy; 2025 FISCO BCOS. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
};

export default App;
