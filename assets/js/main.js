document.addEventListener('DOMContentLoaded', () => {
    /* ----------------------------------------------------
       1. THEME MANAGEMENT (Dark/Light)
       ---------------------------------------------------- */
    const themeToggleBtn = document.getElementById('theme-toggle');
    const htmlElement = document.documentElement;
    
    if (themeToggleBtn) {
        const savedTheme = localStorage.getItem('theme');
        const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      
        const applyTheme = (theme) => {
            htmlElement.setAttribute('data-theme', theme);
            themeToggleBtn.textContent = theme === 'light' ? '🌙' : '☀️';
            themeToggleBtn.setAttribute(
                'aria-label',
                theme === 'light' ? 'Switch to dark theme' : 'Switch to light theme'
            );
        };

        if (savedTheme) {
            applyTheme(savedTheme);
        } else if (systemPrefersDark) {
            applyTheme('dark');
        } else {
            applyTheme('light');
        }
      
        themeToggleBtn.addEventListener('click', () => {
            const currentTheme = htmlElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            applyTheme(newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }
  
    /* ----------------------------------------------------
       2. AI STUDIO VIBE: AUTO-RESIZE TEXTAREA
       ---------------------------------------------------- */
    const textareas = document.querySelectorAll('.auto-resize-textarea');
    
    textareas.forEach(textarea => {
        const resize = () => {
            textarea.style.height = 'auto'; 
            textarea.style.height = `${textarea.scrollHeight}px`; 
        };
        
        textarea.addEventListener('input', resize);
        requestAnimationFrame(resize);
    });
  
    /* ----------------------------------------------------
       3. PANEL TOGGLING & RESPONSIVE ISOLATION (900px)
       ---------------------------------------------------- */
    const settingsBtn = document.getElementById('settings-toggle');
    const settingsPanel = document.getElementById('settings-panel');
    const menuBtn = document.getElementById('menu-toggle');
    const sidebar = document.getElementById('sidebar-nav');

    const syncPanelStates = () => {
        if (window.innerWidth <= 900) {
            if (sidebar) {
                sidebar.classList.remove('active', 'collapsed');
            }
            if (menuBtn) {
                menuBtn.setAttribute('aria-expanded', 'false');
            }
            if (settingsPanel) {
                settingsPanel.classList.remove('active', 'collapsed');
                settingsPanel.classList.add('hidden-mobile');
            }
            if (settingsBtn) {
                settingsBtn.setAttribute('aria-expanded', 'false');
            }
        } else {
            if (sidebar) {
                sidebar.classList.remove('active', 'collapsed');
            }
            if (settingsPanel) {
                settingsPanel.classList.remove('active', 'hidden-mobile');
                const isExpanded = !settingsPanel.classList.contains('collapsed');
                if (settingsBtn) {
                    settingsBtn.setAttribute('aria-expanded', String(isExpanded));
                }
            }
        }
    };

    syncPanelStates();

    let lastIsMobile = window.innerWidth <= 900;
    window.addEventListener('resize', () => {
        const currentIsMobile = window.innerWidth <= 900;
        if (currentIsMobile !== lastIsMobile) {
            lastIsMobile = currentIsMobile;
            syncPanelStates();
        }
    });

    // Toggle Right Panel (Settings / ToC)
    if (settingsBtn && settingsPanel) {
        settingsBtn.addEventListener('click', () => {
            let isExpanded = false;
            if (window.innerWidth > 900) {
                settingsPanel.classList.toggle('collapsed');
                isExpanded = !settingsPanel.classList.contains('collapsed');
            } else {
                if (sidebar && sidebar.classList.contains('active')) {
                    sidebar.classList.remove('active');
                    if (menuBtn) menuBtn.setAttribute('aria-expanded', 'false');
                }
                settingsPanel.classList.remove('hidden-mobile');
                settingsPanel.classList.toggle('active');
                isExpanded = settingsPanel.classList.contains('active');
            }
            settingsBtn.setAttribute('aria-expanded', String(isExpanded));
        });
    }

    // Toggle Left Sidebar (Mobile/Tablet <= 900px Only)
    if (menuBtn && sidebar) {
        menuBtn.addEventListener('click', () => {
            if (window.innerWidth <= 900) {
                if (settingsPanel && settingsPanel.classList.contains('active')) {
                    settingsPanel.classList.remove('active');
                    settingsPanel.classList.add('hidden-mobile');
                    if (settingsBtn) settingsBtn.setAttribute('aria-expanded', 'false');
                }
                sidebar.classList.toggle('active');
                const isExpanded = sidebar.classList.contains('active');
                menuBtn.setAttribute('aria-expanded', String(isExpanded));
            }
        });
    }
  
    /* ----------------------------------------------------
       4. KEYBOARD SHORTCUTS
       ---------------------------------------------------- */
    document.addEventListener('keydown', (e) => {
        // Close mobile drawers on Escape
        if (e.key === 'Escape' && window.innerWidth <= 900) {
            if (sidebar && sidebar.classList.contains('active')) {
                sidebar.classList.remove('active');
                if (menuBtn) menuBtn.setAttribute('aria-expanded', 'false');
            }
            if (settingsPanel && settingsPanel.classList.contains('active')) {
                settingsPanel.classList.remove('active');
                settingsPanel.classList.add('hidden-mobile');
                if (settingsBtn) settingsBtn.setAttribute('aria-expanded', 'false');
            }
        }

        // Focus search bar on '/'
        if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
            const searchBar = document.querySelector('.search-bar');
            if (searchBar) {
                e.preventDefault();
                searchBar.focus();
            }
        }
        
        // Execute Shortcut: Ctrl/Cmd + Enter
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            const processBtn = document.getElementById('btn-process');
            if (processBtn) {
                e.preventDefault();
                processBtn.click();
                
                processBtn.classList.add('is-pressed');
                setTimeout(() => processBtn.classList.remove('is-pressed'), 100);
            }
        }
    });

    /* ----------------------------------------------------
       5. PWA SERVICE WORKER REGISTRATION (Global)
       ---------------------------------------------------- */
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/sw.js')
                .then(() => console.log('VTools SW Registered'))
                .catch(err => console.error('VTools SW Registration Failed', err));
        });
    }
});